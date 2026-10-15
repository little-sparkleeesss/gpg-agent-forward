package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 预检两件事都靠真跑而非匹配命令文本: 所防缺陷只在运行时行为里显现.
// 分类要一个真绑本地端口, 连远端路径的ssh, 由TestForwardSSHHelper重执行本测试二进制充当:
// 是被测生产代码classifyRemoteSocket的对端, 不是mock.

func requireShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the remote command is a POSIX shell command")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("sh is not on PATH to run the command with: %v", err)
	}
}

// 替换而非追加`PATH`: 重复的`PATH`会让子进程继续用继承来的那份.
func envWithPath(path string) []string {
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "PATH=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "PATH="+path)
}

// 像远端登录shell那样把命令串交给`sh`跑, 并由`PATH`决定远端能找到什么.
func localProbeRunner(path string) SSHCommandRunner {
	return func(_ []string, remoteCommand string) (string, error) {
		cmd := exec.Command("sh", "-c", remoteCommand)
		cmd.Env = envWithPath(path)
		out, err := cmd.Output()
		return string(out), err
	}
}

// 只有shell的`PATH`, 代表一台什么工具都没有的远端主机: 形态命令的答案全来自
// shell自带的测试, 那台主机可以没有`ss`, `grep`, `sed`, `readlink`, `stat`.
func pathWithOnlySh(t *testing.T) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh is not on PATH: %v", err)
	}
	dir := t.TempDir()
	if err := os.Symlink(sh, filepath.Join(dir, "sh")); err != nil {
		t.Fatalf("link sh into an otherwise empty PATH: %v", err)
	}
	return dir
}

// 关掉unix监听器默认会连socket文件一起删掉.
func listenAt(t *testing.T, path string) *net.UnixListener {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on %s: %v", path, err)
	}
	return l.(*net.UnixListener)
}

// 造一个无人监听的socket文件: 已结束的会话转发留下的状态, 检查唯一允许删的东西.
func deadSocketAt(t *testing.T, path string) {
	t.Helper()
	l := listenAt(t, path)
	l.SetUnlinkOnClose(false)
	if err := l.Close(); err != nil {
		t.Fatalf("close the listener for %s: %v", path, err)
	}
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket file after closing the listener: %v, %v", path, fi, err)
	}
}

func socketFileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	return err == nil
}

// 造一个接受连接但一言不发的socket: `gpg-agent`就长这样, 分类把它读作live.
func liveSocketAt(t *testing.T, path string) net.Listener {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on %s: %v", path, err)
	}
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				c.Close()
			}
		}()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	return l
}

// 探针在被测路径旁创建控制socket, 两者要一起挤进`sun_path`的107字节上限:
// `t.TempDir`把用例全名编进路径, 名字长的用例会因此撞上限, 与被测行为无关.
// 路径要够短的用例改用本helper, 免得用例名一长就得到与检查无关的失败.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gpg-agent-forward-")
	if err != nil {
		t.Fatalf("make a short scratch directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// 分类命令与形态命令受同一套约束: 单行, 且路径的字节不上命令行; 单行由这两条钉住.
func TestRemoteSocketConnectCommandIsOneLineUnderSh(t *testing.T) {
	// 与形态命令同理: 远端登录shell可能是csh/tcsh, 跨行的引号串它直接拒绝, 之后就什么都不跑.
	cmd := remoteSocketConnect("/run/user/1000/gnupg/S.gpg-agent")
	if strings.ContainsAny(cmd, "\n\r") {
		t.Errorf("command %q spans lines, which the remote login shell refuses to parse", cmd)
	}
	if !strings.HasPrefix(cmd, "sh -c ") {
		t.Errorf("command %q does not run its body under sh", cmd)
	}
}

// 替身解释器: sh脚本, 把收到的路径 (python/perl的体都从argv取路径, 在-c/-e后面, 故是$3)
// 写进evidence, 再打印word; word为空就是"什么都没答", 级联应当继续找下一个.
func fakeInterpreter(t *testing.T, dir, name, word, evidence string) {
	t.Helper()
	body := "#!/bin/sh\n"
	if evidence != "" {
		body += "printf '%s\\n' \"$3\" > " + shellQuoteSingle(evidence) + "\n"
	}
	if word != "" {
		body += "printf '%s\\n' " + shellQuoteSingle(word) + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		t.Fatalf("write the %s stand-in: %v", name, err)
	}
}

// 一个只有sh的PATH加若干替身解释器; sh要在场, 分类命令的外层靠它跑.
func fakeInterpreterDir(t *testing.T) string {
	t.Helper()
	requireShell(t)
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh is not on PATH: %v", err)
	}
	dir := t.TempDir()
	if err := os.Symlink(sh, filepath.Join(dir, "sh")); err != nil {
		t.Fatalf("link sh into the stand-in PATH: %v", err)
	}
	return dir
}

// connectCommandOutput跑分类命令, 原样返回它的输出: 断言既能看判定, 也能看标记行本身.
func connectCommandOutput(t *testing.T, path, pathEnv string) string {
	t.Helper()
	out, err := localProbeRunner(pathEnv)([]string{"host"}, remoteSocketConnect(path))
	if err != nil {
		t.Fatalf("running the classify command for %s failed: %v (output %q)", path, err, out)
	}
	return out
}

func TestRemoteSocketConnectUsesTheInterpretersItFindsInOrder(t *testing.T) {
	// 顺序取第一个能答话的: python3在python前, python在perl前; 被问到的替身留下证据.
	dir := fakeInterpreterDir(t)
	silent, spoken := filepath.Join(dir, "silent.evidence"), filepath.Join(dir, "spoken.evidence")
	fakeInterpreter(t, dir, "python3", "", silent)
	fakeInterpreter(t, dir, "python", "refused", spoken)

	out := connectCommandOutput(t, "/run/user/1000/gnupg/S.gpg-agent", dir)
	verdict, _ := parseSocketConnectVerdict(out)
	if verdict != connectRefused {
		t.Errorf("verdict = %v from output %q, want connectRefused from the second interpreter", verdict, out)
	}
	if _, err := os.Stat(silent); err != nil {
		t.Errorf("the first interpreter was not asked: %v", err)
	}
	if _, err := os.Stat(spoken); err != nil {
		t.Errorf("the cascade did not reach the second interpreter: %v", err)
	}
}

func TestRemoteSocketConnectReportsNoneWhenNoInterpreterIsThere(t *testing.T) {
	// 一台只有shell的主机: 分类没有连接器可用, 标记none让调用方退回sshd转发那条路.
	bare := pathWithOnlySh(t)
	out := connectCommandOutput(t, "/run/user/1000/gnupg/S.gpg-agent", bare)
	if !strings.Contains(out, socketConnectNoneMarker) {
		t.Errorf("output %q should carry %s on a host with no interpreter", out, socketConnectNoneMarker)
	}
	if verdict, _ := parseSocketConnectVerdict(out); verdict != connectNoVerdict {
		t.Errorf("verdict = %v, want connectNoVerdict when nothing reported", verdict)
	}
}

func TestRemoteSocketConnectKeepsItsVerdictToTheWordsItKnows(t *testing.T) {
	// 解释器打了别的东西 (坏了, 或者主机换了一个同名程序): 不是判定, 调用方照旧fail-closed.
	dir := fakeInterpreterDir(t)
	fakeInterpreter(t, dir, "python3", "banana", "")
	out := connectCommandOutput(t, "/run/user/1000/gnupg/S.gpg-agent", dir)
	if verdict, _ := parseSocketConnectVerdict(out); verdict != connectNoVerdict {
		t.Errorf("verdict = %v from output %q, want connectNoVerdict for a word this tool does not know", verdict, out)
	}
}

func TestRemoteSocketConnectNeverPutsThePathOnTheCommandLine(t *testing.T) {
	// 与形态命令同理: csh/tcsh连单引号里也做历史展开与变量替换, 路径的字节只能走八进制.
	requireShell(t)
	canary := filepath.Join(t.TempDir(), "canary")
	paths := []string{
		"/run/user/1000/gnupg!bang/S.gpg-agent",
		"/run/user/1000/gnupg%h/S.gpg-agent",
		"/run/user/1000/it's/S.gpg-agent",
		"/run/user/1000/with space/S.gpg-agent",
		"/run/user/1000/`id`/$HOME/S.gpg-agent",
		"/run/user/1000/back\\slash/S.gpg-agent",
		"/run/user/1000/gnupg-\xe4\xbb\xa3\xe7\x90\x86/S.gpg-agent",
		"/run/user/1000/x';touch " + canary + ";'/S.gpg-agent",
	}
	command := remoteSocketConnect(paths[0])
	for _, path := range paths {
		if strings.Contains(strings.ReplaceAll(command, paths[0], ""), path) {
			t.Errorf("command carries %q verbatim:\n%s", path, command)
		}
	}
	// 解码往返: 替身把收到的路径写出来, 应与给的字节逐个相同.
	dir := fakeInterpreterDir(t)
	evidence := filepath.Join(t.TempDir(), "evidence")
	fakeInterpreter(t, dir, "python3", "refused", evidence)
	for _, path := range paths {
		out := connectCommandOutput(t, path, dir)
		if verdict, _ := parseSocketConnectVerdict(out); verdict != connectRefused {
			t.Fatalf("verdict = %v from output %q for %q", verdict, out, path)
		}
		got, err := os.ReadFile(evidence)
		if err != nil {
			t.Fatalf("the stand-in interpreter recorded nothing for %q: %v", path, err)
		}
		if strings.TrimRight(string(got), "\n") != path {
			t.Errorf("the interpreter was handed %q, want %q", strings.TrimRight(string(got), "\n"), path)
		}
	}
	if _, err := os.Stat(canary); err == nil {
		t.Errorf("%s exists: a byte of the path was run as a command", canary)
	}
}

func TestRemoteSocketConnectCommandRunsUnderTcsh(t *testing.T) {
	// FreeBSD root登录时sshd用的shell; `-f`跳过cshrc, 只量命令不量登录环境.
	tcsh, err := exec.LookPath("tcsh")
	if err != nil {
		t.Skip("tcsh is not installed; TestRemoteSocketConnectCommandIsOneLineUnderSh covers the shape it rejects")
	}
	dir := shortTempDir(t)
	dead := filepath.Join(dir, "dead.sock")
	deadSocketAt(t, dead)
	paths := map[string]string{
		"an ordinary path": dead,
		"a path with the characters csh and tcsh read twice": filepath.Join(dir, "gpg!agent%h$HOME`id`"),
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			out, err := exec.Command(tcsh, "-f", "-c", remoteSocketConnect(path)).Output()
			if err != nil {
				t.Fatalf("tcsh could not run the command: %v (output %q)", err, out)
			}
			want := connectAbsent
			if path == dead {
				want = connectRefused
			}
			if got, _ := parseSocketConnectVerdict(string(out)); got != want {
				t.Errorf("verdict = %v from output %q, want %v", got, out, want)
			}
		})
	}
}

// 连接器归用户域: 远端gpg就是那么连过去的. 每种结果一个用例, 判定必须是它自己给的errno,
// 没有可猜的余地 (这也正是它不需要sshd那条路的正向控制的原因).
func TestRemoteSocketConnectReportsWhatIsAtThePath(t *testing.T) {
	requireShell(t)
	if _, err := anySocketInterpreter(); err != nil {
		t.Skipf("no python3, python or perl to run the classifier with: %v", err)
	}
	dir := shortTempDir(t)
	dead := filepath.Join(dir, "dead.sock")
	deadSocketAt(t, dead)
	live := filepath.Join(dir, "live.sock")
	l := liveSocketAt(t, live)
	defer l.Close()
	greeter := filepath.Join(dir, "greeter.sock")
	g := greeterSocketAt(t, greeter)
	defer g.Close()
	closer := filepath.Join(dir, "closer.sock")
	c := closingSocketAt(t, closer)
	defer c.Close()
	// 连接都不是"没人监听"也不是"有监听者"的错误: 判不了, 调用方照旧拒绝.
	loop := filepath.Join(dir, "loop.sock")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatalf("make a symlink loop at %s: %v", loop, err)
	}

	cases := []struct {
		name string
		path string
		want socketConnectVerdict
	}{
		{"a socket nothing listens on", dead, connectRefused},
		{"a live socket", live, connectHeld},
		{"a socket that greets first", greeter, connectSpoke},
		{"a socket that closes without a word", closer, connectClosed},
		{"a path that is not there", filepath.Join(dir, "nope.sock"), connectAbsent},
		{"a path that cannot be resolved", loop, connectOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, errno := parseSocketConnectVerdict(connectCommandOutput(t, tc.path, os.Getenv("PATH")))
			if got != tc.want {
				t.Errorf("verdict = %v, want %v for %s", got, tc.want, tc.name)
			}
			if tc.want == connectOther && errno == 0 {
				t.Errorf("the other-word should carry that host's errno, got 0")
			}
		})
	}
}

// greeterSocketAt: 连上就说一句话的socket: 判据里"答了话"的那一支.
func greeterSocketAt(t *testing.T, path string) net.Listener {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on %s: %v", path, err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("OK\n"))
				time.Sleep(time.Hour)
			}(c)
		}
	}()
	return l
}

// closingSocketAt: 接受后立刻结束连接的socket: 判据里"没答话就结束"的那一支.
func closingSocketAt(t *testing.T, path string) net.Listener {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on %s: %v", path, err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l
}

// anySocketInterpreter: 分类命令在真主机上要用的解释器, 一个都没有时用例跳过.
func anySocketInterpreter() (string, error) {
	for _, name := range []string{"python3", "python", "perl"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", errors.New("none of python3, python, perl is on PATH")
}

func TestRemoteSocketFormCommandIsOneLineUnderSh(t *testing.T) {
	// sshd先把命令交给远端登录shell: `csh`/`tcsh`对跨行的引号串报"Unmatched '",
	// 之后什么都不跑, 所以多行命令永远报不出结论.
	cmd := remoteSocketForm("/run/user/1000/gnupg/S.gpg-agent")
	if strings.ContainsAny(cmd, "\n\r") {
		t.Errorf("command %q spans lines, which the remote login shell refuses to parse", cmd)
	}
	if !strings.HasPrefix(cmd, "sh -c ") {
		t.Errorf("command %q does not run its body under sh", cmd)
	}
}

func TestRemoteSocketFormCommandRunsUnderTcsh(t *testing.T) {
	// FreeBSD root登录时sshd用的shell; `-f`跳过cshrc, 只量命令不量登录环境.
	// `csh`/`tcsh`连单引号里也做历史展开, 故路径字节在脚本内解码, 不上命令行.
	tcsh, err := exec.LookPath("tcsh")
	if err != nil {
		t.Skip("tcsh is not installed; TestRemoteSocketFormCommandIsOneLineUnderSh covers the shape it rejects")
	}
	paths := map[string]string{
		"an ordinary path": filepath.Join(t.TempDir(), "S.gpg-agent"),
		"a path with the characters csh and tcsh read twice": filepath.Join(t.TempDir(), "gpg!agent%h$HOME`id`/S.gpg-agent"),
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			out, err := exec.Command(tcsh, "-f", "-c", remoteSocketForm(path)).Output()
			if err != nil {
				t.Fatalf("tcsh could not run the command: %v (output %q)", err, out)
			}
			if !strings.Contains(string(out), socketAbsentMarker) {
				t.Errorf("tcsh ran the command but reported %q, want the absent marker in it", out)
			}
		})
	}
}

// 断言编码往返无损: 字节要能被POSIX sh解出, 也要穿过先解析一遍的`csh`/`tcsh`.
func TestOctalEscapesRoundTripThroughTheShell(t *testing.T) {
	requireShell(t)
	paths := []string{
		"/run/user/1000/gnupg/S.gpg-agent",
		"/run/user/1000/gnupg!bang%h/S.gpg-agent",
		"/run/user/1000/it's/S.gpg-agent",
		"/run/user/1000/with space/$HOME`id`/S.gpg-agent",
		"/run/user/1000/back\\slash/S.gpg-agent",
		"/run/user/1000/gnupg-代理/S.gpg-agent",
	}
	// `-f`跳过shell自己的启动文件(这里是本机cshrc): 量的是解析命令, 不是登录环境.
	type shell struct {
		binary string
		args   []string
		wrap   func(cmd string) string
	}
	inner := func(path string) string {
		// 格式串照命令的传法加引号: 不加的话shell会把转义自己吃掉.
		return "p=$(printf " + shellQuoteSingle(octalEscapes(path)) + "); printf '%s' \"$p\""
	}
	var shells []shell
	if sh, err := exec.LookPath("sh"); err == nil {
		shells = append(shells, shell{sh, []string{"-c"}, func(cmd string) string { return cmd }})
	}
	if tcsh, err := exec.LookPath("tcsh"); err == nil {
		shells = append(shells, shell{tcsh, []string{"-f", "-c"}, func(cmd string) string {
			return "sh -c " + shellQuoteSingle(cmd)
		}})
	}
	for _, s := range shells {
		for _, path := range paths {
			out, err := exec.Command(s.binary, append(s.args, s.wrap(inner(path)))...).Output()
			if err != nil {
				t.Fatalf("%s could not decode %q: %v (output %q)", s.binary, path, err, out)
			}
			if string(out) != path {
				t.Errorf("%s decoded %q to %q, want %q", s.binary, octalEscapes(path), out, path)
			}
		}
	}
}

// 查命令形状而非行为: 缺陷在行为上看不见 - 路径以`printf`编码出行, 从不以自身出现.
// `csh`/`tcsh`连单引号里也做历史展开, 路径里的`!`会让命令当场结束;
// 加引号救不了: `$`, `~`和反引号同样被特殊对待, 且都是合法路径字节, 唯一出路是在脚本内解码.
func TestRemoteSocketFormNeverPutsThePathOnTheCommandLine(t *testing.T) {
	requireShell(t)
	canary := filepath.Join(t.TempDir(), "canary")
	paths := []string{
		"/run/user/1000/gnupg!bang/S.gpg-agent",
		"/run/user/1000/gnupg%h/S.gpg-agent",
		"/run/user/1000/it's/S.gpg-agent",
		"/run/user/1000/with space/S.gpg-agent",
		"/run/user/1000/`id`/$HOME/S.gpg-agent",
		"/run/user/1000/back\\slash/S.gpg-agent",
		"/run/user/1000/gnupg-\xe4\xbb\xa3\xe7\x90\x86/S.gpg-agent",
		"/run/user/1000/x';touch " + canary + ";'/S.gpg-agent",
	}
	for _, command := range []string{
		remoteSocketForm(paths[0]),
		remoteSocketRemove(paths[0]),
	} {
		for _, path := range paths {
			if strings.Contains(strings.ReplaceAll(command, paths[0], ""), path) {
				t.Errorf("command carries %q verbatim:\n%s", path, command)
			}
		}
	}
	for _, path := range paths {
		state, err := probeRemoteSocketForm([]string{"host"}, path, localProbeRunner(os.Getenv("PATH")))
		if err != nil {
			t.Fatalf("probeRemoteSocketForm(%q) error = %v", path, err)
		}
		if state != formAbsent {
			t.Errorf("probeRemoteSocketForm(%q) = %v, want formAbsent for a path that is not there", path, state)
		}
	}
	if _, err := os.Stat(canary); err == nil {
		t.Errorf("%s exists: a byte of the path was run as a command", canary)
	}
}

// 删除闸门取决于它: 每种路径一个用例, 答案全来自shell自带的测试.
func TestRemoteSocketFormReportsEachKindOfPath(t *testing.T) {
	requireShell(t)
	dir := t.TempDir()

	absent := filepath.Join(dir, "S.gpg-agent")
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("not a socket\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", plain, err)
	}
	sub := filepath.Join(dir, "adir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("create %s: %v", sub, err)
	}
	dead := filepath.Join(dir, "dead")
	deadSocketAt(t, dead)
	live := filepath.Join(dir, "live")
	l := liveSocketAt(t, live)
	defer l.Close()

	linkToDead := filepath.Join(dir, "link-dead")
	if err := os.Symlink(dead, linkToDead); err != nil {
		t.Fatalf("symlink %s: %v", linkToDead, err)
	}
	linkToLive := filepath.Join(dir, "link-live")
	if err := os.Symlink(live, linkToLive); err != nil {
		t.Fatalf("symlink %s: %v", linkToLive, err)
	}

	cases := []struct {
		name string
		path string
		want socketForm
	}{
		{"a path that is not there", absent, formAbsent},
		{"a plain file", plain, formNotASocket},
		{"a directory", sub, formNotASocket},
		{"a socket nothing listens on", dead, formSocket},
		{"a live socket", live, formSocket},
		{"a symbolic link to a dead socket", linkToDead, formSocket},
		{"a symbolic link to a live socket", linkToLive, formSocket},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := probeRemoteSocketForm([]string{"host"}, tc.path, localProbeRunner(os.Getenv("PATH")))
			if err != nil {
				t.Fatalf("probeRemoteSocketForm(%s) error = %v", tc.path, err)
			}
			if got != tc.want {
				t.Errorf("form = %v, want %v for %s", got, tc.want, tc.name)
			}
		})
	}
}

// 钉住设计所依赖的一点: 形态全来自shell自带的测试, 缺`ss`/`grep`/`sed`等工具的主机
// 答得和齐全的主机一样好, 不会因缺工具而拒掉会话.
func TestRemoteSocketFormNeedsNoToolsOnTheRemoteHost(t *testing.T) {
	requireShell(t)
	bare := pathWithOnlySh(t)
	dir := t.TempDir()
	dead := filepath.Join(dir, "dead")
	deadSocketAt(t, dead)
	live := filepath.Join(dir, "live")
	l := liveSocketAt(t, live)
	defer l.Close()

	cases := []struct {
		name string
		path string
		want socketForm
	}{
		{"a path that is not there", filepath.Join(dir, "nope"), formAbsent},
		{"a dead socket", dead, formSocket},
		{"a live socket", live, formSocket},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := probeRemoteSocketForm([]string{"host"}, tc.path, localProbeRunner(bare))
			if err != nil {
				t.Fatalf("probeRemoteSocketForm() error = %v: the form command shelled out to something", err)
			}
			if got != tc.want {
				t.Errorf("form = %v, want %v for %s on a host with no tools", got, tc.want, tc.name)
			}
		})
	}
}

// 连socket要写权限: 权限被拒在这头就是一条结束的连接, 与无人监听无法区分,
// 故先在主机上正面验证权限. root会绕过它, 故不跳过(跳过就什么都防不住),
// 改用普通用户跑, 让每个能表达该条件的主机都真的过一遍闸门.
func TestRemoteSocketFormReportsAnUnwritablePath(t *testing.T) {
	requireShell(t)
	pid := strconv.Itoa(os.Getpid())
	// 不用`t.TempDir`: 它的父目录是0700, 换成普通用户跑的命令进不去.
	dir, err := os.MkdirTemp("/tmp", "gpg-agent-forward-unwritable-")
	if err != nil {
		t.Fatalf("make a directory to hold the socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod the directory: %v", err)
	}
	path := filepath.Join(dir, "S.gpg-agent-"+pid)
	l := liveSocketAt(t, path)
	defer l.Close()
	if err := os.Chmod(path, 0); err != nil {
		t.Fatalf("chmod the socket: %v", err)
	}

	run := localProbeRunner(os.Getenv("PATH"))
	if os.Geteuid() == 0 {
		run = runAsUnprivileged(t)
	}
	if canWriteAs(run, path) {
		t.Fatalf("the command can write %s, so this test cannot express an unwritable path", path)
	}
	// 试金石: 路径必须对运行者可见, 否则形态命令只会答"不存在", 到不了写闸门.
	if form, err := probeRemoteSocketForm([]string{"host"}, path, run); err != nil || form == formAbsent {
		t.Fatalf("the runner cannot see %s (%v, %v), so this test would not reach the write gate", path, form, err)
	}

	got, err := probeRemoteSocketForm([]string{"host"}, path, run)
	if err != nil {
		t.Fatalf("probeRemoteSocketForm() error = %v", err)
	}
	if got != formUnwritable {
		t.Errorf("form = %v, want formUnwritable for a socket this user cannot write", got)
	}

	// 试金石: 没有写闸门, 这就是会删掉在用agent socket的那个例子.
	state, err := CheckRemoteSocketFree([]string{"host"}, path, run)
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal for a path this user cannot write")
	}
	if state != socketUnwritable {
		t.Errorf("state = %v, want socketUnwritable", state)
	}
	if !socketFileExists(t, path) {
		t.Fatal("a live socket in a path this user cannot write was removed")
	}
}

// 测试进程是root时写权限会被绕过, 故改用普通用户跑; 拿不到用户就直接失败.
func runAsUnprivileged(t *testing.T) SSHCommandRunner {
	t.Helper()
	su, err := exec.LookPath("su")
	if err != nil {
		t.Fatalf("running as root and no su to drop privileges with: %v", err)
	}
	user, err := unprivilegedUser()
	if err != nil {
		t.Fatalf("running as root and no unprivileged user to run the command as: %v", err)
	}
	return func(_ []string, remoteCommand string) (string, error) {
		cmd := exec.Command(su, "-s", "/bin/sh", user, "-c", remoteCommand)
		cmd.Env = envWithPath(os.Getenv("PATH"))
		out, err := cmd.Output()
		return string(out), err
	}
}

// 让测试确认自己真搭出了要考的条件.
func canWriteAs(run SSHCommandRunner, path string) bool {
	out, err := run(nil, "if [ -w "+shellQuoteSingle(path)+" ]; then echo yes; else echo no; fi")
	return err == nil && strings.Contains(out, "yes")
}

// 编码的fail-open面: `printf`不读`\NNN`时, 转义文本本身成了`p`的值, 非空,
// 空解码的守卫看不见它, 脚本的每个问题都答"no". "不存在"是唯一能放行会话和删除
// 的答案, 故绝不能由坏解码产生 - 先证明解码可信, 再信它.
func TestRemoteSocketFormRefusesADecodeItCannotTrust(t *testing.T) {
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")

	// 试金石: 同一路径在会解码的主机上得到"不存在"的正常结论, 坏解码绝不能造出它.
	if form, err := probeRemoteSocketForm([]string{"host"}, path, localProbeRunner(os.Getenv("PATH"))); err != nil || form != formAbsent {
		t.Fatalf("probeRemoteSocketForm() on a host that decodes = (%v, %v), want (formAbsent, nil)", form, err)
	}

	run := localProbeRunner(pathWithNonDecodingPrintf(t, os.Getenv("PATH")))
	form, err := probeRemoteSocketForm([]string{"host"}, path, run)
	if err != nil {
		t.Fatalf("probeRemoteSocketForm() error = %v", err)
	}
	if form == formAbsent {
		t.Fatalf("form = %v, want anything but absent: the path was never decoded, so nothing about it was checked", form)
	}
	if form != formUnknown {
		t.Errorf("form = %v, want formUnknown for a host whose printf cannot decode the path", form)
	}

	// 拒绝会给出越过它的办法: 主机可达, 路径也许真空着, 是否硬启由用户权衡.
	_, err = CheckRemoteSocketFree([]string{"host"}, path, run)
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal when the decode cannot be trusted")
	}
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
	}
}

// 造一个`sh`的`printf`不解析`\NNN`的`PATH`: POSIX要求`printf`读`\NNN`,
// 不读的实现会原样印出转义文本. 没有主机能按需长成这样, 故造在命令找`sh`的地方:
// 排在`PATH`最前的替身`sh`, 把`printf`定义成原样打印格式串的函数, 再跑交来的body.
func pathWithNonDecodingPrintf(t *testing.T, base string) string {
	t.Helper()
	real, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh is not on PATH to stand in for it: %v", err)
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = -c ]; then\n" +
		`  exec ` + shellQuoteSingle(real) + ` -c "printf() { command printf '%s' \"\$1\"; }; $2"` + "\n" +
		"fi\n" +
		"exec " + shellQuoteSingle(real) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "sh"), []byte(script), 0o755); err != nil {
		t.Fatalf("write the stand-in sh: %v", err)
	}
	return dir + string(os.PathListSeparator) + base
}

// 上面检查的另一面: 问题出在主机的`printf`, 不在路径. 反斜杠是合法字节,
// 一刀切拒绝会让本可解码的路径全变成"unknown".
func TestRemoteSocketFormJudgesAPathWithABackslash(t *testing.T) {
	requireShell(t)
	dir := filepath.Join(t.TempDir(), `back\slash`)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	path := filepath.Join(dir, "S.gpg-agent")
	run := localProbeRunner(os.Getenv("PATH"))

	deadSocketAt(t, path)
	form, err := probeRemoteSocketForm([]string{"host"}, path, run)
	if err != nil {
		t.Fatalf("probeRemoteSocketForm() error = %v", err)
	}
	if form != formSocket {
		t.Fatalf("form = %v, want formSocket: a path with a backslash in it is decoded and judged like any other", form)
	}

	// 死socket的文件已被换成活的: 监听者必须是新文件, 不是上一个用例的遗留.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
	l := liveSocketAt(t, path)
	defer l.Close()
	form, err = probeRemoteSocketForm([]string{"host"}, path, run)
	if err != nil {
		t.Fatalf("probeRemoteSocketForm() error = %v", err)
	}
	if form != formSocket {
		t.Errorf("form = %v, want formSocket for a listener at a path with a backslash in it", form)
	}
}

func TestRemoteSocketRemoveReportsWhatHappened(t *testing.T) {
	requireShell(t)
	run := localProbeRunner(os.Getenv("PATH"))

	t.Run("a leftover is removed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "S.gpg-agent")
		deadSocketAt(t, path)
		removed, err := removeRemoteSocket([]string{"host"}, path, run)
		if err != nil {
			t.Fatalf("removeRemoteSocket() error = %v", err)
		}
		if !removed {
			t.Error("removeRemoteSocket() = false, want the leftover reported as removed")
		}
		if socketFileExists(t, path) {
			t.Errorf("%s is still there: a dead socket blocks the next session's bind", path)
		}
	})

	t.Run("a path that cannot be unlinked is not reported as removed", func(t *testing.T) {
		// 删除失败都长这样(目录没有`-r`删不掉): 答"no", 调用方把"yes"当作开跑许可.
		path := filepath.Join(t.TempDir(), "adir")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create %s: %v", path, err)
		}
		removed, err := removeRemoteSocket([]string{"host"}, path, run)
		if err != nil {
			t.Fatalf("removeRemoteSocket() error = %v", err)
		}
		if removed {
			t.Error("removeRemoteSocket() = true for a path that is still there")
		}
		if !socketFileExists(t, path) {
			t.Error("the directory is gone, so this case no longer tests what it means to")
		}
	})

	t.Run("a path that can never be decoded is not reported as removed", func(t *testing.T) {
		bad := pathWithNonDecodingPrintf(t, os.Getenv("PATH"))
		removed, err := removeRemoteSocket([]string{"host"}, "/tmp/whatever", localProbeRunner(bad))
		if err != nil {
			t.Fatalf("removeRemoteSocket() error = %v", err)
		}
		if removed {
			t.Error("removeRemoteSocket() = true for a host whose printf cannot decode the path")
		}
	})

	t.Run("a host that answered nothing is not reported as removed", func(t *testing.T) {
		// 完全没有结论行说明命令没照原样跑起来: 文件还在不在都不知道, 只能读作没删成.
		run := func([]string, string) (string, error) { return "Welcome to the host\n", nil }
		removed, err := removeRemoteSocket([]string{"host"}, "/tmp/whatever", run)
		if err != nil {
			t.Fatalf("removeRemoteSocket() error = %v", err)
		}
		if removed {
			t.Error("removeRemoteSocket() = true when the host reported nothing")
		}
	})
}

const (
	// 标记重执行的替身进程.
	forwardHelperEnv = "GPG_AGENT_FORWARD_TEST_FORWARD_SSH"
	// 替身`ssh`把参数向量写进的文件, 免得helper去解析自己的命令行.
	forwardArgsEnv = "GPG_AGENT_FORWARD_TEST_FORWARD_ARGS"
	// 让替身像转发被拒的`ssh`那样失败: 退出非零, 且从不发布本地端口.
	forwardRefuseEnv = "GPG_AGENT_FORWARD_TEST_FORWARD_REFUSE"
	// 让替身只发布目标端口, 不发布控制端口: 只缺控制的那种连接的形态.
	forwardNoControlEnv = "GPG_AGENT_FORWARD_TEST_FORWARD_NO_CONTROL"
)

// 不是独立的测试: 是分类的远端, 以替身`ssh`重新执行, 做`ssh`与`sshd`
// 对检查所建三个forward该做的事. 路径都在本机, "远端"与"本机"是同一台,
// 连接结果因此可观测: `classifyRemoteSocket`拨这个helper发布的端口看连接怎么走.
func TestForwardSSHHelper(t *testing.T) {
	if os.Getenv(forwardHelperEnv) == "" {
		t.Skip("not the stand-in ssh invocation")
	}
	if os.Getenv(forwardRefuseEnv) != "" {
		// 拒绝转发的`sshd`的产物: 没有本地端口, 且以失败退出; 检查的对照会发现.
		fmt.Fprintln(os.Stderr, "channel 1: open failed: connect failed: open failed")
		os.Exit(255)
	}
	data, err := os.ReadFile(os.Getenv(forwardArgsEnv))
	if err != nil {
		fmt.Fprintf(os.Stderr, "stand-in ssh: %v\n", err)
		os.Exit(1)
	}
	if err := runForwardStandIn(strings.Split(strings.TrimRight(string(data), "\n"), "\n")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(255)
	}
	// 挂住forward直到检查杀掉本进程, 这正是`ssh`的行为: `-N`表示会话只有forward.
	select {}
}

// 绑定一组参数里的forward并服务到进程被杀: `ssh`对纯forward会话也如此.
func runForwardStandIn(args []string) error {
	noControl := os.Getenv(forwardNoControlEnv) != ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-R":
			// `-R PATH:127.0.0.1:PORT`: 绑路径, 转发到端口.
			if i+1 >= len(args) {
				return fmt.Errorf("stand-in ssh: -R without a value")
			}
			parts := strings.SplitN(unescapePercent(args[i+1]), ":", 3)
			if len(parts) != 3 {
				return fmt.Errorf("stand-in ssh: bad -R spec %q", args[i+1])
			}
			path, host, portStr := parts[0], parts[1], parts[2]
			// `sshd`在`StreamLocalBindUnlink`开着时绑定前会先unlink已有socket;
			// 这里模拟的就是它, 也正因此检查的对照路径必须无人使用.
			_ = os.Remove(path)
			l, err := net.Listen("unix", path)
			if err != nil {
				return fmt.Errorf("stand-in ssh: bind %s: %w", path, err)
			}
			go forwardEach(l, "tcp", host+":"+portStr)
			i++
		case "-L":
			// `-L 127.0.0.1:PORT:PATH`: 绑端口, 连到该路径.
			if i+1 >= len(args) {
				return fmt.Errorf("stand-in ssh: -L without a value")
			}
			parts := strings.SplitN(unescapePercent(args[i+1]), ":", 3)
			if len(parts) != 3 {
				return fmt.Errorf("stand-in ssh: bad -L spec %q", args[i+1])
			}
			host, portStr, path := parts[0], parts[1], parts[2]
			if noControl && strings.Contains(path, controlSocketPrefix) {
				// 对照端口刻意从不发布.
				i++
				continue
			}
			l, err := net.Listen("tcp", host+":"+portStr)
			if err != nil {
				// `ExitOnForwardFailure`开着时`ssh`就打出这句并退出: 检查读成"无法判断".
				return fmt.Errorf("Could not request local forwarding: %w", err)
			}
			go forwardEach(l, "unix", path)
			i++
		}
	}
	// 监听者各由自己的goroutine挂住, 随进程存活: 本函数停在末尾不返回,
	// 直到检查杀掉本进程.
	select {}
}

// 还原检查在forward规格里对路径的转义, 让替身服务被问到的路径.
func unescapePercent(s string) string { return strings.ReplaceAll(s, "%%", "%") }

// 在l上accept, 每个连接连到给定地址并双向复制到任一端关闭.
// 远端连不上就立即关闭, 同`sshd`: 调用方看到的是一次结束, 不是拒绝.
func forwardEach(l net.Listener, network, addr string) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			peer, err := net.Dial(network, addr)
			if err != nil {
				return
			}
			defer peer.Close()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(peer, c); done <- struct{}{} }()
			go func() { _, _ = io.Copy(c, peer); done <- struct{}{} }()
			<-done
		}(c)
	}
}

// 写一个替身`ssh`: 对检查的两种连接形态都像远端主机, 返回找到它的`PATH`; 带`-N`的连接是分类,
// 参数向量写进文件, 由helper进程服务forward; 其他连接最后一个参数是远端命令, 用`sh`跑,
// 覆盖一次性form命令与删除. 参数走文件而非helper命令行: 它就是本测试二进制, 其flag解析器管着参数.
func forwardStandInSSH(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	self := selfExe()
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	script := "#!/bin/sh\n" +
		"has_n=0\n" +
		"for a in \"$@\"; do [ \"$a\" = \"-N\" ] && has_n=1; done\n" +
		"if [ \"$has_n\" = \"1\" ]; then\n" +
		"  printf '%s\\n' \"$@\" > " + shellQuoteSingle(argsFile) + "\n" +
		"  exec " + shellQuoteSingle(self) + " -test.run=^TestForwardSSHHelper$\n" +
		"fi\n" +
		// 远端命令是最后一个参数, `ssh`就是这么放的.
		"for last in \"$@\"; do :; done\n" +
		"exec sh -c \"$last\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatalf("write the stand-in ssh: %v", err)
	}
	t.Setenv(forwardHelperEnv, "1")
	t.Setenv(forwardArgsEnv, argsFile)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

// 用替身`ssh`在本机的路径上跑真正的分类.
func classifyWithForwardStandIn(t *testing.T, path string) (socketForwardVerdict, error) {
	t.Helper()
	forwardStandInSSH(t)
	control, err := controlSocketPath(path)
	if err != nil {
		t.Fatalf("controlSocketPath(%s) error = %v", path, err)
	}
	return classifyRemoteSocket([]string{"host"}, path, control)
}

// `forwardStandInSSH`的非特权版, 用于主题是权限而测试进程本会绕过的测试.
// 权限是真的: root读写任何文件, mode-0的socket对它可写, 其连接说明不了
// 普通用户会看到什么. 环境随`su`自己的命令行传递(su不传调用方环境).
func forwardStandInSSHAsUnprivileged(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	if os.Geteuid() != 0 {
		// 本来就是非特权: 调用方自己的用户就表达了这个条件.
		forwardStandInSSH(t)
		return ""
	}
	su, err := exec.LookPath("su")
	if err != nil {
		t.Fatalf("running as root and no su to drop privileges with: %v", err)
	}
	user, err := unprivilegedUser()
	if err != nil {
		t.Fatalf("running as root and no unprivileged user to run the check as: %v", err)
	}

	self := selfExe()
	// 放在`/tmp`而不是`t.TempDir`: 后者是0700且归测试进程所有, 非特权用户
	// 既读不出其中的参数, 也不能从那里运行helper.
	dir, err := os.MkdirTemp("/tmp", "gpg-agent-forward-unprivileged-")
	if err != nil {
		t.Fatalf("make the stand-in's directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod the stand-in's directory: %v", err)
	}
	// 测试二进制也得跟着走: 正在跑的那个在0700的构建目录里, 非特权用户到不了.
	helper := filepath.Join(dir, "helper")
	if err := copyFile(self, helper); err != nil {
		t.Fatalf("copy the test binary to a place the unprivileged user can run it from: %v", err)
	}
	argsFile := filepath.Join(dir, "args")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + shellQuoteSingle(argsFile) + "\n" +
		"exec " + shellQuoteSingle(su) + " -s /bin/sh " + user + " -c " +
		shellQuoteSingle(forwardHelperEnv+"=1 "+forwardArgsEnv+"="+argsFile+" exec "+helper+
			" -test.run=^TestForwardSSHHelper$") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatalf("write the unprivileged stand-in ssh: %v", err)
	}
	t.Setenv(forwardHelperEnv, "1")
	t.Setenv(forwardArgsEnv, argsFile)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return user
}

// 以别的用户能运行helper所需的权限把`src`拷到`dst`.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}

// 返回一个本进程能以其身份运行命令的用户.
func unprivilegedUser() (string, error) {
	su, err := exec.LookPath("su")
	if err != nil {
		return "", err
	}
	for _, user := range []string{"nobody", "daemon", "bin"} {
		if err := exec.Command(su, "-s", "/bin/sh", user, "-c", "true").Run(); err == nil {
			return user, nil
		}
	}
	return "", errors.New("no unprivileged user is reachable through su")
}

// 绝不能走到删除的一例: 接受连接却什么都不说的监听者.
func TestClassifyRemoteSocketSeesALiveListener(t *testing.T) {
	requireShell(t)
	path := filepath.Join(shortTempDir(t), "S.gpg-agent")
	l := liveSocketAt(t, path)
	defer l.Close()

	verdict, err := classifyWithForwardStandIn(t, path)
	if err != nil {
		t.Fatalf("classifyRemoteSocket() error = %v", err)
	}
	if verdict != forwardLive {
		t.Fatalf("verdict = %v, want forwardLive for a listener that accepts and stays silent", verdict)
	}
	if !socketFileExists(t, path) {
		t.Error("a live socket was removed")
	}
}

// 删除只为此一例.
func TestClassifyRemoteSocketSeesALeftover(t *testing.T) {
	requireShell(t)
	path := filepath.Join(shortTempDir(t), "S.gpg-agent")
	deadSocketAt(t, path)

	verdict, err := classifyWithForwardStandIn(t, path)
	if err != nil {
		t.Fatalf("classifyRemoteSocket() error = %v", err)
	}
	if verdict != forwardDead {
		t.Errorf("verdict = %v, want forwardDead for a socket nothing is listening on", verdict)
	}
}

// 覆盖答不上来但不是残留的路径.
// 它们由form命令在分类之前分辨: 这里钉住的是分类本身会判它们死,
// 这正是form命令必须先跑的原因.
func TestClassifyRemoteSocketSeesNoListenerBehindWhatIsNotASocket(t *testing.T) {
	requireShell(t)
	dir := shortTempDir(t)
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("data\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", plain, err)
	}
	sub := filepath.Join(dir, "adir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("create %s: %v", sub, err)
	}
	for _, path := range []string{plain, sub, filepath.Join(dir, "nope")} {
		verdict, err := classifyWithForwardStandIn(t, path)
		if err != nil {
			t.Fatalf("classifyRemoteSocket(%s) error = %v", path, err)
		}
		if verdict != forwardDead {
			t.Errorf("classifyRemoteSocket(%s) = %v, want forwardDead", path, verdict)
		}
	}
}

// 这个对照所针对的发现: 没有它, 活socket与无人监听的socket在本端是同一答案(结束的连接),
// 该答案会授权删掉在用的socket; 对照缺失则什么都不删. 替身`ssh`不驱动任何`sshd`选项,
// 覆盖的是路由不是真实`sshd`行为: 真机夺走对照的方式写在检查本体的文档里.
func TestClassifyRemoteSocketRefusesWhenTheControlIsMissing(t *testing.T) {
	requireShell(t)
	path := filepath.Join(shortTempDir(t), "S.gpg-agent")
	l := liveSocketAt(t, path)
	defer l.Close()

	forwardStandInSSH(t)
	t.Setenv(forwardNoControlEnv, "1")
	control, err := controlSocketPath(path)
	if err != nil {
		t.Fatalf("controlSocketPath() error = %v", err)
	}

	verdict, err := classifyRemoteSocket([]string{"host"}, path, control)
	if verdict != forwardUnjudgeable {
		t.Fatalf("verdict = %v (error %v), want forwardUnjudgeable: a refusal reads exactly like a leftover at this end", verdict, err)
	}
	if !socketFileExists(t, path) {
		t.Error("a live socket was removed on a connection that could not be told apart from a leftover")
	}
}

// 覆盖对照丢失的另一途: `ssh`自己没走够远, 什么都没发布.
func TestClassifyRemoteSocketRefusesWhenSSHFails(t *testing.T) {
	requireShell(t)
	path := filepath.Join(shortTempDir(t), "S.gpg-agent")
	deadSocketAt(t, path)

	forwardStandInSSH(t)
	t.Setenv(forwardRefuseEnv, "1")
	control, err := controlSocketPath(path)
	if err != nil {
		t.Fatalf("controlSocketPath() error = %v", err)
	}

	verdict, err := classifyRemoteSocket([]string{"host"}, path, control)
	if verdict != forwardUnjudgeable {
		t.Fatalf("verdict = %v (error %v), want forwardUnjudgeable when ssh never published a local port", verdict, err)
	}
	if !socketFileExists(t, path) {
		t.Error("a socket was removed after an ssh that never published a local port")
	}
}

// 整套检查的端到端: 路径被另一个网络命名空间里的监听者占着; 一次性form
// 命令在本机跑, 分类经替身`ssh`连接, 两张表都看不到的socket仍绝不会被删.
// 这正是当初重写检查针对的失败形状(容器里的agent共享此目录), 必须保持拒绝.
func TestCheckRemoteSocketFreeKeepsALiveSocketInAnotherNamespace(t *testing.T) {
	requireShell(t)
	socket := filepath.Join(shortTempDir(t), "S.gpg-agent")
	startSocketInAnotherNamespace(t, socket)
	forwardStandInSSH(t)

	state, err := CheckRemoteSocketFree([]string{"host"}, socket, runSSHCommand)
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal for a path in use")
	}
	if state != socketLive {
		t.Errorf("state = %v, want socketLive: a listener in another namespace answers a connection", state)
	}
	if !socketFileExists(t, socket) {
		t.Fatalf("%s was removed: a socket bound in another namespace lost its file", socket)
	}
}

// 整套检查对着死socket跑: form命令报出它, 分类发现没人应答, 删除真的发生.
// 这是用户要的默认行为, 无需任何开关.
func TestCheckRemoteSocketFreeRemovesALeftoverEndToEnd(t *testing.T) {
	requireShell(t)
	socket := filepath.Join(shortTempDir(t), "S.gpg-agent")
	deadSocketAt(t, socket)
	forwardStandInSSH(t)

	state, err := CheckRemoteSocketFree([]string{"host"}, socket, runSSHCommand)
	if err != nil {
		t.Fatalf("CheckRemoteSocketFree() error = %v, want the leftover removed and the session to start", err)
	}
	if state != socketReclaimed {
		t.Errorf("state = %v, want socketReclaimed", state)
	}
	if socketFileExists(t, socket) {
		t.Errorf("%s is still there: a dead socket blocks the next session's bind", socket)
	}
}

// 对照socket生命周期的端到端形态: 无论判定如何, 检查在路径旁创建的socket
// 事后都不见了; 绝不能留下无人监听的socket, 那会被当成用户自己的残留报给用户.
func TestCheckRemoteSocketFreeLeavesTheControlSocketNowhere(t *testing.T) {
	requireShell(t)
	dir := shortTempDir(t)
	socket := filepath.Join(dir, "S.gpg-agent")
	deadSocketAt(t, socket)
	forwardStandInSSH(t)

	if _, err := CheckRemoteSocketFree([]string{"host"}, socket, runSSHCommand); err != nil {
		t.Fatalf("CheckRemoteSocketFree() error = %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), controlSocketPrefix) {
			t.Errorf("the control socket %s was left behind", e.Name())
		}
	}
}

// 检查的本地资源是端口而非socket文件, 能留下的只有一个监听者;
// 它开的每个端口都在退出时关闭, 判定路径与失败路径皆然.
func TestClassifyRemoteSocketLeavesNoLocalListenerBehind(t *testing.T) {
	requireShell(t)
	dir := shortTempDir(t)
	live := filepath.Join(dir, "live")
	l := liveSocketAt(t, live)

	before := countLoopbackListeners(t)
	if _, err := classifyWithForwardStandIn(t, live); err != nil {
		t.Fatalf("classifyRemoteSocket() error = %v", err)
	}
	l.Close()
	deadSocketAt(t, filepath.Join(dir, "dead"))
	if _, err := classifyWithForwardStandIn(t, filepath.Join(dir, "dead")); err != nil {
		t.Fatalf("classifyRemoteSocket() error = %v", err)
	}
	after := countLoopbackListeners(t)

	// 替身`ssh`由检查杀掉, 它的监听者随之而去; 检查自己的两个由defer关闭.
	// 有泄漏的话, 计数会一路爬升.
	if after > before {
		t.Errorf("loopback listeners went from %d to %d, so a local resource outlived the check", before, after)
	}
}

// 返回loopback上正在监听的socket数, 即分类的本地端口.
func countLoopbackListeners(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		t.Skipf("no /proc/net/tcp to count listeners with: %v", err)
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != "0A" {
			continue // 不是监听中的socket
		}
		if strings.HasPrefix(fields[1], "0100007F:") {
			n++
		}
	}
	return n
}

// 给分类测试所依赖的脚手架装上牙齿: 替身若不再绑定并连接,
// 那些测试的成败就与检查无关了.
func TestForwardStandInServesTheForwardsItIsGiven(t *testing.T) {
	requireShell(t)
	dir := t.TempDir()
	dead := filepath.Join(dir, "dead")
	deadSocketAt(t, dead)
	live := filepath.Join(dir, "live")
	l := liveSocketAt(t, live)
	defer l.Close()

	control := filepath.Join(dir, "ctl")
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold listener: %v", err)
	}
	defer hold.Close()
	go func() {
		for {
			c, err := hold.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			time.Sleep(time.Minute)
		}
	}()
	controlPort, err := freeLoopbackPort()
	if err != nil {
		t.Fatalf("freeLoopbackPort: %v", err)
	}
	targetPort, err := freeLoopbackPort()
	if err != nil {
		t.Fatalf("freeLoopbackPort: %v", err)
	}

	args, err := sshForwardArgs([]string{"dev@host"}, socketForwardSpec{
		controlPort: controlPort,
		controlPath: control,
		targetPort:  targetPort,
		targetPath:  live,
		holdPort:    hold.Addr().(*net.TCPAddr).Port,
	})
	if err != nil {
		t.Fatalf("sshForwardArgs() error = %v", err)
	}
	argsFile := filepath.Join(dir, "args")
	if err := os.WriteFile(argsFile, []byte(strings.Join(args, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write the args file: %v", err)
	}
	t.Setenv(forwardArgsEnv, argsFile)

	done := make(chan error, 1)
	go func() { done <- runForwardStandIn(args) }()
	// `runForwardStandIn`绑完后阻塞在末尾不返回(成功路径), 端口要等它出现再继续.
	if err := waitForListener(controlPort); err != nil {
		t.Fatal(err)
	}
	if err := waitForListener(targetPort); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(control); err != nil {
		t.Fatalf("the stand-in did not bind the control path %s: %v", control, err)
	}

	// 对照链: 连上对照端口的连接会到达hold监听者并保持打开.
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", controlPort), 2*time.Second)
	if err != nil {
		t.Fatalf("dial the control port: %v", err)
	}
	defer c.Close()

	// 目标侧: 活socket应答.
	if kind := readKind(t, targetPort); kind != localHeld {
		t.Errorf("target %s: %v, want localHeld", live, kind)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runForwardStandIn() error = %v", err)
		}
	default:
	}
}

// 拨port并按分类的读法报出这次连接的结果.
func readKind(t *testing.T, port int) localConnKind {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return localUnclassifiable
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 1)
	n, err := c.Read(buf)
	if n > 0 {
		return localHeld
	}
	if err == nil {
		return localClosed
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return localHeld
	}
	return localClosed
}

// 等到loopback端口上有人监听为止.
func waitForListener(port int) error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("nothing began listening on 127.0.0.1:%d", port)
}

// 钉住整个分类所依赖的原始判断, 用纯TCP所以完全不依赖`ssh`.
func TestClassifyLocalPortTellsHeldFromEnded(t *testing.T) {
	t.Run("held", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer l.Close()
		go func() {
			var held []net.Conn
			defer func() {
				for _, c := range held {
					c.Close()
				}
			}()
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				held = append(held, c)
			}
		}()
		port := l.Addr().(*net.TCPAddr).Port
		if got := classifyLocalPort(port, nil); got != localHeld {
			t.Errorf("classifyLocalPort() = %v, want localHeld", got)
		}
	})

	t.Run("ended", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer l.Close()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		port := l.Addr().(*net.TCPAddr).Port
		if got := classifyLocalPort(port, nil); got != localClosed {
			t.Errorf("classifyLocalPort() = %v, want localClosed", got)
		}
	})

	t.Run("nothing there", func(t *testing.T) {
		port, err := freeLoopbackPort()
		if err != nil {
			t.Fatalf("freeLoopbackPort: %v", err)
		}
		// 超时路径会花掉整个拨号预算, 所以用寿命很短的监听者来跑:
		// `ssh`退出就是结束等待的东西.
		exited := make(chan struct{})
		go func() {
			time.Sleep(100 * time.Millisecond)
			close(exited)
		}()
		if got := classifyLocalPort(port, exited); got != localUnclassifiable {
			t.Errorf("classifyLocalPort() = %v, want localUnclassifiable", got)
		}
	})
}

// `ssh`对本地端口0报"Bad local forwarding specification", 所以端口必须在这里选.
func TestFreeLoopbackPortIsBindableAndNotZero(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 20; i++ {
		port, err := freeLoopbackPort()
		if err != nil {
			t.Fatalf("freeLoopbackPort() error = %v", err)
		}
		if port == 0 {
			t.Fatal("freeLoopbackPort() = 0, which ssh rejects in a forward specification")
		}
		if seen[port] {
			t.Fatalf("freeLoopbackPort() returned %d twice in a row, so the port was not released", port)
		}
		seen[port] = true
	}
}

// 钉住三条规格的精确拼写(含端口): `ssh`按地址加端口解析, 端口写成别的样子
// (格式化产物, 浮点, 空串)会让`ssh`直接拒绝该规格, 或绑到检查没等的端口上;
// 断言是整条规格的相等: 分隔符, 地址或端口渲染一变就失败在此而非下游.
func TestSSHForwardArgsRenderPortsAsDecimal(t *testing.T) {
	args, err := sshForwardArgs([]string{"host"}, socketForwardSpec{
		controlPort: 40001, controlPath: "/tmp/c", targetPort: 40002, targetPath: "/tmp/t", holdPort: 40003,
	})
	if err != nil {
		t.Fatalf("sshForwardArgs() error = %v", err)
	}
	got := strings.Join(args, " ")
	want := []string{
		"-R /tmp/c:127.0.0.1:40003",
		"-L 127.0.0.1:40001:/tmp/c",
		"-L 127.0.0.1:40002:/tmp/t",
	}
	for _, spec := range want {
		if n := strings.Count(got, spec); n != 1 {
			t.Errorf("sshForwardArgs() = %q, want exactly one %q, got %d", got, spec, n)
		}
	}
	// 顺序也是契约的一部分: 端口按检查等待的顺序发布, 目的地放最后,
	// 让`ssh`把它读成目的地而不是某个forward的值.
	if iR, iL := strings.Index(got, want[0]), strings.Index(got, want[1]); !(0 <= iR && iR < iL) {
		t.Errorf("sshForwardArgs() = %q, want the -R before the first -L", got)
	}
	if !strings.HasSuffix(got, " host") {
		t.Errorf("sshForwardArgs() = %q, want the destination last", got)
	}
}
