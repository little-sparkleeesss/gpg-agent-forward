package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 探针是POSIX shell命令, 故这些测试用`sh`真跑并读输出, 不做命令文本匹配:
// 它防的缺陷 - `ss`失败被读成"无人监听", 地址子串匹配 - 只在脚本跑起来时现形.

// 探针以这行表头作为`ss`答过话的证据, 故替身也必须打印它.
const ssHeader = "Netid State  Recv-Q Send-Q  Local Address:Port     Peer Address:Port"

// 内核unix socket表的表头: 探针的第二证据源, 空白列距是内核原样, 替身不得整理.
const procTableHeader = "Num       RefCount Protocol Flags    Type St Inode Path"

func procTableStub(t *testing.T, table string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "unix")
	if err := os.WriteFile(path, []byte(table), 0o644); err != nil {
		t.Fatalf("write the stand-in socket table: %v", err)
	}
	return path
}

// `/proc/net/unix`是测试无法卸载或遮蔽的绝对路径, 故换成同样性质的缺失路径;
// 脚本把它写成一个字面量, `replaceProbeSource`负责整体替换.
func missingProcTable(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "unix")
}

// 改写探针命令后再跑: 用来造出本机内核表本身做不出的分支.
func replaceProbeSource(run SSHCommandRunner, old, new string) SSHCommandRunner {
	return func(sshArgs []string, remoteCommand string) (string, error) {
		return run(sshArgs, strings.ReplaceAll(remoteCommand, old, new))
	}
}

func requireShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the probe is a POSIX shell command")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("sh is not on PATH to run the probe with: %v", err)
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

// 像远端登录shell那样把命令串交给`sh`跑, 并由`PATH`决定探针找到哪个`ss`.
func localProbeRunner(path string) SSHCommandRunner {
	return func(_ []string, remoteCommand string) (string, error) {
		cmd := exec.Command("sh", "-c", remoteCommand)
		cmd.Env = envWithPath(path)
		out, err := cmd.Output()
		return string(out), err
	}
}

// 首选本机真`ss`, 测试与生产解析同一份输出; 无`ss`时才用替身.
// 替身只答"路径上有没有监听者", 不答"`ss`会不会打印它";
// 两者皆无的主机跳过, 不退而求其次.
func ssPathForProbe(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("ss"); err == nil {
		return os.Getenv("PATH")
	}
	if _, err := os.Stat("/proc/net/unix"); err != nil {
		t.Skipf("no ss on the test host and no /proc/net/unix to stand in for it: %v", err)
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"echo " + shellQuoteSingle(ssHeader) + "\n" +
		"cat /proc/net/unix\n"
	if err := os.WriteFile(filepath.Join(dir, "ss"), []byte(script), 0o755); err != nil {
		t.Fatalf("write the ss stand-in: %v", err)
	}
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

func ssStub(t *testing.T, table string) string {
	t.Helper()
	dir := t.TempDir()
	tableFile := filepath.Join(dir, "table")
	if err := os.WriteFile(tableFile, []byte(table), 0o644); err != nil {
		t.Fatalf("write the ss table: %v", err)
	}
	script := "#!/bin/sh\ncat " + shellQuoteSingle(tableFile) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "ss"), []byte(script), 0o755); err != nil {
		t.Fatalf("write the ss stub: %v", err)
	}
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

func brokenSSStub(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ss"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("write the ss stub: %v", err)
	}
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
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

// 造一个无人监听的socket文件: 已结束的会话转发留下的状态, 探针唯一允许删的东西.
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

func TestRemoteSocketProbeCommandIsOneLine(t *testing.T) {
	// sshd先把命令交给远端登录shell: `csh`/`tcsh`对跨行的引号串报"Unmatched '",
	// 之后什么都不跑, 故多行命令的探针报不出结论.
	cmd := remoteSocketProbe("/run/user/1000/gnupg/S.gpg-agent", keepLeftover)
	if strings.ContainsAny(cmd, "\n\r") {
		t.Errorf("probe %q spans lines, which the remote login shell refuses to parse", cmd)
	}
	if !strings.HasPrefix(cmd, "sh -c ") {
		t.Errorf("probe %q does not run its body under sh", cmd)
	}
}

func TestRemoteSocketProbeCommandRunsUnderTcsh(t *testing.T) {
	// FreeBSD root登录时sshd用的shell; `-f`跳过cshrc, 只量命令不量登录环境.
	// `csh`/`tcsh`连单引号里也做历史展开, 故路径字节在脚本内解码, 不上命令行.
	tcsh, err := exec.LookPath("tcsh")
	if err != nil {
		t.Skip("tcsh is not installed; TestRemoteSocketProbeCommandIsOneLine covers the shape it rejects")
	}
	paths := map[string]string{
		"an ordinary path": filepath.Join(t.TempDir(), "S.gpg-agent"),
		"a path with the characters csh and tcsh read twice": filepath.Join(t.TempDir(), "gpg!agent%h$HOME`id`/S.gpg-agent"),
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			out, err := exec.Command(tcsh, "-f", "-c", remoteSocketProbe(path, keepLeftover)).Output()
			if err != nil {
				t.Fatalf("tcsh could not run the probe: %v (output %q)", err, out)
			}
			if !strings.Contains(string(out), socketAbsentMarker) {
				t.Errorf("tcsh ran the probe but reported %q, want the absent marker in it", out)
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
	// `-f`跳过shell自己的启动文件(这里是本机cshrc), 量的是解析命令而非登录环境.
	// `tcsh`自己不做`p=$(...)`, 只需把引号串原样传下去, 解码仍交给`sh`.
	type shell struct {
		binary string
		args   []string
		wrap   func(cmd string) string
	}
	inner := func(path string) string {
		// 格式串照探针的传法加引号: 不加的话shell会把转义自己吃掉.
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

// 编码后的路径唯一会变空的途径: 主机的shell解不出来, 脚本等于没东西可查.
// 空路径不是文件, 诚实的结论只能是问不了主机, 绝不能是路径空闲.
func TestRemoteSocketProbeRefusesAnEmptyPath(t *testing.T) {
	requireShell(t)
	state, err := probeRemoteSocket([]string{"host"}, "", keepLeftover, localProbeRunner(os.Getenv("PATH")))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketUnjudgeable {
		t.Fatalf("state = %v, want socketUnjudgeable: an empty path is not a free one", state)
	}
	if _, err := CheckRemoteSocketFree([]string{"host"}, "", keepLeftover, localProbeRunner(os.Getenv("PATH"))); err == nil {
		t.Error("CheckRemoteSocketFree() error = nil, want a refusal for a path that was never checked")
	}
}

// 造一个`sh`的`printf`不解析`\NNN`的`PATH`: 转义文本会存活为`p`的值, 非空,
// 守卫空解码的检查看不见它, 于是脚本对每个问题都答"no", 路径没被看过就判空闲.
// 故替身`sh`排在`PATH`最前, 把`printf`定义成原样打印格式串的函数, 再跑探针交来的body.
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

// 编码的fail-open面: `printf`不读`\NNN`时, 转义文本本身成了`p`的值, 非空,
// 空解码的守卫看不见它, 脚本的每个问题都答"no" - "不存在"是能让会话在没查过的
// 路径上开跑的答案, 绝不能由坏解码造出; 故先证明解码可信.
func TestRemoteSocketProbeRefusesADecodeItCannotTrust(t *testing.T) {
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")

	// 试金石: 同一路径在会解码的主机上得到"不存在"的正常结论, 坏解码绝不能造出它.
	if state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(os.Getenv("PATH"))); err != nil || state != socketFree {
		t.Fatalf("probeRemoteSocket() on a host that decodes = (%v, %v), want (socketFree, nil): this test needs the absent verdict to be the one a failed decode would give", state, err)
	}

	run := localProbeRunner(pathWithNonDecodingPrintf(t, os.Getenv("PATH")))
	state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, run)
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state == socketFree || state == socketReclaimed {
		t.Fatalf("state = %v, want neither a free path nor a removal: the path was never decoded, so nothing about it was checked", state)
	}
	if state != socketUnjudgeable {
		t.Errorf("state = %v, want socketUnjudgeable for a host whose printf cannot decode the path", state)
	}
	// 拒绝必须带上越过它的办法: 主机可达, 路径也许真空着, 是否硬启由用户权衡.
	_, err = CheckRemoteSocketFree([]string{"host"}, path, keepLeftover, run)
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal when the decode cannot be trusted")
	}
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
	}
}

// 上面检查的另一面: 问题出在主机的`printf`, 不在路径. 反斜杠是合法字节,
// 一刀切拒绝会让本可解码的路径全变成"unknown".
func TestRemoteSocketProbeJudgesAPathWithABackslash(t *testing.T) {
	requireShell(t)
	dir := filepath.Join(t.TempDir(), `back\slash`)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	path := filepath.Join(dir, "S.gpg-agent")
	run := localProbeRunner(ssPathForProbe(t))

	deadSocketAt(t, path)
	state, err := probeRemoteSocket([]string{"host"}, path, reclaimLeftover, run)
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketReclaimed {
		t.Fatalf("state = %v, want socketReclaimed: a path with a backslash in it is decoded and judged like any other", state)
	}
	if socketFileExists(t, path) {
		t.Errorf("%s is still there: the leftover was not the file the decode produced", path)
	}

	l := listenAt(t, path)
	defer l.Close()
	state, err = probeRemoteSocket([]string{"host"}, path, keepLeftover, run)
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketLive {
		t.Errorf("state = %v, want socketLive for a listener at a path with a backslash in it", state)
	}
	if !socketFileExists(t, path) {
		t.Error("a live socket was removed")
	}
}

func TestRemoteSocketProbeSeesAnAbsentPath(t *testing.T) {
	requireShell(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "S.gpg-agent")

	state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(os.Getenv("PATH")))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketFree {
		t.Fatalf("state = %v, want socketFree for a path that is not there", state)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the probe left %v behind at a path that did not exist: %v", entries, err)
	}
	if _, err := CheckRemoteSocketFree([]string{"host"}, path, keepLeftover, localProbeRunner(os.Getenv("PATH"))); err != nil {
		t.Errorf("CheckRemoteSocketFree() error = %v, want the session to start", err)
	}
}

// 只放`sh`和点名的工具: 没有shell命令根本跑不起来, 到不了想测的分支;
// 少放一个`grep`/`sed`就是在测没有它的主机.
func pathWithoutSS(t *testing.T, extra ...string) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh is not on PATH: %v", err)
	}
	dir := t.TempDir()
	if err := os.Symlink(sh, filepath.Join(dir, "sh")); err != nil {
		t.Fatalf("link sh into an otherwise empty PATH: %v", err)
	}
	for _, name := range extra {
		found, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("%s is not on PATH to put on the probe's: %v", name, err)
		}
		if err := os.Symlink(found, filepath.Join(dir, name)); err != nil {
			t.Fatalf("link %s into the probe's PATH: %v", name, err)
		}
	}
	return dir
}

func TestRemoteSocketProbeReclaimsADeadSocket(t *testing.T) {
	// 死socket本就该删, 这里显式要它: 这就是`--reclaim-remote-socket`买到的行为.
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	deadSocketAt(t, path)

	state, err := probeRemoteSocket([]string{"host"}, path, reclaimLeftover, localProbeRunner(ssPathForProbe(t)))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketReclaimed {
		t.Fatalf("state = %v, want socketReclaimed for a socket nothing listens on", state)
	}
	if socketFileExists(t, path) {
		t.Errorf("%s is still there: a dead socket blocks the next session's bind", path)
	}
	deadSocketAt(t, path)
	state, err = CheckRemoteSocketFree([]string{"host"}, path, reclaimLeftover, localProbeRunner(ssPathForProbe(t)))
	if err != nil || state != socketReclaimed {
		t.Errorf("CheckRemoteSocketFree() = (%v, %v), want (socketReclaimed, nil)", state, err)
	}
}

func TestRemoteSocketProbeLeavesALeftoverSocketInPlace(t *testing.T) {
	// 不用开关: 死socket只报告不删除. 两张表只覆盖一个网络命名空间,
	// 共享目录的容器里的agent两张表都看不到, 同样的证据会误删在用的socket.
	// 分不清两者就一律拒绝, 并把推翻此判断的途径交给调用方.
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	deadSocketAt(t, path)

	state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(ssPathForProbe(t)))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketStale {
		t.Fatalf("state = %v, want socketStale for a socket nothing listens on and no permission to remove it", state)
	}
	if !socketFileExists(t, path) {
		t.Fatalf("%s was removed without --reclaim-remote-socket", path)
	}
	// 拒绝必须可操作: 点名开关, 并带上能在远端删掉这个文件的命令.
	_, err = CheckRemoteSocketFree([]string{"host"}, path, keepLeftover, localProbeRunner(ssPathForProbe(t)))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal for a socket left behind")
	}
	if !strings.Contains(err.Error(), "--reclaim-remote-socket") {
		t.Errorf("error %v should name --reclaim-remote-socket", err)
	}
	if want := "rm -f -- " + shellQuoteSingle(path); !strings.Contains(err.Error(), want) {
		t.Errorf("error %v should carry %q, a command the user can paste on the remote host", err, want)
	}
	if !socketFileExists(t, path) {
		t.Errorf("%s was removed by the refusal path", path)
	}
}

// 查命令形状而非行为: 缺陷在行为上看不见 - 路径以`printf`编码出行, 从不以自身出现.
// `csh`/`tcsh`连单引号里也做历史展开, 路径里的`!`会让命令当场结束;
// 加引号救不了: `$`, `~`和反引号同样被特殊对待, 且都是合法路径字节, 唯一出路是在脚本内解码.
func TestRemoteSocketProbeNeverPutsThePathOnTheCommandLine(t *testing.T) {
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
	for _, path := range paths {
		if cmd := remoteSocketProbe(path, keepLeftover); strings.Contains(cmd, path) {
			t.Errorf("the probe command carries %q verbatim:\n%s", path, cmd)
		}
		state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(os.Getenv("PATH")))
		if err != nil {
			t.Fatalf("probeRemoteSocket(%q) error = %v", path, err)
		}
		if state != socketFree {
			t.Errorf("probeRemoteSocket(%q) = %v, want socketFree for a path that is not there", path, state)
		}
	}
	if _, err := os.Stat(canary); err == nil {
		t.Errorf("%s exists: a byte of the path was run as a command", canary)
	}
}

// 同一文件的各种写法: 探针得先认出它们, 才敢说路径上的东西是自己的遗留.
// 逐个手写而非用`filepath.Join`, 因为它正好会把这些组件清掉.
var pathSpellings = []struct {
	name  string
	other func(t *testing.T, path string) string
}{
	{"a symbolic link to the directory", func(t *testing.T, path string) string {
		t.Helper()
		dir := filepath.Dir(path)
		link := filepath.Join(t.TempDir(), "dir-link")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatalf("symlink %s: %v", link, err)
		}
		return link + "/" + filepath.Base(path)
	}},
	{"a component that goes up and comes back down", func(t *testing.T, path string) string {
		t.Helper()
		dir := filepath.Dir(path)
		return dir + "/../" + filepath.Base(dir) + "/" + filepath.Base(path)
	}},
	{"a doubled separator", func(t *testing.T, path string) string {
		t.Helper()
		return filepath.Dir(path) + "//" + filepath.Base(path)
	}},
}

// 钉住唯一会改远端的那条命令的形状, 行为测试看不见它: 两种拼写当时指向同一文件.
// 但检查与删除之间目录组件可能被改指向, 按输入的拼写删就会落到表从没问过的
// 文件上 - 授权删除的证据是针对解析后拼写收集的, 故删除只写`np`.
func TestRemoteSocketProbeRemovesOnlyTheResolvedSpelling(t *testing.T) {
	const path = "/run/user/1000/gnupg/S.gpg-agent"

	keeping := remoteSocketProbe(path, keepLeftover)
	if strings.Contains(keeping, "rm ") {
		t.Errorf("the probe removes something even though the caller kept the leftover:\n%s", keeping)
	}

	reclaiming := remoteSocketProbe(path, reclaimLeftover)
	if want := `rm -f -- "$np"`; !strings.Contains(reclaiming, want) {
		t.Errorf("the reclaiming probe does not carry %q:\n%s", want, reclaiming)
	}
	if strings.Contains(reclaiming, `rm -f -- "$p"`) {
		t.Errorf("the reclaiming probe removes the spelling the user typed rather than the resolved one:\n%s", reclaiming)
	}
}

func TestRemoteSocketProbeFindsALiveSocketWrittenAnotherWay(t *testing.T) {
	// 内核记的是监听者绑定时用的拼写: 符号链接, ..组件或双斜杠到达的socket也一样.
	// 只按用户输入的拼写匹配, 两张表都会对这个路径沉默, 而沉默正是授权删除的条件,
	// 转发就会删掉一个在用socket. 这里故意允许删除正是在测这种情况, socket必须活下来.
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	l := listenAt(t, path)
	defer l.Close()
	run := localProbeRunner(ssPathForProbe(t))

	for _, tc := range pathSpellings {
		t.Run(tc.name, func(t *testing.T) {
			spelling := tc.other(t, path)
			state, err := probeRemoteSocket([]string{"host"}, spelling, reclaimLeftover, run)
			if err != nil {
				t.Fatalf("probeRemoteSocket() error = %v", err)
			}
			if state != socketLive {
				t.Fatalf("state = %v, want socketLive: %s names the socket at %s", state, spelling, path)
			}
			if !socketFileExists(t, path) {
				t.Fatalf("%s was removed while something was listening on it", path)
			}
			c, err := net.Dial("unix", path)
			if err != nil {
				t.Errorf("the listener no longer accepts connections: %v", err)
			} else {
				c.Close()
			}
			if _, err := CheckRemoteSocketFree([]string{"host"}, spelling, reclaimLeftover, run); err == nil {
				t.Error("CheckRemoteSocketFree() error = nil, want a refusal for a path in use")
			}
		})
	}
}

func TestRemoteSocketProbeReclaimsALeftoverWrittenAnotherWay(t *testing.T) {
	// 同一枚硬币的另一面: 允许删除时, 死socket无论用户怎么写路径都会被删,
	// 删的是两张表被问到的那个文件, 不是它的另一个名字.
	requireShell(t)
	run := localProbeRunner(ssPathForProbe(t))

	for _, tc := range pathSpellings {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "S.gpg-agent")
			deadSocketAt(t, path)
			spelling := tc.other(t, path)

			state, err := probeRemoteSocket([]string{"host"}, spelling, reclaimLeftover, run)
			if err != nil {
				t.Fatalf("probeRemoteSocket() error = %v", err)
			}
			if state != socketReclaimed {
				t.Fatalf("state = %v, want socketReclaimed: %s names the leftover at %s", state, spelling, path)
			}
			if socketFileExists(t, path) {
				t.Errorf("%s is still there: a dead socket blocks the next session's bind", path)
			}
		})
	}
}

// 在`base`前放一个目录, 内有必失败的`readlink`和`realpath`:
// 主机两样都没有的样子. `base`其余部分不动, 探针的其他工具照常作答:
// 要的是解析不工作, 不是表读不出.
func pathWhereResolvingFails(t *testing.T, base string) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range []string{"readlink", "realpath"} {
		script := "#!/bin/sh\nexit 1\n"
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(script), 0o755); err != nil {
			t.Fatalf("write a %s that fails: %v", tool, err)
		}
	}
	return dir + string(os.PathListSeparator) + base
}

func TestRemoteSocketProbeLeavesWhatItCannotResolveAlone(t *testing.T) {
	// 删除按解析后的拼写授权: 解析做不了的主机没有回答删除依赖的问题.
	// 无论调用方允许什么都不删, 拒绝时说解析失败, 而不是说表读得好好的.
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	deadSocketAt(t, path)
	run := localProbeRunner(pathWhereResolvingFails(t, ssPathForProbe(t)))

	state, err := probeRemoteSocket([]string{"host"}, path, reclaimLeftover, run)
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketUnresolved {
		t.Fatalf("state = %v, want socketUnresolved when the path cannot be resolved", state)
	}
	if !socketFileExists(t, path) {
		t.Error("the probe removed a socket whose resolved spelling it never checked")
	}
	_, err = CheckRemoteSocketFree([]string{"host"}, path, reclaimLeftover, run)
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal when the path cannot be resolved")
	}
	if !strings.Contains(err.Error(), "readlink") {
		t.Errorf("error %v should name the resolution as what failed", err)
	}
	if strings.Contains(err.Error(), "/proc/net/unix") {
		t.Errorf("error %v should not blame the kernel's socket table, which was read fine", err)
	}
}

func TestRemoteSocketProbeLeavesALiveSocketAlone(t *testing.T) {
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	l := listenAt(t, path)
	defer l.Close()

	state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(ssPathForProbe(t)))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketLive {
		t.Fatalf("state = %v, want socketLive for a socket something listens on", state)
	}
	if !socketFileExists(t, path) {
		t.Fatalf("%s was removed while something was listening on it", path)
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Errorf("the listener no longer accepts connections: %v", err)
	} else {
		c.Close()
	}
	if _, err := CheckRemoteSocketFree([]string{"host"}, path, keepLeftover, localProbeRunner(ssPathForProbe(t))); err == nil {
		t.Error("CheckRemoteSocketFree() error = nil, want a refusal for a path in use")
	}
}

func TestRemoteSocketProbeLeavesAPlainFileAlone(t *testing.T) {
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	const content = "not a socket\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(ssPathForProbe(t)))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketNotASocket {
		t.Fatalf("state = %v, want socketNotASocket for a plain file", state)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != content {
		t.Errorf("%s now holds %q (%v), want it untouched", path, got, err)
	}
}

func TestRemoteSocketProbeReportsASymlinkAsUndecidable(t *testing.T) {
	requireShell(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "real-S.gpg-agent")
	l := listenAt(t, target)
	defer l.Close()
	path := filepath.Join(dir, "S.gpg-agent")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink %s: %v", path, err)
	}

	state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(ssPathForProbe(t)))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state == socketReclaimed || state == socketLive {
		t.Fatalf("state = %v, want neither a removal nor a live verdict for a symbolic link", state)
	}
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is no longer the symbolic link it was: %v, %v", path, fi, err)
	}
	if !socketFileExists(t, target) {
		t.Errorf("the listener's own socket at %s was removed", target)
	}
	// 错误必须说真正的原因: 怪到`ss`头上会让用户查错方向.
	_, err = CheckRemoteSocketFree([]string{"host"}, path, keepLeftover, localProbeRunner(ssPathForProbe(t)))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal for a symbolic link")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("error %v should say the path is a symbolic link", err)
	}
	if strings.Contains(err.Error(), "ss") {
		t.Errorf("error %v should not blame ss for a link it was never asked about", err)
	}
}

func TestRemoteSocketProbeIsUndecidedWithoutSS(t *testing.T) {
	// 没有`ss`的主机不能授权删除: 内核表只能说有socket绑在该路径, 只有`ss`
	// 能证明无人监听它, 所以无人听的socket留在原地, 调用方被告知主机答不了.
	// 读表工具与`sh`一起放进`PATH`, 判定针对缺`ss`, 不是第二个读不出的来源.
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	deadSocketAt(t, path)

	noSS := pathWithoutSS(t, "grep", "sed")
	state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(noSS))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketUnjudgeable {
		t.Fatalf("state = %v, want socketUnjudgeable where ss cannot be found", state)
	}
	if !socketFileExists(t, path) {
		t.Errorf("%s was removed by a probe that could not tell what it was", path)
	}
}

func TestRemoteSocketProbeNamesALiveSocketWithoutSS(t *testing.T) {
	// 内核表不依赖`ss`也能点出活着的agent: 否则只会报"could not tell",
	// 而该判定给出的`--skip-remote-check`会让sshd顶掉远端agent.
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	l := listenAt(t, path)
	defer l.Close()

	noSS := pathWithoutSS(t, "grep", "sed")
	state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(noSS))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketLive {
		t.Fatalf("state = %v, want socketLive: the kernel table lists %s on a host that has no ss", state, path)
	}
	if !socketFileExists(t, path) {
		t.Fatal("a live socket was removed on a host whose probe never mentioned it")
	}
	_, err = CheckRemoteSocketFree([]string{"host"}, path, keepLeftover, localProbeRunner(noSS))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal for a path in use")
	}
	if !strings.Contains(err.Error(), "in use") {
		t.Errorf("error %v should say the path is in use rather than that the host could not be checked", err)
	}
}

func TestRemoteSocketProbeDoesNotRemoveWhenSSFails(t *testing.T) {
	// `ss`失败时输出为空, 而管道报的是管道里最后一条命令的状态, 不是`ss`的:
	// 空输出不等于"无人监听", 要先看`ss`自己的退出码; 来源少一个就什么都不许删.
	requireShell(t)
	ssPath := brokenSSStub(t)

	t.Run("a live socket survives, and is still named as live", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "S.gpg-agent")
		l := listenAt(t, path)
		defer l.Close()

		state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(ssPath))
		if err != nil {
			t.Fatalf("probeRemoteSocket() error = %v", err)
		}
		// 内核表不因`ss`坏掉而失灵: 路径被占用就准确报出, 不是含糊其辞.
		if state != socketLive {
			t.Fatalf("state = %v, want socketLive: the kernel table lists the listener whatever ss does", state)
		}
		if !socketFileExists(t, path) {
			t.Fatal("the probe removed a live socket because a broken ss printed nothing")
		}
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Errorf("the listener no longer accepts connections: %v", err)
		} else {
			c.Close()
		}
		if _, err := CheckRemoteSocketFree([]string{"host"}, path, keepLeftover, localProbeRunner(ssPath)); err == nil {
			t.Error("CheckRemoteSocketFree() error = nil, want a refusal for a path that is in use")
		}
	})

	t.Run("a dead socket is left in place", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "S.gpg-agent")
		deadSocketAt(t, path)

		state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(ssPath))
		if err != nil {
			t.Fatalf("probeRemoteSocket() error = %v", err)
		}
		if state != socketUnjudgeable {
			t.Fatalf("state = %v, want socketUnjudgeable when ss fails", state)
		}
		if !socketFileExists(t, path) {
			t.Error("the probe removed a socket on the word of an ss that never answered")
		}
	})
}

func TestRemoteSocketProbeTellsUnknownWhenSSPrintsNothing(t *testing.T) {
	// `ss`干净退出但什么都没打印, 不等于无人监听, 所以判成无法判断而非可删.
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	deadSocketAt(t, path)

	state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(ssStub(t, "")))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketUnjudgeable {
		t.Fatalf("state = %v, want socketUnjudgeable when ss prints no table", state)
	}
	if !socketFileExists(t, path) {
		t.Error("the probe removed a socket on an ss that printed nothing")
	}
}

// 覆盖单来源的缺陷: `ss`退出0且打印成形的表, 却漏掉真实存在的监听者,
// 其输出与"无人监听"时诚实的`ss`一模一样, 只看`ss`就会删掉活socket.
func TestRemoteSocketProbeRefusesToBelieveASingleSource(t *testing.T) {
	requireShell(t)

	// 替身通过探针对`ss`自身的每项检查(存在, 退出0, 打出表头), 只是从不列出任何东西.
	lyingSS := ssStub(t, ssHeader)

	t.Run("a live socket is not removed on the word of a lying ss", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "S.gpg-agent")
		l := listenAt(t, path)
		defer l.Close()

		state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(lyingSS))
		if err != nil {
			t.Fatalf("probeRemoteSocket() error = %v", err)
		}
		if state != socketLive {
			t.Fatalf("state = %v, want socketLive: the kernel table lists %s whatever ss says", state, path)
		}
		if !socketFileExists(t, path) {
			t.Fatal("the probe removed a live socket on the word of an ss that never listed it")
		}
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Errorf("the listener no longer accepts connections: %v", err)
		} else {
			c.Close()
		}
		if _, err := CheckRemoteSocketFree([]string{"host"}, path, keepLeftover, localProbeRunner(lyingSS)); err == nil {
			t.Error("CheckRemoteSocketFree() error = nil, want the live verdict surfaced as a refusal")
		}
	})

	t.Run("the same stub is believed when it is the only source left", func(t *testing.T) {
		// 上一个子测试的牙齿: 单来源探针在这里会走出删除, 上一个子测试在它手里会失败.
		// 第二来源换成读得到且形如空表的替身, 内核表不再参与, 说谎的`ss`便会删掉活socket.
		path := filepath.Join(t.TempDir(), "S.gpg-agent")
		l := listenAt(t, path)
		defer l.Close()

		run := replaceProbeSource(localProbeRunner(lyingSS), procNetUnixPath, procTableStub(t, procTableHeader+"\n"))
		state, err := probeRemoteSocket([]string{"host"}, path, reclaimLeftover, run)
		if err != nil {
			t.Fatalf("probeRemoteSocket() error = %v", err)
		}
		if state != socketReclaimed {
			t.Fatalf("state = %v, want socketReclaimed with ss as the only source that can answer", state)
		}
		if socketFileExists(t, path) {
			t.Error("the socket is still there, so this stub alone does not drive the removal the subtest above guards against")
		}
	})

	t.Run("the same stub reclaims a dead socket when both sources omit it", func(t *testing.T) {
		// 交叉核对不是拒绝清理: 两张表都没列出的socket, 调用方要求的删除照旧执行.
		// 复用的替身对死socket打印的表与诚实`ss`无异.
		path := filepath.Join(t.TempDir(), "S.gpg-agent")
		deadSocketAt(t, path)

		state, err := probeRemoteSocket([]string{"host"}, path, reclaimLeftover, localProbeRunner(lyingSS))
		if err != nil {
			t.Fatalf("probeRemoteSocket() error = %v", err)
		}
		if state != socketReclaimed {
			t.Fatalf("state = %v, want socketReclaimed when neither source lists the path", state)
		}
		if socketFileExists(t, path) {
			t.Errorf("%s is still there: a dead socket blocks the next session's bind", path)
		}
	})
}

// 第二个来源完全不作答, 与回答"这里没有"不同: 只有一个来源时,
// 无论它多健康, 都不得删除.
func TestRemoteSocketProbeIsUndecidedWithoutTheKernelTable(t *testing.T) {
	requireShell(t)

	t.Run("a live socket survives", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "S.gpg-agent")
		l := listenAt(t, path)
		defer l.Close()

		// 空目录里的路径, 对脚本来说就是`/proc/net/unix`未挂载或读不到的样子.
		run := replaceProbeSource(localProbeRunner(ssStub(t, ssHeader)), procNetUnixPath, missingProcTable(t))
		state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, run)
		if err != nil {
			t.Fatalf("probeRemoteSocket() error = %v", err)
		}
		if state != socketUnjudgeable {
			t.Fatalf("state = %v, want socketUnjudgeable when the kernel table cannot be read", state)
		}
		if !socketFileExists(t, path) {
			t.Fatal("the probe removed a live socket with only ss to speak for it")
		}
		// 拒绝要给出绕过它的路: `/proc/net/unix`被屏蔽的主机, 用户仍可能想用.
		_, err = CheckRemoteSocketFree([]string{"host"}, path, keepLeftover, run)
		if err == nil {
			t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal while one source is missing")
		}
		if !strings.Contains(err.Error(), "--skip-remote-check") {
			t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
		}
	})

	t.Run("a dead socket is left in place", func(t *testing.T) {
		// 唯一作答的来源说"这里没有"也还不够: 删除要两个来源都同意.
		path := filepath.Join(t.TempDir(), "S.gpg-agent")
		deadSocketAt(t, path)

		run := replaceProbeSource(localProbeRunner(ssPathForProbe(t)), procNetUnixPath, missingProcTable(t))
		state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, run)
		if err != nil {
			t.Fatalf("probeRemoteSocket() error = %v", err)
		}
		if state != socketUnjudgeable {
			t.Fatalf("state = %v, want socketUnjudgeable when the kernel table cannot be read", state)
		}
		if !socketFileExists(t, path) {
			t.Error("the probe removed a socket with only ss to vouch for it")
		}
	})
}

// 覆盖两个来源对路径拼写不一致的情形: `ss`可以把空格打成`\x20`,
// 探针按真实拼写做整字段匹配就会漏掉那行; 内核表原样打印路径,
// 所以监听者仍被找到, socket不会被删.
func TestRemoteSocketProbeFindsALiveSocketWhosePathSSEscapes(t *testing.T) {
	requireShell(t)
	dir := t.TempDir()
	sub := filepath.Join(dir, "with space")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("create %s: %v", sub, err)
	}
	path := filepath.Join(sub, "S.gpg-agent")
	l := listenAt(t, path)
	defer l.Close()

	// 成形的表, 唯一毛病是路径拼写: `ss`对监听者诚实, 对它的名字不诚实.
	escaped := strings.ReplaceAll(path, " ", `\x20`)
	ssPath := ssStub(t, ssHeader+"\nu_str LISTEN 0 4096 "+escaped+" 4242 * 0")

	state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(ssPath))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketLive {
		t.Fatalf("state = %v, want socketLive: the kernel table prints %s as it is", state, path)
	}
	if !socketFileExists(t, path) {
		t.Fatal("the probe removed a live socket because ss escaped the space in its path")
	}
	if _, err := CheckRemoteSocketFree([]string{"host"}, path, keepLeftover, localProbeRunner(ssPath)); err == nil {
		t.Error("CheckRemoteSocketFree() error = nil, want a refusal for a path in use")
	}
}

func TestRemoteSocketProbeMatchesWholeAddressFields(t *testing.T) {
	requireShell(t)

	t.Run("a longer path is not this path", func(t *testing.T) {
		// 默认agent路径是`S.gpg-agent.extra`的前缀: 子串匹配会把死socket认成活,
		// 让它挡住bind, 而诊断会怪到远端agent头上.
		dir := t.TempDir()
		path := filepath.Join(dir, "S.gpg-agent")
		deadSocketAt(t, path)
		table := strings.Join([]string{
			ssHeader,
			"u_str LISTEN 0 4096 " + path + ".extra 4242 * 0",
			"u_str LISTEN 0 4096 /tmp/x" + path + "y 4243 * 0",
		}, "\n")

		state, err := probeRemoteSocket([]string{"host"}, path, reclaimLeftover, localProbeRunner(ssStub(t, table)))
		if err != nil {
			t.Fatalf("probeRemoteSocket() error = %v", err)
		}
		if state != socketReclaimed {
			t.Fatalf("state = %v, want socketReclaimed: a listening sibling is not this path", state)
		}
		if socketFileExists(t, path) {
			t.Errorf("%s is still there, so the dead socket was read as live", path)
		}
	})

	t.Run("a path that ends a line is still this path", func(t *testing.T) {
		// 地址是这行的最后一个字段, 后面什么都没有: 省掉对端列的表就是这样.
		path := filepath.Join(t.TempDir(), "S.gpg-agent")
		l := listenAt(t, path)
		defer l.Close()
		table := ssHeader + "\nu_str LISTEN 0 4096 " + path

		state, err := probeRemoteSocket([]string{"host"}, path, keepLeftover, localProbeRunner(ssStub(t, table)))
		if err != nil {
			t.Fatalf("probeRemoteSocket() error = %v", err)
		}
		if state != socketLive {
			t.Fatalf("state = %v, want socketLive for the last field of a line", state)
		}
		if !socketFileExists(t, path) {
			t.Error("a live socket was removed because its address ended a line")
		}
	})
}

// 返回内核形状的unix socket表, 内有n个绑定的socket:
// 用来量探针在socket很多的主机上的开销. 成本在shell处理表的部分,
// 而表每次调用都要读, 最忙的主机表最大, 所以这部分必须有界.
func largeSocketTable(n int) string {
	var b strings.Builder
	b.WriteString(procTableHeader)
	b.WriteString("\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "0000000000000000: 00000002 00000000 00010000 0002 01 %8d /run/sockets/socket-%d\n", 100000+i, i)
	}
	return b.String()
}

// 同一台主机在`ss`眼里的样子: 每个socket一行监听记录.
func largeSSTable(n int) string {
	var b strings.Builder
	b.WriteString(ssHeader)
	b.WriteString("\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "u_str LISTEN 0 4096 /run/sockets/socket-%d 4242 * 0\n", i)
	}
	return b.String()
}

// 搭一台有rows个unix socket和一条无关路径的主机, 返回在那边跑探针的runner.
// 路径是死socket, 所以探针必须读两张表才能说出任何话.
func benchProbeOnALargeTable(b *testing.B, rows int) (SSHCommandRunner, string) {
	b.Helper()
	if runtime.GOOS == "windows" {
		b.Skip("the probe is a POSIX shell command")
	}
	dir := b.TempDir()
	probed := filepath.Join(dir, "S.gpg-agent")
	procTable := filepath.Join(dir, "unix")
	if err := os.WriteFile(procTable, []byte(largeSocketTable(rows)), 0o644); err != nil {
		b.Fatalf("write the stand-in kernel table: %v", err)
	}
	ssTable := filepath.Join(dir, "ss-table")
	if err := os.WriteFile(ssTable, []byte(largeSSTable(rows)), 0o644); err != nil {
		b.Fatalf("write the stand-in ss table: %v", err)
	}
	ssDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(ssDir, 0o755); err != nil {
		b.Fatalf("make a directory for the ss stand-in: %v", err)
	}
	stub := "#!/bin/sh\ncat " + shellQuoteSingle(ssTable) + "\n"
	if err := os.WriteFile(filepath.Join(ssDir, "ss"), []byte(stub), 0o755); err != nil {
		b.Fatalf("write the ss stand-in: %v", err)
	}
	path := ssDir + string(os.PathListSeparator) + os.Getenv("PATH")
	run := replaceProbeSource(localProbeRunner(path), procNetUnixPath, procTable)
	return run, probed
}

// 留下一个无人监听的socket文件: 探针要读两张表才能判的状态. 是`deadSocketAt`
// 的benchmark版(它要`testing.T`); 路径上已有文件先删, 否则bind会失败.
func deadSocketAtForBench(b *testing.B, path string) {
	b.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		b.Fatalf("clear %s: %v", path, err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		b.Fatalf("listen on %s: %v", path, err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := l.Close(); err != nil {
		b.Fatalf("close the listener for %s: %v", path, err)
	}
}

// 量一次探针: 200000个绑定unix socket的主机, 路径上放一个死socket.
// socket文件每轮重建(探针会删掉它), 要量的是探针而非删除;
// `BenchmarkDeadSocketSetup`量搭建, 两者之差即探针自身成本.
func BenchmarkRemoteSocketProbeOnALargeTable(b *testing.B) {
	run, probed := benchProbeOnALargeTable(b, 200000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		deadSocketAtForBench(b, probed)
		b.StartTimer()
		if _, err := probeRemoteSocket([]string{"host"}, probed, reclaimLeftover, run); err != nil {
			b.Fatalf("probeRemoteSocket() error = %v", err)
		}
	}
}

// 量`BenchmarkRemoteSocketProbeOnALargeTable`花在探针之外的部分, 好把它减掉.
func BenchmarkDeadSocketSetup(b *testing.B) {
	if runtime.GOOS == "windows" {
		b.Skip("the socket file is made with a unix listener")
	}
	path := filepath.Join(b.TempDir(), "S.gpg-agent")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		deadSocketAtForBench(b, path)
	}
}
