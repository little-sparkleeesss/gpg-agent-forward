package cli

import (
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
	cmd := remoteSocketProbe("/run/user/1000/gnupg/S.gpg-agent")
	if strings.ContainsAny(cmd, "\n\r") {
		t.Errorf("probe %q spans lines, which the remote login shell refuses to parse", cmd)
	}
	if !strings.HasPrefix(cmd, "sh -c ") {
		t.Errorf("probe %q does not run its body under sh", cmd)
	}
}

func TestRemoteSocketProbeCommandRunsUnderTcsh(t *testing.T) {
	// FreeBSD root登录时sshd用的shell; `-f`跳过cshrc, 只量命令不量登录环境.
	tcsh, err := exec.LookPath("tcsh")
	if err != nil {
		t.Skip("tcsh is not installed; TestRemoteSocketProbeCommandIsOneLine covers the shape it rejects")
	}
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	out, err := exec.Command(tcsh, "-f", "-c", remoteSocketProbe(path)).Output()
	if err != nil {
		t.Fatalf("tcsh could not run the probe: %v (output %q)", err, out)
	}
	if !strings.Contains(string(out), socketAbsentMarker) {
		t.Errorf("tcsh ran the probe but reported %q, want the absent marker in it", out)
	}
}

func TestRemoteSocketProbeSeesAnAbsentPath(t *testing.T) {
	requireShell(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "S.gpg-agent")

	state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(os.Getenv("PATH")))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketFree {
		t.Fatalf("state = %v, want socketFree for a path that is not there", state)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the probe left %v behind at a path that did not exist: %v", entries, err)
	}
	if _, err := CheckRemoteSocketFree([]string{"host"}, path, localProbeRunner(os.Getenv("PATH"))); err != nil {
		t.Errorf("CheckRemoteSocketFree() error = %v, want the session to start", err)
	}
}

// 只放`sh`和点名工具的`PATH`: 没有shell命令跑不起来, 到不了测试想去的分支.
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
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	deadSocketAt(t, path)

	state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(ssPathForProbe(t)))
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
	state, err = CheckRemoteSocketFree([]string{"host"}, path, localProbeRunner(ssPathForProbe(t)))
	if err != nil || state != socketReclaimed {
		t.Errorf("CheckRemoteSocketFree() = (%v, %v), want (socketReclaimed, nil)", state, err)
	}
}

func TestRemoteSocketProbeLeavesALiveSocketAlone(t *testing.T) {
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	l := listenAt(t, path)
	defer l.Close()

	state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(ssPathForProbe(t)))
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
	if _, err := CheckRemoteSocketFree([]string{"host"}, path, localProbeRunner(ssPathForProbe(t))); err == nil {
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

	state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(ssPathForProbe(t)))
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

	state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(ssPathForProbe(t)))
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
	_, err = CheckRemoteSocketFree([]string{"host"}, path, localProbeRunner(ssPathForProbe(t)))
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
	// 没有`ss`就无从授权删除: 内核表只说路径上有绑定, 只有`ss`能证明没人在听,
	// 故无人监听的socket留在原地, 调用方被告知主机答不了.
	// 把`tr`放进`PATH`是为了让内核表真能读, 免得结论变成第二来源也读不了.
	requireShell(t)
	path := filepath.Join(t.TempDir(), "S.gpg-agent")
	deadSocketAt(t, path)

	noSS := pathWithoutSS(t, "tr")
	state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(noSS))
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

	noSS := pathWithoutSS(t, "tr")
	state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(noSS))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketLive {
		t.Fatalf("state = %v, want socketLive: the kernel table lists %s on a host that has no ss", state, path)
	}
	if !socketFileExists(t, path) {
		t.Fatal("a live socket was removed on a host whose probe never mentioned it")
	}
	_, err = CheckRemoteSocketFree([]string{"host"}, path, localProbeRunner(noSS))
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

		state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(ssPath))
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
		if _, err := CheckRemoteSocketFree([]string{"host"}, path, localProbeRunner(ssPath)); err == nil {
			t.Error("CheckRemoteSocketFree() error = nil, want a refusal for a path that is in use")
		}
	})

	t.Run("a dead socket is left in place", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "S.gpg-agent")
		deadSocketAt(t, path)

		state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(ssPath))
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

	state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(ssStub(t, "")))
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

		state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(lyingSS))
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
		if _, err := CheckRemoteSocketFree([]string{"host"}, path, localProbeRunner(lyingSS)); err == nil {
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
		state, err := probeRemoteSocket([]string{"host"}, path, run)
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

	t.Run("a dead socket is still removed when both sources omit it", func(t *testing.T) {
		// 交叉核对不是拒绝清理: 两张表都没列出的socket照旧被回收.
		// 复用的替身对死socket打印的表与诚实`ss`无异.
		path := filepath.Join(t.TempDir(), "S.gpg-agent")
		deadSocketAt(t, path)

		state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(lyingSS))
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
		state, err := probeRemoteSocket([]string{"host"}, path, run)
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
		_, err = CheckRemoteSocketFree([]string{"host"}, path, run)
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
		state, err := probeRemoteSocket([]string{"host"}, path, run)
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

	state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(ssPath))
	if err != nil {
		t.Fatalf("probeRemoteSocket() error = %v", err)
	}
	if state != socketLive {
		t.Fatalf("state = %v, want socketLive: the kernel table prints %s as it is", state, path)
	}
	if !socketFileExists(t, path) {
		t.Fatal("the probe removed a live socket because ss escaped the space in its path")
	}
	if _, err := CheckRemoteSocketFree([]string{"host"}, path, localProbeRunner(ssPath)); err == nil {
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

		state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(ssStub(t, table)))
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

		state, err := probeRemoteSocket([]string{"host"}, path, localProbeRunner(ssStub(t, table)))
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
