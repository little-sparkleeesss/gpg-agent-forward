package cli

import (
	"errors"
	"strings"
	"testing"
)

// 预检的调用方分支: 哪些结论放行, 哪些拒绝, 每个拒绝让用户做什么. 检查所建的连接
// (表单命令, 控制连接, 分类)由`remote_probe_test.go`对真绑真连的替身ssh端到端覆盖.

// `runForm`报告一次性表单命令在路径上看到的结果.
func runForm(marker string) SSHCommandRunner {
	return func([]string, string) (string, error) {
		if marker == "" {
			return "Welcome to the host\n", nil
		}
		return marker + "\n", nil
	}
}

// `runFormThenRemoval`让表单命令与删除命令各答各的, 测试按内容分辨两者.
func runFormThenRemoval(formMarker, removalMarker string) SSHCommandRunner {
	return func(_ []string, remoteCommand string) (string, error) {
		if strings.Contains(remoteCommand, "rm -f") {
			return removalMarker + "\n", nil
		}
		return formMarker + "\n", nil
	}
}

// 替换分类结论: 这是检查里唯一需要活ssh连接的部分,
// 替换本身由`remote_probe_test.go`覆盖.
func withClassification(t *testing.T, verdict socketForwardVerdict, err error) {
	t.Helper()
	old := classifyRemoteSocketForward
	classifyRemoteSocketForward = func([]string, string, string) (socketForwardVerdict, error) {
		return verdict, err
	}
	t.Cleanup(func() { classifyRemoteSocketForward = old })
}

func TestCheckRemoteSocketFreeAcceptsAFreePath(t *testing.T) {
	// 路径上什么都没有才是健康: 不存在的路径后面不可能有监听者, sshd的绑定可取用它.
	if _, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", runForm(socketAbsentMarker)); err != nil {
		t.Errorf("CheckRemoteSocketFree() error = %v, want nil for a free path", err)
	}
}

// 无人监听的socket是上次会话的遗留, 直接删除让下一次会话能绑定, 无需任何开关.
func TestCheckRemoteSocketFreeReclaimsALeftover(t *testing.T) {
	withClassification(t, forwardDead, nil)
	state, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent",
		runFormThenRemoval(socketSocketMarker, socketReclaimedMarker))
	if err != nil {
		t.Fatalf("CheckRemoteSocketFree() error = %v, want the leftover removed and the session to start", err)
	}
	if state != socketReclaimed {
		t.Errorf("state = %v, want socketReclaimed", state)
	}
}

// 钉住检查存在的理由: 路径属于远端自己的agent, 转发过去会让gpg跟错agent.
func TestCheckRemoteSocketFreeRefusesALiveSocket(t *testing.T) {
	withClassification(t, forwardLive, nil)
	_, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent",
		runForm(socketSocketMarker))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal for a path in use")
	}
	if !strings.Contains(err.Error(), "/run/user/1000/gnupg/S.gpg-agent") {
		t.Errorf("error %v should name the path", err)
	}
	if !strings.Contains(err.Error(), "no-autostart") {
		t.Errorf("error %v should say how to stop the remote agent", err)
	}
}

// fail-closed核心: 分类做不成(sshd拒绝stream-local转发, ssh连不上)时就绝不能走到删路径,
// 因为被拒绝在这端和无人监听无从区分; 唯一允许的删除是检查自己的控制socket, 所以这里
// 的断言都针对被测路径.
func TestCheckRemoteSocketFreeRemovesNothingWhenItCannotTell(t *testing.T) {
	var commands []string
	run := func(_ []string, remoteCommand string) (string, error) {
		commands = append(commands, remoteCommand)
		if strings.Contains(remoteCommand, "rm -f") && !isControlSocketRemoval(t, remoteCommand) {
			t.Errorf("the check ran a removal it had no verdict for: %s", remoteCommand)
		}
		return socketSocketMarker + "\n", nil
	}
	withClassification(t, forwardUnjudgeable, errors.New("the control connection was not established"))

	state, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", run)
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal when the check cannot tell")
	}
	if state != socketUnjudgeable {
		t.Errorf("state = %v, want socketUnjudgeable", state)
	}
	// 拒绝必须给出绕行路: 主机可达, 路径很可能空闲, 是否冒险启动由用户权衡.
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
	}
	if len(commands) == 0 {
		t.Error("no remote command was run at all, so this proves nothing about what was not removed")
	}
}

// `isControlSocketRemoval`区分远端命令删的是检查自己的控制socket还是被测路径:
// 控制路径是随机名, 靠其前缀的八进制编码拼写识别.
func isControlSocketRemoval(t *testing.T, remoteCommand string) bool {
	t.Helper()
	return strings.Contains(remoteCommand, octalEscapes("/"+controlSocketPrefix))
}

func TestCheckRemoteSocketFreeRefusesAFileThatIsNotASocket(t *testing.T) {
	// 路径上的东西不是遗留agent socket, 就不是本工具该删的: 里面可能是用户的数据.
	_, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", runForm(socketNotASocketMarker))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal for a non-socket file")
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("error %v should say the file is not a socket", err)
	}
}

// 覆盖让"无权限"情形安全的那道闸门: 连接socket需要它的写权限, 权限拒绝到达本端时表现为
// 连接被关闭, 与无人监听的socket一模一样; 所以先在主机上正面测权限, 再信任任何连接.
func TestCheckRemoteSocketFreeRefusesAPathItCannotWrite(t *testing.T) {
	_, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", runForm(socketUnwritableMarker))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal for a path this user cannot write")
	}
	if !strings.Contains(err.Error(), "cannot be written") {
		t.Errorf("error %v should say the path cannot be written", err)
	}
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
	}
}

// 覆盖由删除结果本身决定结论: 目录不可写或路径本身是目录时连接也会被拒,
// 所以"没人应答"本身证明不了文件是遗留.
func TestCheckRemoteSocketFreeRefusesAStuckSocket(t *testing.T) {
	withClassification(t, forwardDead, nil)
	state, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent",
		runFormThenRemoval(socketSocketMarker, socketStuckMarker))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal when the leftover cannot be removed")
	}
	if state != socketStuck {
		t.Errorf("state = %v, want socketStuck", state)
	}
	if !strings.Contains(err.Error(), "could not be removed") {
		t.Errorf("error %v should say the socket could not be removed", err)
	}
}

func TestCheckRemoteSocketFreeRefusesWhenNoVerdictIsReported(t *testing.T) {
	// 毫无标记说明远端命令没按原样跑: 登录shell解析不了, 输出被过滤, 主机没有`sh`.
	// 那种情况没删东西, 但也没检查过.
	state, err := CheckRemoteSocketFree([]string{"host"}, "/p", runForm(""))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal when nothing was reported")
	}
	if state != socketUnjudgeable {
		t.Errorf("CheckRemoteSocketFree() state = %v, want socketUnjudgeable", state)
	}
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
	}
}

// 判定取的是远端命令独立成行打印的标记, 不是扫全部输出:
// 登录banner里的普通词被读成判定就会改变答案.
func TestCheckRemoteSocketFreeIgnoresBannerMentioningAMarkerWord(t *testing.T) {
	withClassification(t, forwardLive, nil)
	run := func([]string, string) (string, error) {
		return "WARNING: nothing is gpg-agent-forward-socket-absent here\n" + socketSocketMarker + "\n", nil
	}
	if _, err := CheckRemoteSocketFree([]string{"host"}, "/p", run); err == nil {
		t.Error("CheckRemoteSocketFree() error = nil, want the socket verdict taken from the marker line, not from the banner")
	}
}

// `--skip-remote-check`只对做不成的检查有效, 对已达成的结论无效:
// 活socket, 非socket文件, 删不掉的socket的报错都不得提供它.
func TestCheckRemoteSocketFreeOffersNoSkipForAVerdictItReached(t *testing.T) {
	cases := []struct {
		name     string
		form     string
		verdict  socketForwardVerdict
		removal  string
		wantWant string
	}{
		{"a live socket", socketSocketMarker, forwardLive, "", "in use"},
		{"a file that is not a socket", socketNotASocketMarker, forwardLive, "", "not a socket"},
		{"a socket that could not be removed", socketSocketMarker, forwardDead, socketStuckMarker, "could not be removed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withClassification(t, tc.verdict, nil)
			_, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent",
				runFormThenRemoval(tc.form, tc.removal))
			if err == nil {
				t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal")
			}
			if strings.Contains(err.Error(), "--skip-remote-check") {
				t.Errorf("error for %s offers --skip-remote-check: %v", tc.name, err)
			}
			if !strings.Contains(err.Error(), tc.wantWant) {
				t.Errorf("error %v should say %q", err, tc.wantWant)
			}
		})
	}
}

func TestCheckRemoteSocketFreeSurfacesRunnerFailure(t *testing.T) {
	run := func([]string, string) (string, error) { return "", errors.New("ssh: connection failed") }
	if _, err := CheckRemoteSocketFree([]string{"host"}, "/p", run); err == nil {
		t.Error("CheckRemoteSocketFree() error = nil, want the ssh failure surfaced")
	}
}

// 覆盖检查自己的临时资源: 无论结论如何, 它在路径旁创建的socket都会删掉,
// 且绝不是被测路径.
func TestCheckRemoteSocketFreeRemovesTheControlSocket(t *testing.T) {
	var removed []string
	run := func(_ []string, remoteCommand string) (string, error) {
		if strings.Contains(remoteCommand, "rm -f") {
			removed = append(removed, remoteCommand)
			return socketReclaimedMarker + "\n", nil
		}
		return socketSocketMarker + "\n", nil
	}
	withClassification(t, forwardLive, nil)

	if _, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", run); err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want the live verdict refused")
	}
	if len(removed) != 1 {
		t.Fatalf("removals = %d, want exactly the control socket removed once", len(removed))
	}
	if !isControlSocketRemoval(t, removed[0]) {
		t.Errorf("the removal is not of a control socket: %s", removed[0])
	}
	if isPathRemoval(t, removed[0], "/run/user/1000/gnupg/S.gpg-agent") {
		t.Errorf("the control cleanup removed the path under test: %s", removed[0])
	}
}

// `isPathRemoval`判断远端命令是否删了给定路径: 找删除所发送的八进制编码拼写,
// 路径没有任何一个字节出现在远端命令行上 (详见`remoteSocketRemove`).
func isPathRemoval(t *testing.T, remoteCommand, path string) bool {
	t.Helper()
	return strings.Contains(remoteCommand, octalEscapes(path))
}

// 控制socket是检查自己的资源, 分类成功与否都要删掉;
// 删失败留下的是无人监听的socket, 下一次预检会回收.
func TestCheckRemoteSocketFreeRemovesTheControlSocketOnAFailedClassification(t *testing.T) {
	var removals int
	run := func(_ []string, remoteCommand string) (string, error) {
		if strings.Contains(remoteCommand, "rm -f") {
			removals++
			return socketStuckMarker + "\n", nil
		}
		return socketSocketMarker + "\n", nil
	}
	withClassification(t, forwardUnjudgeable, errors.New("no control"))

	if _, err := CheckRemoteSocketFree([]string{"host"}, "/p", run); err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal")
	}
	if removals != 1 {
		t.Errorf("removals = %d, want the control socket cleaned up once even though the classification failed", removals)
	}
}

// 控制socket需要的两条性质: 与被测路径同目录(sshd要绑该路径, 该目录本来就得可写),
// 且绝不等于被测路径, 否则删控制socket就成了删会话自己的socket.
func TestControlSocketPathIsBesideThePathAndNeverIt(t *testing.T) {
	const p = "/run/user/1000/gnupg/S.gpg-agent"
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		got, err := controlSocketPath(p)
		if err != nil {
			t.Fatalf("controlSocketPath(%q) error = %v", p, err)
		}
		if got == p {
			t.Fatalf("controlSocketPath(%q) = the path itself", p)
		}
		if dir := strings.TrimSuffix(got, "/"+baseName(got)); dir != "/run/user/1000/gnupg" {
			t.Errorf("controlSocketPath(%q) = %q, want it in the path's own directory", p, got)
		}
		if err := ValidateRemoteSocket(got); err != nil {
			t.Errorf("controlSocketPath(%q) = %q, which ValidateRemoteSocket refuses: %v", p, got, err)
		}
		seen[got] = true
	}
	if len(seen) != 100 {
		t.Errorf("%d distinct control paths out of 100, want a unique name each time", len(seen))
	}
}

// 控制socket名比旁边的路径更长; 本用例的路径是113字节, 本身已越过107字节上限,
// 放不下它. 超限报错而非截断: 截断的控制路径可能落到别处, 所以这里选拒绝决断.
func TestControlSocketPathSurvivesALongPath(t *testing.T) {
	long := "/run/user/1000/gnupg/" + strings.Repeat("d", 80) + "/S.gpg-agent"
	got, err := controlSocketPath(long)
	if err == nil {
		if len(got) >= 108 {
			t.Fatalf("controlSocketPath returned a %d-byte path, past the 107-byte limit", len(got))
		}
		t.Fatalf("controlSocketPath(%q) = %q, want either a usable path or an error", long, got)
	}
	if !strings.Contains(err.Error(), "control socket") {
		t.Errorf("error %v should say the control socket is what could not be named", err)
	}
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// 钉住分类连接的转发形状: 控制socket一条`-R`, 控制一条`-L`, 被测路径一条`-L`,
// 外加`ClearAllForwardings=no`, 少了它ssh会把三条一起丢掉 (详见`sshKeepForwardings`).
func TestSSHForwardArgsCarryTheThreeForwards(t *testing.T) {
	args, err := sshForwardArgs([]string{"dev@host"}, socketForwardSpec{
		controlPort: 1111,
		controlPath: "/run/user/1000/gnupg/.gpg-agent-forward-probe-abc",
		targetPort:  2222,
		targetPath:  "/run/user/1000/gnupg/S.gpg-agent",
		holdPort:    3333,
	})
	if err != nil {
		t.Fatalf("sshForwardArgs() error = %v", err)
	}
	got := strings.Join(args, " ")
	for _, want := range []string{
		"-o ClearAllForwardings=no",
		"-N",
		"-R /run/user/1000/gnupg/.gpg-agent-forward-probe-abc:127.0.0.1:3333",
		"-L 127.0.0.1:1111:/run/user/1000/gnupg/.gpg-agent-forward-probe-abc",
		"-L 127.0.0.1:2222:/run/user/1000/gnupg/S.gpg-agent",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("sshForwardArgs() = %q, want it to contain %q", got, want)
		}
	}
	if !strings.HasSuffix(got, "dev@host") {
		t.Errorf("sshForwardArgs() = %q, want the destination last", got)
	}
}

// 路径写在`-L`/`-R`规格里, ssh会展开其中的`%`, 不写成`%%`就会指向别的socket; 用户参数原样透传.
func TestSSHForwardArgsEscapePercentInPaths(t *testing.T) {
	args, err := sshForwardArgs([]string{"-p", "2222", "dev@host"}, socketForwardSpec{
		controlPort: 1, controlPath: "/tmp/a%h", targetPort: 2, targetPath: "/tmp/b%d", holdPort: 3,
	})
	if err != nil {
		t.Fatalf("sshForwardArgs() error = %v", err)
	}
	got := strings.Join(args, " ")
	if !strings.Contains(got, "-R /tmp/a%%h:127.0.0.1:3") {
		t.Errorf("sshForwardArgs() = %q, want the control path's per cent doubled", got)
	}
	if !strings.Contains(got, "-L 127.0.0.1:2:/tmp/b%%d") {
		t.Errorf("sshForwardArgs() = %q, want the target path's per cent doubled", got)
	}
	if !strings.Contains(got, "-p 2222") {
		t.Errorf("sshForwardArgs() = %q, want the user's own flags passed through", got)
	}
}

// 只有独立成行的标记才算判定: banner, 残缺的一行, 什么都没有,
// 都留下未决, 即`formUnknown`.
func TestParseSocketFormIsStrict(t *testing.T) {
	tests := []struct {
		in   string
		want socketForm
	}{
		{socketAbsentMarker + "\n", formAbsent},
		{socketUnwritableMarker + "\n", formUnwritable},
		{socketNotASocketMarker + "\n", formNotASocket},
		{socketSocketMarker + "\n", formSocket},
		{socketUnknownMarker + "\n", formUnknown},
		{"", formUnknown},
		{"banner\n" + socketAbsentMarker + "\nmore\n", formAbsent},
		{"x" + socketAbsentMarker + "\n", formUnknown},
		{"welcome to the host\n", formUnknown},
	}
	for _, tt := range tests {
		if got := parseSocketForm(tt.in); got != tt.want {
			t.Errorf("parseSocketForm(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestShellQuoteSingleEscapesQuotes(t *testing.T) {
	// `ValidateRemoteSocket`不拒绝单引号, 含单引号的路径必须作为单个字面词传入,
	// 否则会提前闭合引号并把后面的内容当命令跑; 转义用标准的闭合-转义-重开形式.
	tests := []struct {
		in   string
		want string
	}{
		{"/run/user/1000/gnupg/S.gpg-agent", "'/run/user/1000/gnupg/S.gpg-agent'"},
		{"/tmp/x';id;echo '", `'/tmp/x'\'';id;echo '\'''`},
		{"it's", `'it'\''s'`},
	}
	for _, tt := range tests {
		if got := shellQuoteSingle(tt.in); got != tt.want {
			t.Errorf("shellQuoteSingle(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
