package cli

import (
	"errors"
	"strings"
	"testing"
)

// `runReporting`返回的runner对每次探测都只回一行给定判定.
func runReporting(verdict string) SSHCommandRunner {
	return func([]string, string) (string, error) { return verdict + "\n", nil }
}

func TestCheckRemoteSocketFreeAcceptsAFreePath(t *testing.T) {
	if _, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", keepLeftover, runReporting(socketAbsentMarker)); err != nil {
		t.Errorf("CheckRemoteSocketFree() error = %v, want nil for a free path", err)
	}
}

func TestCheckRemoteSocketFreeAcceptsAReclaimedPath(t *testing.T) {
	// 无人监听的socket是结束会话的遗留而非远端agent: 在远端删除, 用户不必每次先手动清理.
	if _, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", keepLeftover, runReporting(socketReclaimedMarker)); err != nil {
		t.Errorf("CheckRemoteSocketFree() error = %v, want nil after a dead socket is reclaimed", err)
	}
}

func TestCheckRemoteSocketFreeRefusesALeftoverSocket(t *testing.T) {
	// 无人绑定的socket像是结束会话的遗留, 但证据只是远端主机自己的socket表, 它们只描述一个
	// 网络命名空间: 共享该目录的容器里的agent在两张表里都看不见, 删文件会连它的socket一起删.
	// 会话就此停下, 报错带上决策所需: 远端删掉这个文件的命令, 和交出决定的开关.
	_, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", keepLeftover, runReporting(socketStaleMarker))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal for a socket left behind")
	}
	if !strings.Contains(err.Error(), "--reclaim-remote-socket") {
		t.Errorf("error %v should name --reclaim-remote-socket as the way to have it removed", err)
	}
	if !strings.Contains(err.Error(), "rm -f -- '/run/user/1000/gnupg/S.gpg-agent'") {
		t.Errorf("error %v should carry the command that removes the socket on the remote host", err)
	}
	// 已达成的结论而非做不成的检查: 已有socket时会话本就起不来, `--skip-remote-check`在这里无事可做.
	if strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error for a leftover socket offers --skip-remote-check: %v", err)
	}
}

func TestCheckRemoteSocketFreeRefusesALiveSocket(t *testing.T) {
	// 活socket属于远端自己的gpg-agent: 转发到它要靠`StreamLocalBindUnlink`顶掉占位,
	// 会把gpg静默导向那里应答的东西, 所以报告为问题, 不能覆盖.
	_, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", keepLeftover, runReporting(socketLiveMarker))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a warning for a path in use")
	}
	if !strings.Contains(err.Error(), "/run/user/1000/gnupg/S.gpg-agent") {
		t.Errorf("error %v should name the path", err)
	}
	if !strings.Contains(err.Error(), "no-autostart") {
		t.Errorf("error %v should say how to stop the remote agent", err)
	}
}

func TestCheckRemoteSocketFreeRefusesAFileThatIsNotASocket(t *testing.T) {
	// 路径上的东西不是遗留agent socket, 就不是本工具该删的: 里面可能是用户的数据.
	_, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", keepLeftover, runReporting(socketNotASocketMarker))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal for a non-socket file")
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("error %v should say the file is not a socket", err)
	}
}

func TestCheckRemoteSocketFreeRefusesAStuckSocket(t *testing.T) {
	_, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", keepLeftover, runReporting(socketStuckMarker))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal when a dead socket cannot be removed")
	}
	if !strings.Contains(err.Error(), "could not be removed") {
		t.Errorf("error %v should say the socket could not be removed", err)
	}
}

func TestCheckRemoteSocketFreeRefusesWhenItCannotTell(t *testing.T) {
	// 两张socket表不都有答案时(任一来源答不上来), 死socket与活socket无从区分,
	// 猜"死"就可能删掉活agent的socket; 拒绝要讲清来源没答上的情形, 并给出照常启动的开关.
	_, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", keepLeftover, runReporting(socketUnknownMarker))
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal when the host cannot tell")
	}
	if !strings.Contains(err.Error(), "ss") {
		t.Errorf("error %v should name ss among the sources that did not answer", err)
	}
	if !strings.Contains(err.Error(), "/proc/net/unix") {
		t.Errorf("error %v should name the kernel's socket table among the sources that did not answer", err)
	}
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
	}
}

func TestCheckRemoteSocketFreeOffersNoSkipForAVerdictItReached(t *testing.T) {
	// `--skip-remote-check`只对做不成的检查有效, 对已达成的结论无效:
	// 活socket, 非socket文件, 符号链接, 遗留, 删不掉的socket都是确定答案, 不是信息缺失而是
	// 停下的理由, 报错不得提供该开关; 遗留是本端唯一可处理的结论, 其报错改带删除命令和开关.
	for _, marker := range []string{socketLiveMarker, socketNotASocketMarker, socketStuckMarker, socketSymlinkMarker, socketStaleMarker} {
		_, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", keepLeftover, runReporting(marker))
		if err == nil {
			t.Errorf("CheckRemoteSocketFree(%s) error = nil, want a refusal", marker)
			continue
		}
		if strings.Contains(err.Error(), "--skip-remote-check") {
			t.Errorf("error for %s offers --skip-remote-check: %v", marker, err)
		}
	}
}

func TestCheckRemoteSocketFreeRefusesWhenNoVerdictIsReported(t *testing.T) {
	// 毫无标记说明探针没按原样跑(如登录shell解析不了): 没删东西, 也没检查, 而这样启动正是
	// sshd绑上活agent socket的途径. 拒绝要给出绕行开关, 让这个风险是用户明知的选择.
	run := func([]string, string) (string, error) { return "Welcome to the host\n", nil }
	state, err := CheckRemoteSocketFree([]string{"host"}, "/p", keepLeftover, run)
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal when nothing was reported")
	}
	if state != socketUnreported {
		t.Errorf("CheckRemoteSocketFree() state = %v, want socketUnreported", state)
	}
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
	}
}

func TestCheckRemoteSocketFreeIgnoresBannerMentioningAMarkerWord(t *testing.T) {
	// 判定只能取探针独立成行打印的标记, 不能扫全部输出: 登录banner里出现普通词,
	// 被读成判定就会改变答案.
	run := func([]string, string) (string, error) {
		return "WARNING: your token is absent, present it soon\n" + socketLiveMarker + "\n", nil
	}
	if _, err := CheckRemoteSocketFree([]string{"host"}, "/p", keepLeftover, run); err == nil {
		t.Error("CheckRemoteSocketFree() error = nil, want the live verdict taken from the marker, not from the banner")
	}
}

func TestCheckRemoteSocketFreeRefusesASymlink(t *testing.T) {
	// 符号链接既不删除也不判为空闲: 它背后是什么在这端看不出, 归咎于缺少`ss`会让用户
	// 找错方向.
	_, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", keepLeftover, runReporting(socketSymlinkMarker))
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

// 探针自身行为(删什么, 留什么, 拒绝判什么)靠`remote_probe_test.go`真跑它生成的命令覆盖:
// 只比对命令文本抓不到`ss`失败被读成"无人监听".

func TestRemoteSocketProbeEscapesAQuoteInThePath(t *testing.T) {
	// `ValidateRemoteSocket`不拒绝单引号, 含单引号的路径必须以字面文本到达远端,
	// 而不是提前闭合引号; 这里转义要过两层: 路径在脚本里被引号一次, 脚本再为`sh -c`引号一次.
	const quotePath = "/tmp/x';id;echo '"
	var seen string
	run := func(_ []string, cmd string) (string, error) {
		seen = cmd
		return socketAbsentMarker + "\n", nil
	}
	CheckRemoteSocketFree([]string{"host"}, quotePath, keepLeftover, run)

	if !strings.HasPrefix(seen, "sh -c ") {
		t.Fatalf("remote command %q should run under sh", seen)
	}
	// 去掉外层引号, 按远端`sh`的读法看脚本: 里面的路径必须是单独一个单引号词,
	// 这样路径里的";id;"才不会是独立命令.
	script := shellUnquoteSingle(strings.TrimPrefix(seen, "sh -c "))
	want := "p=" + shellQuoteSingle(quotePath)
	if !strings.Contains(script, want) {
		t.Errorf("script does not carry the path as one quoted word:\n  got  %q,\n want it to contain %q", script, want)
	}
}

// `shellUnquoteSingle`是`shellQuoteSingle`的逆操作, 便于测试按shell的读法还原引号串.
func shellUnquoteSingle(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		s = s[1 : len(s)-1]
	}
	return strings.ReplaceAll(s, `'\''`, "'")
}

func TestCheckRemoteSocketFreeSurfacesRunnerFailure(t *testing.T) {
	run := func([]string, string) (string, error) { return "", errors.New("ssh: connection failed") }
	if _, err := CheckRemoteSocketFree([]string{"host"}, "/p", keepLeftover, run); err == nil {
		t.Error("CheckRemoteSocketFree() error = nil, want the ssh failure surfaced")
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
