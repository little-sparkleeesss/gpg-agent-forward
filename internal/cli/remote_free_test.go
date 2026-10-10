package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateRemoteSocketRejectsOccupiedPathCheck(t *testing.T) {
	// 远端路径上已存在的socket属于远端自己的gpg-agent: 转发到它要靠`StreamLocalBindUnlink`顶掉占位,
	// 会把gpg静默导向那里应答的东西, 所以按问题处理, 不能覆盖.
	occupied := func([]string, string) (string, error) { return socketPresentMarker + "\n", nil }
	free := func([]string, string) (string, error) { return socketAbsentMarker + "\n", nil }

	err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", occupied)
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a warning for an occupied path")
	}
	if !strings.Contains(err.Error(), "/run/user/1000/gnupg/S.gpg-agent") {
		t.Errorf("error %v should name the path", err)
	}
	if !strings.Contains(err.Error(), "no-autostart") {
		t.Errorf("error %v should say how to stop the remote agent", err)
	}

	if err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", free); err != nil {
		t.Errorf("CheckRemoteSocketFree() error = %v, want nil for a free path", err)
	}
}

func TestCheckRemoteSocketFreeIgnoresBannerMentioningPresent(t *testing.T) {
	// 判定必须来自远端测试打印的标记, 不能扫全部输出: 登录banner里有"present"这种普通词,
	// 就会让空闲的路径被误判而中止隧道.
	run := func([]string, string) (string, error) {
		return "WARNING: certificate expires soon; present your token\n" + socketAbsentMarker + "\n", nil
	}
	if err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", run); err != nil {
		t.Errorf("CheckRemoteSocketFree() error = %v, want nil when the path is free", err)
	}
}

func TestCheckRemoteSocketFreeQuotesThePath(t *testing.T) {
	// 路径会被拼进远端主机上的shell命令, 必须加引号, 不能原样插值.
	var seen string
	run := func(_ []string, cmd string) (string, error) { seen = cmd; return socketAbsentMarker + "\n", nil }

	CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", run)
	if !strings.Contains(seen, "'/run/user/1000/gnupg/S.gpg-agent'") {
		t.Errorf("remote command %q does not quote the path", seen)
	}
	if !strings.Contains(seen, "test -e") {
		t.Errorf("remote command %q does not test for existence", seen)
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

func TestCheckRemoteSocketFreeEscapesAQuoteInThePath(t *testing.T) {
	var seen string
	run := func(_ []string, cmd string) (string, error) { seen = cmd; return socketAbsentMarker + "\n", nil }

	CheckRemoteSocketFree([]string{"host"}, "/tmp/x';id;echo '", run)
	want := `test -e '/tmp/x'\'';id;echo '\''' && echo ` + socketPresentMarker + ` || echo ` + socketAbsentMarker
	if seen != want {
		t.Errorf("remote command =\n  %q\nwant\n  %q", seen, want)
	}
}

func TestCheckRemoteSocketFreeSurfacesRunnerFailure(t *testing.T) {
	run := func([]string, string) (string, error) { return "", errors.New("ssh: connection failed") }
	if err := CheckRemoteSocketFree([]string{"host"}, "/p", run); err == nil {
		t.Error("CheckRemoteSocketFree() error = nil, want the ssh failure surfaced")
	}
}
