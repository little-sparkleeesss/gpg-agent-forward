package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSSHArgsInsertsRemoteForward(t *testing.T) {
	got := BuildSSHArgs(
		[]string{"-p", "22", "dev@example.com"},
		"/run/user/1000/gnupg/S.gpg-agent",
		29173,
	)
	want := []string{
		"-R", "/run/user/1000/gnupg/S.gpg-agent:127.0.0.1:29173",
		"-o", "ExitOnForwardFailure=yes",
		"-p", "22", "dev@example.com",
	}
	if len(got) != len(want) {
		t.Fatalf("BuildSSHArgs() = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("arg %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBuildSSHArgsFailsLoudlyWhenForwardFails(t *testing.T) {
	// 不设`ExitOnForwardFailure`时ssh只警告并继续: 用户得到没有隧道的shell, 签名会静默
	// 改用远端主机上的agent, 而不是Windows上的那个.
	got := BuildSSHArgs([]string{"dev@host"}, "/s", 1234)
	if !containsPair(got, "-o", "ExitOnForwardFailure=yes") {
		t.Errorf("BuildSSHArgs() = %q, want it to force ExitOnForwardFailure=yes", got)
	}
}

func TestBuildSSHArgsRespectsUserForwardFailureChoice(t *testing.T) {
	// 用户已显式设置这个选项时就沿用它, 不追加冲突值.
	for _, userArgs := range [][]string{
		{"-o", "ExitOnForwardFailure=no", "dev@host"},
		{"-o", "ExitOnForwardFailure yes", "dev@host"},
		{"-oExitOnForwardFailure=no", "dev@host"},
	} {
		got := BuildSSHArgs(userArgs, "/s", 1234)
		if countOccurrences(got, "ExitOnForwardFailure") > 1 {
			t.Errorf("BuildSSHArgs(%q) = %q, want the user's setting not duplicated", userArgs, got)
		}
	}
}

func containsPair(args []string, a, b string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == a && args[i+1] == b {
			return true
		}
	}
	return false
}

func countOccurrences(args []string, needle string) int {
	n := 0
	for _, a := range args {
		if strings.Contains(a, needle) {
			n++
		}
	}
	return n
}

func TestBuildSSHArgsWithNoExtraArgs(t *testing.T) {
	got := BuildSSHArgs(nil, "/run/user/1000/gnupg/S.gpg-agent", 29173)
	want := []string{
		"-R", "/run/user/1000/gnupg/S.gpg-agent:127.0.0.1:29173",
		"-o", "ExitOnForwardFailure=yes",
	}
	if !equalStrings(got, want) {
		t.Errorf("BuildSSHArgs() = %q, want %q", got, want)
	}
}

func TestBuildSSHArgsAlwaysBindsLoopback(t *testing.T) {
	// 转发目的地由本地ssh进程回拨, 必须是relay的loopback监听, 不能是别的.
	got := BuildSSHArgs(nil, "/s", 1234)
	if got[1] != "/s:127.0.0.1:1234" {
		t.Errorf("forward spec = %q, want %q", got[1], "/s:127.0.0.1:1234")
	}
}

func TestBuildSSHArgsDoesNotMutateInput(t *testing.T) {
	in := []string{"-p", "22"}
	BuildSSHArgs(in, "/s", 1234)
	if len(in) != 2 || in[0] != "-p" || in[1] != "22" {
		t.Errorf("input slice was mutated: %q", in)
	}
}

func TestSplitSSHArgsLeavesSSHFlagsAlone(t *testing.T) {
	// `-N`, `-p`, `-i`, `-o`是ssh自己的flag: 目的地之后和本程序不认识的参数必须原样到达ssh.
	tests := []struct {
		name        string
		in          []string
		wantOwn     []string
		wantThrough []string
	}{
		{
			name:        "ssh flags pass through",
			in:          []string{"-N", "-p", "22", "-i", "key", "dev@host"},
			wantOwn:     nil,
			wantThrough: []string{"-N", "-p", "22", "-i", "key", "dev@host"},
		},
		{
			name:        "own flags are consumed",
			in:          []string{"--port", "1234", "--remote-socket", "/s", "-N", "dev@host"},
			wantOwn:     []string{"--port", "1234", "--remote-socket", "/s"},
			wantThrough: []string{"-N", "dev@host"},
		},
		{
			name:        "idle is consumed, never passed to ssh",
			in:          []string{"--idle", "5m", "dev@host"},
			wantOwn:     []string{"--idle", "5m"},
			wantThrough: []string{"dev@host"},
		},
		{
			name:        "idle with an attached value is consumed too",
			in:          []string{"--idle=5m", "dev@host"},
			wantOwn:     []string{"--idle=5m"},
			wantThrough: []string{"dev@host"},
		},
		{
			name:        "single dash form works too",
			in:          []string{"-port", "1234", "dev@host"},
			wantOwn:     []string{"-port", "1234"},
			wantThrough: []string{"dev@host"},
		},
		{
			name:        "equals form works",
			in:          []string{"--port=1234", "dev@host"},
			wantOwn:     []string{"--port=1234"},
			wantThrough: []string{"dev@host"},
		},
		{
			name:        "own flag after destination still consumed",
			in:          []string{"dev@host", "--port", "1234", "-N"},
			wantOwn:     []string{"--port", "1234"},
			wantThrough: []string{"dev@host", "-N"},
		},
		{
			name:        "everything after -- goes to ssh",
			in:          []string{"--", "-N", "dev@host"},
			wantOwn:     nil,
			wantThrough: []string{"-N", "dev@host"},
		},
		{
			name:        "no args",
			in:          nil,
			wantOwn:     nil,
			wantThrough: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			own, through := SplitSSHArgs(tt.in)
			if !equalStrings(own, tt.wantOwn) {
				t.Errorf("own = %q, want %q", own, tt.wantOwn)
			}
			if !equalStrings(through, tt.wantThrough) {
				t.Errorf("through = %q, want %q", through, tt.wantThrough)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDefaultSocketFileUsesLocalAppDataOnWindows(t *testing.T) {
	got := DefaultSocketFile(`C:\Users\me\AppData\Local`, `C:\Users\me`)
	want := filepath.Join(`C:\Users\me\AppData\Local`, "gnupg", "S.gpg-agent.extra")
	if got != want {
		t.Errorf("DefaultSocketFile() = %q, want %q", got, want)
	}
}

func TestDefaultSocketFileExtraByDefault(t *testing.T) {
	// 额外的agent socket是GnuPG给远端转发文档化的受限接口: 能签名, 不能管理密钥或访问口令.
	got := DefaultSocketFile(`C:\lad`, `C:\Users\me`)
	if filepath.Base(got) != "S.gpg-agent.extra" {
		t.Errorf("DefaultSocketFile() = %q, want the .extra socket", got)
	}
}

func TestValidatePort(t *testing.T) {
	for _, p := range []int{1, 1024, 29173, 65535} {
		if err := ValidatePort(p); err != nil {
			t.Errorf("ValidatePort(%d) error = %v, want nil", p, err)
		}
	}
	for _, p := range []int{0, -1, 65536, 100000} {
		if err := ValidatePort(p); err == nil {
			t.Errorf("ValidatePort(%d) error = nil, want rejection", p)
		}
	}
}

func TestValidateRemoteSocket(t *testing.T) {
	ok := []string{
		"/run/user/1000/gnupg/S.gpg-agent",
		"/home/me/.gnupg-forwarded/S.gpg-agent",
		"relative/path/S.gpg-agent",
	}
	for _, p := range ok {
		if err := ValidateRemoteSocket(p); err != nil {
			t.Errorf("ValidateRemoteSocket(%q) error = %v, want nil", p, err)
		}
	}

	// 冒号会被ssh当作地址分隔符, 静默转发到非预期位置.
	if err := ValidateRemoteSocket("/tmp/a:b"); err == nil {
		t.Error("ValidateRemoteSocket() error = nil, want rejection of a colon")
	}
	if err := ValidateRemoteSocket(""); err == nil {
		t.Error("ValidateRemoteSocket() error = nil, want rejection of an empty path")
	}
	// `sockaddr_un`的`sun_path`上限108字节, 含结尾符.
	long := "/" + string(make([]byte, 108))
	if err := ValidateRemoteSocket(long); err == nil {
		t.Error("ValidateRemoteSocket() error = nil, want rejection of an over-long path")
	}
}

func TestParsePort(t *testing.T) {
	if p, err := ParsePort("29173"); err != nil || p != 29173 {
		t.Errorf("ParsePort(\"29173\") = (%d, %v), want (29173, nil)", p, err)
	}
	for _, s := range []string{"", "abc", "0", "-5", "65536", "12.5"} {
		if _, err := ParsePort(s); err == nil {
			t.Errorf("ParsePort(%q) error = nil, want rejection", s)
		}
	}
}
