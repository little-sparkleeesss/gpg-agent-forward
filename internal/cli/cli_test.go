package cli

import (
	"os/exec"
	"path/filepath"
	"runtime"
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

func TestBuildSSHArgsEscapesThePercentSign(t *testing.T) {
	// ssh会展开`-R`参数里的`%`记号: 路径里的`%h`变成远端主机名, 探针查一个路径而sshd
	// 绑另一个; 不认识的记号 (如`%Q`) 让ssh直接拒绝启动. 字面百分号要写成`%%`.
	got := BuildSSHArgs(nil, "/run/user/1000/gnupg%h/S.gpg-agent", 29173)
	want := "/run/user/1000/gnupg%%h/S.gpg-agent:127.0.0.1:29173"
	if got[1] != want {
		t.Errorf("forward spec = %q, want %q", got[1], want)
	}
}

func TestRemoteSocketForwardSpecSurvivesRealSSHPercentExpansion(t *testing.T) {
	// 转义有没有用要问ssh本身: `-G`打印它将建立的转发 (百分号已展开), 其中的socket必须
	// 与探针检查的一致. 运行失败或该ssh不支持`-G`时跳过而非失败: 答案只关乎测试机的ssh.
	if runtime.GOOS == "windows" {
		t.Skip("ssh -G is asked for on the test host")
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skipf("no ssh on PATH to ask what -R means: %v", err)
	}
	const path = "/run/user/1000/gnupg%h/S.gpg-agent"
	spec := BuildSSHArgs(nil, path, 29173)[1]
	// `-F /dev/null`把测试机自己的配置挡在答案之外.
	out, err := exec.Command(sshBin, "-F", "/dev/null", "-G", "-R", spec, "example.invalid").Output()
	if err != nil {
		t.Skipf("ssh could not report what -R %s would set up: %v", spec, err)
	}
	listen := ""
	for _, line := range strings.Split(string(out), "\n") {
		rest, ok := strings.CutPrefix(line, "remoteforward ")
		if !ok {
			continue
		}
		listen, _, _ = strings.Cut(rest, " ")
		break
	}
	if listen == "" {
		t.Skipf("ssh -G did not report a remote forward for %q:\n%s", spec, out)
	}
	if listen != path {
		t.Errorf("ssh would listen on %q, want %q: the probe checks one and sshd binds the other", listen, path)
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
		// 空格和单引号在Unix路径里合法, 探针会为远端shell引用路径, 拒绝它们会错杀能用的路径.
		"/run/user/1000/gnupg dir/S.gpg-agent",
		"/run/user/1000/it's/S.gpg-agent",
		// 非ASCII名字是普通Unix路径 (用转义写以保持本文件ASCII); 校验的是会不会破坏远端
		// 命令, 而不是locale允许什么.
		"/run/user/1000/gnupg-\xe4\xbb\xa3\xe7\x90\x86/S.gpg-agent",
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

	// 控制字符. 换行最要命: 探针是交给远端登录shell的单行命令, `csh`/`tcsh`拒绝跨行的
	// 引号词, 于是探针什么都不跑, 所有检查都读成`could not be checked`.
	// 其余字符在路径里也没用, 还会让路径对不上远端列出的地址.
	rejected := []struct {
		name string
		path string
	}{
		{"newline", "/run/user/1000/gnupg\n/S.gpg-agent"},
		{"carriage return", "/run/user/1000/gnupg\r/S.gpg-agent"},
		{"tab", "/run/user/1000/gnupg\t/S.gpg-agent"},
		{"DEL", "/run/user/1000/gnupg\x7f/S.gpg-agent"},
	}
	for _, tc := range rejected {
		if err := ValidateRemoteSocket(tc.path); err == nil {
			t.Errorf("ValidateRemoteSocket(%q) error = nil, want rejection of a %s", tc.path, tc.name)
		}
	}
	// 报错必须说出原因, 不只说字符非法: 原因才让用户明白这路径无论怎么引用都不行.
	if err := ValidateRemoteSocket("/tmp/a\nb"); err == nil || !strings.Contains(err.Error(), "single-line") {
		t.Errorf("ValidateRemoteSocket() error = %v, want it to explain the single-line remote command", err)
	}

	// `sockaddr_un`的`sun_path`含结尾符上限108字节: 路径107字节放得下, 108不行.
	fits := "/" + strings.Repeat("a", 106)
	if err := ValidateRemoteSocket(fits); err != nil {
		t.Errorf("ValidateRemoteSocket(%d-byte path) error = %v, want nil", len(fits), err)
	}
	if err := ValidateRemoteSocket(fits + "a"); err == nil {
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
