package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSSHDestination(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{
			name: "plain destination",
			args: []string{"user@192.0.2.10"},
			want: "user@192.0.2.10",
		},
		{
			name: "flags before destination",
			args: []string{"-p", "45731", "-i", "key", "user@192.0.2.10"},
			want: "user@192.0.2.10",
		},
		{
			name: "value attached to short flag",
			args: []string{"-p22", "host"},
			want: "host",
		},
		{
			name: "value attached to -o",
			args: []string{"-oStrictHostKeyChecking=no", "host"},
			want: "host",
		},
		{
			name: "-o with separate value",
			args: []string{"-o", "StrictHostKeyChecking=no", "host"},
			want: "host",
		},
		{
			name: "bundled value flag mid-group",
			args: []string{"-4o", "StrictHostKeyChecking=no", "host"},
			want: "host",
		},
		{
			// 同一个选项的GNU式拼写: 它的值是一个独立参数, 不解析它就会把值当成目的地.
			name: "--option's value is not the destination",
			args: []string{"--option", "StrictHostKeyChecking=no", "user@192.0.2.10"},
			want: "user@192.0.2.10",
		},
		{
			name: "no-value flags bundled",
			args: []string{"-4vN", "host"},
			want: "host",
		},
		{
			name: "destination followed by a remote command",
			args: []string{"host", "uptime"},
			want: "host",
		},
		{
			name: "options after the destination are still parsed",
			args: []string{"user@host", "-p", "2222"},
			want: "user@host",
		},
		{
			name: "value-taking option after the destination is not the destination",
			args: []string{"user@host", "-B", "eth0"},
			want: "user@host",
		},
		{
			name: "bind interface before the destination",
			args: []string{"-B", "eth0", "user@example.com"},
			want: "user@example.com",
		},
		{
			name: "tag option takes a value",
			args: []string{"-P", "mytag", "user@example.com"},
			want: "user@example.com",
		},
		{
			name: "double dash ends option parsing",
			args: []string{"--", "-weird-host"},
			want: "-weird-host",
		},
		{
			name: "ipv6 literal",
			args: []string{"-p", "22", "user@[::1]"},
			want: "user@[::1]",
		},
		{
			name:    "no destination",
			args:    []string{"-N"},
			wantErr: true,
		},
		{
			name:    "empty",
			args:    nil,
			wantErr: true,
		},
		{
			name:    "only a remote command, no destination",
			args:    []string{"-o", "X=1"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := ParseSSHArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseSSHArgs(%q) error = nil, want error", tt.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSSHArgs(%q) error = %v", tt.args, err)
			}
			if got != tt.want {
				t.Errorf("destination = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSSHArgsConnectionFlags(t *testing.T) {
	// 发现连接要保留连接选项, 丢掉会抑制远端命令或建立通道的: `-N`会让查询挂住, 多余的
	// `-R`可能与relay自己的转发冲突.
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "connection options are kept",
			args: []string{"-p", "45731", "-i", "key", "host"},
			want: []string{"-p", "45731", "-i", "key"},
		},
		{
			name: "-N is dropped",
			args: []string{"-N", "-p", "22", "host"},
			want: []string{"-p", "22"},
		},
		{
			name: "forwards are dropped with their values",
			args: []string{"-R", "/a:/b", "-L", "1:2:3", "host"},
			want: nil,
		},
		{
			name: "backgrounding and control flags are dropped",
			args: []string{"-f", "-M", "-S", "ctl", "host"},
			want: nil,
		},
		{
			name: "attached forms are dropped too",
			args: []string{"-Nf", "-p22", "host"},
			want: []string{"-p22"},
		},
		{
			name: "destination and command are not flags",
			args: []string{"host", "gpgconf"},
			want: nil,
		},
		{
			name: "no flags at all",
			args: []string{"host"},
			want: nil,
		},
		{
			// ssh会重排参数, 目的地之后的选项也必须进查询连接: 丢掉它就会按默认端口查询,
			// 而真实会话用的是另一个端口.
			name: "options after the destination are collected",
			args: []string{"host", "-p", "2222", "-i", "key"},
			want: []string{"-p", "2222", "-i", "key"},
		},
		{
			name: "options after a remote command are not collected",
			args: []string{"host", "uptime", "-p", "2222"},
			want: nil,
		},
		{
			name: "bind interface is dropped with its value",
			args: []string{"-B", "eth0", "-p", "22", "host"},
			want: []string{"-p", "22"},
		},
		{
			// `-R`和`-L`有长拼写, 只有字母的flag表看不见它; 查询连接上的转发会绑定它正要检查
			// 的路径, 把刚建出的socket报成占用.
			name: "forwards spelled as options are dropped too",
			args: []string{"-o", "RemoteForward=/a:/b", "-oLocalForward=/tmp/l:/tmp/r", "-p", "22", "host"},
			want: []string{"-p", "22"},
		},
		{
			name: "a dynamic forward is dropped with its value",
			args: []string{"-o", "DynamicForward=1080", "host"},
			want: nil,
		},
		{
			name: "an option bundled behind another short flag is read the same way",
			args: []string{"-4oRemoteForward=/a:/b", "-p", "22", "host"},
			want: []string{"-4", "-p", "22"},
		},
		{
			// ssh在`=`或空白处拆分关键字和值: `RemoteForward /a:/b`这种写法与
			// `RemoteForward=/a:/b`等价; 只按`=`拆分会漏掉前者.
			name: "the space-separated spelling of an option sets the same thing",
			args: []string{"-o", "RemoteForward /a:/b", "-p", "22", "host"},
			want: []string{"-p", "22"},
		},
		{
			name: "whitespace before an option's keyword does not hide it",
			args: []string{"-o", "  RemoteForward = /a:/b", "-p", "22", "host"},
			want: []string{"-p", "22"},
		},
		{
			name: "keywords are matched without regard to case",
			args: []string{"-o", "REMOTEFORWARD=/a:/b", "-o", "forkafterauthentication=yes", "host"},
			want: nil,
		},
		{
			// 用户自己的命令会顶替查询命令; 强制tty把答案变成交互会话的输出 (提示符, 回显,
			// CRLF), 查询答案的严格解析不是为这种输出写的.
			name: "a remote command or a forced tty is dropped",
			args: []string{"-o", "RemoteCommand=uptime", "-o", "RequestTTY=force", "-p", "22", "host"},
			want: []string{"-p", "22"},
		},
		{
			// ssh对标量取先读到的值, 而本包把`ClearAllForwardings=yes`放在用户参数之前: 用户的
			// 值赢不了它. 键仍然被丢掉而不是留在向量里, 好让清空不只依赖这条规则.
			name: "the user's own ClearAllForwardings is dropped",
			args: []string{"-o", "ClearAllForwardings=no", "-p", "22", "host"},
			want: []string{"-p", "22"},
		},
		{
			// ssh会跳过选项与关键字之间的一个`=`: 这些写法与普通拼写等效, 而按第一个`=`切分的
			// 过滤器会从它们里读出空关键字并放行.
			name: "one leading '=' before the keyword changes nothing for ssh or for us",
			args: []string{"-o", "=RemoteForward=/a:/b", "-o", "  =DynamicForward=1080", "-o", "= RemoteCommand=uptime", "-o=RequestTTY=force", "-p", "22", "host"},
			want: []string{"-p", "22"},
		},
		{
			name: "the clearing option is dropped in the leading-'=' spelling too",
			args: []string{"-o=ClearAllForwardings=no", "host"},
			want: nil,
		},
		{
			// 两个`=`下ssh什么也不设置, 查询也就照原样放过它. 丢掉在这里无害, 但保留才与会话
			// 一致.
			name: "two leading '=' set nothing in ssh and so leave nothing to filter",
			args: []string{"-o", "==RemoteForward=/a:/b", "-p", "22", "host"},
			want: []string{"-o", "==RemoteForward=/a:/b", "-p", "22"},
		},
		{
			// `-t`是`RequestTTY`自己的拼写, 与`RequestTTY`是同一个选项: pty会把一次性
			// 答案变成交互输出; `-tt`只是同一个flag两次.
			name: "a forced tty is dropped in its short spelling too",
			args: []string{"-t", "-4tt", "-p", "22", "host"},
			want: []string{"-4", "-p", "22"},
		},
		{
			name: "options this package has no quarrel with are kept as written",
			args: []string{"-o", "StrictHostKeyChecking=accept-new", "-oForwardAgent=yes", "-o", "ExitOnForwardFailure=yes", "host"},
			want: []string{"-o", "StrictHostKeyChecking=accept-new", "-oForwardAgent=yes", "-o", "ExitOnForwardFailure=yes"},
		},
		{
			// ssh自己拒绝`--option`, 这种拼写做不出可用的连接; 在这里读它是不让值被当成目的地,
			// 并让同一套关键字过滤作用到它.
			name: "--option is read as the option it spells",
			args: []string{"--option=RemoteForward=/a:/b", "--option", "RemoteCommand=uptime", "-p", "22", "host"},
			want: []string{"-p", "22"},
		},
		{
			name: "--option with a keyword this package keeps is passed through as written",
			args: []string{"--option=ConnectTimeout=5", "host"},
			want: []string{"--option=ConnectTimeout=5"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, flags, err := ParseSSHArgs(tt.args)
			if err != nil {
				t.Fatalf("ParseSSHArgs(%q) error = %v", tt.args, err)
			}
			if !equalStrings(flags, tt.want) {
				t.Errorf("connection flags = %q, want %q", flags, tt.want)
			}
		})
	}
}

func TestParseSSHArgsDoesNotMutateInput(t *testing.T) {
	in := []string{"-N", "-p", "22", "host"}
	ParseSSHArgs(in)
	if !equalStrings(in, []string{"-N", "-p", "22", "host"}) {
		t.Errorf("input mutated: %q", in)
	}
}

// `sshCommandArgs`必须清掉配置文件要求, 参数过滤看不见的转发, 且不让用户的值压过
// 它: 标量选项ssh取先读到的值, 所以清空值要放在向量最前, 而不是用户参数之后.
func TestSSHCommandArgsClearsForwardingsOnTheOneShotConnection(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "no flags at all",
			args: []string{"host"},
			want: []string{"-o", "ClearAllForwardings=yes", "host", "true"},
		},
		{
			name: "the clear goes ahead of every option the user wrote, before the destination",
			args: []string{"-o", "RemoteForward=/a:/b", "-p", "45731", "user@host"},
			want: []string{"-o", "ClearAllForwardings=yes", "-p", "45731", "user@host", "true"},
		},
		{
			name: "a value of the user's for the same key cannot come first",
			args: []string{"-o", "ClearAllForwardings=no", "host"},
			want: []string{"-o", "ClearAllForwardings=yes", "host", "true"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sshCommandArgs(tt.args, "true")
			if err != nil {
				t.Fatalf("sshCommandArgs(%q) error = %v", tt.args, err)
			}
			if !equalStrings(got, tt.want) {
				t.Errorf("sshCommandArgs(%q) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

// `sshEffectiveConfig`用真ssh的`-G`模式问一组参数的含义, 返回按选项名归并的配置.
// `-G`不连接任何地方, 又是唯一读真实连接同一份选项表的办法; `-F`空配置文件让答案
// 只关乎向量本身, 不受测试机`ssh_config`影响. 自带配置文件的测试详见`sshEffectiveConfigWith`.
func sshEffectiveConfig(t *testing.T, args []string) map[string][]string {
	t.Helper()
	return sshEffectiveConfigWith(t, "", args)
}

// `sshEffectiveConfigWith`就是`sshEffectiveConfig`加一份测试自己的配置文件:
// ssh从它读到的值与向量选项按同一规则合并, 本包设的`ClearAllForwardings`正是为压过它.
func sshEffectiveConfigWith(t *testing.T, configFile string, args []string) map[string][]string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the vectors these tests use carry POSIX socket paths, which a Windows ssh parses its own way")
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skipf("no ssh client on PATH to ask what the arguments amount to: %v", err)
	}
	writtenConfig := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(writtenConfig, []byte(configFile), 0o600); err != nil {
		t.Fatalf("write the ssh config for the test: %v", err)
	}

	cmd := exec.Command(sshBin, append([]string{"-F", writtenConfig, "-G"}, args...)...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh -G %q: %v: %s", args, err, strings.TrimSpace(stderr.String()))
	}

	config := map[string][]string{}
	for _, line := range strings.Split(stdout.String(), "\n") {
		name, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		config[name] = append(config[name], strings.TrimSpace(value))
	}
	return config
}

func oneValue(t *testing.T, config map[string][]string, name string) string {
	t.Helper()
	values := config[name]
	if len(values) != 1 {
		t.Fatalf("ssh reported %s = %q, want exactly one value", name, values)
	}
	return values[0]
}

// 一次性连接由用户自己的参数拼成, 所以要紧的是ssh怎么理解这组向量: 幸存到里面的
// 选项会改变查询的行为, 而查询的答案正是会话据以校验的东西.
func TestOneShotConnectionForwardsNothing(t *testing.T) {
	// 一条像样的会话命令行: agent socket的转发, 后台化请求, 用户自己的命令, 两种拼写的
	// 强制tty, 被关掉的`ClearAllForwardings`, 一个端口. 在查询连接上前三个直接搞坏它
	// (绑定正要检查的socket, 主机从此显得忙), tty和用户的清空值则与本包设的值打架.
	userArgs := []string{
		"-o", "RemoteForward=/run/user/1000/gnupg/S.gpg-agent:/tmp/windows-agent",
		"-o", "LocalForward 1234 localhost:22",
		"-oDynamicForward=1080",
		"-oForkAfterAuthentication=yes",
		"-o", "RemoteCommand=uptime",
		"-o", "RequestTTY=force",
		"-t",
		"-o", "ClearAllForwardings=no",
		"-o", "StrictHostKeyChecking=accept-new",
		"-p", "45731",
		"user@192.0.2.10",
	}
	args, err := sshCommandArgs(userArgs, "gpgconf --list-dirs agent-socket")
	if err != nil {
		t.Fatalf("sshCommandArgs(%q) error = %v", userArgs, err)
	}
	config := sshEffectiveConfig(t, args)

	// 转发必须整个去掉, 不能靠覆盖: `ClearAllForwardings`是标量, 而转发是加到列表里,
	// 后写的值挤不掉用户先写的.
	for _, name := range []string{"remoteforward", "localforward", "dynamicforward"} {
		if values := config[name]; len(values) != 0 {
			t.Errorf("the effective config still forwards through %s: %q", name, values)
		}
	}
	if got := oneValue(t, config, "clearallforwardings"); got != "yes" {
		t.Errorf("clearallforwardings = %q, want yes: it is what clears the forwards config files ask for", got)
	}
	if got := oneValue(t, config, "requesttty"); got != "auto" {
		t.Errorf("requesttty = %q, want ssh's own default of auto: a pty turns the query's answer into an interactive session's output", got)
	}
	if got := oneValue(t, config, "forkafterauthentication"); got != "no" {
		t.Errorf("forkafterauthentication = %q, want no: a query that goes to the background returns no answer", got)
	}
	if got := oneValue(t, config, "batchmode"); got != "no" {
		t.Errorf("batchmode = %q, want no: a host that can only be reached with a password would never pass the check", got)
	}
	if got := config["remotecommand"]; len(got) != 0 && (len(got) != 1 || got[0] != "none") {
		t.Errorf("remotecommand = %q, want it unset: the query's own command is the one that has to run", got)
	}
	// 查询建立的连接仍然是用户的: 同一目的地, 同一端口, 同一套到达主机的选项.
	if got := oneValue(t, config, "hostname"); got != "192.0.2.10" {
		t.Errorf("hostname = %q, want the destination the user named", got)
	}
	if got := oneValue(t, config, "user"); got != "user" {
		t.Errorf("user = %q, want the user the user named", got)
	}
	if got := oneValue(t, config, "port"); got != "45731" {
		t.Errorf("port = %q, want 45731: the query must reach the same port as the session", got)
	}
	if got := oneValue(t, config, "stricthostkeychecking"); got != "accept-new" {
		t.Errorf("stricthostkeychecking = %q, want the user's own accept-new: an option this package keeps has to reach the query", got)
	}
}

// 被过滤的选项是丢掉而不是覆盖, 这是真ssh那一侧的依据: 标量选项取先读到的值, 追加在
// 用户值之后的会输; 转发是加到列表, 根本无法被挤掉.
func TestOptionsCouldNotHaveBeenOverriddenInsteadOfDropped(t *testing.T) {
	scalar := sshEffectiveConfig(t, []string{"-o", "ClearAllForwardings=no", "-o", "ClearAllForwardings=yes", "host", "true"})
	if got := oneValue(t, scalar, "clearallforwardings"); got != "no" {
		t.Errorf("clearallforwardings = %q, want the first value (no)", got)
	}

	// 同一条规则也是清空值放向量最前的原因: 那里没有ssh后来读到的值能关掉清空.
	ahead := sshEffectiveConfig(t, []string{"-o", "ClearAllForwardings=yes", "-o", "ClearAllForwardings=no", "host", "true"})
	if got := oneValue(t, ahead, "clearallforwardings"); got != "yes" {
		t.Errorf("clearallforwardings = %q, want yes: the first value wins wherever it is written", got)
	}

	forwards := sshEffectiveConfig(t, []string{"-o", "RemoteForward=/a:/b", "-o", "RemoteForward=/c:/d", "host", "true"})
	if got := forwards["remoteforward"]; len(got) != 2 {
		t.Errorf("ssh kept %q of two RemoteForward values, want both: a forward adds to a list", got)
	}
}

// 配置文件要的转发在向量里根本没有, 参数过滤看不见, 只有本包加的清空选项能碰到它们.
// 向量里还有过滤器必须读懂的拼写: ssh接受选项与关键字间的单个`=`, 只按第一个`=`
// 切分会读出空关键字 - 转发和用户的清空值都会到达ssh; 清空值在向量最前, 用户的值到不了它前面.
func TestOneShotConnectionClearsTheForwardsAConfigFileAsksFor(t *testing.T) {
	const configFile = "Host *\n" +
		"  RemoteForward /cfg-socket:/cfg-remote-socket\n" +
		"  LocalForward 1234 localhost:22\n"
	userArgs := []string{
		"-o=RemoteForward=/leaked-socket:/leaked-remote-socket",
		"-o", "=LocalForward 1234 localhost:22",
		"-o=ClearAllForwardings=no",
		"-p", "45731",
		"user@192.0.2.10",
	}
	args, err := sshCommandArgs(userArgs, "gpgconf --list-dirs agent-socket")
	if err != nil {
		t.Fatalf("sshCommandArgs(%q) error = %v", userArgs, err)
	}
	config := sshEffectiveConfigWith(t, configFile, args)

	for _, name := range []string{"remoteforward", "localforward", "dynamicforward"} {
		if values := config[name]; len(values) != 0 {
			t.Errorf("the effective config still forwards through %s: %q", name, values)
		}
	}
	if got := oneValue(t, config, "clearallforwardings"); got != "yes" {
		t.Errorf("clearallforwardings = %q, want yes: with it off, the config file's own forwards are back", got)
	}
}

func TestParseRemoteSocketOutput(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		want    string
		wantErr bool
	}{
		{
			name: "plain path",
			out:  "/run/user/1000/gnupg/S.gpg-agent\n",
			want: "/run/user/1000/gnupg/S.gpg-agent",
		},
		{
			name: "non-default homedir hash subdirectory",
			out:  "/run/user/1234/gnupg/d.abcdefghij/S.gpg-agent\n",
			want: "/run/user/1234/gnupg/d.abcdefghij/S.gpg-agent",
		},
		{
			name: "login banner before the path",
			out:  "Activate the web console with: systemctl enable --now cockpit.socket\n/run/user/1000/gnupg/S.gpg-agent\n",
			want: "/run/user/1000/gnupg/S.gpg-agent",
		},
		{
			name: "carriage returns",
			out:  "/run/user/1000/gnupg/S.gpg-agent\r\n",
			want: "/run/user/1000/gnupg/S.gpg-agent",
		},
		{
			name:    "empty output",
			out:     "",
			wantErr: true,
		},
		{
			name:    "command not found",
			out:     "bash: gpgconf: command not found\n",
			wantErr: true,
		},
		{
			name:    "relative path is not accepted",
			out:     ".gnupg/S.gpg-agent\n",
			wantErr: true,
		},
		{
			name:    "two candidate paths are ambiguous",
			out:     "/run/user/1000/gnupg/S.gpg-agent\n/run/user/1001/gnupg/S.gpg-agent\n",
			wantErr: true,
		},
		{
			name:    "path with spaces is not a path",
			out:     "/run/user/1000/gnupg/S.gpg-agent extra\n",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRemoteSocketOutput(tt.out)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseRemoteSocketOutput(%q) error = nil, want error", tt.out)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRemoteSocketOutput(%q) error = %v", tt.out, err)
			}
			if got != tt.want {
				t.Errorf("path = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSocketConnectVerdict(t *testing.T) {
	// 结果词是解释器打的, 认不出来的东西都不是判定: 判成"没人监听"就会删掉在用的socket.
	tests := []struct {
		name      string
		out       string
		want      socketConnectVerdict
		wantErrno int
	}{
		{"refused", socketConnectPrefix + socketConnectRefusedWord + "\n", connectRefused, 0},
		{"absent", socketConnectPrefix + socketConnectAbsentWord + "\n", connectAbsent, 0},
		{"held", socketConnectPrefix + socketConnectHeldWord + "\n", connectHeld, 0},
		{"spoke", socketConnectPrefix + socketConnectSpokeWord + "\n", connectSpoke, 0},
		{"closed", socketConnectPrefix + socketConnectClosedWord + "\n", connectClosed, 0},
		{"other carries the errno", socketConnectPrefix + socketConnectOtherWord + "-13\n", connectOther, 13},
		{"none is not a verdict", socketConnectNoneMarker + "\n", connectNoVerdict, 0},
		{"banners and unknown words", "Welcome to the host\n" + socketConnectPrefix + "banana\n", connectNoVerdict, 0},
		{"an other-word without a number", socketConnectPrefix + socketConnectOtherWord + "-\n", connectNoVerdict, 0},
		{"the marker with trailing text", socketConnectPrefix + socketConnectRefusedWord + "x\n", connectNoVerdict, 0},
		{"nothing at all", "", connectNoVerdict, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errno := parseSocketConnectVerdict(tt.out)
			if got != tt.want || errno != tt.wantErrno {
				t.Errorf("parseSocketConnectVerdict(%q) = %v, %d; want %v, %d", tt.out, got, errno, tt.want, tt.wantErrno)
			}
		})
	}
}

// 解释器体与被测标记名要一直对得上: 结果词在两边各写一份 (Go里一份, 解释器里一份), 漂了就是判不出.
// 少一个词不是少一种判定, 是那一类结果从此读不出来.
func TestSocketConnectWordsMatchTheInterpreterBodies(t *testing.T) {
	words := []string{
		socketConnectRefusedWord,
		socketConnectAbsentWord,
		socketConnectHeldWord,
		socketConnectSpokeWord,
		socketConnectClosedWord,
		socketConnectOtherWord,
	}
	for name, body := range map[string]string{"python": pythonSocketConnect, "perl": perlSocketConnect} {
		for _, word := range words {
			if !strings.Contains(body, word) {
				t.Errorf("the %s body does not mention the word %q:\n%s", name, word, body)
			}
		}
	}
}

func TestDiscoverRemoteSocketUsesTheRemoteAnswer(t *testing.T) {
	var gotArgs []string
	runner := func(args []string) (string, error) {
		gotArgs = args
		return "/run/user/4242/gnupg/S.gpg-agent\n", nil
	}

	got, err := DiscoverRemoteSocket([]string{"-N", "-p", "45731", "user@192.0.2.10"}, runner)
	if err != nil {
		t.Fatalf("DiscoverRemoteSocket() error = %v", err)
	}
	if got != "/run/user/4242/gnupg/S.gpg-agent" {
		t.Errorf("path = %q, want the remote's answer", got)
	}
	// 必须问远端而不是假定uid, 并且去掉`-N`让远端命令能跑.
	for _, a := range gotArgs {
		if a == "-N" {
			t.Errorf("discovery args include -N, which suppresses the remote command: %q", gotArgs)
		}
	}
	if !containsString(gotArgs, "user@192.0.2.10") {
		t.Errorf("discovery args %q do not address the destination", gotArgs)
	}
	if !containsString(gotArgs, "gpgconf --list-dirs agent-socket") {
		t.Errorf("discovery args %q do not query gpgconf", gotArgs)
	}
}

func TestDiscoverRemoteSocketFailsWhenRunnerFails(t *testing.T) {
	runner := func([]string) (string, error) { return "", errors.New("ssh: connect failed") }
	if _, err := DiscoverRemoteSocket([]string{"host"}, runner); err == nil {
		t.Error("DiscoverRemoteSocket() error = nil, want the runner's failure surfaced")
	}
}

func TestDiscoverRemoteSocketFailsWithoutDestination(t *testing.T) {
	called := false
	runner := func([]string) (string, error) { called = true; return "/x", nil }
	if _, err := DiscoverRemoteSocket([]string{"-N"}, runner); err == nil {
		t.Error("DiscoverRemoteSocket() error = nil, want an error when there is no destination")
	}
	if called {
		t.Error("discovery ran ssh despite having no destination")
	}
}

func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

// 下面的测试真的拉起查询路径的ssh: `PATH`上的替身ssh就是`runSSHQueryContext`会启动的
// 二进制. 场景真实: `ProxyCommand`, 包装脚本, 登录后fork的sshd都会留下继承stdout的
// 后代进程, 它在ssh退出后仍攥着管道不放.

func standInSSHPath(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("write the stand-in ssh: %v", err)
	}
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

func requireStandInSSH(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
}

// `pipeHolder`是继承ssh stdout的后代进程, 比启动它的shell活得久: shell退出后它仍开着
// 管道写端, `exec`里拷贝stdout的goroutine一直读不到头.
const pipeHolder = "sleep 30 &\n"

func TestRunSSHQueryKeepsTheOutputWhenADescendantHoldsThePipe(t *testing.T) {
	// ssh退出0且已打出答案, 遗留的后代攥着继承的stdout: 等待被`WaitDelay`截断, `exec`报
	// `ErrWaitDelay`, 命令本身成功. 因它丢弃输出会把答过话的主机报成连不上.
	requireStandInSSH(t)
	t.Setenv("PATH", standInSSHPath(t, "echo "+socketAbsentMarker+"\n"+pipeHolder+"exit 0\n"))

	out, err := runSSHQuery([]string{"host", "true"})
	if err != nil {
		t.Fatalf("runSSHQuery() error = %v, want the query to succeed: ssh exited 0", err)
	}
	if !strings.Contains(out, socketAbsentMarker) {
		t.Errorf("runSSHQuery() output = %q, want the verdict ssh printed", out)
	}
}

func TestCheckRemoteSocketFreeAcceptsAHostThatAnsweredBeforeThePipeWasHeld(t *testing.T) {
	// 调用方看到的同一次运行: 探针答了话, 路径就是空的, 会话可以开始. 把攥着的管道读成
	// 探针失败, 会拒绝一台正常工作的主机.
	requireStandInSSH(t)
	t.Setenv("PATH", standInSSHPath(t, "echo "+socketAbsentMarker+"\n"+pipeHolder+"exit 0\n"))

	state, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", runSSHCommand)
	if err != nil {
		t.Fatalf("CheckRemoteSocketFree() error = %v, want nil: the probe answered", err)
	}
	if state != socketFree {
		t.Errorf("state = %v, want socketFree", state)
	}
}

func TestDiscoverRemoteSocketKeepsThePathWhenADescendantHoldsThePipe(t *testing.T) {
	// 发现是同一种查询换了个命令的输出: 路径来自主机的答话, 没有它会话根本起不来.
	requireStandInSSH(t)
	const path = "/run/user/1000/gnupg/S.gpg-agent"
	t.Setenv("PATH", standInSSHPath(t, "echo "+path+"\n"+pipeHolder+"exit 0\n"))

	got, err := DiscoverRemoteSocket([]string{"host"}, runSSHQuery)
	if err != nil {
		t.Fatalf("DiscoverRemoteSocket() error = %v, want the path the host reported", err)
	}
	if got != path {
		t.Errorf("path = %q, want %q", got, path)
	}
}

func TestCheckRemoteSocketFreeStillRefusesWhenNothingWasReported(t *testing.T) {
	// 反例: 什么都没打印就留下攥管道后代的主机, 等于什么也没报告. 收到过的
	// 输出不等于有答案; 路径仍是未检查, 调用方必须拒绝.
	requireStandInSSH(t)
	t.Setenv("PATH", standInSSHPath(t, pipeHolder+"exit 0\n"))

	state, err := CheckRemoteSocketFree([]string{"host"}, "/run/user/1000/gnupg/S.gpg-agent", runSSHCommand)
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal when the probe reported nothing")
	}
	if state != socketUnjudgeable {
		t.Errorf("state = %v, want socketUnjudgeable", state)
	}
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
	}

	if _, err := DiscoverRemoteSocket([]string{"host"}, runSSHQuery); err == nil {
		t.Error("DiscoverRemoteSocket() error = nil, want a refusal when the host reported no path")
	}
}

func TestRunSSHQueryStillFailsWhenSSHFails(t *testing.T) {
	// `ErrWaitDelay`只关乎管道: 命令失败时不能套用保留成功命令输出的那条分支,
	// 无论管道被谁攥着.
	requireStandInSSH(t)

	t.Run("a non-zero exit is still an error with a descendant holding the pipe", func(t *testing.T) {
		t.Setenv("PATH", standInSSHPath(t, "echo "+socketAbsentMarker+"\n"+pipeHolder+"exit 1\n"))
		if _, err := runSSHQuery([]string{"host", "true"}); err == nil {
			t.Error("runSSHQuery() error = nil, want the failing exit status reported")
		}
	})

	t.Run("ssh's own error text is still reported", func(t *testing.T) {
		t.Setenv("PATH", standInSSHPath(t, "echo 'Permission denied (publickey).' >&2\nexit 255\n"))
		_, err := runSSHQuery([]string{"host", "true"})
		if err == nil {
			t.Fatal("runSSHQuery() error = nil, want ssh's failure reported")
		}
		if !strings.Contains(err.Error(), "Permission denied") {
			t.Errorf("error %v should carry what ssh said", err)
		}
	})
}

// `noisyAnswer`是说得远多于所需的远端 (登录横幅, 会回显的rc文件): 无论它愿意说
// 多少, 本进程保留的输出必须有界.
const noisyAnswer = `i=0; while [ $i -lt 2000 ]; do echo "noise line $i"; i=$((i+1)); done`

func TestRunSSHQueryBoundsTheOutputItCollects(t *testing.T) {
	requireStandInSSH(t)

	t.Run("stdout", func(t *testing.T) {
		t.Setenv("PATH", standInSSHPath(t, "echo "+socketAbsentMarker+"\n"+noisyAnswer+"\n"))
		out, err := runSSHQuery([]string{"host", "true"})
		if err != nil {
			t.Fatalf("runSSHQuery() error = %v, want the query to succeed", err)
		}
		// 上限就是relay日志的上限; 只有那条说输出被丢弃的通知允许越过它.
		if len(out) > maxRelayLogBytes+64 {
			t.Errorf("runSSHQuery() kept %d bytes of stdout, want at most the %d-byte bound", len(out), maxRelayLogBytes)
		}
	})

	t.Run("stderr", func(t *testing.T) {
		// 失败且长篇解释自己的命令: 用户看到的解释同样有界.
		t.Setenv("PATH", standInSSHPath(t, noisyAnswer+" >&2\nexit 1\n"))
		_, err := runSSHQuery([]string{"host", "true"})
		if err == nil {
			t.Fatal("runSSHQuery() error = nil, want the failing exit status reported")
		}
		if len(err.Error()) > maxRelayLogBytes+64 {
			t.Errorf("the error carries %d bytes of ssh's stderr, want at most the %d-byte bound", len(err.Error()), maxRelayLogBytes)
		}
	})
}

func TestRunSSHQueryTruncationNeverReportsAFreePath(t *testing.T) {
	// 主机先报路径被占用再猛刷, 被丢掉的恰好是结论那部分. 剩下的
	// 是没结论, 必须拒绝; 若让其余输出冒充答案, 就会在已占用的路径上开会话.
	requireStandInSSH(t)
	t.Setenv("PATH", standInSSHPath(t, "echo "+socketUnknownMarker+"\n"+noisyAnswer+"\n"))

	state, err := CheckRemoteSocketFree([]string{"host"}, "/p", runSSHCommand)
	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal when the verdict was dropped")
	}
	if state == socketFree || state == socketReclaimed {
		t.Errorf("state = %v, want a verdict that does not start a session", state)
	}
}

func TestCheckRemoteSocketFreeGivesUpOnAHostThatNeverAnswers(t *testing.T) {
	// 一次性查询有自己的截止时间: 等到主机答话或超时, 先到为准. 没有它时预检查会在
	// 不应答的主机上一挂不起; 预检查又跑在任何信号处理安装之前, 连中断都做不到.
	requireStandInSSH(t)
	t.Setenv("PATH", standInSSHPath(t, "sleep 30\n"))

	start := time.Now()
	state, err := CheckRemoteSocketFree([]string{"host"}, "/p", runSSHCommand)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("CheckRemoteSocketFree() error = nil, want a refusal when the host never answered")
	}
	if state == socketFree || state == socketReclaimed {
		t.Errorf("state = %v, want a verdict that does not start a session", state)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v should name the deadline it ran out of", err)
	}
	if elapsed < sshQueryTimeout {
		t.Errorf("the call returned after %v, before the %v deadline", elapsed, sshQueryTimeout)
	}
	if elapsed > sshQueryTimeout+10*time.Second {
		t.Errorf("the call took %v with a %v deadline, so the wait on a host that never answers is unbounded", elapsed, sshQueryTimeout)
	}
}
