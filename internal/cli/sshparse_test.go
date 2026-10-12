package cli

import (
	"context"
	"errors"
	"os"
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
	if state != socketUnreported {
		t.Errorf("state = %v, want socketUnreported", state)
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
	t.Setenv("PATH", standInSSHPath(t, "echo "+socketLiveMarker+"\n"+noisyAnswer+"\n"))

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
