package cli

import (
	"errors"
	"testing"
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
