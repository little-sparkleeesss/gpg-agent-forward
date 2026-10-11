package cli

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gpg-agent-forward/internal/relaylock"
)

func TestProbeDetectsListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	if !Probe(ln.Addr().String()) {
		t.Error("Probe() = false, want true for a listening port")
	}
}

func TestProbeReturnsFalseWhenNothingListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if Probe(addr) {
		t.Error("Probe() = true, want false when nothing is listening")
	}
}

func TestEnsureRelayDoesNotStartWhenAlreadyRunning(t *testing.T) {
	// 认出正在运行的relay靠它的身份锁, 不只是端口被占.
	port := startFakeRelay(t, relaylock.Info{SocketFile: "/tmp/sock"})

	// 故意写坏的`exePath`证明`EnsureRelay`没尝试拉起任何进程: 试了就会失败报错.
	stop, err := EnsureRelay(`C:\does\not\exist.exe`, "/tmp/sock", port, time.Minute)
	if err != nil {
		t.Errorf("EnsureRelay() error = %v, want nil when a relay is already listening", err)
	}
	if stop != nil {
		t.Error("EnsureRelay() stop != nil, want nil when a relay was already listening")
	}
}

func TestBoundedBufferStopsGrowingAtTheLimit(t *testing.T) {
	var b boundedBuffer
	chunk := bytes.Repeat([]byte("x"), 4096)
	for i := 0; i < 100; i++ {
		if _, err := b.Write(chunk); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	got := b.String()
	if len(got) > maxRelayLogBytes+len("\n[earlier output truncated]") {
		t.Errorf("boundedBuffer grew to %d bytes, want at most the limit plus the notice", len(got))
	}
	if !strings.Contains(got, "truncated") {
		t.Error("boundedBuffer did not note that output was truncated")
	}
}

func TestBoundedBufferKeepsShortOutputIntact(t *testing.T) {
	var b boundedBuffer
	if _, err := b.Write([]byte("socket file is unusable\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := b.String(); got != "socket file is unusable\n" {
		t.Errorf("boundedBuffer.String() = %q, want the output unchanged", got)
	}
}

func TestBoundedBufferKeepsTheMostRecentOutput(t *testing.T) {
	var b boundedBuffer
	if _, err := b.Write([]byte("first line\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := b.Write(bytes.Repeat([]byte("x"), maxRelayLogBytes)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := b.Write([]byte("last line\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := b.String()
	if !strings.Contains(got, "last line") {
		t.Error("the most recent output was dropped; the reason the relay exited is likely in it")
	}
	if strings.Contains(got, "first line") {
		t.Error("the oldest output was kept in place of the newest")
	}
	if !strings.HasPrefix(got, "[earlier output truncated]") {
		t.Errorf("the truncation notice must say that earlier output was dropped, got %q", got)
	}
}

func TestEnsureRelayAdoptsARelayForAnEquivalentlySpelledSocketFile(t *testing.T) {
	// relay把socket文件原样记下, 之后的调用可能换一种拼写: 相对路径, 或带多余`..`的路径.
	// 它们指同一个文件, 应复用它而不是当成另一个agent的relay.
	dir := t.TempDir()
	sep := string(filepath.Separator)
	abs := filepath.Join(dir, "S.gpg-agent.extra")

	spellings := []string{dir + sep + "sub" + sep + ".." + sep + "S.gpg-agent.extra"}
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, abs); err == nil {
			spellings = append(spellings, rel)
		}
	}

	for _, spelling := range spellings {
		if spelling == abs {
			continue // 已是最短拼写
		}
		port := startFakeRelay(t, relaylock.Info{SocketFile: abs})
		stop, err := EnsureRelay("unused", spelling, port, 0)
		if err != nil {
			t.Errorf("EnsureRelay(%q) error = %v, want adoption of the relay recorded for %q",
				spelling, err, abs)
			continue
		}
		if stop != nil {
			t.Errorf("EnsureRelay(%q) stop != nil, want nil for a relay it did not start", spelling)
		}
	}
}

func TestSameSocketFileFoldsSpellingButNotIdentity(t *testing.T) {
	dir := t.TempDir()
	sep := string(filepath.Separator)
	path := filepath.Join(dir, "S.gpg-agent.extra")

	if !sameSocketFile(path, dir+sep+"sub"+sep+".."+sep+"S.gpg-agent.extra") {
		t.Error("a redundant path component was treated as a different file")
	}
	if sameSocketFile(path, filepath.Join(dir, "other")) {
		t.Error("two different files were treated as the same")
	}
	if sameSocketFile("", path) {
		t.Error("an empty path was treated as naming a file")
	}
	if runtime.GOOS == "windows" {
		// Windows上一个路径用任一分隔符都能拼, 大小写也不区分.
		if !sameSocketFile(`C:\Users\me\gnupg\S.gpg-agent.extra`, `c:/users/me/gnupg/S.gpg-agent.extra`) {
			t.Error("Windows spelling differences were not folded")
		}
	}
}

func TestRunSSHAcceptsAndIgnoresIdle(t *testing.T) {
	// `--idle`必须被ssh子命令消费: 透传给ssh会拒启 (`unknown option -- idle`). 取值虽被
	// 忽略, 仍必须是合法时长: 非法值在这里报错, 而不是被静默跳过.
	var out, errOut bytes.Buffer
	err := Run([]string{"ssh", "--idle", "5m"}, &out, &errOut)
	if err == nil {
		t.Fatal("Run(ssh --idle 5m) error = nil, want the missing destination to be reported")
	}
	if strings.Contains(err.Error(), "flag provided but not defined") {
		t.Errorf("Run(ssh --idle 5m) = %v, want --idle accepted by the ssh subcommand", err)
	}

	err = Run([]string{"ssh", "--idle", "not-a-duration", "dev@host"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "idle") {
		t.Errorf("Run(ssh --idle not-a-duration) = %v, want the value rejected", err)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"bogus"}, &out, &errOut); err == nil {
		t.Error("Run() error = nil, want rejection of an unknown command")
	}
}

func TestRunHelpSucceeds(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"--help"}, &out, &errOut); err != nil {
		t.Errorf("Run(--help) error = %v, want nil", err)
	}
	if out.Len() == 0 {
		t.Error("Run(--help) wrote no usage text")
	}
}

func TestRunServeRejectsUnusableSocketFile(t *testing.T) {
	// `Serve`必须尽早失败并说明原因, 不能占着用不了的文件: 否则ssh转发看似正常, 每次签名却
	// 都失败. 断言错误原因而不只是发生了错误, 免得无关的校验失败掩盖这里.
	dir := t.TempDir()
	malformed := filepath.Join(dir, "S.gpg-agent.extra")
	if err := os.WriteFile(malformed, []byte("nota-port\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"absent file", filepath.Join(dir, "absent")},
		{"malformed file", malformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			err := Run([]string{
				"serve",
				"--socket-file", tt.path,
				"--port", "29873",
				"--idle", "1s",
			}, &out, &errOut)
			if err == nil {
				t.Fatal("Run(serve) error = nil, want an error")
			}
			if !strings.Contains(err.Error(), tt.path) {
				t.Errorf("Run(serve) error = %v, want it to name the socket file %s", err, tt.path)
			}
		})
	}
}
