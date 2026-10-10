package cli

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	port := startFakeRelay(t)

	// 故意写坏的`exePath`证明`EnsureRelay`没尝试拉起任何进程: 试了就会失败报错.
	stop, err := EnsureRelay(`C:\does\not\exist.exe`, "/tmp/sock", port, time.Minute)
	if err != nil {
		t.Errorf("EnsureRelay() error = %v, want nil when a relay is already listening", err)
	}
	if stop != nil {
		t.Error("EnsureRelay() stop != nil, want nil when a relay was already listening")
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
