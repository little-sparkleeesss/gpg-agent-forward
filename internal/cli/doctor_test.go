package cli

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeAgentFile(t *testing.T, greeting string, drop bool) (path string, nonce []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	nonce = make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				got := make([]byte, 16)
				if _, err := readFull(c, got); err != nil {
					return
				}
				if string(got) != string(nonce) || drop {
					return
				}
				c.Write([]byte(greeting))
			}()
		}
	}()

	dir := t.TempDir()
	path = filepath.Join(dir, "S.gpg-agent.extra")
	body := append([]byte(fmt.Sprintf("%d\n", ln.Addr().(*net.TCPAddr).Port)), nonce...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write socket file: %v", err)
	}
	return path, nonce
}

func readFull(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		if err != nil {
			return n, err
		}
		n += m
	}
	return n, nil
}

func TestProbeAgentReportsGreeting(t *testing.T) {
	greeting := "OK Pleased to meet you, process 1234\n"
	path, _ := fakeAgentFile(t, greeting, false)

	got, err := ProbeAgent(path)
	if err != nil {
		t.Fatalf("ProbeAgent() error = %v", err)
	}
	if !strings.Contains(got, "OK Pleased to meet you") {
		t.Errorf("ProbeAgent() greeting = %q, want the agent greeting", got)
	}
}

func TestProbeAgentErrorsWhenNonceRejected(t *testing.T) {
	// agent断开连接说明nonce不匹配, 这正是socket文件已过期的症状.
	path, _ := fakeAgentFile(t, "OK\n", true)

	if _, err := ProbeAgent(path); err == nil {
		t.Error("ProbeAgent() error = nil, want an error when the agent drops the connection")
	}
}

func TestProbeAgentErrorsOnMalformedSocketFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "S.gpg-agent.extra")
	if err := os.WriteFile(path, []byte("nonsense\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ProbeAgent(path); err == nil {
		t.Error("ProbeAgent() error = nil, want an error for a malformed socket file")
	}
}

func TestProbeAgentErrorsWhenAgentNotListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "S.gpg-agent.extra")
	body := append([]byte(fmt.Sprintf("%d\n", port)), make([]byte, 16)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ProbeAgent(path); err == nil {
		t.Error("ProbeAgent() error = nil, want an error when nothing is listening")
	}
}

func TestDescribeSocketFile(t *testing.T) {
	path, nonce := fakeAgentFile(t, "OK\n", false)

	desc, err := DescribeSocketFile(path)
	if err != nil {
		t.Fatalf("DescribeSocketFile() error = %v", err)
	}
	if !strings.Contains(desc, path) {
		t.Errorf("description %q should name the file", desc)
	}
	if strings.Contains(desc, fmt.Sprintf("%x", nonce)) {
		t.Error("description leaks the nonce; it must not be printed")
	}
}
