package cli

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gpg-agent-forward/internal/winpeer"
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

func TestSelfPeerCheckResultAcceptsVerdicts(t *testing.T) {
	if err := selfPeerCheckResult(nil); err != nil {
		t.Errorf("selfPeerCheckResult(nil) = %v, want nil (the peer was allowed)", err)
	}
	// 拒绝peer是策略在工作, 不是失败.
	if err := selfPeerCheckResult(winpeer.ErrPeerNotAllowed); err != nil {
		t.Errorf("selfPeerCheckResult(ErrPeerNotAllowed) = %v, want nil", err)
	}
}

func TestSelfPeerCheckResultReportsNoVerdict(t *testing.T) {
	// 身份识别失败即得不出结论; 错误向上返回, doctor报成note而不是FAIL.
	lookupErr := errors.New("winpeer: no TCP table entry for 127.0.0.1:1 -> 127.0.0.1:2")
	if err := selfPeerCheckResult(lookupErr); !errors.Is(err, lookupErr) {
		t.Errorf("selfPeerCheckResult() = %v, want the lookup error back", err)
	}
}

// `TestSelfPeerCheckSeparatesPolicyFromLive`只断言策略检查不误报: 支持它的平台上策略
// 失败会让测试失败, 非Windows下策略是no-op; live腿的错误被丢弃, 不在断言之列.
func TestSelfPeerCheckSeparatesPolicyFromLive(t *testing.T) {
	policyErr, liveErr := selfPeerCheck()
	if peerCheckSupported() {
		if policyErr != nil {
			t.Fatalf("peerPolicyCheck() failed on a supported platform: %v", policyErr)
		}
		return
	}
	if policyErr != nil {
		t.Errorf("policy error off Windows = %v, want nil (there is no policy)", policyErr)
	}
	_ = liveErr // live腿有没有结论都可以
}

func TestDoctorReportsPeerCheckNAOffWindows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "S.gpg-agent.extra")
	if err := os.WriteFile(path, []byte("nonsense\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err := runDoctor([]string{"--socket-file", path, "--port", "0"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("runDoctor() = nil, want an error for a malformed socket file")
	}
	out := stdout.String()
	if strings.Contains(out, "peer check available") {
		t.Errorf("doctor output claims a peer check passed: %q", out)
	}
	if !strings.Contains(out, "n/a") || !strings.Contains(out, "peer check") {
		t.Errorf("doctor output should report the peer check as n/a off Windows, got %q", out)
	}
}
