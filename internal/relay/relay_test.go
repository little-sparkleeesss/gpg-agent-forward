package relay

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gpg-agent-forward/internal/nonce"
)

// 模拟Windows `gpg-agent`的IPC: loopback TCP监听要求16字节nonce作首字节,
// 并写socket文件描述端口与nonce; 回显收到的数据, 证明relay双向透传.
type fakeAgent struct {
	t       *testing.T
	ln      net.Listener
	nonce   [16]byte
	file    string
	echo    bool
	mu      sync.Mutex
	got     [][]byte // 每连接一条: 实际收到的nonce
	serving bool
}

func newFakeAgent(t *testing.T, dir string, echo bool) *fakeAgent {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakeAgent listen: %v", err)
	}
	a := &fakeAgent{t: t, ln: ln, echo: echo}
	if _, err := rand.Read(a.nonce[:]); err != nil {
		t.Fatalf("fakeAgent nonce: %v", err)
	}
	a.file = filepath.Join(dir, "S.gpg-agent.extra")
	a.WriteSocketFile()
	go a.serve()
	t.Cleanup(func() { ln.Close() })
	return a
}

// 写出libassuan`_assuan_sock_bind()`产生的确切磁盘编码:
// ASCII十进制端口, 单个LF, 16字节原始nonce.
func (a *fakeAgent) WriteSocketFile() {
	a.mu.Lock()
	defer a.mu.Unlock()
	port := a.ln.Addr().(*net.TCPAddr).Port
	body := append([]byte(fmt.Sprintf("%d\n", port)), a.nonce[:]...)
	if err := os.WriteFile(a.file, body, 0o600); err != nil {
		a.t.Fatalf("write socket file: %v", err)
	}
}

func (a *fakeAgent) serve() {
	for {
		c, err := a.ln.Accept()
		if err != nil {
			return
		}
		go a.handle(c)
	}
}

func (a *fakeAgent) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(a.nonce))
	if _, err := io.ReadFull(c, got); err != nil {
		return
	}
	a.mu.Lock()
	a.got = append(a.got, got)
	a.mu.Unlock()
	if !bytes.Equal(got, a.nonce[:]) {
		return // nonce错误: 像真agent一样断开连接
	}
	if !a.echo {
		return
	}
	io.Copy(c, c)
}

func (a *fakeAgent) noncesSeen() [][]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([][]byte(nil), a.got...)
}

// 模拟`gpg-agent`重启: 换新端口和新nonce, 并重写socket文件.
func (a *fakeAgent) restart() {
	a.t.Helper()
	a.ln.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		a.t.Fatalf("fakeAgent restart listen: %v", err)
	}
	a.mu.Lock()
	a.ln = ln
	a.mu.Unlock()
	if _, err := rand.Read(a.nonce[:]); err != nil {
		a.t.Fatalf("fakeAgent restart nonce: %v", err)
	}
	a.WriteSocketFile()
	go a.serve()
}

func (a *fakeAgent) port() int { return a.ln.Addr().(*net.TCPAddr).Port }

func startRelay(t *testing.T, agentFile string) *Relay {
	t.Helper()
	r, err := New(Config{ListenAddr: "127.0.0.1:0", SocketFile: agentFile})
	if err != nil {
		t.Fatalf("relay New: %v", err)
	}
	go func() { _ = r.Serve() }()
	t.Cleanup(func() { r.Close() })
	return r
}

func TestRelayForwardsBytesBothWaysAfterSendingNonce(t *testing.T) {
	dir := t.TempDir()
	agent := newFakeAgent(t, dir, true)
	r := startRelay(t, agent.file)

	c, err := net.Dial("tcp", r.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	// relay须自行完成nonce握手: 客户端看到的第一段就是业务负载.
	if _, err := c.Write([]byte("PKSIGN-request")); err != nil {
		t.Fatalf("write to relay: %v", err)
	}
	buf := make([]byte, len("PKSIGN-request"))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo from relay: %v", err)
	}
	if string(buf) != "PKSIGN-request" {
		t.Errorf("echo = %q, want %q", buf, "PKSIGN-request")
	}

	seen := agent.noncesSeen()
	if len(seen) != 1 {
		t.Fatalf("agent saw %d connections, want 1", len(seen))
	}
	if !bytes.Equal(seen[0], agent.nonce[:]) {
		t.Errorf("agent received wrong nonce: %x", seen[0])
	}
}

func TestRelayRereadsNonceForEveryConnection(t *testing.T) {
	// `gpg-agent`每次启动都换端口和nonce, relay须每连接查socket文件, 不能缓存.
	dir := t.TempDir()
	agent := newFakeAgent(t, dir, true)
	r := startRelay(t, agent.file)

	roundTrip := func(payload string) {
		t.Helper()
		c, err := net.Dial("tcp", r.Addr().String())
		if err != nil {
			t.Fatalf("dial relay: %v", err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte(payload)); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf) != payload {
			t.Fatalf("echo = %q, want %q", buf, payload)
		}
	}

	roundTrip("before-restart")
	oldPort := agent.port()

	agent.restart()
	if agent.port() == oldPort {
		t.Skip("agent happened to reuse the same port; rerun")
	}

	roundTrip("after-restart")

	seen := agent.noncesSeen()
	if len(seen) != 2 {
		t.Fatalf("agent saw %d connections, want 2", len(seen))
	}
	if bytes.Equal(seen[0], seen[1]) {
		t.Error("nonce was reused across connections; relay cached it")
	}
}

func TestRelayClosesClientWhenSocketFileMissing(t *testing.T) {
	dir := t.TempDir()
	r := startRelay(t, filepath.Join(dir, "does-not-exist"))

	c, err := net.Dial("tcp", r.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// 读须立即返回EOF/错误, 绝不永久阻塞.
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("Read() = nil error, want the relay to close the connection")
	}
}

func TestRelayClosesClientWhenAgentIsDown(t *testing.T) {
	dir := t.TempDir()
	agent := newFakeAgent(t, dir, true)
	r := startRelay(t, agent.file)

	// 撤走agent但留下socket文件: relay读到合法端口后连接失败.
	agent.ln.Close()
	time.Sleep(50 * time.Millisecond)

	c, err := net.Dial("tcp", r.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("Read() = nil error, want the relay to close the connection")
	}
}

func TestRelayDoesNotTruncateTheReplyWhenTheClientHalfCloses(t *testing.T) {
	// 半关写端的客户端仍须收到完整回复: client->agent方向一拷完就拆对,
	// 会截断还在回传的字节, 故须等两个方向都结束.
	dir := t.TempDir()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const replySize = 1 << 20 // 大于任何socket缓冲区, 提前关闭必然截断
	reply := bytes.Repeat([]byte("R"), replySize)

	nonce := make([]byte, 16)
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
				got := make([]byte, len(nonce))
				if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, nonce) {
					return
				}
				// 先等客户端半关再回复, 使回复此刻可证仍在途.
				_, _ = io.Copy(io.Discard, c)
				_, _ = c.Write(reply)
			}()
		}
	}()

	socketFile := filepath.Join(dir, "S.gpg-agent.extra")
	body := append([]byte(fmt.Sprintf("%d\n", ln.Addr().(*net.TCPAddr).Port)), nonce...)
	if err := os.WriteFile(socketFile, body, 0o600); err != nil {
		t.Fatalf("write socket file: %v", err)
	}
	r := startRelay(t, socketFile)

	c, err := net.Dial("tcp", r.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("half-close: %v", err)
	}

	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("reading the reply: %v (want the relay to deliver the whole reply)", err)
	}
	if len(got) != replySize {
		t.Errorf("reply is %d bytes, want %d: the relay truncated the direction that was still copying",
			len(got), replySize)
	}
}

func TestRelayServesConcurrentConnections(t *testing.T) {
	dir := t.TempDir()
	agent := newFakeAgent(t, dir, true)
	r := startRelay(t, agent.file)

	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := fmt.Sprintf("payload-%02d", i)
			c, err := net.Dial("tcp", r.Addr().String())
			if err != nil {
				errs <- fmt.Errorf("conn %d dial: %w", i, err)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.Write([]byte(payload)); err != nil {
				errs <- fmt.Errorf("conn %d write: %w", i, err)
				return
			}
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(c, buf); err != nil {
				errs <- fmt.Errorf("conn %d read: %w", i, err)
				return
			}
			if string(buf) != payload {
				errs <- fmt.Errorf("conn %d echo = %q, want %q", i, buf, payload)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := len(agent.noncesSeen()); got != n {
		t.Errorf("agent saw %d connections, want %d", got, n)
	}
}

func TestRelayRejectsPeerWhenCheckFails(t *testing.T) {
	dir := t.TempDir()
	agent := newFakeAgent(t, dir, true)

	r, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		SocketFile: agent.file,
		AllowPeer:  func(net.Conn) error { return fmt.Errorf("peer not allowed") },
	})
	if err != nil {
		t.Fatalf("relay New: %v", err)
	}
	go func() { _ = r.Serve() }()
	defer r.Close()

	c, err := net.Dial("tcp", r.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("Read() = nil error, want the relay to reject the peer")
	}
	if got := len(agent.noncesSeen()); got != 0 {
		t.Errorf("agent saw %d connections, want 0 (nonce must not be sent to a rejected peer)", got)
	}
}

func TestNewRejectsNonLoopbackListenAddr(t *testing.T) {
	// 暴露到loopback之外等于允许其他主机签名; 主机名`localhost`同样拒绝:
	// 它依赖名字解析, 被篡改的hosts文件可把它指到机外.
	dir := t.TempDir()
	agent := newFakeAgent(t, dir, true)

	for _, addr := range []string{
		"0.0.0.0:29173",
		":29173",
		"192.168.1.5:29173",
		"[::]:29173",
		"localhost:29173",
		"localhost.localdomain:29173",
		"garbage",
		"10.0.0.1:29173",
	} {
		t.Run(addr, func(t *testing.T) {
			r, err := New(Config{ListenAddr: addr, SocketFile: agent.file})
			if err == nil {
				r.Close()
				t.Fatalf("New(%q) error = nil, want rejection", addr)
			}
			if !errors.Is(err, ErrNotLoopback) {
				t.Errorf("New(%q) error = %v, want ErrNotLoopback", addr, err)
			}
		})
	}

	for _, addr := range []string{"127.0.0.1:0", "127.0.0.5:0", "[::1]:0"} {
		t.Run("accept/"+addr, func(t *testing.T) {
			r, err := New(Config{ListenAddr: addr, SocketFile: agent.file})
			if err != nil {
				t.Fatalf("New(%q) error = %v, want nil", addr, err)
			}
			r.Close()
		})
	}
}

func TestDialAgentRejectsMalformedSocketFile(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		body []byte
	}{
		{"non-digit port", append([]byte("notaport\n"), make([]byte, 16)...)},
		{"truncated nonce", append([]byte("41667\n"), []byte("short")...)},
		{"empty", nil},
		{"no terminator", []byte("41667")},
		{"port zero", append([]byte("0\n"), make([]byte, 16)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, "sock")
			if err := os.WriteFile(path, tt.body, 0o600); err != nil {
				t.Fatalf("write socket file: %v", err)
			}
			r, err := New(Config{ListenAddr: "127.0.0.1:0", SocketFile: path})
			if err != nil {
				t.Fatalf("relay New: %v", err)
			}
			defer r.Close()

			c, err := r.dialAgent()
			if err == nil {
				c.Close()
				t.Fatal("dialAgent() error = nil, want error for a malformed socket file")
			}
			// 钉住失败原因: 拨假端口也会失败, 错误必须表明解析失败而非连接失败.
			if !errors.Is(err, nonce.ErrMalformed) {
				t.Errorf("dialAgent() error = %v, want it to wrap nonce.ErrMalformed", err)
			}
		})
	}
}

func TestServeReturnsErrIdleAfterIdleTimeout(t *testing.T) {
	// tunnel按需启动, 不能永久滞留: 闲置超配置时长即退出.
	dir := t.TempDir()
	agent := newFakeAgent(t, dir, true)

	r, err := New(Config{
		ListenAddr:  "127.0.0.1:0",
		SocketFile:  agent.file,
		IdleTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("relay New: %v", err)
	}
	defer r.Close()

	done := make(chan error, 1)
	go func() { done <- r.Serve() }()

	select {
	case err := <-done:
		if !errors.Is(err, ErrIdle) {
			t.Errorf("Serve() error = %v, want ErrIdle", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return after the idle timeout")
	}
}

func TestServeDoesNotExitIdleWhileConnectionIsActive(t *testing.T) {
	dir := t.TempDir()
	agent := newFakeAgent(t, dir, true)

	r, err := New(Config{
		ListenAddr:  "127.0.0.1:0",
		SocketFile:  agent.file,
		IdleTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("relay New: %v", err)
	}
	defer r.Close()

	done := make(chan error, 1)
	go func() { done <- r.Serve() }()

	c, err := net.Dial("tcp", r.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatalf("read: %v", err)
	}

	// 连接保持打开, 远超闲置超时.
	select {
	case err := <-done:
		t.Fatalf("Serve() returned %v while a connection was active", err)
	case <-time.After(4 * 150 * time.Millisecond):
	}

	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrIdle) {
			t.Errorf("Serve() error = %v, want ErrIdle after the last connection closed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not go idle after the connection closed")
	}
}

func TestServeWithoutIdleTimeoutRunsUntilClosed(t *testing.T) {
	dir := t.TempDir()
	agent := newFakeAgent(t, dir, true)
	r := startRelay(t, agent.file) // 不设`IdleTimeout`

	done := make(chan error, 1)
	go func() { done <- r.Serve() }()

	select {
	case err := <-done:
		t.Fatalf("Serve() returned %v, want it to keep running", err)
	case <-time.After(400 * time.Millisecond):
	}
}

func TestRelayKeepsRunningAfterLongConnectionCloses(t *testing.T) {
	// 长ssh会话可持续远超闲置超时: 断开后须重新计满闲置窗口, 而非立刻退出.
	dir := t.TempDir()
	agent := newFakeAgent(t, dir, true)

	const idle = 200 * time.Millisecond
	r, err := New(Config{
		ListenAddr:  "127.0.0.1:0",
		SocketFile:  agent.file,
		IdleTimeout: idle,
	})
	if err != nil {
		t.Fatalf("relay New: %v", err)
	}
	defer r.Close()

	done := make(chan error, 1)
	go func() { done <- r.Serve() }()

	c, err := net.Dial("tcp", r.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatalf("read: %v", err)
	}

	// 保持打开, 远超闲置超时.
	time.Sleep(3 * idle)
	c.Close()

	// 须活过一整个新窗口, 而不是立刻退出.
	select {
	case err := <-done:
		t.Fatalf("Serve() returned %v immediately after the connection closed, "+
			"want a fresh idle window", err)
	case <-time.After(idle / 2):
	}

	// 随后真正空闲时仍要退出.
	select {
	case err := <-done:
		if !errors.Is(err, ErrIdle) {
			t.Errorf("Serve() error = %v, want ErrIdle", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not go idle")
	}
}

func TestNewRejectsEmptySocketFile(t *testing.T) {
	r, err := New(Config{ListenAddr: "127.0.0.1:0", SocketFile: ""})
	if err == nil {
		r.Close()
		t.Fatal("New() error = nil, want rejection of an empty SocketFile")
	}
}

func TestDialAgentErrorsWhenNothingIsListening(t *testing.T) {
	// 端口无监听时须报错, 而不是半开连接.
	dir := t.TempDir()
	// 先绑后关, 得到一个几乎必然空闲的端口.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	path := filepath.Join(dir, "sock")
	body := append([]byte(fmt.Sprintf("%d\n", port)), make([]byte, 16)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write socket file: %v", err)
	}
	r, err := New(Config{ListenAddr: "127.0.0.1:0", SocketFile: path})
	if err != nil {
		t.Fatalf("relay New: %v", err)
	}
	defer r.Close()

	c, err := r.dialAgent()
	if err == nil {
		c.Close()
		t.Fatal("dialAgent() error = nil, want error when nothing is listening")
	}
}

func TestDialAgentErrorsWhenSocketFileMissing(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		SocketFile: filepath.Join(dir, "absent"),
	})
	if err != nil {
		t.Fatalf("relay New: %v", err)
	}
	defer r.Close()

	c, err := r.dialAgent()
	if err == nil {
		c.Close()
		t.Fatal("dialAgent() error = nil, want error when the socket file is missing")
	}
}
