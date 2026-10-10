package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"gpg-agent-forward/internal/relaylock"
)

// 不是真测试: 被当作子进程重执行, 扮演绑端口并等待的relay,
// 不启动真二进制就能练启停生命周期.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GPG_AGENT_FORWARD_HELPER") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" && i+1 < len(args) {
			args = args[i+1:]
			break
		}
	}
	if len(args) < 1 {
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper listen:", err)
		os.Exit(3)
	}
	defer ln.Close()
	// 真relay会拿身份锁, helper也必须拿: 否则父进程会(正确地)拒绝把这个端口当relay.
	if _, ok := relaylock.TryLock(ln.Addr().String()); !ok {
		fmt.Fprintln(os.Stderr, "helper lock:", "already held")
		os.Exit(4)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			os.Exit(0)
		}
		c.Close()
	}
}

// 绑loopback端口并拿身份锁, 让调用方把它当真relay; 返回端口.
func startFakeRelay(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	release, ok := relaylock.TryLock(ln.Addr().String())
	if !ok {
		ln.Close()
		t.Fatal("could not take the relay identity lock")
	}
	t.Cleanup(func() {
		release()
		ln.Close()
	})
	return ln.Addr().(*net.TCPAddr).Port
}

// 换掉`startHook`: 起helper进程代替真二进制, 并记下要求它绑的地址.
func helperStarter(t *testing.T, bindAddr *string) {
	t.Helper()
	startHook = func(exePath string, args []string) *exec.Cmd {
		addr := "127.0.0.1:" + portFromServeArgs(t, args)
		if bindAddr != nil {
			*bindAddr = addr
		}
		cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", addr)
		cmd.Env = append(os.Environ(), "GPG_AGENT_FORWARD_HELPER=1")
		return cmd
	}
	t.Cleanup(func() { startHook = func(p string, a []string) *exec.Cmd { return exec.Command(p, a...) } })
}

func recordingStarter(t *testing.T, argsOut *[]string) {
	t.Helper()
	startHook = func(exePath string, args []string) *exec.Cmd {
		if argsOut != nil {
			*argsOut = append([]string(nil), args...)
		}
		return exec.Command(exePath, args...)
	}
	t.Cleanup(func() { startHook = func(p string, a []string) *exec.Cmd { return exec.Command(p, a...) } })
}

func TestEnsureRelayForwardsTheIdleTimeout(t *testing.T) {
	// 调用方的`--idle`必须原样传到relay; 丢掉它, relay会静默变成永不过期, 用户的要求就落空.
	var got []string
	recordingStarter(t, &got)

	// 假的`exePath`让`Start`失败无妨: 参数在失败之前已记录.
	_, _ = EnsureRelay(`C:\does\not\exist.exe`, "/tmp/sock", 29173, 5*time.Minute)

	if v := flagValue(got, "--idle"); v != "5m0s" {
		t.Errorf("--idle = %q in %q, want the caller's 5m0s", v, got)
	}
}

func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func TestEnsureRelayReportsAChildThatExitsImmediately(t *testing.T) {
	// 启动即死的relay(如socket文件不可读, 端口被占)必须立刻带上自己的错误信息上报,
	// 而不是等满超时再报一句误导性的`did not begin listening`.
	startHook = func(exePath string, args []string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessCrash")
		cmd.Env = append(os.Environ(), "GPG_AGENT_FORWARD_CRASH_HELPER=1")
		return cmd
	}
	t.Cleanup(func() { startHook = func(p string, a []string) *exec.Cmd { return exec.Command(p, a...) } })

	start := time.Now()
	_, err := EnsureRelay("unused", "/tmp/sock", 45999, 0)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("EnsureRelay() error = nil, want an error when the child dies at startup")
	}
	if !strings.Contains(err.Error(), "socket file is unusable") {
		t.Errorf("EnsureRelay() error = %v, want it to carry the child's own message", err)
	}
	if elapsed > time.Second {
		t.Errorf("EnsureRelay() took %v, want it to return as soon as the child exited", elapsed)
	}
}

// 不是真测试: 扮演启动即失败的relay, 立刻带stderr信息退出.
func TestHelperProcessCrash(t *testing.T) {
	if os.Getenv("GPG_AGENT_FORWARD_CRASH_HELPER") != "1" {
		return
	}
	fmt.Fprintln(os.Stderr, "socket file is unusable")
	os.Exit(1)
}

func portFromServeArgs(t *testing.T, args []string) string {
	t.Helper()
	for i, a := range args {
		if a == "--port" && i+1 < len(args) {
			return args[i+1]
		}
	}
	t.Fatalf("no --port in %q", args)
	return ""
}

func TestEnsureRelayStartsRelayAndReturnsStop(t *testing.T) {
	var bindAddr string
	helperStarter(t, &bindAddr)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	stop, err := EnsureRelay("unused", "/tmp/sock", port, 0)
	if err != nil {
		t.Fatalf("EnsureRelay() error = %v", err)
	}
	if stop == nil {
		t.Fatal("EnsureRelay() stop = nil, want a stop function for a relay it started")
	}
	if !Probe(fmt.Sprintf("127.0.0.1:%d", port)) {
		t.Fatal("relay is not listening after EnsureRelay returned")
	}

	stop()
	// 端口必须尽快释放, 后续运行才能重新绑定.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !Probe(fmt.Sprintf("127.0.0.1:%d", port)) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("relay still listening after stop()")
}

func TestEnsureRelayReturnsNilStopWhenAlreadyRunning(t *testing.T) {
	helperStarter(t, nil)

	// 已有relay在听: 不能再起第二个, 也不返回`stop`函数.
	port := startFakeRelay(t)

	stop, err := EnsureRelay("unused", "/tmp/sock", port, 0)
	if err != nil {
		t.Fatalf("EnsureRelay() error = %v", err)
	}
	if stop != nil {
		t.Error("EnsureRelay() stop != nil, want nil when a relay was already running")
	}
}

func TestEnsureRelayDoesNotMistakeASquatterForTheRelay(t *testing.T) {
	// 占用端口的外来进程不能被当成relay: 误认就不会再起relay, 远端gpg socket会被
	// 转发给这个冒名者, 它就能替用户应答签名请求.
	var spawned bool
	startHook = func(exePath string, args []string) *exec.Cmd {
		spawned = true
		return exec.Command(exePath, args...)
	}
	t.Cleanup(func() { startHook = func(p string, a []string) *exec.Cmd { return exec.Command(p, a...) } })

	// 只监听而没有身份锁的, 就是冒名者.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// 假`exePath`必让`Start`失败: 报错即证明它试图自己起relay, 没有轻信那个监听者.
	if _, err := EnsureRelay(`C:\does\not\exist.exe`, "/tmp/sock", port, 0); err == nil {
		t.Error("EnsureRelay() error = nil, want it to try starting a relay rather than trust a squatter")
	}
	if !spawned {
		t.Error("EnsureRelay() did not try to start a relay; a bare listener was accepted as the relay")
	}
}

func TestStopIsIdempotent(t *testing.T) {
	helperStarter(t, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	stop, err := EnsureRelay("unused", "/tmp/sock", port, 0)
	if err != nil {
		t.Fatalf("EnsureRelay() error = %v", err)
	}
	if stop == nil {
		t.Fatal("EnsureRelay() stop = nil, want non-nil")
	}
	stop()
	stop() // 不能panic
}
