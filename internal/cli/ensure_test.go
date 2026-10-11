package cli

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	// 真relay会拿身份锁, helper也得拿: 否则父进程会(正确地)拒绝把它当relay; 锁还记录被传入的
	// socket文件, 调用方检查元数据才能找到自己要求的那个. `release`必须活到helper结束: 丢掉它,
	// 被锁的`*os.File`会在下次GC被finalizer关掉, 锁被静默释放, 父进程会另起relay而不是收养它.
	info := relaylock.Info{}
	if len(args) > 1 {
		info.SocketFile = args[1]
	}
	keepRelease, ok := relaylock.TryLock(ln.Addr().String(), info)
	if !ok {
		fmt.Fprintln(os.Stderr, "helper lock:", "already held")
		os.Exit(4)
	}
	defer keepRelease()
	for {
		c, err := ln.Accept()
		if err != nil {
			os.Exit(0)
		}
		c.Close()
	}
}

// 绑loopback端口并拿身份锁, 让调用方把它当真relay; 返回端口, 测试结束时关掉listener.
// `info`是锁记录的元数据, 调用方据此判断能否收养既有relay; 零值`Info`对应空闲超时
// 已禁用的relay, 正是ssh需要的.
func startFakeRelay(t *testing.T, info relaylock.Info) int {
	t.Helper()
	port, _ := startFakeRelayStoppable(t, info)
	return port
}

// 带即停手柄的`startFakeRelay`, 模拟空闲超时到点; 返回的`stop`幂等, 测试结束时也会自动跑.
func startFakeRelayStoppable(t *testing.T, info relaylock.Info) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	release, ok := relaylock.TryLock(ln.Addr().String(), info)
	if !ok {
		ln.Close()
		t.Fatal("could not take the relay identity lock")
	}
	var once sync.Once
	stop = func() {
		once.Do(func() {
			release()
			ln.Close()
		})
	}
	t.Cleanup(stop)
	return ln.Addr().(*net.TCPAddr).Port, stop
}

// 换掉`startHook`: 起helper进程代替真二进制, 并记下要求它绑的地址.
func helperStarter(t *testing.T, bindAddr *string) {
	t.Helper()
	helperStarterRecording(t, bindAddr, nil)
}

// `helperStarter`的加记录版: 记下每次要求启动relay的参数, 便于检查relay(或后来的
// 替换者)是按什么策略启动的.
func helperStarterRecording(t *testing.T, bindAddr *string, argsOut *[][]string) {
	t.Helper()
	startHook = func(exePath string, args []string) *exec.Cmd {
		if argsOut != nil {
			*argsOut = append(*argsOut, append([]string(nil), args...))
		}
		addr := "127.0.0.1:" + portFromServeArgs(t, args)
		if bindAddr != nil {
			*bindAddr = addr
		}
		cmd := exec.Command(selfExe(), "-test.run=TestHelperProcess", "--", addr, socketFileFromServeArgs(t, args))
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
	// 启动即死的relay必须立刻带上自己的错误信息上报, 不能等满超时再报误导性的话; 错误里
	// 既要带子进程自己说的, 也要带退出状态, 被杀的进程才能与干净退出的区分开.
	startHook = func(exePath string, args []string) *exec.Cmd {
		cmd := exec.Command(selfExe(), "-test.run=TestHelperProcessCrash")
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
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("EnsureRelay() error = %v, want it to carry the child's exit status", err)
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

func socketFileFromServeArgs(t *testing.T, args []string) string {
	t.Helper()
	for i, a := range args {
		if a == "--socket-file" && i+1 < len(args) {
			return args[i+1]
		}
	}
	t.Fatalf("no --socket-file in %q", args)
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
	port := startFakeRelay(t, relaylock.Info{SocketFile: "/tmp/sock"})

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

func TestStopDoesNotWaitForAGrandchildHoldingThePipe(t *testing.T) {
	// relay若起了继承其stdout/stderr的子进程, 被杀后管道的写端仍开着; 没有`WaitDelay`,
	// `Wait`(也就是`stop`)会在每次拆卸时卡到那个持有者退出或兜底超时.
	startHook = func(exePath string, args []string) *exec.Cmd {
		addr := "127.0.0.1:" + portFromServeArgs(t, args)
		cmd := exec.Command(selfExe(), "-test.run=TestHelperProcessWithGrandchild", "--",
			addr, socketFileFromServeArgs(t, args))
		cmd.Env = append(os.Environ(), "GPG_AGENT_FORWARD_GRANDCHILD_HELPER=1")
		return cmd
	}
	t.Cleanup(func() { startHook = func(p string, a []string) *exec.Cmd { return exec.Command(p, a...) } })

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

	start := time.Now()
	stop()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("stop() took %v, want it bounded by WaitDelay well under the fallback", elapsed)
	}
}

// 扮演起了子进程的relay: 子进程继承stdout/stderr, relay被杀后它仍占着管道写端.
func TestHelperProcessWithGrandchild(t *testing.T) {
	if os.Getenv("GPG_AGENT_FORWARD_GRANDCHILD_HELPER") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" && i+1 < len(args) {
			args = args[i+1:]
			break
		}
	}
	ln, err := net.Listen("tcp", args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper listen:", err)
		os.Exit(3)
	}
	defer ln.Close()
	info := relaylock.Info{}
	if len(args) > 1 {
		info.SocketFile = args[1]
	}
	release, ok := relaylock.TryLock(ln.Addr().String(), info)
	if !ok {
		os.Exit(4)
	}
	defer release()

	gc := exec.Command(selfExe(), "-test.run=TestHelperGrandchild")
	gc.Env = append(os.Environ(), "GPG_AGENT_FORWARD_GRANDCHILD=1")
	gc.Stdout, gc.Stderr = os.Stdout, os.Stderr
	if err := gc.Start(); err != nil {
		os.Exit(5)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			os.Exit(0)
		}
		c.Close()
	}
}

// 把继承来的stdout/stderr占一会儿再自己退出, 免得活过测试.
func TestHelperGrandchild(t *testing.T) {
	if os.Getenv("GPG_AGENT_FORWARD_GRANDCHILD") != "1" {
		return
	}
	time.Sleep(2 * time.Second)
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

func TestEnsureRelayDoesNotAdoptARelayForAnotherSocketFile(t *testing.T) {
	// 桥接别的agent的relay会用错密钥签名, 而各项检查都报成功, 绝不能被收养.
	port := startFakeRelay(t, relaylock.Info{SocketFile: "A"})

	if _, err := EnsureRelay("unused", "B", port, 0); err == nil {
		t.Error("EnsureRelay() error = nil, want a refusal to reuse a relay for a different socket file")
	}
}

func TestEnsureRelayAdoptsARelayWithAFiniteIdleTimeout(t *testing.T) {
	// ssh必须复用转发到同一socket文件的relay, 不管其空闲超时, 否则会话根本起不来
	// (`ensure`起的relay默认记15m); 中途退出由`relayKeepAlive`在同端口补一个.
	port := startFakeRelay(t, relaylock.Info{SocketFile: "/tmp/sock", IdleTimeout: 15 * time.Minute})

	stop, err := EnsureRelay("unused", "/tmp/sock", port, 0)
	if err != nil {
		t.Fatalf("EnsureRelay() error = %v, want adoption of a relay for the same socket file", err)
	}
	if stop != nil {
		t.Error("EnsureRelay() stop != nil, want nil for a relay it did not start")
	}
}

func TestEnsureRelayAdoptsARelayItWouldHaveStarted(t *testing.T) {
	// socket文件相同且空闲禁用: 这正是ssh会起的那个relay, 应当收养而不是重复起.
	port := startFakeRelay(t, relaylock.Info{SocketFile: "/tmp/sock"})

	stop, err := EnsureRelay("unused", "/tmp/sock", port, 0)
	if err != nil {
		t.Fatalf("EnsureRelay() error = %v, want adoption of a matching relay", err)
	}
	if stop != nil {
		t.Error("EnsureRelay() stop != nil, want nil for a relay it did not start")
	}
}

func TestEnsureRelayDoesNotAdoptAnotherInvocationSRelayAtStartup(t *testing.T) {
	// 本调用起的relay因端口被抢走启动即死, 那里应答的是另一调用的relay; 把在听且上锁
	// 当成成功收下它, 本会话就被转发到别的agent的socket文件, 收尾还会杀掉不属于自己的relay.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	var releaseOther func()
	startHook = func(exePath string, args []string) *exec.Cmd {
		// 别的调用的relay出现在这个端口上...
		other, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Errorf("startHook: bind the other relay: %v", err)
			return exec.Command("no-such-binary")
		}
		release, ok := relaylock.TryLock(other.Addr().String(), relaylock.Info{SocketFile: "A"})
		if !ok {
			t.Errorf("startHook: could not take the identity lock")
			return exec.Command("no-such-binary")
		}
		releaseOther = func() { release(); other.Close() }
		// ...而本条调用要起的relay因端口已被占而退出.
		cmd := exec.Command(selfExe(), "-test.run=TestHelperProcessCrash")
		cmd.Env = append(os.Environ(), "GPG_AGENT_FORWARD_CRASH_HELPER=1")
		return cmd
	}
	t.Cleanup(func() {
		startHook = func(p string, a []string) *exec.Cmd { return exec.Command(p, a...) }
		if releaseOther != nil {
			releaseOther()
		}
	})

	stop, err := EnsureRelay("unused", "B", port, 0)
	if err == nil {
		t.Fatal("EnsureRelay() error = nil, want a failure rather than adoption of another invocation's relay")
	}
	if stop != nil {
		t.Error("EnsureRelay() stop != nil, want no stop function for a relay this session did not start")
	}
	if !strings.Contains(err.Error(), "socket file is unusable") {
		t.Errorf("EnsureRelay() error = %v, want the child relay's own message", err)
	}
}

func waitUntil(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

// 把keep-alive看门狗的tick调快, 测试不必等生产用的间隔.
func shortenRelayWatch(t *testing.T) {
	t.Helper()
	old := relayWatchInterval
	relayWatchInterval = 20 * time.Millisecond
	t.Cleanup(func() { relayWatchInterval = old })
}

func TestRelayKeepAliveReplacesARelayThatGoesAway(t *testing.T) {
	// 收养的relay可能自己退出(通常是有限空闲超时), 而ssh仍在往那个端口转发, 远端socket
	// 就指向空; 替换者必须出现在同端口, 启动时空闲超时禁用(免得再退), 并在会话结束时停掉.
	shortenRelayWatch(t)

	var started [][]string
	helperStarterRecording(t, nil, &started)

	port, stopAdopted := startFakeRelayStoppable(t, relaylock.Info{
		SocketFile:  "/tmp/sock",
		IdleTimeout: 15 * time.Minute,
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	keepAlive := newRelayKeepAlive("unused", "/tmp/sock", port, nil, io.Discard)
	keepAlive.start()

	stopAdopted()
	waitUntil(t, func() bool { return relayRunning(addr) },
		"the watchdog did not put a replacement relay on the port")

	keepAlive.shutdown()
	// 先`shutdown`再读`started`才无竞态: 那时看门狗goroutine已经结束.

	if len(started) != 1 {
		t.Fatalf("relay starts = %d, want exactly one replacement", len(started))
	}
	if v := flagValue(started[0], "--idle"); v != "0s" {
		t.Errorf("replacement --idle = %q, want 0s so the replacement does not exit again", v)
	}
	if v := flagValue(started[0], "--port"); v != fmt.Sprint(port) {
		t.Errorf("replacement --port = %q, want the port ssh forwards to (%d)", v, port)
	}
	// 替换者属于本会话, 会话关闭时必须把它清掉.
	waitUntil(t, func() bool { return !relayRunning(addr) },
		"the relay this session started is still running after shutdown")
	keepAlive.shutdown() // 不得停掉别的, 也不能panic
}

func TestRelayKeepAliveLeavesAnAdoptedRelayRunning(t *testing.T) {
	// 这个relay不是本会话起的, 就不能停它: 别的调用可能还在用.
	shortenRelayWatch(t)

	port := startFakeRelay(t, relaylock.Info{SocketFile: "/tmp/sock"})
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	keepAlive := newRelayKeepAlive("unused", "/tmp/sock", port, nil, io.Discard)
	keepAlive.start()
	// 放过几个tick, 好让见谁停谁的看门狗有机会现形.
	time.Sleep(10 * relayWatchInterval)
	keepAlive.shutdown()

	if !relayRunning(addr) {
		t.Error("the session stopped a relay it did not start")
	}
}

func TestRelayKeepAliveDoesNotRestartAfterTheSessionEnds(t *testing.T) {
	// 会话结束后才退出的relay不得被替换: 看门狗已停,
	// 此时起的relay会被一个已不存在的会话遗弃.
	shortenRelayWatch(t)

	var started [][]string
	helperStarterRecording(t, nil, &started)

	port, stopAdopted := startFakeRelayStoppable(t, relaylock.Info{SocketFile: "/tmp/sock"})

	keepAlive := newRelayKeepAlive("unused", "/tmp/sock", port, nil, io.Discard)
	keepAlive.start()
	keepAlive.shutdown()

	stopAdopted()
	// 给停掉的看门狗几个周期, 看它会不会乱来.
	time.Sleep(10 * relayWatchInterval)

	if len(started) != 0 {
		t.Errorf("the watchdog started %d relay(s) after the session ended: %q", len(started), started)
	}
}

// 把替身ssh放进`PATH`: 对wrapper发往远端的命令回话; 会话本身则按`sessionStarted`
// 建出标记文件再活几秒. 测试靠该标记确知会话在跑, 也即wrapper已确保过自己的relay.
func fakeSSH(t *testing.T, sessionStarted string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"case \"$*\" in\n" +
		"  *\"test -e\"*) echo gpg-agent-forward-socket-absent ;;\n" +
		"  *) : > " + shellQuoteSingle(sessionStarted) + " ; sleep 4 ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatalf("write the fake ssh: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRunSSHKeepsARelayOnThePortForTheSession(t *testing.T) {
	// 按ssh的真实用法测看门狗: 会话收养可能因空闲超时自退的relay, 端口在会话存续期间
	// 要一直有替换者, 会话结束又要腾出来.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	shortenRelayWatch(t)

	marker := filepath.Join(t.TempDir(), "session-started")
	fakeSSH(t, marker)

	var started [][]string
	helperStarterRecording(t, nil, &started)

	port, stopAdopted := startFakeRelayStoppable(t, relaylock.Info{
		SocketFile:  "/tmp/sock",
		IdleTimeout: 15 * time.Minute,
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	var out, errOut bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- Run([]string{
			"ssh",
			"--port", fmt.Sprint(port),
			"--socket-file", "/tmp/sock",
			"--remote-socket", "/run/user/1000/gnupg/S.gpg-agent",
			"dev@host",
		}, &out, &errOut)
	}()

	// 等会话本身而不只是等relay: wrapper先确保relay再起ssh, 会话跑起来就说明它已经
	// 收养了这个relay, 而不是在竞态里另起了一个.
	waitUntil(t, func() bool { _, err := os.Stat(marker); return err == nil },
		"the ssh session never started")
	if !relayRunning(addr) {
		t.Fatal("the session is not forwarding to the relay it adopted")
	}

	// 让收养的relay像空闲超时到点一样退出.
	stopAdopted()
	waitUntil(t, func() bool { return relayRunning(addr) },
		"no replacement relay appeared while the session was still running")

	if err := <-done; err != nil {
		t.Fatalf("Run(ssh) error = %v, want the session to run against the relay; output: %q", err, errOut.String())
	}
	// 会话结束: 它起的relay必须随之下线; 此处再读`started`无竞态, 会话goroutine已结束.
	waitUntil(t, func() bool { return !relayRunning(addr) },
		"the relay this session started outlived the session")
	if len(started) != 1 {
		t.Errorf("relay starts = %d, want exactly one replacement owned by the session", len(started))
	}
}

// 覆盖抢端口输给同一socket文件的relay: 预检看到端口空也不保证抢到, 赢家可能在本
// 调用的孩子已退出后才占上; 孩子的退出不是失败, 赢家正是本调用要的relay.
func TestEnsureRelayAdoptsARelayThatClaimsThePortLate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	const socketFile = "/tmp/sock"
	relayUp := make(chan struct{})
	var (
		relayLn      net.Listener
		relayRelease func()
	)
	startHook = func(exePath string, args []string) *exec.Cmd {
		go func() {
			defer close(relayUp)
			// 足够晚: 本调用的孩子已因端口退出, 测试先看到它的退出, 再看到赢家出现.
			time.Sleep(200 * time.Millisecond)
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				t.Errorf("the stand-in relay could not take the port: %v", err)
				return
			}
			relayLn = ln
			release, ok := relaylock.TryLock(ln.Addr().String(), relaylock.Info{SocketFile: socketFile})
			if !ok {
				t.Errorf("the stand-in relay could not take the identity lock")
				return
			}
			relayRelease = release
		}()
		// 本条调用自己的孩子输掉了端口竞争.
		cmd := exec.Command(selfExe(), "-test.run=TestHelperProcessPortTaken")
		cmd.Env = append(os.Environ(), "GPG_AGENT_FORWARD_PORT_TAKEN=1")
		return cmd
	}
	t.Cleanup(func() {
		startHook = func(p string, a []string) *exec.Cmd { return exec.Command(p, a...) }
		// 等这个goroutine结束, 字段才无竞态, 它内部的`t.Errorf`也才合法.
		<-relayUp
		if relayRelease != nil {
			relayRelease()
		}
		if relayLn != nil {
			relayLn.Close()
		}
	})

	stop, err := EnsureRelay("unused", socketFile, port, 0)
	if err != nil {
		t.Fatalf("EnsureRelay() error = %v, want adoption of the relay that claimed the port", err)
	}
	if stop != nil {
		t.Error("EnsureRelay() stop != nil: either the relay was not adopted on the child-exit path, or this child outlived the stand-in's delay and a later poll accepted it, so this test no longer covers what it was written for")
	}
	if !relayRunning(fmt.Sprintf("127.0.0.1:%d", port)) {
		t.Error("no relay for the requested socket file is serving the port")
	}
}

// 扮演因端口已被占而listen失败的relay.
func TestHelperProcessPortTaken(t *testing.T) {
	if os.Getenv("GPG_AGENT_FORWARD_PORT_TAKEN") != "1" {
		return
	}
	fmt.Fprintln(os.Stderr, "relay: listen on 127.0.0.1: bind: address already in use")
	os.Exit(1)
}
