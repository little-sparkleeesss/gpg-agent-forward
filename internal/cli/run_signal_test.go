package cli

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"
)

// 信号到达后会话允许的结束时限: 会话要算"被信号结束", 信号必须到达ssh且ssh必须死,
// 所以只有立刻被处理的信号(而不是被wrapper扣住不让默认动作生效的)才装得进这个预算.
const signalExitBudget = 2 * time.Second

// 信号发出后等待会话结束的时限: 既不完结也不应答的会话会被报出来, 而不是拖到测试框架超时.
const sessionEndDeadline = 10 * time.Second

// `signalSelf`把信号发给本进程: 信号必须投给安装了handler的进程, 而handler正是被测对象.
// 用`os`而不是`syscall.Kill`, 后者在Windows上不存在, 用它的测试在那里跳过.
func signalSelf(t *testing.T, sig os.Signal) {
	t.Helper()
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("find this process: %v", err)
	}
	if err := p.Signal(sig); err != nil {
		t.Fatalf("send %v to this process: %v", sig, err)
	}
}

// 覆盖"先装handler再启动ssh"打开的那个窗口: 落在窗口里的信号还没有进程可以转发.
// 丢失是静默的: 会话继续跑, 要求结束的Ctrl-C或kill要等ssh自己结束才有回应.
// 替身进程扮演ssh: 已启动但故意不交给转发, 因此到达它的信号只可能是交接前就扣下的.
// 信号发给本进程: handler装在这里, 拦住信号不让测试运行被结束; `forwardSignals`先于发送安装.
func TestForwardSignalsDeliversASignalItSawBeforeTheProcessExisted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no SIGTERM, and the forwarder there is a no-op")
	}
	victim := exec.Command("sleep", "30")
	if err := victim.Start(); err != nil {
		t.Fatalf("start the victim process: %v", err)
	}
	defer victim.Process.Kill()
	waited := make(chan struct{})
	go func() {
		_ = victim.Wait()
		close(waited)
	}()

	signals := forwardSignals()
	defer signals.stop()

	signalSelf(t, syscall.SIGTERM)

	// 留足余量让运行时把信号交给转发器, 此时还没有可转发的进程;
	// 紧随其后的检查才是重点: 替身是转发器唯一能发给的进程且毫发无损, 说明交接时信号仍未发出.
	time.Sleep(200 * time.Millisecond)
	select {
	case <-waited:
		t.Fatal("the victim was signalled before the hand-over: the signal was not one that had to be kept")
	default:
	}

	signals.attach(victim.Process)

	select {
	case <-waited:
	case <-time.After(signalExitBudget):
		t.Fatal("the victim was still running after the hand-over: the signal that arrived before the process existed was dropped")
	}
}

// 替身ssh故意起得慢, 能在预算内结束会话的只有经wrapper到达ssh的信号; 善后归会话自己的
// 拆除: 停掉本会话起的中继, 远端还持有的转发socket不归本次运行删; 信号发给本进程(会话
// 跑在这里), 等替身报告启动才发, 落在handler装好之后: 不装handler会结束整轮测试而非让本测试失败.
func TestRunSSHForwardsASignalThatEndsTheSessionWhileItIsStillStarting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script, and Windows has no signals")
	}
	shortenRelayWatch(t)

	// 会话自己的中继, 好让拆除有属于会话的东西可停: 看门狗和它起的中继.
	var startedRelays [][]string
	helperStarterRecording(t, nil, &startedRelays)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// 会话分支比本测试活得久得多.
	fake := newStandInSSH(t, "sleep 30")

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

	// 替身一跑起来就说明会话的ssh已启动: 这正是下面的信号要找到的状态,
	// wrapper已装好handler并交接过进程, 而会话本身还没结束.
	waitUntil(t, func() bool { _, err := os.Stat(fake.started); return err == nil },
		"the stand-in ssh never started the session")
	if !relayRunning(addr) {
		t.Fatal("the session is not forwarding to a relay of its own")
	}

	startedAt := time.Now()
	signalSelf(t, syscall.SIGTERM)

	var sessionErr error
	select {
	case sessionErr = <-done:
	case <-time.After(sessionEndDeadline):
		t.Fatalf("Run(ssh) was still running %v after SIGTERM: the signal did not reach ssh, whose stand-in sits there for 30s",
			sessionEndDeadline)
	}

	var exitErr *exec.ExitError
	if !errors.As(sessionErr, &exitErr) || exitErr.ExitCode() != -1 {
		t.Errorf("Run(ssh) error = %v after %v, want the session to have died from the signal forwarded to it",
			sessionErr, time.Since(startedAt))
	}
	// 会话是预检探针之后的唯一一次调用: 被信号杀死的会话其ssh也已退出,
	// 本次运行在其后不再开自己的连接.
	if want := []string{"probe", "session"}; !slices.Equal(fake.invocations(t), want) {
		t.Errorf("ssh invocations = %q, want %q: the run opens no connection after the session",
			fake.invocations(t), want)
	}
	// 会话goroutine已结束, 此时读这些是无竞态的.
	waitUntil(t, func() bool { return !relayRunning(addr) },
		"the relay this session started outlived the session")
	if len(startedRelays) != 1 {
		t.Errorf("relay starts = %d, want exactly the one this session began with: the watchdog must not outlive the session and start another",
			len(startedRelays))
	}
}
