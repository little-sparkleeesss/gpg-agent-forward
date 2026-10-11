package cli

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"
)

// 子进程收到SIGTERM后允许的结束时限: 它的替身ssh在清理分支里坐得久得多, 清理本身
// 又受remoteCleanupTimeout(5s)限定, 所以只有立刻被处理的信号才装得进这个预算.
const signalExitBudget = 2 * time.Second

// 等待子进程进入清理窗口的时限: 死了或一直没到就会被报出来, 而不是拖到测试框架自己的超时.
const cleanupWindowDeadline = 10 * time.Second

// 这不是一个真测试: 下面的测试把它作为子进程再执行, 拿一个自己的gpg-agent-forward去发信号.
// 进程吞掉的信号在它内部观测不到, 发给测试二进制本身又会杀掉整轮测试而不是让一个测试失败.
// 中继端口经环境变量传入, 其余参数与runSSHAgainstStandIn相同, 子进程因而沿用父进程起的中继.
func TestHelperRunSSHSession(t *testing.T) {
	if os.Getenv("GPG_AGENT_FORWARD_SIGNAL_HELPER") != "1" {
		return
	}
	port := os.Getenv("GPG_AGENT_FORWARD_SIGNAL_HELPER_PORT")
	if port == "" {
		fmt.Fprintln(os.Stderr, "helper: GPG_AGENT_FORWARD_SIGNAL_HELPER_PORT is not set")
		os.Exit(2)
	}
	err := Run([]string{
		"ssh",
		"--port", port,
		"--socket-file", "/tmp/sock",
		"--remote-socket", "/run/user/1000/gnupg/S.gpg-agent",
		"dev@host",
	}, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper: Run(ssh) =", err)
		os.Exit(1)
	}
	os.Exit(0)
}

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

// 替身ssh故意起得慢, 只有经wrapper到达ssh的信号能在预算内结束会话; 会话被信号杀死后,
// 属于它的一切都要随之倒下: 本会话起的中继, 以及远端还持有的转发socket; 信号发给本进程
// (会话跑在这里), 等替身报告启动才发(落在handler装好之后); 不装handler会结束整轮测试.
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
	fake := newStandInSSH(t, "sleep 30", "exit 0")

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
	case <-time.After(cleanupWindowDeadline):
		t.Fatalf("Run(ssh) was still running %v after SIGTERM: the signal did not reach ssh, whose stand-in sits there for 30s",
			cleanupWindowDeadline)
	}

	var exitErr *exec.ExitError
	if !errors.As(sessionErr, &exitErr) || exitErr.ExitCode() != -1 {
		t.Errorf("Run(ssh) error = %v after %v, want the session to have died from the signal forwarded to it",
			sessionErr, time.Since(startedAt))
	}
	// 清理连接是第三条: 预检探针, 会话, 清理. 被信号杀死的会话正会留下转发socket, 所以清理必须为它跑.
	if want := []string{"probe", "session", "probe"}; !slices.Equal(fake.invocations(t), want) {
		t.Errorf("ssh invocations = %q, want %q: the remote cleanup must run for a session killed by a signal",
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

// 清理窗口: 清理连接要开自己的ssh, 最多坐满remoteCleanupTimeout; 会话拆除必须先于它: 转发
// 装着时SIGINT/SIGTERM/SIGHUP被扣住而ssh已退出, 窗口里的kill既结束不了gpg-agent-forward也够不到活物.
// runSSH因此先结束会话再清理; 信号发子进程, 要排除的是信号被吞: 自己发自己只会挂住而非失败.
func TestRunSSHIsKillableWhileTheRemoteCleanupRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no SIGTERM, and the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	// 会话分支立刻退出, 清理分支久留: 从它的标记文件出现到下面发信号之间, 全在清理窗口里.
	fake := newStandInSSH(t, "exit 0", "sleep 30")

	// 子进程输出写真实文件而不是管道: `exec`的输出若不是`*os.File`, 复制输出的goroutine
	// 要等所有持有者关闭管道才结束; 清理ssh(信号够不到)继承管道且按设计比子进程活得久,
	// Wait就会一直等到那条连接自己结束.
	logPath := filepath.Join(t.TempDir(), "child-output")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create the child's output file: %v", err)
	}
	defer logFile.Close()

	child := exec.Command(selfExe(), "-test.run=TestHelperRunSSHSession")
	child.Env = append(os.Environ(),
		"GPG_AGENT_FORWARD_SIGNAL_HELPER=1",
		"GPG_AGENT_FORWARD_SIGNAL_HELPER_PORT="+fmt.Sprint(port))
	child.Stdout, child.Stderr = logFile, logFile
	if err := child.Start(); err != nil {
		t.Fatalf("start the child gpg-agent-forward: %v", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- child.Wait() }()
	exited := false
	// 不能有子进程活过测试: 还坐在清理窗口里的会占着替身ssh和本测试的临时目录.
	defer func() {
		if !exited {
			_ = child.Process.Kill()
			<-waited
		}
	}()

	// `childOutput`只在子进程被回收后才读, 此时已无人再写该文件.
	childOutput := func() string {
		data, err := os.ReadFile(logPath)
		if err != nil {
			return fmt.Sprintf("(the child's output is unreadable: %v)", err)
		}
		return string(data)
	}

	// 清理连接一启动子进程就进入清理窗口: 该连接先建标记文件再安顿下来.
	// 已经退出的子进程(失败, 或没走到)连自己的输出一起报出来, 而不是干等.
	deadline := time.Now().Add(cleanupWindowDeadline)
	for {
		if _, err := os.Stat(fake.cleanup); err == nil {
			break
		}
		select {
		case err := <-waited:
			exited = true
			t.Fatalf("the child exited with %v before it reached the remote cleanup; it must be alive inside that window. its output:\n%s", err, childOutput())
		default:
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("the child never reached the remote cleanup window within %v. its output:\n%s", cleanupWindowDeadline, childOutput())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// 清理是第三条连接: 预检探针, 会话, 清理. 在这里检查它, 才把窗口锁定为被测的那个,
	// 而不是运行中的其他时点.
	if got, want := fake.invocations(t), []string{"probe", "session", "probe"}; !slices.Equal(got, want) {
		t.Fatalf("ssh invocations = %q, want %q, with the cleanup connection open", got, want)
	}

	started := time.Now()
	if err := child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to the child: %v", err)
	}
	var waitErr error
	select {
	case waitErr = <-waited:
		exited = true
	case <-time.After(cleanupWindowDeadline):
		t.Fatalf("the child was still running %v after SIGTERM, want it to end at once: the signal is being swallowed while the cleanup runs. its output:\n%s", cleanupWindowDeadline, childOutput())
	}
	elapsed := time.Since(started)

	// 状态必须指名SIGTERM而非"某个信号": 其他原因结束子进程会让测试因错误的原因通过.
	// `ProcessState.Sys`是Unix上的内核等待状态, 其`Signaled`/`Signal`报告杀死进程的信号.
	var exitErr *exec.ExitError
	switch {
	case waitErr == nil:
		t.Errorf("the child exited with status 0 %v after SIGTERM, want it to be killed by the signal: it was consumed during the cleanup window", elapsed)
	case !errors.As(waitErr, &exitErr):
		t.Errorf("the child ended with %v %v after SIGTERM, want it to be killed by SIGTERM", waitErr, elapsed)
	default:
		status, ok := exitErr.Sys().(syscall.WaitStatus)
		if !ok {
			t.Errorf("the child's status is reported as %T, want a syscall.WaitStatus naming the signal", exitErr.Sys())
		} else if !status.Signaled() || status.Signal() != syscall.SIGTERM {
			t.Errorf("the child ended with %v (signaled=%v, signal=%v) %v after SIGTERM, want death by SIGTERM", status, status.Signaled(), status.Signal(), elapsed)
		}
	}
	if elapsed > signalExitBudget {
		t.Errorf("the child took %v to end after SIGTERM, want under %v: the signal must not wait for the cleanup connection", elapsed, signalExitBudget)
	}
}
