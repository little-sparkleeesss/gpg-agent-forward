package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"gpg-agent-forward/internal/relaylock"
)

// `PATH`上的替身ssh, 每次调用记一行日志: 测试据此看wrapper问了远端什么,
// 以及session结束后没再问. 带探针marker的调用是探针, 回测试选定的结论;
// 其余是session, 跑测试给的片段.
type standInSSH struct {
	log     string
	started string // 由session分支创建
}

func newStandInSSH(t *testing.T, sessionBody string) *standInSSH {
	t.Helper()
	return newStandInSSHSaying(t, socketAbsentMarker, sessionBody)
}

// 同`newStandInSSH`, 但探针应答由测试选定: 回free才能开session;
// 空应答表示探针什么都报不回来, 即主机上跑不了它.
func newStandInSSHSaying(t *testing.T, verdict, sessionBody string) *standInSSH {
	t.Helper()
	dir := t.TempDir()
	f := &standInSSH{
		log:     filepath.Join(dir, "invocations"),
		started: filepath.Join(dir, "session-started"),
	}
	// 用`:`而非空行: shell拒绝空的then/else分支, 什么都不答的探针也必须是条命令.
	answer := ":"
	if verdict != "" {
		answer = "echo " + verdict
	}
	// session调用带`-R`与目标主机; 探针调用把marker放在远端脚本里.
	script := fmt.Sprintf(`#!/bin/sh
case "$*" in
  *%s*)
    echo probe >> %s
    %s
    ;;
  *)
    echo session >> %s
    : > %s
    %s
    ;;
esac
`,
		socketAbsentMarker, shellQuoteSingle(f.log),
		answer,
		shellQuoteSingle(f.log), shellQuoteSingle(f.started), sessionBody)
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatalf("write the stand-in ssh: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return f
}

// 各次调用留下的日志行; 只在session goroutine结束后读, 文件已不再被写.
func (f *standInSSH) invocations(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatalf("read the stand-in ssh log: %v", err)
	}
	return strings.Fields(string(data))
}

// 在空闲端口放一个让session收养的relay, 免得wrapper自己起relay子进程.
func startAdoptedRelay(t *testing.T) (port int, addr string, stop func()) {
	t.Helper()
	port, stop = startFakeRelayStoppable(t, relaylock.Info{SocketFile: "/tmp/sock"})
	return port, fmt.Sprintf("127.0.0.1:%d", port), stop
}

// `extra`里的gpg-agent-forward选项放在目标主机之前; 返回`Run`的error和写到诊断输出的内容.
func runSSHAgainstStandIn(t *testing.T, port int, extra ...string) (error, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	args := []string{
		"ssh",
		"--port", fmt.Sprint(port),
		"--socket-file", "/tmp/sock",
		"--remote-socket", "/run/user/1000/gnupg/S.gpg-agent",
	}
	args = append(args, extra...)
	args = append(args, "dev@host")
	err := Run(args, &out, &errOut)
	return err, errOut.String()
}

func TestRunSSHReportsAFailedSessionAndOpensNoFurtherConnection(t *testing.T) {
	// ssh在session尚未建立就失败时退出255: 主机不可达, key被拒, host key变了.
	// 该状态就是session的结果, `Run`原样交回调用者; 远端只被问一件事 - pre-check,
	// 因为session之后不在那里跑任何东西.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSH(t, "exit 255")

	err, _ := runSSHAgainstStandIn(t, port)

	// 替身ssh退出255, 这正是本用例的前提; 换别的状态, 下面的断言就没有意义.
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 255 {
		t.Fatalf("Run(ssh) error = %v, want the stand-in ssh's own 255", err)
	}
	want := []string{"probe", "session"}
	if got := fake.invocations(t); !slices.Equal(got, want) {
		t.Errorf("ssh invocations = %q, want %q: the run opens no connection after the session", got, want)
	}
}

func TestRunSSHOpensNoFurtherConnectionAfterASessionThatRan(t *testing.T) {
	// 结束的session可能留下forward socket, 但那留给下一次调用的pre-check:
	// 本次run在session之后不再开第二条连接.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSH(t, "exit 0")

	err, errOut := runSSHAgainstStandIn(t, port)

	if err != nil {
		t.Fatalf("Run(ssh) error = %v, want the session to end cleanly", err)
	}
	want := []string{"probe", "session"}
	if got := fake.invocations(t); !slices.Equal(got, want) {
		t.Errorf("ssh invocations = %q, want %q: the run opens no connection after the session", got, want)
	}
	if strings.Contains(errOut, "could not clean up") {
		t.Errorf("diagnostics = %q, want no cleanup of the remote socket reported", errOut)
	}
}

func TestRunSSHOpensNoFurtherConnectionAfterASessionKilledByASignal(t *testing.T) {
	// Ctrl-C或kill掉的session最容易留下forward socket, 这里也一样:
	// 留下的由下一次调用的pre-check看, 本次不在退出路上再开连接去删;
	// `Run`仍报session自己的状态.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script, and Windows has no signals")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSH(t, "kill -TERM $$")

	err, _ := runSSHAgainstStandIn(t, port)

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != -1 {
		t.Fatalf("Run(ssh) error = %v, want the session to have died from the signal rather than exited", err)
	}
	want := []string{"probe", "session"}
	if got := fake.invocations(t); !slices.Equal(got, want) {
		t.Errorf("ssh invocations = %q, want %q: the run opens no connection after the session", got, want)
	}
}

// session路径在ssh退出后允许的耗时上限: 之后全是本进程内毫秒级的活
// (结束session, 停relay watchdog), 只有等本进程之外的东西才会把测试推过上限 -
// 那正是用到它的测试要找的.
const sessionEndBudget = 5 * time.Second

// 在测试goroutine之外跑ssh子命令, 报告它是否在budget内返回: ssh已退出而它的后代
// 进程仍握着`exec`建的输出管道时, 等管道只受session命令的`WaitDelay`约束,
// 没有它`Run`会一直等到最后一个持有者退出, 而不是结束session.
func runSSHWithin(t *testing.T, port int, budget time.Duration) (error, bool) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		err, _ := runSSHAgainstStandIn(t, port)
		done <- err
	}()
	select {
	case err := <-done:
		return err, true
	case <-time.After(budget):
		return nil, false
	}
}

func TestRunSSHSessionEndsWhenADescendantOfSSHHoldsItsStderr(t *testing.T) {
	// ssh退出时后代进程仍开着ssh的`stderr`管道 (ProxyCommand, wrapper): `errOut`不是`*os.File`,
	// `exec`经管道复制`stderr`, 要等最后一个持有者关闭才结束; 不设上限session永不结束, 其后的
	// teardown不跑. ssh退出0, `exec.Cmd.Wait`自关管道时用`ErrWaitDelay`顶替成功状态, 详见`WaitDelay`;
	// 该诊断不能当成失败session, 否则`Run`返回error会让CLI报会话错误并非零退出.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSH(t, "sleep 30 & exit 0")

	sessionErr, ended := runSSHWithin(t, port, sessionEndBudget)

	if !ended {
		t.Fatalf("Run(ssh) was still running %v after ssh exited 0: a descendant holding ssh's stderr kept the session alive",
			sessionEndBudget)
	}
	if sessionErr != nil {
		t.Errorf("Run(ssh) error = %v, want a session that ended normally: ssh exited 0, and only its stderr pipe was still held",
			sessionErr)
	}
	if want := []string{"probe", "session"}; !slices.Equal(fake.invocations(t), want) {
		t.Errorf("ssh invocations = %q, want %q: a session that ended is still a session whose ssh has exited",
			fake.invocations(t), want)
	}
}

func TestRunSSHSessionKeepsItsOwnStatusWhenADescendantOfSSHHoldsItsStderr(t *testing.T) {
	// 失败一侧不能动: ssh非零退出或被信号杀死, session就是失败了, 后代仍握`stderr`也不改变.
	// `ErrWaitDelay`只顶替成功状态, session路径只把它映射回已结束, 不是失败.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script, and Windows has no signals")
	}
	cases := []struct {
		name     string
		body     string
		wantCode int
	}{
		{"a session that exited non-zero", "sleep 30 & exit 7", 7},
		{"a session killed by a signal", "sleep 30 & kill -TERM $$", -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port, _, _ := startAdoptedRelay(t)
			fake := newStandInSSH(t, tc.body)

			sessionErr, ended := runSSHWithin(t, port, sessionEndBudget)

			if !ended {
				t.Fatalf("Run(ssh) was still running %v: a descendant holding ssh's stderr kept the session alive",
					sessionEndBudget)
			}
			var exitErr *exec.ExitError
			if !errors.As(sessionErr, &exitErr) || exitErr.ExitCode() != tc.wantCode {
				t.Fatalf("Run(ssh) error = %v, want the session's own exit status %d reported",
					sessionErr, tc.wantCode)
			}
			if want := []string{"probe", "session"}; !slices.Equal(fake.invocations(t), want) {
				t.Errorf("ssh invocations = %q, want %q: the session's own status is not a reason to run anything else on the remote host",
					fake.invocations(t), want)
			}
		})
	}
}

func TestForwardSignalsStoppingTwiceIsSafe(t *testing.T) {
	// session一结束`runSSH`就停forwarding, deferred的stop还会再跟一次, 所以必须能停两次:
	// POSIX实现里第二次close done channel会在teardown中途panic, 那是最糟的位置.
	// stop是deferred的, 从未到达session的路径也会走到 - 这里第二个forwarder就代表这种.
	signals := forwardSignals()
	signals.stop()
	signals.stop()

	noSession := forwardSignals()
	noSession.stop()
}

func TestRunSSHStartsWithTheFlagWhenTheHostCannotTellWhatIsAtThePath(t *testing.T) {
	// 探针答unknown (没有`ss`, `ss`失败, 内核socket表读不到)不是关于路径的结论;
	// `--skip-remote-check`的help承诺远端查不了时就开session, 这类回答同样要能被它放行.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}

	t.Run("without the flag the session does not open", func(t *testing.T) {
		port, _, _ := startAdoptedRelay(t)
		fake := newStandInSSHSaying(t, socketUnknownMarker, "exit 0")

		err, _ := runSSHAgainstStandIn(t, port)

		if err == nil {
			t.Fatal("Run(ssh) error = nil, want a refusal when the host could not tell")
		}
		if !strings.Contains(err.Error(), "--skip-remote-check") {
			t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
		}
		if want := []string{"probe"}; !slices.Equal(fake.invocations(t), want) {
			t.Errorf("ssh invocations = %q, want %q: the session must not open", fake.invocations(t), want)
		}
	})

	t.Run("with the flag the session runs", func(t *testing.T) {
		port, _, _ := startAdoptedRelay(t)
		fake := newStandInSSHSaying(t, socketUnknownMarker, "exit 0")

		err, errOut := runSSHAgainstStandIn(t, port, "--skip-remote-check")

		if err != nil {
			t.Fatalf("Run(ssh) error = %v, want the session to run with the flag given; diagnostics: %q", err, errOut)
		}
		if want := []string{"probe", "session"}; !slices.Equal(fake.invocations(t), want) {
			t.Errorf("ssh invocations = %q, want %q", fake.invocations(t), want)
		}
		if !strings.Contains(errOut, "--skip-remote-check") {
			t.Errorf("diagnostics = %q, want the skipped check reported", errOut)
		}
	})
}

func TestRunSSHRefusesALiveSocketWhateverTheFlagSays(t *testing.T) {
	// 活socket是远端自己的agent, 盖上去正是检查要防的故障;
	// 这个flag只覆盖没能查, 放宽到未决状态也不能放到这一种.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHSaying(t, socketLiveMarker, "exit 0")

	err, _ := runSSHAgainstStandIn(t, port, "--skip-remote-check")

	if err == nil {
		t.Fatal("Run(ssh) error = nil, want a refusal for a live socket even with --skip-remote-check")
	}
	if want := []string{"probe"}; !slices.Equal(fake.invocations(t), want) {
		t.Errorf("ssh invocations = %q, want %q: the session must not open", fake.invocations(t), want)
	}
}
