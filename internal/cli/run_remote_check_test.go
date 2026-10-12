package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestSplitSSHArgsKeepsTheDestinationAfterASwitch(t *testing.T) {
	// gpg-agent-forward的开关自身不取值, 其后的参数仍是目标主机;
	// 把它当开关的取值消费, 就没有主机可连.
	own, through := SplitSSHArgs([]string{"--skip-remote-check", "dev@host"})
	if want := []string{"--skip-remote-check"}; !slices.Equal(own, want) {
		t.Errorf("own = %q, want %q", own, want)
	}
	if want := []string{"dev@host"}; !slices.Equal(through, want) {
		t.Errorf("through = %q, want %q", through, want)
	}

	// ssh自身的选项仍被透传; 开关上写了=就不需要后面的参数.
	own, through = SplitSSHArgs([]string{"--skip-remote-check=true", "-p", "2222", "dev@host"})
	if want := []string{"--skip-remote-check=true"}; !slices.Equal(own, want) {
		t.Errorf("own = %q, want %q", own, want)
	}
	if want := []string{"-p", "2222", "dev@host"}; !slices.Equal(through, want) {
		t.Errorf("through = %q, want %q", through, want)
	}
}

// 替身ssh对run的每种调用分别作答, 结果可按调用内容区分:
// 带`socketAbsentMarker`的form命令回`formMarker`; 带rm的删除分两条 - control socket
// 那条回`socketReclaimedMarker`, 被测路径那条回`removalMarker`; 其余是session.
func newStandInSSHForForm(t *testing.T, formMarker, removalMarker string) *standInSSH {
	t.Helper()
	dir := t.TempDir()
	f := &standInSSH{
		log:     filepath.Join(dir, "invocations"),
		started: filepath.Join(dir, "session-started"),
	}
	form := ":"
	if formMarker != "" {
		form = "echo " + formMarker
	}
	removal := "echo " + socketReclaimedMarker
	if removalMarker != "" {
		removal = "echo " + removalMarker
	}
	script := fmt.Sprintf(`#!/bin/sh
case "$*" in
  *%s*)
    echo probe >> %s
    %s
    ;;
  *rm\ -f*)
    case "$*" in
      *%s*)
        echo ctl >> %s
        echo %s
        ;;
      *)
        echo remove >> %s
        %s
        ;;
    esac
    ;;
  *)
    echo session >> %s
    : > %s
    exit 0
    ;;
esac
`,
		socketAbsentMarker, shellQuoteSingle(f.log), form,
		casePatternFor(octalEscapes("/"+controlSocketPrefix)), shellQuoteSingle(f.log), socketReclaimedMarker,
		shellQuoteSingle(f.log), removal,
		shellQuoteSingle(f.log), shellQuoteSingle(f.started))
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatalf("write the stand-in ssh: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return f
}

// 把run的探测接起来: form命令由`PATH`上的替身ssh作答, 分类结果换成测试选定的值.
// 分类是唯一需要真ssh连接的部分, 详见`remote_probe_test.go`.
func withFormAndClassification(t *testing.T, verdict socketForwardVerdict, err error) {
	t.Helper()
	old := classifyRemoteSocketForward
	classifyRemoteSocketForward = func([]string, string, string) (socketForwardVerdict, error) {
		return verdict, err
	}
	t.Cleanup(func() { classifyRemoteSocketForward = old })
}

// 把`s`转义后用作shell case pattern: 远端命令里带的是八进制转义,
// 不转义的话每个反斜杠会被pattern当成引用符.
func casePatternFor(s string) string {
	return strings.ReplaceAll(s, `\`, `\\`)
}

// 滤掉control socket自身的清理记录: 检查无论结论如何都会删自己的控制socket,
// 那些行对断言被测路径上的处理是噪声.
func checkInvocations(t *testing.T, f *standInSSH) []string {
	t.Helper()
	var kept []string
	for _, got := range f.invocations(t) {
		if got == "ctl" {
			continue
		}
		kept = append(kept, got)
	}
	return kept
}

func TestRunSSHStartsWithTheFlagWhenTheHostCannotBeChecked(t *testing.T) {
	// form命令没报告, 路径上有什么无从得知; 此时仍开session会顶掉活着的agent socket.
	// `--skip-remote-check`是显式通道: session照开, 并报告没做检查.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHForForm(t, "", "")

	err, _ := runSSHAgainstStandIn(t, port)

	if err == nil {
		t.Fatal("Run(ssh) error = nil, want a refusal when the remote host answered nothing")
	}
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
	}
	if want := []string{"probe"}; !slices.Equal(checkInvocations(t, fake), want) {
		t.Errorf("ssh invocations = %q, want %q: the session must not open", checkInvocations(t, fake), want)
	}

	port2, _, _ := startAdoptedRelay(t)
	fake2 := newStandInSSHForForm(t, "", "")
	err, errOut := runSSHAgainstStandIn(t, port2, "--skip-remote-check")
	if err != nil {
		t.Fatalf("Run(ssh) error = %v, want the session to run with the flag given; diagnostics: %q", err, errOut)
	}
	if want := []string{"probe", "session"}; !slices.Equal(checkInvocations(t, fake2), want) {
		t.Errorf("ssh invocations = %q, want %q", checkInvocations(t, fake2), want)
	}
	if !strings.Contains(errOut, "--skip-remote-check") {
		t.Errorf("diagnostics = %q, want the skipped check reported", errOut)
	}
}

func TestRunSSHRefusesALiveSocketWhateverTheFlagSays(t *testing.T) {
	// 活socket是远端自己的agent, 盖上去正是检查要防的故障;
	// `--skip-remote-check`只覆盖没能查, 放宽到未决状态也不能放到这一种.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHForForm(t, socketSocketMarker, socketReclaimedMarker)
	withFormAndClassification(t, forwardLive, nil)

	err, _ := runSSHAgainstStandIn(t, port, "--skip-remote-check")

	if err == nil {
		t.Fatal("Run(ssh) error = nil, want a refusal for a live socket even with --skip-remote-check")
	}
	if want := []string{"probe"}; !slices.Equal(checkInvocations(t, fake), want) {
		t.Errorf("ssh invocations = %q, want %q: the session must not open", checkInvocations(t, fake), want)
	}
}

// 无人监听的残留socket默认即删, 无需开关; 删除被报告, session照开.
func TestRunSSHStartsAfterReclaimingALeftover(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHForForm(t, socketSocketMarker, socketReclaimedMarker)
	withFormAndClassification(t, forwardDead, nil)

	err, errOut := runSSHAgainstStandIn(t, port)

	if err != nil {
		t.Fatalf("Run(ssh) error = %v, want the session to run; diagnostics: %q", err, errOut)
	}
	// 两次删除是设计使然: 一次删被测路径, 一次删检查自己建的控制socket.
	if want := []string{"probe", "remove", "session"}; !slices.Equal(checkInvocations(t, fake), want) {
		t.Errorf("ssh invocations = %q, want %q", checkInvocations(t, fake), want)
	}
	if !strings.Contains(errOut, "removed a leftover socket") {
		t.Errorf("diagnostics = %q, want the removal reported", errOut)
	}
}

// 删除本身的结果才是最后答案: 目录不可写时connect也会被拒,
// 所以没有应答不构成启动的许可.
func TestRunSSHStopsWhenTheLeftoverCannotBeRemoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHForForm(t, socketSocketMarker, socketStuckMarker)
	withFormAndClassification(t, forwardDead, nil)

	err, _ := runSSHAgainstStandIn(t, port)

	if err == nil {
		t.Fatal("Run(ssh) error = nil, want a refusal when the leftover could not be removed")
	}
	// 答案来自那次删除尝试; session不会跟着打开.
	if want := []string{"probe", "remove"}; !slices.Equal(checkInvocations(t, fake), want) {
		t.Errorf("ssh invocations = %q, want %q: the session must not open", checkInvocations(t, fake), want)
	}
}

// `Run`层的fail-closed核心: 拒绝stream-local forwarding的`sshd`会让活socket看着也像死的,
// 所以分不出类时必须停在原地, 不能开session.
func TestRunSSHStopsWhenTheClassificationCannotBeMade(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHForForm(t, socketSocketMarker, socketReclaimedMarker)
	withFormAndClassification(t, forwardUnjudgeable, fmt.Errorf("the control connection was not established"))

	err, _ := runSSHAgainstStandIn(t, port)

	if err == nil {
		t.Fatal("Run(ssh) error = nil, want a refusal when the check cannot tell")
	}
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
	}
	if want := []string{"probe"}; !slices.Equal(checkInvocations(t, fake), want) {
		t.Errorf("ssh invocations = %q, want %q: the session must not open", checkInvocations(t, fake), want)
	}

	port2, _, _ := startAdoptedRelay(t)
	fake2 := newStandInSSHForForm(t, socketSocketMarker, socketReclaimedMarker)
	withFormAndClassification(t, forwardUnjudgeable, fmt.Errorf("the control connection was not established"))
	err, errOut := runSSHAgainstStandIn(t, port2, "--skip-remote-check")
	if err != nil {
		t.Fatalf("Run(ssh) error = %v, want the session to run; diagnostics: %q", err, errOut)
	}
	if want := []string{"probe", "session"}; !slices.Equal(checkInvocations(t, fake2), want) {
		t.Errorf("ssh invocations = %q, want %q", checkInvocations(t, fake2), want)
	}
	if !strings.Contains(errOut, "--skip-remote-check") {
		t.Errorf("diagnostics = %q, want the skipped check reported", errOut)
	}
}

// 权限关口: 连socket需要写权限, 权限被拒与无人监听在连接层同样是关闭, 无从区分,
// 所以先在远端正面测权限, 默认是拒绝而不是删除. `--skip-remote-check`确实能放行这里,
// 这是刻意的: 路径判不了正是该开关的用途; 代价是`sshd`的bind可能unlink别人的socket.
func TestRunSSHStopsAtAPathItCannotWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHForForm(t, socketUnwritableMarker, "")

	err, _ := runSSHAgainstStandIn(t, port)

	if err == nil {
		t.Fatal("Run(ssh) error = nil, want a refusal for a path this user cannot write")
	}
	if !strings.Contains(err.Error(), "cannot be written") {
		t.Errorf("error %v should say the path cannot be written", err)
	}
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the deliberate way to start anyway", err)
	}
	if want := []string{"probe"}; !slices.Equal(checkInvocations(t, fake), want) {
		t.Errorf("ssh invocations = %q, want %q: the session must not open", checkInvocations(t, fake), want)
	}
}

func TestRunHelpNamesTheCheckAndNotAReclaimSwitch(t *testing.T) {
	// 帮助要说明检查做什么: 删除现在是默认行为, 它为何安全从命令行看不出来.
	// 需要用户主动选择的reclaim开关已删除, 没有可opt in的东西了.
	var out, errOut bytes.Buffer
	if err := Run([]string{"--help"}, &out, &errOut); err != nil {
		t.Fatalf("Run(--help) error = %v, want nil", err)
	}
	help := out.String()
	if !strings.Contains(help, "--skip-remote-check") {
		t.Errorf("help does not list --skip-remote-check:\n%s", help)
	}
	if strings.Contains(help, "reclaim-remote-socket") {
		t.Errorf("help still lists --reclaim-remote-socket, which no longer exists:\n%s", help)
	}
	if !strings.Contains(help, "removes it") && !strings.Contains(help, "is removed") {
		t.Errorf("help does not say that a leftover socket is removed:\n%s", help)
	}
}
