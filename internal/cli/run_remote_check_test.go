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

// 替身ssh的discovery分支等的标记文件, 由测试在通报时创建:
// 先通报连接再提问才过得去, 先问后通报的到不了session.
func discoveryAnnouncedMarker(f *standInSSH) string {
	return f.log + ".discovery-announced"
}

// 替身ssh对run的五种调用分别作答: 带`gpgconf`的discovery查询只在run通报到`stderr`
// 之后才回`standInRemoteSocketPath`; 删除分两条: control socket回`socketReclaimedMarker`,
// 被测路径回`removalMarker`; 带`socketAbsentMarker`的form命令回`formMarker`;
// 带`command -v`的用户域分类命令回none (这些用例测的是退回sshd转发之后的调用方行为), 其余是session.
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
  *gpgconf*)
    echo query >> %s
    i=0
    while [ ! -e %s ] && [ "$i" -lt 100 ]; do i=$((i+1)); sleep 0.05; done
    [ -e %s ] || exit 1
    echo %s
    ;;
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
  *command\ -v*)
    echo connect >> %s
    echo %s
    ;;
  *)
    echo session >> %s
    : > %s
    exit 0
    ;;
esac
`,
		shellQuoteSingle(f.log), shellQuoteSingle(discoveryAnnouncedMarker(f)), shellQuoteSingle(discoveryAnnouncedMarker(f)), standInRemoteSocketPath,
		socketAbsentMarker, shellQuoteSingle(f.log), form,
		casePatternFor(octalEscapes("/"+controlSocketPrefix)), shellQuoteSingle(f.log), socketReclaimedMarker,
		shellQuoteSingle(f.log), removal,
		shellQuoteSingle(f.log), socketConnectNoneMarker,
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
	withFormAndClassificationCalling(t, verdict, err, nil)
}

// 在`withFormAndClassification`上加一个分类被调用时触发的hook,
// 用来判断那时诊断里已经写了什么.
func withFormAndClassificationCalling(t *testing.T, verdict socketForwardVerdict, err error, onCall func()) {
	t.Helper()
	old := classifyRemoteSocketForward
	classifyRemoteSocketForward = func([]string, string, string) (socketForwardVerdict, error) {
		if onCall != nil {
			onCall()
		}
		return verdict, err
	}
	t.Cleanup(func() { classifyRemoteSocketForward = old })
}

// 由函数充当`io.Writer`, 供逐段观察诊断输出的测试使用.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

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
	if !strings.Contains(errOut, "starting without a verdict") {
		t.Errorf("diagnostics = %q, want the skip reported as a missing verdict", errOut)
	}
	if !strings.Contains(errOut, "the host did not answer") {
		t.Errorf("diagnostics = %q, want the reason the check could not be made", errOut)
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
	if want := []string{"probe", "connect"}; !slices.Equal(checkInvocations(t, fake), want) {
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
	if want := []string{"probe", "connect", "remove", "session"}; !slices.Equal(checkInvocations(t, fake), want) {
		t.Errorf("ssh invocations = %q, want %q", checkInvocations(t, fake), want)
	}
	if !strings.Contains(errOut, "removed a leftover socket") {
		t.Errorf("diagnostics = %q, want the removal reported", errOut)
	}
}

// 无`--remote-socket`的run会多开两条连接, 这是第一条: 在检查之前先问远端
// agent socket在哪. 它和pre-check一样可能在终端上提示, 所以同样要先通报;
// 替身的查询分支只在通报行写出后才作答, 先问后通报的到不了session.
func TestRunSSHAnnouncesTheDiscoveryConnectionBeforeItRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHForForm(t, socketSocketMarker, socketReclaimedMarker)
	withFormAndClassification(t, forwardDead, nil)

	var diagnostics bytes.Buffer
	announced := false
	w := writerFunc(func(p []byte) (int, error) {
		if !announced && strings.Contains(string(p), "asking the remote host where its agent socket is") {
			announced = true
			if err := os.WriteFile(discoveryAnnouncedMarker(fake), nil, 0o600); err != nil {
				t.Errorf("mark the announced discovery connection: %v", err)
			}
		}
		return diagnostics.Write(p)
	})
	err := runSSHCommandLine(t, port, w)

	if err != nil {
		t.Fatalf("Run(ssh) error = %v, want the session to run; diagnostics: %q", err, diagnostics.String())
	}
	want := []string{"query", "probe", "connect", "remove", "session"}
	if got := checkInvocations(t, fake); !slices.Equal(got, want) {
		t.Errorf("ssh invocations = %q, want %q", got, want)
	}
	if !announced {
		t.Errorf("diagnostics = %q, want the discovery connection announced", diagnostics.String())
	}
	checked := strings.Index(diagnostics.String(), "checking what is at "+standInRemoteSocketPath)
	if checked < 0 {
		t.Fatalf("diagnostics = %q, want the check announced by path", diagnostics.String())
	}
	if named := strings.Index(diagnostics.String(), "asking the remote host where its agent socket is"); named < 0 || named > checked {
		t.Errorf("diagnostics = %q, want the discovery connection named before the check", diagnostics.String())
	}

	// 这行与查询结果无关: 这里查询失败, 要的就是先于查询写出.
	requireStandInSSH(t)
	t.Setenv("PATH", standInSSHPath(t, "exit 1\n"))
	if _, failedOut := runSSHDiscoveringAgainstStandIn(t, port); !strings.Contains(failedOut, "asking the remote host where its agent socket is") {
		t.Errorf("diagnostics = %q, want the discovery connection named even when the query fails", failedOut)
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
	if want := []string{"probe", "connect", "remove"}; !slices.Equal(checkInvocations(t, fake), want) {
		t.Errorf("ssh invocations = %q, want %q: the session must not open", checkInvocations(t, fake), want)
	}
}

// `Run`层的fail-closed核心: 拒绝stream-local forwarding的`sshd`会让活socket也像死的,
// 分不出类时只能停下. 这里还固定检查的上下文行必须先写出:
// 检查期间ssh的提示(host-key确认, passphrase)走`/dev/tty`, 这行是用户判断谁在问的线索.
func TestRunSSHStopsWhenTheClassificationCannotBeMade(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHForForm(t, socketSocketMarker, socketReclaimedMarker)
	var classified bool
	withFormAndClassificationCalling(t, forwardUnjudgeable, fmt.Errorf("the control connection was not established"),
		func() { classified = true })

	// writer逐段看诊断输出: 通报必须在分类还没被问到时到达.
	var diagnostics bytes.Buffer
	announcedBeforeTheCheck := false
	err := runSSHCommandLine(t, port, writerFunc(func(p []byte) (int, error) {
		if !classified && strings.Contains(string(p), "checking what is at") {
			announcedBeforeTheCheck = true
		}
		return diagnostics.Write(p)
	}), "--remote-socket", standInRemoteSocketPath)

	if err == nil {
		t.Fatal("Run(ssh) error = nil, want a refusal when the check cannot tell")
	}
	if !strings.Contains(diagnostics.String(), "checking what is at "+standInRemoteSocketPath) {
		t.Errorf("diagnostics = %q, want the check announced by path", diagnostics.String())
	}
	if !announcedBeforeTheCheck {
		t.Error("the check was announced only after it had run, so the line cannot tell the user who is asking while ssh prompts")
	}
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
	}
	if want := []string{"probe", "connect"}; !slices.Equal(checkInvocations(t, fake), want) {
		t.Errorf("ssh invocations = %q, want %q: the session must not open", checkInvocations(t, fake), want)
	}

	// 带flag时session照开, 报告检查被跳过, 并把检查没能定下的原因打印出来而不是吞掉.
	port2, _, _ := startAdoptedRelay(t)
	fake2 := newStandInSSHForForm(t, socketSocketMarker, socketReclaimedMarker)
	withFormAndClassification(t, forwardUnjudgeable, fmt.Errorf("the control connection was not established"))
	err, errOut := runSSHAgainstStandIn(t, port2, "--skip-remote-check")
	if err != nil {
		t.Fatalf("Run(ssh) error = %v, want the session to run; diagnostics: %q", err, errOut)
	}
	if want := []string{"probe", "connect", "session"}; !slices.Equal(checkInvocations(t, fake2), want) {
		t.Errorf("ssh invocations = %q, want %q", checkInvocations(t, fake2), want)
	}
	if !strings.Contains(errOut, "--skip-remote-check") || !strings.Contains(errOut, "starting without a verdict") {
		t.Errorf("diagnostics = %q, want the skipped check reported as a missing verdict", errOut)
	}
	if !strings.Contains(errOut, "the control connection was not established") {
		t.Errorf("diagnostics = %q, want the reason the check could not be made", errOut)
	}
}

// 权限关口: 连socket需要写权限, 权限被拒与无人监听在连接层同样是关闭, 无从区分,
// 所以先在远端正面测权限, 默认是拒绝而不是删除. 这里的拒绝只提`--remote-socket`,
// 不提`--skip-remote-check`: 该开关只覆盖没能查, 而这是已发现一个查不了的东西, 出路是换路径.
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
	if !strings.Contains(err.Error(), "--remote-socket") {
		t.Errorf("error %v should name --remote-socket, the way that actually works here", err)
	}
	if strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error for an unwritable path offers --skip-remote-check, which cannot help here: %v", err)
	}
	if want := []string{"probe"}; !slices.Equal(checkInvocations(t, fake), want) {
		t.Errorf("ssh invocations = %q, want %q: the session must not open", checkInvocations(t, fake), want)
	}

	// 这个flag到这里就到头了: 给了它, run对同一状态照样拒绝, session不开.
	fake2 := newStandInSSHForForm(t, socketUnwritableMarker, "")
	err2, _ := runSSHAgainstStandIn(t, port, "--skip-remote-check")
	if err2 == nil {
		t.Fatal("Run(ssh) error = nil, want the refusal to stand with --skip-remote-check given")
	}
	if !strings.Contains(err2.Error(), "cannot be written") {
		t.Errorf("error %v should still say the path cannot be written", err2)
	}
	if want := []string{"probe"}; !slices.Equal(checkInvocations(t, fake2), want) {
		t.Errorf("ssh invocations = %q, want %q: the session must not open", checkInvocations(t, fake2), want)
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
