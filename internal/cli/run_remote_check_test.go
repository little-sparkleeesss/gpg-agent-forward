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

	// `--reclaim-remote-socket`是同类开关, 同样必须在这里消费掉:
	// ssh不认这个选项, 会拒绝启动session.
	own, through = SplitSSHArgs([]string{"--reclaim-remote-socket", "dev@host"})
	if want := []string{"--reclaim-remote-socket"}; !slices.Equal(own, want) {
		t.Errorf("own = %q, want %q", own, want)
	}
	if want := []string{"dev@host"}; !slices.Equal(through, want) {
		t.Errorf("through = %q, want %q", through, want)
	}
}

// 替身ssh按探针命令里带的marker作答: 带reclaim marker的说明开关传到了远端命令;
// 一律同样作答的替身看不出哪套策略到了远端, 而开关只有到得了远端才算接对.
func newStandInSSHForReclaim(t *testing.T) *standInSSH {
	t.Helper()
	dir := t.TempDir()
	f := &standInSSH{
		log:     filepath.Join(dir, "invocations"),
		started: filepath.Join(dir, "session-started"),
	}
	script := fmt.Sprintf(`#!/bin/sh
case "$*" in
  *%s*)
    echo probe >> %s
    echo %s
    ;;
  *%s*)
    echo probe >> %s
    echo %s
    ;;
  *)
    echo session >> %s
    : > %s
    exit 0
    ;;
esac
`,
		socketReclaimedMarker, shellQuoteSingle(f.log), socketReclaimedMarker,
		socketStaleMarker, shellQuoteSingle(f.log), socketStaleMarker,
		shellQuoteSingle(f.log), shellQuoteSingle(f.started))
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatalf("write the stand-in ssh: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return f
}

func TestRunSSHStopsAtASocketLeftOnTheRemoteHost(t *testing.T) {
	// 无人监听的socket也要用户要求才删: 证据只来自一个network namespace的socket表,
	// 另一个namespace里的agent(共享目录的容器)看不到. 错误里同时给出删除命令和开关.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHForReclaim(t)

	err, _ := runSSHAgainstStandIn(t, port)

	if err == nil {
		t.Fatal("Run(ssh) error = nil, want a refusal for a socket left at the remote path")
	}
	if !strings.Contains(err.Error(), "--reclaim-remote-socket") {
		t.Errorf("error %v should name --reclaim-remote-socket as the way to have it removed", err)
	}
	const want = "rm -f -- '/run/user/1000/gnupg/S.gpg-agent'"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %v should carry %q, the command that removes the file on the remote host", err, want)
	}
	if got := fake.invocations(t); !slices.Equal(got, []string{"probe"}) {
		t.Errorf("ssh invocations = %q, want [probe]: the session must not open", got)
	}
}

func TestRunSSHReclaimsASocketLeftOnTheRemoteHostWhenAsked(t *testing.T) {
	// 带`--reclaim-remote-socket`时删除并报告: 对远端的改动必须让用户看得见.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHForReclaim(t)

	err, errOut := runSSHAgainstStandIn(t, port, "--reclaim-remote-socket")

	if err != nil {
		t.Fatalf("Run(ssh) error = %v, want the session to run with the switch given; diagnostics: %q", err, errOut)
	}
	// 替身只对带开关的探针命令回reclaimed, 所以session开起来就证明开关到了探针;
	// 只有pre-check会探: session之后不再开任何连接.
	if got := fake.invocations(t); !slices.Equal(got, []string{"probe", "session"}) {
		t.Errorf("ssh invocations = %q, want [probe session]", got)
	}
	if !strings.Contains(errOut, "removed a leftover socket") {
		t.Errorf("diagnostics = %q, want the removal reported", errOut)
	}
}

func TestRunHelpNamesTheReclaimSwitch(t *testing.T) {
	// 拒绝信息点名了开关, help里就必须有它: 查不到的开关, 用户没法据以决定;
	// help还要说明它接受什么, 因为默认保留文件的原因不在开关名字里.
	var out, errOut bytes.Buffer
	if err := Run([]string{"--help"}, &out, &errOut); err != nil {
		t.Fatalf("Run(--help) error = %v, want nil", err)
	}
	help := out.String()
	if !strings.Contains(help, "--reclaim-remote-socket") {
		t.Errorf("help does not list --reclaim-remote-socket:\n%s", help)
	}
	if !strings.Contains(help, "namespace") {
		t.Errorf("help does not say that the evidence covers one network namespace, which is what the switch accepts:\n%s", help)
	}
}

func TestRunSSHRefusesAHostItCannotCheck(t *testing.T) {
	// 探针没有报告, 路径上有什么无从得知; 此时仍开session会顶掉活着的agent socket.
	// 所以在这里停下, 并给出显式接受这个风险的办法.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHSaying(t, "", "exit 0")

	err, _ := runSSHAgainstStandIn(t, port)

	if err == nil {
		t.Fatal("Run(ssh) error = nil, want a refusal when the remote host could not be checked")
	}
	if !strings.Contains(err.Error(), "--skip-remote-check") {
		t.Errorf("error %v should name --skip-remote-check as the way to start anyway", err)
	}
	if want := []string{"probe"}; !slices.Equal(fake.invocations(t), want) {
		t.Errorf("ssh invocations = %q, want %q: the session must not open", fake.invocations(t), want)
	}
}

func TestRunSSHStartsWithTheFlagWhenTheHostCannotBeChecked(t *testing.T) {
	// `--skip-remote-check`是主机查不了时的显式通道: session照开, 并明确说出没做检查.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh is a shell script")
	}
	port, _, _ := startAdoptedRelay(t)
	fake := newStandInSSHSaying(t, "", "exit 0")

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
}
