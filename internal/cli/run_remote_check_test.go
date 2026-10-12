package cli

import (
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
