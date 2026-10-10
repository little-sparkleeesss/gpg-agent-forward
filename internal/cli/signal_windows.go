//go:build windows

package cli

import "os/exec"

// Windows上的no-op: Go程序收不到POSIX信号, 控制台事件也不会这样传给子进程.
func forwardSignalsImpl(cmd *exec.Cmd) func() {
	return func() {}
}
