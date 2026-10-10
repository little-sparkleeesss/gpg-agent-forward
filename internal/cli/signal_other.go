//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// 把SIGINT, SIGTERM转发给cmd: kill或Ctrl-C也能到达ssh, 中继清理得以执行.
func forwardSignalsImpl(cmd *exec.Cmd) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-ch:
				if cmd.Process != nil {
					_ = cmd.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}
