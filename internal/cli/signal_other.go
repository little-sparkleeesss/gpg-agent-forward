//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
)

// 把SIGINT, SIGTERM, SIGHUP转发给cmd: kill或Ctrl-C也能到达ssh, 中继清理得以执行.
// 返回的stop幂等: 会话结束后立即停转发, 免得远端清理阶段信号被吞; defer调用作为兜底.
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
	var once sync.Once
	return func() {
		once.Do(func() {
			signal.Stop(ch)
			close(done)
		})
	}
}
