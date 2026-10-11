//go:build windows

package cli

import "os"

// Windows上的no-op转发器: Go程序收不到POSIX信号, 控制台事件也不会这样传给子进程.
type windowsSignalForwarder struct{}

func forwardSignalsImpl() signalForwarder { return windowsSignalForwarder{} }

func (windowsSignalForwarder) attach(*os.Process) {}

func (windowsSignalForwarder) stop() {}
