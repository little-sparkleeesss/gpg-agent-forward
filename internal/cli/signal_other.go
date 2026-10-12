//go:build !windows

package cli

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// 把SIGINT, SIGTERM, SIGHUP转发给会话的ssh: 杀wrapper或Ctrl-C要能结束会话, 不等ssh自己结束.
// handler先于ssh启动安装, 详见`forwardSignalsImpl`; 窗口期信号先挂起, 交接时补发.
type posixSignalForwarder struct {
	// 接收runtime投递的信号: 必须有缓冲, 这是`signal.Notify`对不能阻塞的通道的要求.
	ch chan os.Signal
	// 会话进程就绪后经此交接: 有缓冲, 使调用方的attach不必等转发goroutine.
	handover chan *os.Process
	done     chan struct{}
	once     sync.Once
}

func forwardSignalsImpl() signalForwarder {
	f := &posixSignalForwarder{
		ch:       make(chan os.Signal, 1),
		handover: make(chan *os.Process, 1),
		done:     make(chan struct{}),
	}
	// 先于goroutine也先于ssh启动: 信号从此投递给本通道而非走默认动作, 暂无处可转也先留住.
	signal.Notify(f.ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go f.run()
	return f
}

// 见到信号就转给会话进程; 进程还没到时先留住第一个.
func (f *posixSignalForwarder) run() {
	var (
		proc *os.Process
		// ssh就绪前到达的信号暂存于此; 丢了它, 已被要求停止的会话还会继续跑.
		pending os.Signal
	)
	for {
		select {
		case s := <-f.ch:
			if proc == nil {
				// 一个信号就够结束会话, 通道也只收得住一个: 留首个, 其余不必管.
				if pending == nil {
					pending = s
				}
				continue
			}
			_ = proc.Signal(s)
		case p := <-f.handover:
			proc = p
			if pending != nil {
				_ = proc.Signal(pending)
				pending = nil
			}
		case <-f.done:
			return
		}
	}
}

func (f *posixSignalForwarder) attach(p *os.Process) { f.handover <- p }

func (f *posixSignalForwarder) stop() {
	f.once.Do(func() {
		signal.Stop(f.ch)
		close(f.done)
	})
}
