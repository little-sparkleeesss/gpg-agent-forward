//go:build !windows

package relaylock

import (
	"os"
	"syscall"
)

// `flock`按open file description计, 与Windows的`File.Lock`不是同一族锁.
// 各平台只跟自己的锁打交道, 无需互通.
func held(path string) bool {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true // 别人持有
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}

func tryLock(path string) (func(), bool) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, false
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, true
}

// 试加锁再立刻释放, 是判断文件系统支持`flock`的唯一办法.
func canLock() bool {
	f, err := os.CreateTemp("", "gpg-agent-forward-lockprobe-")
	if err != nil {
		return false
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return false
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return true
}
