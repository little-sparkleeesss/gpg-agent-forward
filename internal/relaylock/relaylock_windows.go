//go:build windows

package relaylock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
)

// 环境在进程内不变, 结果(含失败)解析一次即够: 没有user profile的调用方不必每次重探.
// 但测试要能改环境, 所以不是裸`sync.Once`: 改环境的测试必须调`resetLockDirCache`.
var lockDirCache struct {
	once sync.Once
	dir  string
	err  error
}

// 丢弃锁目录缓存; 只有改环境的测试可以调它.
func resetLockDirCache() {
	lockDirCache = struct {
		once sync.Once
		dir  string
		err  error
	}{}
}

// fail-closed: 拿不到本用户私有目录就报错, 不退回共享位置; 那里的锁说明不了身份.
func lockDir() (string, error) {
	lockDirCache.once.Do(func() {
		lockDirCache.dir, lockDirCache.err = resolveLockDir()
	})
	return lockDirCache.dir, lockDirCache.err
}

// `%LocalAppData%`本就私有, 锁放这里而不放`%TEMP%`: 后者可被策略改到共享位置.
func resolveLockDir() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("relaylock: no per-user directory for the identity lock: %w", err)
		}
		base = cache
	}
	dir := filepath.Join(base, "gpg-agent-forward")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("relaylock: create identity lock directory %s: %w", dir, err)
	}
	return dir, nil
}

// 成功后调用方须保持文件打开; 锁的可见性靠这个打开的锁定句柄, 释放走`unlockFile`.
// 只有`lockTaken`会带回文件: 别人持有或根本拿不到都返回nil, 什么都没锁上.
func lockExclusive(path string) (*os.File, lockState) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, lockUnavailable
	}
	ol := new(windows.Overlapped)
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if err != nil {
		f.Close()
		// 只有争用算"有人持有"; 其他错误(文件系统不支持, 权限问题)说明这把锁加不上,
		// 什么也证明不了.
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, lockOtherHolder
		}
		return nil, lockUnavailable
	}
	return f, lockTaken
}

func unlockFile(f *os.File) {
	ol := new(windows.Overlapped)
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
	f.Close()
}
