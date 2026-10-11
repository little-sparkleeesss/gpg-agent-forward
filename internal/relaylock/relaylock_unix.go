//go:build !windows

package relaylock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// 环境在进程内不变, 结果(含失败)解析一次即够, 不必每次调用重探.
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

// `$XDG_RUNTIME_DIR`天生私有, 是这类运行时状态的正当住处, 但只在真属于本用户时才用:
// 继承自他人(或管理员)的值会把锁交给它的所有者; 退路是cache目录下0700的每用户目录.
func resolveLockDir() (string, error) {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		if err := ownPrivateDir(dir); err == nil {
			return dir, nil
		}
		// 设了却不可用: 换cache目录继续, 不为一个用不上的环境变量让每次锁都失败.
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("relaylock: no per-user directory for the identity lock: %w", err)
	}
	dir := filepath.Join(base, "gpg-agent-forward")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("relaylock: create identity lock directory %s: %w", dir, err)
	}
	// `MkdirAll`不动已有目录的模式, umask又掩掉新建目录的0700: 两条路都要再强制设一遍.
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("relaylock: secure identity lock directory %s: %w", dir, err)
	}
	return dir, nil
}

// 要求`dir`是本用户所有的目录, 别人读写不了: 只有这样, 里面的锁文件才只证明本用户的relay.
func ownPrivateDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d, not %d", dir, sys.Uid, os.Getuid())
	}
	if mode := st.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%s has mode %o, want at most 0700", dir, mode)
	}
	return nil
}

// 成功后调用方须保持文件打开(=持锁), 释放走`unlockFile`.
// 只有`lockTaken`会带回文件: 别人持有或根本拿不到都返回nil, 什么都没锁上.
func lockExclusive(path string) (*os.File, lockState) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, lockUnavailable
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, lockOtherHolder
		}
		return nil, lockUnavailable
	}
	return f, lockTaken
}

func unlockFile(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	f.Close()
}
