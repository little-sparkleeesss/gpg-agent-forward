//go:build !windows

package relaylock

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLockDirPrefersAPrivateXDGRuntimeDir(t *testing.T) {
	defer saveEnv("XDG_RUNTIME_DIR", "HOME", "XDG_CACHE_HOME")()
	privateDir(t)

	// 本用户所有且0700的runtime目录, 真实的runtime目录都是这个样子.
	xdg := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(xdg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("XDG_RUNTIME_DIR", xdg); err != nil {
		t.Fatal(err)
	}
	resetLockDirCache()

	lockPath, err := lockFile("127.0.0.1:59400")
	if err != nil {
		t.Fatalf("lockFile(): %v", err)
	}
	if want := filepath.Join(xdg, "gpg-agent-forward-127.0.0.1_59400.lock"); lockPath != want {
		t.Errorf("lockFile() = %q, want %q", lockPath, want)
	}
}

func TestLockDirRejectsASharedXDGRuntimeDir(t *testing.T) {
	defer saveEnv("XDG_RUNTIME_DIR", "HOME", "XDG_CACHE_HOME")()
	cache := privateDir(t)

	// 别人够得到的目录不能照单全收: 里面的锁文件也会被他们够到并抢先锁住.
	// `t.TempDir()`的父目录带sticky位, 所以直接拿0777目录调`ownPrivateDir`测这条性质.
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := ownPrivateDir(shared); err == nil {
		t.Fatalf("ownPrivateDir(%q) = nil, want a world-writable directory rejected", shared)
	}
	if err := os.Setenv("XDG_RUNTIME_DIR", shared); err != nil {
		t.Fatal(err)
	}
	resetLockDirCache()

	lockPath, err := lockFile("127.0.0.1:59401")
	if err != nil {
		t.Fatalf("lockFile(): %v", err)
	}
	if got := filepath.Dir(lockPath); got != cache {
		t.Errorf("lockFile() dir = %q, want the per-user cache dir %q", got, cache)
	}
	// 共享的XDG值不致命: cache目录接手, 锁仍须在那里拿到.
	release, ok := TryLock("127.0.0.1:59401", Info{})
	if !ok {
		t.Fatal("TryLock() ok = false, want the per-user cache dir to take over")
	}
	release()
}

func TestLockDirRejectsAMissingXDGRuntimeDir(t *testing.T) {
	defer saveEnv("XDG_RUNTIME_DIR", "HOME", "XDG_CACHE_HOME")()
	cache := privateDir(t)

	// 指向已消失目录的陈旧变量不能让每次锁都失败, cache目录还好好的.
	if err := os.Setenv("XDG_RUNTIME_DIR", filepath.Join(t.TempDir(), "gone")); err != nil {
		t.Fatal(err)
	}
	resetLockDirCache()

	lockPath, err := lockFile("127.0.0.1:59402")
	if err != nil {
		t.Fatalf("lockFile(): %v", err)
	}
	if got, want := filepath.Dir(lockPath), cache; got != want {
		t.Errorf("lockFile() dir = %q, want the cache dir %q", got, want)
	}
}

func TestLockDirIsCreatedPrivate(t *testing.T) {
	// cache退路自己建目录, 它必须对别人不可达: 里面的锁文件用于证明relay身份,
	// 能抢先建并锁住的人就会被当成relay.
	defer saveEnv("XDG_RUNTIME_DIR", "HOME", "XDG_CACHE_HOME")()
	tmpHome := t.TempDir()
	if err := os.Setenv("HOME", tmpHome); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("XDG_CACHE_HOME", filepath.Join(tmpHome, "cache")); err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("XDG_RUNTIME_DIR")
	resetLockDirCache()

	// 目录是解析锁路径这一步创建的.
	if _, err := lockFile("127.0.0.1:59403"); err != nil {
		t.Fatalf("lockFile(): %v", err)
	}
	dir, err := lockDir()
	if err != nil {
		t.Fatalf("lockDir(): %v", err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o700 {
		t.Errorf("lock dir mode = %o, want 0700", got)
	}
}
