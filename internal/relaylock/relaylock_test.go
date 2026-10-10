package relaylock

import (
	"strings"
	"testing"
)

func TestLockFileIsPerAddress(t *testing.T) {
	// 不同端口的relay不得共用锁: 否则一个会被当成另一个, wrapper会信任错的监听者.
	a := LockFile("127.0.0.1:29173")
	b := LockFile("127.0.0.1:29174")
	if a == b {
		t.Errorf("LockFile() returned the same path for two addresses: %q", a)
	}
}

func TestLockFileIsSafeAsAFilename(t *testing.T) {
	// 地址含冒号, `sanitize`必须清掉, 路径才能在每个平台都是普通文件名.
	got := LockFile("127.0.0.1:29173")
	if strings.ContainsAny(got[len(got)-len("127.0.0.1_29173.lock"):], ":") {
		t.Errorf("LockFile() = %q, want no colon in the file name", got)
	}
	if !strings.HasSuffix(got, "127.0.0.1_29173.lock") {
		t.Errorf("LockFile() = %q, want it to end with the sanitized address", got)
	}
}

func TestHeldIsFalseWhenNobodyHoldsIt(t *testing.T) {
	if !CanLock() {
		t.Skip("locking is unavailable here")
	}
	if Held("127.0.0.1:59311") {
		t.Error("Held() = true, want false when no one has taken the lock")
	}
}

func TestTryLockIsExclusive(t *testing.T) {
	if !CanLock() {
		t.Skip("locking is unavailable here")
	}
	const addr = "127.0.0.1:59312"

	release, ok := TryLock(addr)
	if !ok {
		t.Fatal("TryLock() ok = false, want to take a free lock")
	}
	if !Held(addr) {
		t.Error("Held() = false, want true while the lock is held")
	}
	// 第二次尝试必须失败: 锁能证明持有者就是已在运行的那个relay, 靠的正是这一点.
	if _, ok := TryLock(addr); ok {
		t.Error("TryLock() ok = true for an address already locked, want false")
	}

	release()
	if Held(addr) {
		t.Error("Held() = true after release, want false")
	}
	release2, ok := TryLock(addr)
	if !ok {
		t.Fatal("TryLock() ok = false after release, want to re-take the lock")
	}
	release2()
}
