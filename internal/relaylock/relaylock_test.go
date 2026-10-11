package relaylock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 恢复环境变量的同时把锁目录缓存一并丢掉: 不丢的话, 下一个测试会用到按这一个的环境缓存的值.
func saveEnv(keys ...string) func() {
	old := make(map[string]string, len(keys))
	for _, k := range keys {
		old[k] = os.Getenv(k)
	}
	return func() {
		for _, k := range keys {
			if v := old[k]; v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
		resetLockDirCache()
	}
}

// 让本进程的锁目录可解析并返回它; 同时丢缓存, 以调用方设定的环境为准.
func privateDir(t *testing.T) string {
	t.Helper()
	if err := os.Setenv("XDG_RUNTIME_DIR", ""); err != nil {
		t.Fatal(err)
	}
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "gpg-agent-forward")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	resetLockDirCache()
	return dir
}

func TestLockFileIsPerAddress(t *testing.T) {
	defer saveEnv("XDG_RUNTIME_DIR")()
	privateDir(t)
	// 不同端口的relay不得共用锁: 否则一个会被当成另一个, wrapper会信任错的监听者.
	a, err := lockFile("127.0.0.1:29173")
	if err != nil {
		t.Fatal(err)
	}
	b, err := lockFile("127.0.0.1:29174")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Errorf("lockFile() returned the same path for two addresses: %q", a)
	}
	if infoFile(a) == infoFile(b) {
		t.Errorf("infoFile() returned the same path for two addresses: %q", infoFile(a))
	}
}

func TestLockFileIsSafeAsAFilename(t *testing.T) {
	defer saveEnv("XDG_RUNTIME_DIR")()
	privateDir(t)
	// 地址含冒号, `sanitize`必须清掉, 路径才能在每个平台都是普通文件名.
	got, err := lockFile("127.0.0.1:29173")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(got[len(got)-len("127.0.0.1_29173.lock"):], ":") {
		t.Errorf("lockFile() = %q, want no colon in the file name", got)
	}
	if !strings.HasSuffix(got, "127.0.0.1_29173.lock") {
		t.Errorf("lockFile() = %q, want it to end with the sanitized address", got)
	}
}

func TestLockFileIsNotInTheSharedTempDir(t *testing.T) {
	defer saveEnv("XDG_RUNTIME_DIR")()
	privateDir(t)
	// 人人可写的目录里, 任何本地用户都能先建并锁住它, 再被当成relay.
	lockPath, err := lockFile("127.0.0.1:29173")
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Clean(os.TempDir())
	if dir := filepath.Dir(lockPath); dir == tmp {
		t.Errorf("lockFile() dir = %q, want a per-user directory, not the shared temp dir", dir)
	}
	if dir := filepath.Dir(infoFile(lockPath)); dir == tmp {
		t.Errorf("infoFile() dir = %q, want a per-user directory, not the shared temp dir", dir)
	}
}

func TestLockFailsWhenNoPrivateDirectoryIsAvailable(t *testing.T) {
	// 没有home或XDG变量时, 唯一剩的共享临时目录里的锁证明不了任何事,
	// 所以每个入口都必须fail-closed, 不许退到那里.
	defer saveEnv(
		"HOME", "USERPROFILE", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME", "LOCALAPPDATA", "APPDATA",
	)()
	for _, k := range []string{
		"HOME", "USERPROFILE", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME", "LOCALAPPDATA", "APPDATA",
	} {
		os.Unsetenv(k)
	}
	resetLockDirCache()

	if _, err := lockFile("127.0.0.1:59310"); err == nil {
		t.Fatalf("lockFile() = %q, want an error when no per-user directory exists",
			filepath.Dir(os.TempDir()))
	}
	if _, ok := TryLock("127.0.0.1:59310", Info{}); ok {
		t.Error("TryLock() ok = true without a private lock directory, want false")
	}
	if Held("127.0.0.1:59310") {
		t.Error("Held() = true without a private lock directory, want false")
	}
	if _, ok := ReadInfo("127.0.0.1:59310"); ok {
		t.Error("ReadInfo() ok = true without a private lock directory, want false")
	}
	// 哪里都不许建文件, 共享临时目录更不行.
	if _, err := os.Stat(filepath.Join(os.TempDir(), "gpg-agent-forward-127.0.0.1_59310.lock")); err == nil {
		t.Error("a lock file was left in the shared temp dir")
	}
}

func TestLockPathThatCannotBeOpenedIsNotHeld(t *testing.T) {
	// 锁路径存在却没法当锁文件用: 这不是relay的证据, 不能报成有relay.
	defer saveEnv("XDG_RUNTIME_DIR")()
	privateDir(t)
	lockPath, err := lockFile("127.0.0.1:59315")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(lockPath)

	if Held("127.0.0.1:59315") {
		t.Error("Held() = true when the lock file cannot be opened, want false")
	}
	if _, ok := ReadInfo("127.0.0.1:59315"); ok {
		t.Error("ReadInfo() ok = true when the lock file cannot be opened, want false")
	}
	if _, ok := TryLock("127.0.0.1:59315", Info{}); ok {
		t.Error("TryLock() ok = true when the lock file cannot be opened, want false")
	}
}

func TestHeldIsFalseWhenNobodyHoldsIt(t *testing.T) {
	defer saveEnv("XDG_RUNTIME_DIR")()
	privateDir(t)
	if Held("127.0.0.1:59311") {
		t.Error("Held() = true, want false when no one has taken the lock")
	}
}

func TestTryLockIsExclusive(t *testing.T) {
	defer saveEnv("XDG_RUNTIME_DIR")()
	privateDir(t)
	const addr = "127.0.0.1:59312"

	release, ok := TryLock(addr, Info{})
	if !ok {
		t.Fatal("TryLock() ok = false, want to take a free lock")
	}
	if !Held(addr) {
		t.Error("Held() = false, want true while the lock is held")
	}
	// 第二次尝试必须失败: 锁能证明持有者就是已在运行的那个relay, 靠的正是这一点.
	if _, ok := TryLock(addr, Info{}); ok {
		t.Error("TryLock() ok = true for an address already locked, want false")
	}

	release()
	if Held(addr) {
		t.Error("Held() = true after release, want false")
	}
	release2, ok := TryLock(addr, Info{})
	if !ok {
		t.Fatal("TryLock() ok = false after release, want to re-take the lock")
	}
	release2()
}

func TestInfoRoundTrips(t *testing.T) {
	defer saveEnv("XDG_RUNTIME_DIR")()
	privateDir(t)
	const addr = "127.0.0.1:59313"
	want := Info{
		SocketFile:  `C:\Users\me\AppData\Local\gnupg\S.gpg-agent.extra`,
		IdleTimeout: 15 * time.Minute,
	}
	release, ok := TryLock(addr, want)
	if !ok {
		t.Fatal("TryLock() ok = false, want to take a free lock")
	}
	defer release()

	got, ok := ReadInfo(addr)
	if !ok {
		t.Fatal("ReadInfo() ok = false, want the metadata of the held lock")
	}
	if got != want {
		t.Errorf("ReadInfo() = %+v, want %+v", got, want)
	}
}

func TestMetadataFileCarriesTheInfo(t *testing.T) {
	defer saveEnv("XDG_RUNTIME_DIR")()
	privateDir(t)
	const addr = "127.0.0.1:59319"
	want := Info{SocketFile: "/tmp/sock", IdleTimeout: time.Minute}
	lockPath, err := lockFile(addr)
	if err != nil {
		t.Fatal(err)
	}
	// 先记下文件原样: 早先的运行可能留下过数据, 不归这次调用管.
	// 被测性质是抢锁不写文件, 所以与改动前比, 不与空比.
	before, _ := os.ReadFile(lockPath)
	// 下面的反证会往锁文件写负载; 用例收尾删掉, 重复运行才从同一状态起跑.
	t.Cleanup(func() { os.Remove(lockPath) })

	release, ok := TryLock(addr, want)
	if !ok {
		t.Fatal("TryLock() ok = false, want to take a free lock")
	}
	defer release()

	// 锁文件只是锁, 什么都不写进去, 内容再变也伤不到读者.
	// Windows锁住首字节: 持锁时别的句柄读该字节必失败.
	data, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(before) {
		t.Errorf("lock file changed from %q to %q; taking the lock must not write to it", before, data)
	}
	infoPath := infoFile(lockPath)
	if infoPath == lockPath {
		t.Fatal("info file and lock file are the same path")
	}
	raw, err := os.ReadFile(infoPath)
	if err != nil {
		t.Fatalf("read info file %s: %v", infoPath, err)
	}
	decoded, err := decodeInfo(raw)
	if err != nil {
		t.Fatalf("decodeInfo(%q): %v", raw, err)
	}
	if decoded != want {
		t.Errorf("info file holds %+v, want %+v", decoded, want)
	}
	// 反证"元数据绝不从锁文件读": 往锁文件塞负载, `ReadInfo`仍须只答info文件的内容.
	if err := os.WriteFile(lockPath, encodeInfo(Info{SocketFile: "from-the-lock-file"}), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadInfo(addr)
	if !ok {
		t.Fatal("ReadInfo() ok = false, want the metadata of the held lock")
	}
	if got != want {
		t.Errorf("ReadInfo() = %+v, want the info file's %+v (the lock file must not be read)", got, want)
	}
}

func TestMetadataIsReplacedWholesale(t *testing.T) {
	// 新元数据必须整体替换旧的而非叠加: 读到上一位relay的socket文件, 签名请求就会转给错的agent.
	defer saveEnv("XDG_RUNTIME_DIR")()
	privateDir(t)
	const addr = "127.0.0.1:59316"

	release, ok := TryLock(addr, Info{SocketFile: "old-socket", IdleTimeout: time.Minute})
	if !ok {
		t.Fatal("TryLock() ok = false, want to take a free lock")
	}
	got, ok := ReadInfo(addr)
	if !ok || got.SocketFile != "old-socket" {
		t.Fatalf("ReadInfo() = %+v, %v; want the first relay's metadata", got, ok)
	}
	release()

	want := Info{SocketFile: "new-socket", IdleTimeout: 30 * time.Second}
	release2, ok := TryLock(addr, want)
	if !ok {
		t.Fatal("TryLock() ok = false, want to take the lock after release")
	}
	defer release2()

	got, ok = ReadInfo(addr)
	if !ok {
		t.Fatal("ReadInfo() ok = false, want the metadata of the new relay")
	}
	if got != want {
		t.Errorf("ReadInfo() = %+v, want %+v (no trace of the previous relay)", got, want)
	}
}

func TestReadInfoIsFalseWhenTheLockIsFree(t *testing.T) {
	defer saveEnv("XDG_RUNTIME_DIR")()
	privateDir(t)
	// 无锁即无可描述的relay, 哪怕退出的relay留下了旧文件.
	if _, ok := ReadInfo("127.0.0.1:59314"); ok {
		t.Error("ReadInfo() ok = true for an unheld lock, want false")
	}
}

func TestReadInfoIgnoresMetadataWithoutTheLock(t *testing.T) {
	// 死relay的残留, 或别人种下的元数据文件, 都说明不了什么: 只有锁被持有它才有意义.
	defer saveEnv("XDG_RUNTIME_DIR")()
	privateDir(t)
	const addr = "127.0.0.1:59317"

	lockPath, err := lockFile(addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeInfo(infoFile(lockPath), Info{SocketFile: "planted"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadInfo(addr); ok {
		t.Error("ReadInfo() ok = true for metadata without a held lock, want false")
	}
}

func TestStaleMetadataIsOnlyTrustedWhileTheLockIsHeld(t *testing.T) {
	// relay退出只放锁, 元数据文件留在原地; 此时它什么也不描述, 不能报成活relay供复用,
	// 否则会把签名请求转给当下占着端口的任何东西.
	defer saveEnv("XDG_RUNTIME_DIR")()
	privateDir(t)
	const addr = "127.0.0.1:59318"

	release, ok := TryLock(addr, Info{SocketFile: "gone"})
	if !ok {
		t.Fatal("TryLock() ok = false, want to take a free lock")
	}
	release()

	if _, ok := ReadInfo(addr); ok {
		t.Error("ReadInfo() ok = true for metadata left by an exited relay, want false")
	}
	// 文件仍在: 读者的结论来自锁, 不来自文件在不在.
	lockPath, err := lockFile(addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(infoFile(lockPath)); err != nil {
		t.Fatalf("stat %s, want the stale file to be left behind: %v", infoFile(lockPath), err)
	}
	// 又被持有时, 它就是这个持有者的元数据, 不管谁写的.
	release2, ok := TryLock(addr, Info{SocketFile: "revived"})
	if !ok {
		t.Fatal("TryLock() ok = false after release, want to re-take the lock")
	}
	defer release2()
	got, ok := ReadInfo(addr)
	if !ok || got.SocketFile != "revived" {
		t.Errorf("ReadInfo() = %+v, %v; want the current holder's metadata", got, ok)
	}
}

func TestDecodeInfoKeepsEverythingAfterTheFirstEquals(t *testing.T) {
	// Windows socket路径可含`=`和空格; 分隔符只认第一个`=`, 路径必须原样保留.
	want := Info{SocketFile: `C:\Users\a b\gnupg\S.gpg-agent=x`, IdleTimeout: 15 * time.Minute}
	got, err := decodeInfo(encodeInfo(want))
	if err != nil {
		t.Fatalf("decodeInfo(encodeInfo(%+v)): %v", want, err)
	}
	if got != want {
		t.Errorf("decodeInfo(encodeInfo(%+v)) = %+v", want, got)
	}
}

func TestDecodeInfoRejectsUnknownSchema(t *testing.T) {
	if _, err := decodeInfo([]byte("schema=99\nsocket-file=/tmp/s\nidle-ns=0\n")); err == nil {
		t.Error("decodeInfo() accepted an unknown schema")
	}
	if _, err := decodeInfo(nil); err == nil {
		t.Error("decodeInfo() accepted empty data")
	}
}
