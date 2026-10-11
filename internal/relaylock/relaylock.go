// Package `relaylock`让调用方证明监听relay端口的就是relay本身, 而非恰好占着端口的其他进程.
// 单靠TCP不行: wrapper信任端口上的应答者; relay按监听地址认领锁文件, 调用方以排他方式抢同一把锁.
// 拿不到锁即按没有relay处理(fail-closed): 锁打不开或加不上时报false, 不能当成"有".
// 锁是"监听者就是本relay"的唯一证据, 加不上的锁不能顶替这份证据.
// 把加不上的锁当成"有", 端口上的外来进程就能冒充relay.
// 元数据(详见`Info`)记在锁旁的单独文件, 只在锁被别人持有时读, 用来判断找到的relay能否复用.
package relaylock

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 元数据文件格式的版本号: 未知`schema`一律拒收, 不冒险误读.
const infoSchema = "1"

// 拿不到锁与锁被别人持有必须分开: 把拿不到的锁当成持有, 端口上的外来进程就能冒充relay.
type lockState int

const (
	lockTaken lockState = iota
	lockOtherHolder
	// 锁打不开或加不上: 说不出谁持有, 各调用方一律当无relay.
	lockUnavailable
)

// relay为它的锁记录的元数据: 调用方发现活relay后据此判断能否复用, 不必走端口上的协议.
type Info struct {
	// relay转发到的`gpg-agent` socket文件: 想要别的agent的调用方不得复用它.
	SocketFile string
	// 0表示不因闲置退出.
	IdleTimeout time.Duration
}

// 锁文件放在本用户私有目录里(详见`resolveLockDir`): 共享位置(如临时目录)会让任何本地用户
// 抢先创建并锁住它, 再被当成relay.
// 文件内容无意义, 从不读写: Windows的强制字节范围锁让持锁时读失败; relay元数据在锁旁另一个文件里.
func lockFile(listenAddr string) (string, error) {
	dir, err := lockDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "gpg-agent-forward-"+sanitize(listenAddr)+".lock"), nil
}

// 元数据文件与锁文件同目录, 写入才能靠同目录内`rename`做到原子.
func infoFile(lf string) string {
	return strings.TrimSuffix(lf, ".lock") + ".info"
}

// 把地址压成文件名安全的字符, 保证两个地址的锁文件不会同名.
func sanitize(addr string) string {
	b := []byte(addr)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '-', c == '_':
		default:
			b[i] = '_'
		}
	}
	return string(b)
}

// 返回的释放函数要保持到不再需要被认作relay为止.
// 锁或元数据写不下也报false: 记不下身份的relay与抢占者无法区分, 调用方都会拒用, 所以不启动.
func TryLock(listenAddr string, info Info) (release func(), ok bool) {
	lf, err := lockFile(listenAddr)
	if err != nil {
		return nil, false
	}
	f, state := lockExclusive(lf)
	if state != lockTaken {
		return nil, false
	}
	ip := infoFile(lf)
	// 先删上一位relay留下的元数据: 锁已持有而自己的还没写上的窗口里,
	// 读者必须看到"无元数据", 绝不能看到已死relay的.
	if err := removeInfo(ip); err != nil {
		unlockFile(f)
		return nil, false
	}
	if err := writeInfo(ip, info); err != nil {
		unlockFile(f)
		return nil, false
	}
	return func() { unlockFile(f) }, true
}

// fail-closed: 锁打不开或拿不到时报false而非true, 加不上的锁不能顶替"监听者是relay"的证据.
func Held(listenAddr string) bool {
	lf, err := lockFile(listenAddr)
	if err != nil {
		return false
	}
	f, state := lockExclusive(lf)
	if state == lockTaken {
		unlockFile(f)
		return false
	}
	return state == lockOtherHolder
}

// 只在有relay持锁时返回它的元数据; 一切返回false的情形(地址空闲, 被没认领锁的进程占着,
// 元数据缺失或读不了)都不许把监听者当成自己的relay.
func ReadInfo(listenAddr string) (Info, bool) {
	lf, err := lockFile(listenAddr)
	if err != nil {
		return Info{}, false
	}
	f, state := lockExclusive(lf)
	switch state {
	case lockTaken:
		// 锁是自己拿的, 说明没有别人持有它.
		unlockFile(f)
		return Info{}, false
	case lockUnavailable:
		return Info{}, false
	}
	// 别人持锁; 其元数据只在持锁期间可信, 死掉的relay留下的文件不会被当成活的.
	info, ok := readInfo(infoFile(lf))
	unlockFile(f)
	return info, ok
}

func encodeInfo(info Info) []byte {
	return []byte(fmt.Sprintf("schema=%s\nsocket-file=%s\nidle-ns=%d\n",
		infoSchema, info.SocketFile, info.IdleTimeout.Nanoseconds()))
}

// 写满临时文件再`rename`覆盖旧内容: 读者要么见旧记录要么见新记录, 绝无半截.
// 临时文件与目标同目录, `rename`才不跨文件系统, 才能原子.
func writeInfo(path string, info Info) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// `CreateTemp`给的mode会被umask掩掉, 故在已打开的文件上重设; 元数据不对外公开.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := f.Write(encodeInfo(info)); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	// `rename`前先`Sync`: 否则崩溃可能留下一个名字完整, 内容为空的文件.
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func removeInfo(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func readInfo(path string) (Info, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Info{}, false
	}
	info, err := decodeInfo(data)
	if err != nil {
		return Info{}, false
	}
	return info, true
}

func decodeInfo(data []byte) (Info, error) {
	var (
		info Info
		seen bool
	)
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "schema":
			if value != infoSchema {
				return Info{}, fmt.Errorf("relaylock: unsupported schema %q", value)
			}
			seen = true
		case "socket-file":
			// 取第一个`=`之后的全部作为值: 路径本身可能含`=`, 这样才能原样往返.
			info.SocketFile = value
		case "idle-ns":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return Info{}, fmt.Errorf("relaylock: bad idle-ns %q", value)
			}
			info.IdleTimeout = time.Duration(n)
		}
	}
	if !seen {
		return Info{}, fmt.Errorf("relaylock: no schema line")
	}
	return info, nil
}
