// Package `relaylock`让调用方证明监听relay端口的就是relay本身, 而不是恰好占了端口的其他进程.
// TCP只能说明有东西在接受连接; 而wrapper信任端口上的应答者, 抢占端口者就能看到并替换应答.
// relay按监听地址认领一个锁文件, 调用方以排他方式拿同一把锁: 锁由持有进程持有, 无需可伪造的协议.
package relaylock

import (
	"os"
	"path/filepath"
)

func LockFile(listenAddr string) string {
	return filepath.Join(os.TempDir(), "gpg-agent-forward-"+sanitize(listenAddr)+".lock")
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

func Held(listenAddr string) bool {
	return held(LockFile(listenAddr))
}

// 平台拿不了锁时`Held`无意义, 调用方须另想办法判断监听者是不是relay.
func CanLock() bool {
	return canLock()
}

// 返回的释放函数要一直保留到不再需要被认作relay为止.
func TryLock(listenAddr string) (release func(), ok bool) {
	return tryLock(LockFile(listenAddr))
}
