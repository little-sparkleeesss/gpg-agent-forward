// Package `winpeer`校验已接受的loopback连接的对端进程.
// TCP说不出对端是哪个用户: 其他用户也能连上端口, 借本用户的agent签名.
// 故要求对端是同一用户的ssh客户端; 这只是补偿控制, 真正的信任边界仍是agent的nonce文件.
package winpeer

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// `Verify`认出对端却不允许它使用中继时返回这个错.
// 它与"根本认不出对端"的错误不同: 策略拒绝说明检查在工作, 查不到说明检查坏了.
var ErrPeerNotAllowed = errors.New("winpeer: peer not allowed")

type Peer struct {
	// 对端可执行文件路径, 例如`C:\Windows\System32\OpenSSH\ssh.exe`.
	ImagePath string
	// 对端用户的`SID`字符串.
	SID string
}

type Self struct {
	// 本进程用户的`SID`字符串.
	SID string
	// 本进程自己的可执行文件路径: 用来让自身的存活探针不被白名单拒掉.
	ImagePath string
}

// 允许作为隧道客户端的可执行文件名.
var allowedImages = map[string]bool{
	"ssh.exe": true,
}

func Verify(peer Peer, self Self) error {
	if self.SID == "" {
		return fmt.Errorf("winpeer: own user SID is unknown")
	}
	if peer.SID == "" {
		return fmt.Errorf("winpeer: peer user SID is unknown")
	}
	if !strings.EqualFold(peer.SID, self.SID) {
		return fmt.Errorf("%w: peer runs as a different user (%s)", ErrPeerNotAllowed, peer.SID)
	}
	if peer.ImagePath == "" {
		return fmt.Errorf("winpeer: peer image path is unknown")
	}
	// Windows两种分隔符都认, 归一化才能取准文件名.
	name := imageName(peer.ImagePath)
	if allowedImages[name] {
		return nil
	}
	// 包装器会探测自己的中继, 探针来自同一个可执行文件; 放行它不扩大信任边界, 它就是本进程.
	// 身份取整条路径而非文件名: 同用户进程可以任意命名自己的二进制, 只比文件名就不查白名单放行.
	if self.ImagePath != "" && sameImagePath(peer.ImagePath, self.ImagePath) {
		return nil
	}
	return fmt.Errorf("%w: peer image %q is not an allowed client", ErrPeerNotAllowed, name)
}

// 用合成对端跑白名单, 正反两种判定都验证.
// 活体探针证明不了策略已生效: 本进程的连接按设计被放行, 策略正常或比较反了都返回nil.
func PolicyCheck(self Self) error {
	if self.SID == "" {
		return fmt.Errorf("winpeer: own user SID is unknown")
	}
	if err := Verify(Peer{ImagePath: sshImageForCheck, SID: "S-1-5-21-0-0-0-9999"}, self); !errors.Is(err, ErrPeerNotAllowed) {
		return fmt.Errorf("winpeer: a peer from another user was not rejected (%v)", err)
	}
	if err := Verify(Peer{ImagePath: `C:\Windows\Temp\not-allowed.exe`, SID: self.SID}, self); !errors.Is(err, ErrPeerNotAllowed) {
		return fmt.Errorf("winpeer: a foreign client image was not rejected (%v)", err)
	}
	// 自己的ssh客户端必须被接受: 否则拒绝一切的策略也显得健康, 而真实会话全部失败.
	if err := Verify(Peer{ImagePath: sshImageForCheck, SID: self.SID}, self); err != nil {
		return fmt.Errorf("winpeer: an ssh client of our own user was not accepted (%v)", err)
	}
	return nil
}

// 策略应当放行的ssh客户端路径.
const sshImageForCheck = `C:\Windows\System32\OpenSSH\ssh.exe`

// 比较两条路径是否同一文件: 大小写和分隔符写法只是不同Win32 API的拼写差异, 不改变身份.
func sameImagePath(a, b string) bool {
	return strings.EqualFold(normalizeImagePath(a), normalizeImagePath(b))
}

func normalizeImagePath(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}

func imageName(p string) string {
	return strings.ToLower(path.Base(strings.ReplaceAll(p, `\`, "/")))
}
