//go:build windows

package winpeer

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// `Check`是relay在Windows上的`AllowPeer`钩子.
// 对端pid取自系统TCP表而非客户端提供的值, 客户端无法冒充ssh.
func Check(c net.Conn) error {
	peer, err := lookupPeer(c)
	if err != nil {
		return err
	}
	self, err := selfInfo()
	if err != nil {
		return err
	}
	return Verify(peer, self)
}

func lookupPeer(c net.Conn) (Peer, error) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return Peer{}, fmt.Errorf("winpeer: connection is not TCP")
	}
	remote, ok := tcp.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return Peer{}, fmt.Errorf("winpeer: unexpected remote address type %T", tcp.RemoteAddr())
	}
	local, ok := tcp.LocalAddr().(*net.TCPAddr)
	if !ok {
		return Peer{}, fmt.Errorf("winpeer: unexpected local address type %T", tcp.LocalAddr())
	}

	pid, err := pidForConnection(local, remote)
	if err != nil {
		return Peer{}, err
	}
	path, sid, err := processImageAndSID(pid)
	if err != nil {
		return Peer{}, err
	}
	return Peer{ImagePath: path, SID: sid}, nil
}

// 找对端连接的属主进程: 对端socket是本端镜像, 我们的远端端点是它的本地端点.
func pidForConnection(local, remote *net.TCPAddr) (uint32, error) {
	localAddr, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return 0, fmt.Errorf("winpeer: unusable local address %v", local.IP)
	}
	remoteAddr, ok := netip.AddrFromSlice(remote.IP)
	if !ok {
		return 0, fmt.Errorf("winpeer: unusable remote address %v", remote.IP)
	}
	// 归一化IPv4-mapped形式, 让IPv4连接与它的表行对得上.
	localAddr = localAddr.Unmap()
	remoteAddr = remoteAddr.Unmap()

	// 绑到::1的relay也会接受IPv6连接, 两族都要查.
	// 只查IPv4会丢掉所有到[::1]的连接, 而checkLoopback有意允许它.
	var rows []Conn4
	var err error
	if localAddr.Is4() && remoteAddr.Is4() {
		rows, err = ipv4Table()
	} else {
		rows, err = ipv6Table()
	}
	if err != nil {
		return 0, err
	}
	pid, ok := FindPID(rows, remoteAddr, remote.Port, localAddr, local.Port)
	if !ok {
		return 0, fmt.Errorf("winpeer: no TCP table entry for %s -> %s", remote, local)
	}
	return pid, nil
}

const (
	afInet                = 2
	afInet6               = 23
	tcpTableOwnerPidAll   = 5
	processQueryLimitedIn = 0x1000
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

// 包装Win32调用: `class`参数对owner-pid表无用, 但在ABI里.
// 返回的错来自调用的状态值而非`GetLastError`, 详见`tableStatusError`.
func getExtendedTcpTable(table *byte, size *uint32, order bool, family, class, reserved uint32) error {
	var orderInt uint32
	if order {
		orderInt = 1
	}
	status, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(table)),
		uintptr(unsafe.Pointer(size)),
		uintptr(orderInt),
		uintptr(family),
		uintptr(class),
		uintptr(reserved),
	)
	return tableStatusError(uint32(status))
}

func ipv4Table() ([]Conn4, error) {
	return readTable(func(buf []byte, size *uint32) error {
		return getExtendedTcpTable(bytePtr(buf), size, false, afInet, tcpTableOwnerPidAll, 0)
	}, parseTCPTable)
}

func ipv6Table() ([]Conn4, error) {
	return readTable(func(buf []byte, size *uint32) error {
		return getExtendedTcpTable(bytePtr(buf), size, false, afInet6, tcpTableOwnerPidAll, 0)
	}, parseTCP6Table)
}

// 给Win32调用传缓冲区指针; nil表示探测大小, 是该API约定的问法.
func bytePtr(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}

func processImageAndSID(pid uint32) (string, string, error) {
	h, err := windows.OpenProcess(processQueryLimitedIn, false, pid)
	if err != nil {
		return "", "", fmt.Errorf("winpeer: open peer process %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)

	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return "", "", fmt.Errorf("winpeer: open peer token: %w", err)
	}
	defer token.Close()

	path, err := processImagePath(h)
	if err != nil {
		return "", "", err
	}
	sid, err := tokenUserSID(token)
	if err != nil {
		return "", "", err
	}
	return path, sid, nil
}

func tokenUserSID(token windows.Token) (string, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("winpeer: get token user: %w", err)
	}
	if user.User.Sid == nil {
		return "", fmt.Errorf("winpeer: token has no user SID")
	}
	return user.User.Sid.String(), nil
}

func processImagePath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", fmt.Errorf("winpeer: query process image: %w", err)
	}
	return windows.UTF16ToString(buf[:size]), nil
}

func currentUserSID() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", fmt.Errorf("winpeer: open own token: %w", err)
	}
	defer token.Close()
	return tokenUserSID(token)
}

// 本进程的`SID`与可执行路径: `SID`必需, 路径尽力而为, 只用于识别自身存活探针.
func selfInfo() (Self, error) {
	sid, err := currentUserSID()
	if err != nil {
		return Self{}, err
	}
	exe, err := os.Executable()
	if err != nil {
		// `os.Args[0]`可能是裸名或相对路径, 而对端路径总是完整限定, 故走同一套解析.
		// 否则自身存活探针会被`Verify`拒掉, `EnsureRelay`会报告中继从未起来.
		exe = os.Args[0]
	}
	// 两个来源走同一套解析, 在`sameImagePath`两侧比较时不会有谁落单.
	return Self{SID: sid, ImagePath: resolveImagePath(exe)}, nil
}

// 用本进程身份跑`PolicyCheck`, 供诊断报告本机对端策略是否生效.
func PolicyCheckSelf() error {
	self, err := selfInfo()
	if err != nil {
		return err
	}
	return PolicyCheck(self)
}
