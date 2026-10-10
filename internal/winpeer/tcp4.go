package winpeer

import (
	"errors"
	"fmt"
	"net/netip"
	"unsafe"
)

const (
	statusSuccess            = 0
	statusInsufficientBuffer = 122 // ERROR_INSUFFICIENT_BUFFER
)

// 表示缓冲区不够: 再调一次, 用刚写回的长度.
var errInsufficientBuffer = errors.New("winpeer: insufficient buffer")

// 结果只在`GetExtendedTcpTable`的返回值里, 它不保证设置last-error.
// Go的syscall包装返回的error恒非nil, 携带的是无关的`GetLastError`, 不能用来判结果.
func tableStatusError(status uint32) error {
	switch status {
	case statusSuccess:
		return nil
	case statusInsufficientBuffer:
		return errInsufficientBuffer
	default:
		return fmt.Errorf("winpeer: GetExtendedTcpTable failed with status %d", status)
	}
}

// `MIB_TCPTABLE_OWNER_PID`无填充, 端口与地址DWORD为网络序.
const (
	tableHeaderSize = 4  // DWORD行数
	rowSize         = 24 // MIB_TCPROW_OWNER_PID
)

// Windows IPv4 TCP表的一行, 归一化自Win32结构体, 便于脱离Windows测匹配.
type Conn4 struct {
	Local      netip.Addr
	LocalPort  int
	Remote     netip.Addr
	RemotePort int
	PID        uint32
}

// `MIB_TCPROW_OWNER_PID`把端口存成网络序DWORD: 只有低16位有意义, 需要交换字节.
func DecodePort(raw uint32) int {
	return int(uint16(raw>>8) | uint16(raw&0xFF)<<8)
}

// 不用build tag: 偏移量算术可在任何平台测.
func parseTCPTable(buf []byte) ([]Conn4, error) {
	if len(buf) < tableHeaderSize {
		return nil, fmt.Errorf("winpeer: TCP table too short (%d bytes)", len(buf))
	}
	raw := *(*uint32)(unsafe.Pointer(&buf[0]))
	// 行数源自缓冲区, 不可信: 用除法比较, 乘法溢出会让检查被绕过, 循环越界.
	avail := uint64(len(buf) - tableHeaderSize)
	if uint64(raw) > avail/uint64(rowSize) {
		return nil, fmt.Errorf("winpeer: TCP table truncated: %d rows in %d bytes",
			raw, len(buf)-tableHeaderSize)
	}
	count := int(raw)
	rows := make([]Conn4, 0, count)
	for i := 0; i < count; i++ {
		off := tableHeaderSize + i*rowSize
		row := buf[off : off+rowSize]
		rows = append(rows, Conn4{
			Local:      netip.AddrFrom4([4]byte{row[4], row[5], row[6], row[7]}),
			LocalPort:  DecodePort(*(*uint32)(unsafe.Pointer(&row[8]))),
			Remote:     netip.AddrFrom4([4]byte{row[12], row[13], row[14], row[15]}),
			RemotePort: DecodePort(*(*uint32)(unsafe.Pointer(&row[16]))),
			PID:        *(*uint32)(unsafe.Pointer(&row[20])),
		})
	}
	return rows, nil
}

// 对端socket是本端镜像: 调用方传它在表里的本地地址与端口, 我们的监听端口是它的远端端口.
func FindPID(rows []Conn4, laddr netip.Addr, lport int, raddr netip.Addr, rport int) (uint32, bool) {
	for _, row := range rows {
		if row.Local == laddr && row.LocalPort == lport &&
			row.Remote == raddr && row.RemotePort == rport {
			return row.PID, true
		}
	}
	return 0, false
}
