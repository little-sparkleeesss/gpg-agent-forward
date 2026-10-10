package winpeer

import (
	"fmt"
	"net/netip"
	"unsafe"
)

// `MIB_TCP6ROW_OWNER_PID`无填充, 地址后各字段DWORD对齐.
const (
	table6HeaderSize = 4  // DWORD行数
	row6Size         = 56 // MIB_TCP6ROW_OWNER_PID
)

// `MIB_TCP6TABLE_OWNER_PID`解码成与IPv4表相同的形状, 匹配逻辑不关心地址族.
func parseTCP6Table(buf []byte) ([]Conn4, error) {
	if len(buf) < table6HeaderSize {
		return nil, fmt.Errorf("winpeer: IPv6 TCP table too short (%d bytes)", len(buf))
	}
	raw := *(*uint32)(unsafe.Pointer(&buf[0]))
	// 行数不可信: 用除法比较, 防乘法溢出绕过检查.
	avail := uint64(len(buf) - table6HeaderSize)
	if uint64(raw) > avail/uint64(row6Size) {
		return nil, fmt.Errorf("winpeer: IPv6 TCP table truncated: %d rows in %d bytes",
			raw, len(buf)-table6HeaderSize)
	}
	count := int(raw)
	rows := make([]Conn4, 0, count)
	for i := 0; i < count; i++ {
		off := table6HeaderSize + i*row6Size
		row := buf[off : off+row6Size]
		rows = append(rows, Conn4{
			Local:      netip.AddrFrom16([16]byte(row[0:16])).Unmap(),
			LocalPort:  DecodePort(*(*uint32)(unsafe.Pointer(&row[20]))),
			Remote:     netip.AddrFrom16([16]byte(row[24:40])).Unmap(),
			RemotePort: DecodePort(*(*uint32)(unsafe.Pointer(&row[44]))),
			PID:        *(*uint32)(unsafe.Pointer(&row[52])),
		})
	}
	return rows, nil
}
