package winpeer

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestDecodePortSwapsNetworkOrder(t *testing.T) {
	// Windows把端口放在DWORD低16位且是网络字节序, 取回数值要交换字节.
	tests := []struct {
		raw  uint32
		want int
	}{
		{0x0000F571, 29173},
		{0x0000901F, 8080},
		{0x0000E8FD, 65000},
		{0x00001600, 22},
		{0x00005000, 80},
	}
	for _, tt := range tests {
		if got := DecodePort(tt.raw); got != tt.want {
			t.Errorf("DecodePort(%#x) = %d, want %d", tt.raw, got, tt.want)
		}
	}
}

func TestFindPIDMatchesExactQuadruple(t *testing.T) {
	// 从我们这侧看对端socket: 对端local port是ssh连出的源端口, remote port是我们的监听端口.
	rows := []Conn4{
		{Local: netip.MustParseAddr("127.0.0.1"), LocalPort: 1111,
			Remote: netip.MustParseAddr("127.0.0.1"), RemotePort: 2222, PID: 100},
		{Local: netip.MustParseAddr("127.0.0.1"), LocalPort: 3333,
			Remote: netip.MustParseAddr("127.0.0.1"), RemotePort: 29173, PID: 4242},
	}

	got, ok := FindPID(rows,
		netip.MustParseAddr("127.0.0.1"), 3333,
		netip.MustParseAddr("127.0.0.1"), 29173)
	if !ok {
		t.Fatal("FindPID() ok = false, want true")
	}
	if got != 4242 {
		t.Errorf("FindPID() PID = %d, want 4242", got)
	}
}

func TestFindPIDDoesNotMatchOnPartialOverlap(t *testing.T) {
	// 部分匹配不算命中: 否则会把连接归因到无关进程.
	rows := []Conn4{
		{Local: netip.MustParseAddr("127.0.0.1"), LocalPort: 3333,
			Remote: netip.MustParseAddr("127.0.0.1"), RemotePort: 9999, PID: 100},
		{Local: netip.MustParseAddr("127.0.0.1"), LocalPort: 8888,
			Remote: netip.MustParseAddr("127.0.0.1"), RemotePort: 29173, PID: 200},
		{Local: netip.MustParseAddr("10.0.0.7"), LocalPort: 3333,
			Remote: netip.MustParseAddr("127.0.0.1"), RemotePort: 29173, PID: 300},
	}

	if pid, ok := FindPID(rows,
		netip.MustParseAddr("127.0.0.1"), 3333,
		netip.MustParseAddr("127.0.0.1"), 29173); ok {
		t.Errorf("FindPID() = (%d, true), want no match", pid)
	}
}

func TestFindPIDReturnsFalseWhenAbsent(t *testing.T) {
	if _, ok := FindPID(nil,
		netip.MustParseAddr("127.0.0.1"), 1,
		netip.MustParseAddr("127.0.0.1"), 2); ok {
		t.Error("FindPID() ok = true on an empty table, want false")
	}
}

func TestParseTCPTableDecodesRows(t *testing.T) {
	// 手工拼`MIB_TCPTABLE_OWNER_PID`缓冲, 把unsafe偏移算术钉在文档的Win32布局上:
	// DWORD行数, 然后每行`dwState`, `dwLocalAddr`, `dwLocalPort`,
	// `dwRemoteAddr`, `dwRemotePort`, `dwOwningPid`各4字节.
	buf := []byte{
		2, 0, 0, 0,
		// 第0行: 127.0.0.1:49152 -> 127.0.0.1:29173, pid 4242
		0, 0, 0, 0,
		127, 0, 0, 1,
		0xC0, 0x00, 0, 0,
		127, 0, 0, 1,
		0x71, 0xF5, 0, 0,
		0x92, 0x10, 0, 0,
		// 第1行: 10.0.0.7:1234 -> 10.0.0.9:5678, pid 99
		0, 0, 0, 0,
		10, 0, 0, 7,
		0x04, 0xD2, 0, 0,
		10, 0, 0, 9,
		0x16, 0x2E, 0, 0,
		99, 0, 0, 0,
	}

	rows, err := parseTCPTable(buf)
	if err != nil {
		t.Fatalf("parseTCPTable() error = %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("parseTCPTable() returned %d rows, want 2", len(rows))
	}

	want := []Conn4{
		{Local: netip.MustParseAddr("127.0.0.1"), LocalPort: 49152,
			Remote: netip.MustParseAddr("127.0.0.1"), RemotePort: 29173, PID: 4242},
		{Local: netip.MustParseAddr("10.0.0.7"), LocalPort: 1234,
			Remote: netip.MustParseAddr("10.0.0.9"), RemotePort: 5678, PID: 99},
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
}

func TestParseTCP6Table(t *testing.T) {
	// `MIB_TCP6ROW_OWNER_PID`行布局: 16字节本地地址, 本地scope, 本地端口,
	// 16字节远端地址, 远端scope, 远端端口, 状态, pid.
	buf := make([]byte, table6HeaderSize+row6Size)
	buf[0] = 1

	row := buf[table6HeaderSize:]
	copy(row[0:16], netip.MustParseAddr("::1").AsSlice())
	row[20], row[21] = 0xC0, 0x00
	copy(row[24:40], netip.MustParseAddr("::1").AsSlice())
	row[44], row[45] = 0x71, 0xF5
	row[52], row[53] = 0x92, 0x10

	rows, err := parseTCP6Table(buf)
	if err != nil {
		t.Fatalf("parseTCP6Table() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("parseTCP6Table() returned %d rows, want 1", len(rows))
	}
	want := Conn4{
		Local: netip.MustParseAddr("::1"), LocalPort: 49152,
		Remote: netip.MustParseAddr("::1"), RemotePort: 29173, PID: 4242,
	}
	if rows[0] != want {
		t.Errorf("row = %+v, want %+v", rows[0], want)
	}
}

func TestParseTCP6TableRejectsTruncatedBuffer(t *testing.T) {
	buf := []byte{3, 0, 0, 0} // 声称3行却不给数据.
	if _, err := parseTCP6Table(buf); err == nil {
		t.Error("parseTCP6Table() error = nil, want error for a truncated table")
	}
	if _, err := parseTCP6Table([]byte{1, 0}); err == nil {
		t.Error("parseTCP6Table() error = nil, want error for a short header")
	}
}

func TestFindPIDMatchesAnIPv6Quadruple(t *testing.T) {
	// 监听::1的中继看到IPv6对端, 查找不支持的话, `checkLoopback`对[::1]的放行就成了陷阱.
	rows := []Conn4{
		{Local: netip.MustParseAddr("::1"), LocalPort: 49152,
			Remote: netip.MustParseAddr("::1"), RemotePort: 29173, PID: 4242},
	}
	pid, ok := FindPID(rows, netip.MustParseAddr("::1"), 49152, netip.MustParseAddr("::1"), 29173)
	if !ok || pid != 4242 {
		t.Errorf("FindPID() = (%d, %v), want (4242, true)", pid, ok)
	}
}

func TestReadTableRetriesWhenTheTableGrows(t *testing.T) {
	// 探测大小与读取是两次调用, 繁忙机器可能把表撑大.
	// 再次`ERROR_INSUFFICIENT_BUFFER`意为按新尺寸重试: 当成致命错误会丢掉合法的ssh连接.
	calls := 0
	fetch := func(buf []byte, size *uint32) error {
		calls++
		if buf == nil {
			*size = 4 + rowSize
			return errInsufficientBuffer
		}
		if calls == 2 {
			*size = 4 + 2*rowSize
			return errInsufficientBuffer
		}
		return nil
	}

	buf := make([]byte, 4+2*rowSize)
	buf[0] = 2
	parse := func(b []byte) ([]Conn4, error) {
		if len(b) < 4+2*rowSize {
			return nil, fmt.Errorf("got a %d-byte buffer, want room for two rows", len(b))
		}
		return []Conn4{{PID: 1}, {PID: 2}}, nil
	}

	rows, err := readTable(fetch, parse)
	if err != nil {
		t.Fatalf("readTable() error = %v, want a retry to succeed", err)
	}
	if len(rows) != 2 {
		t.Errorf("readTable() returned %d rows, want 2", len(rows))
	}
}

func TestReadTableGivesUpOnAPermanentlyGrowingTable(t *testing.T) {
	// 重试循环必须有上限.
	calls := 0
	fetch := func(buf []byte, size *uint32) error {
		calls++
		*size = uint32(4 + calls*rowSize)
		return errInsufficientBuffer
	}
	parse := func([]byte) ([]Conn4, error) { return nil, nil }

	if _, err := readTable(fetch, parse); err == nil {
		t.Error("readTable() error = nil, want it to give up on a table that keeps growing")
	}
	if calls != maxTableAttempts+1 { // 1次尺寸探测加`maxTableAttempts`次读取.
		t.Errorf("readTable() made %d calls, want %d", calls, maxTableAttempts+1)
	}
}

func TestReadTableReportsAFatalStatus(t *testing.T) {
	fetch := func(buf []byte, size *uint32) error {
		return errors.New("access denied")
	}
	if _, err := readTable(fetch, func([]byte) ([]Conn4, error) { return nil, nil }); err == nil {
		t.Error("readTable() error = nil, want a fatal status surfaced")
	}
}

func TestReadTableAcceptsAnEmptyTable(t *testing.T) {
	fetch := func(buf []byte, size *uint32) error {
		*size = 0
		return nil
	}
	rows, err := readTable(fetch, func([]byte) ([]Conn4, error) {
		t.Error("parse was called for an empty table")
		return nil, nil
	})
	if err != nil || rows != nil {
		t.Errorf("readTable() = (%v, %v), want (nil, nil)", rows, err)
	}
}

func TestParseTCPTableRejectsTruncatedBuffer(t *testing.T) {
	// 声称3行却不给数据: 解析不得越界读.
	buf := []byte{3, 0, 0, 0}
	if _, err := parseTCPTable(buf); err == nil {
		t.Error("parseTCPTable() error = nil, want error for a truncated table")
	}

	// 短到连行数字段都放不下的缓冲也要拒.
	if _, err := parseTCPTable([]byte{1, 0}); err == nil {
		t.Error("parseTCPTable() error = nil, want error for a short header")
	}
}

func TestParseTCPTableRejectsACountThatOverflowsTheLengthCheck(t *testing.T) {
	// 178956971 * 24在`uint32`里回绕成8: 乘法做的长度检查会放过12字节缓冲, 循环随即越界读.
	overflowing := uint32(0x0AAAAAAB)
	buf := []byte{byte(overflowing), byte(overflowing >> 8), byte(overflowing >> 16), byte(overflowing >> 24)}
	buf = append(buf, make([]byte, 8)...)

	if _, err := parseTCPTable(buf); err == nil {
		t.Error("parseTCPTable() error = nil, want error for a count that overflows the length check")
	}
}

func TestParseTCPTableAcceptsEmptyTable(t *testing.T) {
	rows, err := parseTCPTable([]byte{0, 0, 0, 0})
	if err != nil {
		t.Fatalf("parseTCPTable() error = %v, want nil", err)
	}
	if len(rows) != 0 {
		t.Errorf("parseTCPTable() returned %d rows, want 0", len(rows))
	}
}

func TestVerifyAllowsTheRelaysOwnExecutable(t *testing.T) {
	// wrapper连自己的中继做存活探测, 这探测来自gpg-agent-forward自己的二进制, 不能拒.
	self := Self{
		SID:       "S-1-5-21-1-2-3-1001",
		ImagePath: `D:\Code\temp\gpg-agent-forward-windows-amd64.exe`,
	}

	for _, img := range []string{
		`D:\Code\temp\gpg-agent-forward-windows-amd64.exe`,
		`d:\code\temp\gpg-agent-forward-windows-amd64.exe`, // 大小写不同
		`D:/Code/temp/gpg-agent-forward-windows-amd64.exe`, // 分隔符不同
	} {
		peer := Peer{ImagePath: img, SID: self.SID}
		if err := Verify(peer, self); err != nil {
			t.Errorf("Verify(image=%q) error = %v, want nil for the relay's own binary", img, err)
		}
	}
}

func TestVerifyRejectsASameNamedBinaryElsewhere(t *testing.T) {
	// 同用户进程可把二进制命名成`gpg-agent-forward-windows-amd64.exe`放到别处, 自身探针豁免必须比全路径;
	// 只比文件名就会绕过白名单直接放行.
	self := Self{
		SID:       "S-1-5-21-1-2-3-1001",
		ImagePath: `D:\Code\temp\gpg-agent-forward-windows-amd64.exe`,
	}
	peer := Peer{ImagePath: `C:\elsewhere\GPG-TUNNEL-WINDOWS-AMD64.EXE`, SID: self.SID}
	if err := Verify(peer, self); !errors.Is(err, ErrPeerNotAllowed) {
		t.Errorf("Verify() error = %v, want ErrPeerNotAllowed for a same-named binary elsewhere", err)
	}
}

func TestPolicyCheckAcceptsAWorkingPolicy(t *testing.T) {
	self := Self{
		SID:       "S-1-5-21-1-2-3-1001",
		ImagePath: `D:\Code\temp\gpg-agent-forward-windows-amd64.exe`,
	}
	if err := PolicyCheck(self); err != nil {
		t.Errorf("PolicyCheck() error = %v, want nil for a working policy", err)
	}
}

func TestPolicyCheckRejectsAnUnknownOwnSID(t *testing.T) {
	if err := PolicyCheck(Self{ImagePath: `D:\x.exe`}); err == nil {
		t.Error("PolicyCheck() error = nil, want an error when our own SID is unknown")
	}
}

func TestPolicyCheckCatchesAnAllowlistThatRejectsEverything(t *testing.T) {
	// 策略检查必须包含正例: 全拒的策略(如`SID`比较写反)会显得健康, 而真实ssh会话全失败.
	original := allowedImages
	allowedImages = map[string]bool{}
	t.Cleanup(func() { allowedImages = original })

	self := Self{SID: "S-1-5-21-1-2-3-1001", ImagePath: `D:\Code\temp\gpg-agent-forward-windows-amd64.exe`}
	if err := PolicyCheck(self); err == nil {
		t.Error("PolicyCheck() error = nil, want it to notice that an ssh client is never accepted")
	}
}

func TestVerifyStillRejectsOtherImagesWhereSelfHasNoImage(t *testing.T) {
	// 自身镜像未知就无可豁免, 白名单仍必须生效.
	self := Self{SID: "S-1-5-21-1-2-3-1001"}
	peer := Peer{ImagePath: `D:\Code\temp\gpg-agent-forward-windows-amd64.exe`, SID: self.SID}
	if err := Verify(peer, self); !errors.Is(err, ErrPeerNotAllowed) {
		t.Errorf("Verify() error = %v, want ErrPeerNotAllowed", err)
	}
}

func TestVerifyRejectsOtherUserEvenWhenImageMatchesOurs(t *testing.T) {
	// 自身探针豁免不能成为另一个用户跑同款可执行文件的入口.
	self := Self{
		SID:       "S-1-5-21-1-2-3-1001",
		ImagePath: `D:\Code\temp\gpg-agent-forward-windows-amd64.exe`,
	}
	peer := Peer{
		ImagePath: `C:\Users\someone\gpg-agent-forward-windows-amd64.exe`,
		SID:       "S-1-5-21-1-2-3-9999",
	}
	if err := Verify(peer, self); !errors.Is(err, ErrPeerNotAllowed) {
		t.Errorf("Verify() error = %v, want ErrPeerNotAllowed for another user", err)
	}
}

func TestVerifyDistinguishesPolicyRejectionFromLookupFailure(t *testing.T) {
	// 调用方要区分"检查跑了但拒了"和"检查没跑成": 前者说明机制正常, 后者说明机制坏了.
	self := Self{SID: "S-1-5-21-1-2-3-1001"}
	img := `C:\Windows\System32\OpenSSH\ssh.exe`

	policy := []struct {
		name string
		peer Peer
	}{
		{"different user", Peer{ImagePath: img, SID: "S-1-5-21-1-2-3-1002"}},
		{"disallowed image", Peer{ImagePath: `C:\evil.exe`, SID: self.SID}},
	}
	for _, tt := range policy {
		t.Run("policy/"+tt.name, func(t *testing.T) {
			err := Verify(tt.peer, self)
			if err == nil {
				t.Fatal("Verify() error = nil, want rejection")
			}
			if !errors.Is(err, ErrPeerNotAllowed) {
				t.Errorf("Verify() error = %v, want it to wrap ErrPeerNotAllowed", err)
			}
		})
	}

	lookup := []struct {
		name string
		peer Peer
		self Self
	}{
		{"our own SID unknown", Peer{ImagePath: img, SID: self.SID}, Self{}},
		{"peer SID unknown", Peer{ImagePath: img}, self},
		{"peer image unknown", Peer{SID: self.SID}, self},
	}
	for _, tt := range lookup {
		t.Run("lookup/"+tt.name, func(t *testing.T) {
			err := Verify(tt.peer, tt.self)
			if err == nil {
				t.Fatal("Verify() error = nil, want rejection")
			}
			if errors.Is(err, ErrPeerNotAllowed) {
				t.Errorf("Verify() error = %v, want a lookup failure, not a policy rejection", err)
			}
		})
	}
}

func TestTableStatusError(t *testing.T) {
	// `GetExtendedTcpTable`的结果走返回值而非`GetLastError`, Win32调用返回的Go error恒非nil,
	// 携带的`GetLastError`对本API无意义, 不能拿它当状态.
	tests := []struct {
		name       string
		status     uint32
		wantNil    bool
		wantBuffer bool
	}{
		{name: "success", status: 0, wantNil: true},
		{name: "buffer too small", status: 122, wantBuffer: true},
		{name: "access denied", status: 5},
		{name: "invalid parameter", status: 87},
		{name: "not enough memory", status: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tableStatusError(tt.status)
			switch {
			case tt.wantNil:
				if err != nil {
					t.Errorf("tableStatusError(%d) = %v, want nil", tt.status, err)
				}
			case tt.wantBuffer:
				if !errors.Is(err, errInsufficientBuffer) {
					t.Errorf("tableStatusError(%d) = %v, want errInsufficientBuffer", tt.status, err)
				}
			default:
				if err == nil {
					t.Fatalf("tableStatusError(%d) = nil, want an error", tt.status)
				}
				if errors.Is(err, errInsufficientBuffer) {
					t.Errorf("tableStatusError(%d) = errInsufficientBuffer, want a distinct failure", tt.status)
				}
				if !strings.Contains(err.Error(), fmt.Sprint(tt.status)) {
					t.Errorf("tableStatusError(%d) = %v, want the status in the message", tt.status, err)
				}
			}
		})
	}
}

func TestVerifyAcceptsSameUserSSH(t *testing.T) {
	peer := Peer{
		ImagePath: `C:\Windows\System32\OpenSSH\ssh.exe`,
		SID:       "S-1-5-21-1-2-3-1001",
	}
	self := Self{SID: "S-1-5-21-1-2-3-1001"}

	if err := Verify(peer, self); err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

func TestVerifyAcceptsSSHFromAnyDirectoryAndCase(t *testing.T) {
	self := Self{SID: "S-1-5-21-1-2-3-1001"}
	for _, img := range []string{
		`C:\Windows\System32\OpenSSH\ssh.exe`,
		`D:\tools\ssh.EXE`,
		`ssh.exe`,
		`C:\Users\me\scoop\apps\openssh\current\ssh.exe`,
	} {
		peer := Peer{ImagePath: img, SID: self.SID}
		if err := Verify(peer, self); err != nil {
			t.Errorf("Verify(image=%q) error = %v, want nil", img, err)
		}
	}
}

func TestVerifyRejectsWrongImageName(t *testing.T) {
	// 非ssh客户端可能是本地攻击者的进程, 所以镜像名也是检查的一部分.
	self := Self{SID: "S-1-5-21-1-2-3-1001"}
	for _, img := range []string{
		`C:\Windows\System32\cmd.exe`,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`C:\tmp\notssh.exe`,
		`C:\tmp\ssh.exe.bak`,
		`C:\tmp\ssh.exe.evil`,
		`C:\tmp\xssh.exe`,
		`C:\tmp\my-ssh.exe`,
		``,
	} {
		peer := Peer{ImagePath: img, SID: self.SID}
		if err := Verify(peer, self); err == nil {
			t.Errorf("Verify(image=%q) error = nil, want rejection", img)
		}
	}
}

func TestVerifyRejectsDifferentUser(t *testing.T) {
	// 这是loopback TCP挡不住的情形: 别的本地用户能连上我们的中继,
	// 但不能借用我们的agent.
	peer := Peer{
		ImagePath: `C:\Windows\System32\OpenSSH\ssh.exe`,
		SID:       "S-1-5-21-1-2-3-1002",
	}
	self := Self{SID: "S-1-5-21-1-2-3-1001"}

	if err := Verify(peer, self); err == nil {
		t.Error("Verify() error = nil, want rejection of a different user")
	}
}

func TestVerifyRejectsEmptySIDs(t *testing.T) {
	self := Self{SID: "S-1-5-21-1-2-3-1001"}
	img := `C:\Windows\System32\OpenSSH\ssh.exe`

	if err := Verify(Peer{ImagePath: img, SID: ""}, self); err == nil {
		t.Error("Verify() error = nil, want rejection when the peer SID is unknown")
	}
	if err := Verify(Peer{ImagePath: img, SID: self.SID}, Self{}); err == nil {
		t.Error("Verify() error = nil, want rejection when our own SID is unknown")
	}
}
