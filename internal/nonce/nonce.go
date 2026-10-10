// Package `nonce`解析Windows上`gpg-agent`的socket文件: Windows无AF_UNIX,
// libassuan用loopback TCP监听加16字节nonce模拟; 文件内容为ASCII十进制端口,
// 单个LF, 16字节原始nonce, 详见libassuan`assuan-socket.c`的`_assuan_sock_bind()`.
package nonce

import (
	"errors"
	"fmt"
)

// libassuan要求nonce恰好16字节, 详见`assuan-socket.c`的`_assuan_sock_check_nonce`.
const NonceLen = 16

// `Parse`的每个错误都包装它, 供调用方区分文件不可用和agent不可达.
var ErrMalformed = errors.New("nonce: malformed socket file")

// Windows `gpg-agent`socket文件的解码结果: 客户端须把nonce作为连接首字节发出.
type Info struct {
	Port  int
	Nonce [NonceLen]byte
}

func Parse(data []byte) (*Info, error) {
	// 端口最多5位: 限位防止累加器回绕, 回绕值可能落入合法范围而被接受.
	const maxPortDigits = 5
	port := 0
	i := 0
	for ; i < len(data) && data[i] != '\n'; i++ {
		if data[i] < '0' || data[i] > '9' {
			return nil, fmt.Errorf("%w: invalid port byte %q at offset %d", ErrMalformed, data[i], i)
		}
		if i >= maxPortDigits {
			return nil, fmt.Errorf("%w: port has more than %d digits", ErrMalformed, maxPortDigits)
		}
		port = port*10 + int(data[i]-'0')
	}
	if i == len(data) {
		return nil, fmt.Errorf("%w: missing port terminator", ErrMalformed)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: port %d out of range", ErrMalformed, port)
	}
	rest := data[i+1:]
	if len(rest) < NonceLen {
		return nil, fmt.Errorf("%w: nonce is %d bytes, want %d", ErrMalformed, len(rest), NonceLen)
	}
	var info Info
	info.Port = port
	copy(info.Nonce[:], rest[:NonceLen])
	return &info, nil
}
