package nonce

import (
	"errors"
	"testing"
)

func TestParseWindowsSocketFile(t *testing.T) {
	// `gpg-agent`写出的原始字节: ASCII十进制端口, 单个LF, 16字节原始nonce.
	// 详见libassuan`assuan-socket.c`的`_assuan_sock_bind()`.
	body := append([]byte("41667\n"), []byte("0123456789abcdef")...)

	got, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if got.Port != 41667 {
		t.Errorf("Port = %d, want 41667", got.Port)
	}
	if string(got.Nonce[:]) != "0123456789abcdef" {
		t.Errorf("Nonce = %q, want %q", got.Nonce, "0123456789abcdef")
	}
}

func TestParseRejectsTruncatedNonce(t *testing.T) {
	// nonce不足16字节必须拒收: 否则只发半截握手, agent随后断连.
	body := append([]byte("41667\n"), []byte("0123456789abcde")...)

	if _, err := Parse(body); err == nil {
		t.Fatal("Parse() error = nil, want error for a short nonce")
	}
}

func TestParseRejectsOverlongPort(t *testing.T) {
	// 超长数字串必须拒绝而非累加: 回绕值(如下例2^64+1变1)可能落进合法端口范围.
	port := "18446744073709551617"
	body := append([]byte(port+"\n"), make([]byte, 16)...)
	_, err := Parse(body)
	if err == nil {
		t.Fatalf("Parse(%q) error = nil, want rejection of an over-long port", port)
	}
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("Parse(%q) error = %v, want it to wrap ErrMalformed", port, err)
	}
}

func TestParseAcceptsAFiveDigitPort(t *testing.T) {
	// 上限不得误伤合法的5位端口.
	body := append([]byte("65535\n"), make([]byte, 16)...)
	got, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if got.Port != 65535 {
		t.Errorf("Port = %d, want 65535", got.Port)
	}
}

func TestParseReportsErrMalformed(t *testing.T) {
	// 解析失败必须包装成一个可辨识的错误, 让调用方区分文件不可用和agent不可达.
	tests := []struct {
		name string
		body []byte
	}{
		{"non-digit port", append([]byte("notaport\n"), make([]byte, 16)...)},
		{"no terminator", []byte("41667")},
		{"empty", nil},
		{"port zero", append([]byte("0\n"), make([]byte, 16)...)},
		{"port too large", append([]byte("65536\n"), make([]byte, 16)...)},
		{"truncated nonce", append([]byte("41667\n"), []byte("short")...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.body)
			if err == nil {
				t.Fatal("Parse() error = nil, want error")
			}
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("Parse() error = %v, want it to wrap ErrMalformed", err)
			}
		})
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{"non-digit port", append([]byte("notaport\n"), make([]byte, 16)...)},
		{"no terminator", []byte("41667")},
		{"empty", nil},
		{"port zero", append([]byte("0\n"), make([]byte, 16)...)},
		{"port too large", append([]byte("65536\n"), make([]byte, 16)...)},
		{"negative-looking port", append([]byte("-1\n"), make([]byte, 16)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.body); err == nil {
				t.Fatalf("Parse(%q) error = nil, want error", tt.body)
			}
		})
	}
}
