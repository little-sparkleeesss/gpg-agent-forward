// gpg-agent-forward(Windows侧)让远端Linux主机借用Windows gpg-agent的OpenPGP密钥签名, 不导出密钥,
// 也不用ssh签名; relay经`ssh -R`在远端发布为Unix socket. 刻意只转发agent的extra socket:
// GnuPG为远端转发场景专门文档化了它, 只允许签名和解密, 拒绝导入, 导出, 删除和口令查询.
package main

import (
	"fmt"
	"os"

	"gpg-agent-forward/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gpg-agent-forward: %v\n", err)
		os.Exit(1)
	}
}
