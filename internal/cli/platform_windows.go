//go:build windows

package cli

import (
	"io"
	"log"
	"os"

	"gpg-agent-forward/internal/winpeer"
)

func init() {
	// Windows上relay的入口是loopback TCP端口, 端口本身不说明谁在连接.
	// 要求对端是本用户的ssh客户端, 防止机器上其他用户经它访问agent.
	allowPeerHook = winpeer.Check
}

// libassuan在Windows上把agent的模拟socket放在`%LOCALAPPDATA%\gnupg\S.gpg-agent.extra`.
func defaultSocketFile() string {
	return DefaultSocketFile(os.Getenv("LOCALAPPDATA"), os.Getenv("USERPROFILE"))
}

func newLogger(w io.Writer) *log.Logger {
	return log.New(w, "gpg-agent-forward: ", 0)
}

// 用本进程自身身份跑一遍relay的对端策略, 让doctor能验证策略真的生效.
func peerPolicyCheck() error { return winpeer.PolicyCheckSelf() }

// 对端策略只在Windows上生效 (连接经loopback端口到达), doctor的对端检查也只在那里有意义.
func peerCheckSupported() bool { return true }
