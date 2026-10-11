package cli

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// `DefaultRelayPort`是relay监听的loopback端口: 数字取好记的, 被占用时用`--port`改.
const DefaultRelayPort = 29173

// 用参数向量而不是shell字符串, 保住用户自己的ssh参数, 无引号与注入之虞.
// 用户没自己配置`ExitOnForwardFailure`时补上: 缺了它失败是静默的, ssh只警告并保持会话,
// 签名会悄悄改用远端主机上的agent, 用户却拿到有效签名, 想不到YubiKey从未参与.
func BuildSSHArgs(userArgs []string, remoteSocket string, port int) []string {
	spec := fmt.Sprintf("%s:127.0.0.1:%d", remoteSocket, port)
	args := make([]string, 0, len(userArgs)+4)
	args = append(args, "-R", spec)
	if !userSetForwardFailure(userArgs) {
		args = append(args, "-o", "ExitOnForwardFailure=yes")
	}
	args = append(args, userArgs...)
	return args
}

// 用户已显式设置它时沿用它, 不追加; ssh接受的任一写法都算.
func userSetForwardFailure(userArgs []string) bool {
	for i := 0; i < len(userArgs); i++ {
		a := userArgs[i]
		if strings.Contains(a, "ExitOnForwardFailure") {
			return true
		}
		if a == "-o" && i+1 < len(userArgs) && strings.Contains(userArgs[i+1], "ExitOnForwardFailure") {
			return true
		}
	}
	return false
}

// ssh子命令认这些选项, 其余选项形状的参数都归ssh. `--idle`的值虽被忽略也必须在这里
// 消费掉: ssh没有这个选项, 透传过去会拒绝启动会话, 详见`runSSH`.
var sshOwnFlags = map[string]bool{
	"-socket-file":    true,
	"--socket-file":   true,
	"-port":           true,
	"--port":          true,
	"-idle":           true,
	"--idle":          true,
	"-remote-socket":  true,
	"--remote-socket": true,
}

// ssh自带`-N`, `-p`, `-i`, `-o`, 交给通用flag解析器会被拒; 这里只消费自己认识的选项,
// 其余原样透传并保持顺序; `--`结束gpg-agent-forward的解析.
func SplitSSHArgs(args []string) (own, through []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			through = append(through, args[i+1:]...)
			return own, through
		}
		name := a
		hasValue := false
		if eq := indexByte(a, '='); eq >= 0 {
			name, hasValue = a[:eq], true
		}
		if sshOwnFlags[name] {
			own = append(own, a)
			if !hasValue && i+1 < len(args) {
				i++
				own = append(own, args[i])
			}
			continue
		}
		through = append(through, a)
	}
	return own, through
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// Windows上gpg-agent extra socket文件的路径; libassuan把模拟socket放在`%LOCALAPPDATA%\gnupg`,
// 与通常放密钥的GnuPG homedir(`%APPDATA%\gnupg`)不是同一个目录.
func DefaultSocketFile(localAppData, homedir string) string {
	if localAppData == "" {
		return filepath.Join(homedir, "S.gpg-agent.extra")
	}
	return filepath.Join(localAppData, "gnupg", "S.gpg-agent.extra")
}

func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of range 1-65535", port)
	}
	return nil
}

// 拒绝ssh会读错的远端socket路径: 冒号会被解析成地址分隔符; 超长则越过两端都强制的
// `sockaddr_un`上限(含终止符108字节, 可用107).
func ValidateRemoteSocket(p string) error {
	if p == "" {
		return fmt.Errorf("remote socket path is empty")
	}
	for _, r := range p {
		if r == ':' {
			return fmt.Errorf("remote socket path %q must not contain ':'", p)
		}
	}
	if len(p) >= 108 {
		return fmt.Errorf("remote socket path is %d bytes, limit is 107", len(p))
	}
	return nil
}

func ParsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if err := ValidatePort(p); err != nil {
		return 0, err
	}
	return p, nil
}
