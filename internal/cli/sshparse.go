package cli

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// sshFlagTakesValue: 会吃掉下一个参数的ssh选项, 不必穷尽.
// 漏掉一条会让该选项的值被当成目标主机.
var sshFlagTakesValue = map[byte]bool{
	'B': true, // 绑定接口
	'b': true, // 绑定地址
	'c': true, // 加密算法
	'D': true, // 动态转发
	'E': true, // 日志文件
	'e': true, // 转义字符
	'F': true, // 配置文件
	'I': true, // pkcs11提供者
	'i': true, // 私钥文件
	'J': true, // 跳板机
	'L': true, // 本地转发
	'l': true, // 登录名
	'm': true, // MAC算法
	'O': true, // 控制命令
	'o': true, // 选项
	'P': true, // 标签
	'p': true, // 端口
	'Q': true, // 查询
	'R': true, // 远程转发
	'S': true, // 控制路径
	'W': true, // netcat主机:端口
	'w': true, // tun设备
}

// sshFlagDroppedForQuery: 不能带进探测连接的选项.
// `-N`和`-f`会让远端命令跑不起来, 控制类选项会改变连接的建立方式, 转发会与中继自己的`-R`撞车.
var sshFlagDroppedForQuery = map[byte]bool{
	'B': true, 'b': true, 'D': true, 'L': true, 'R': true, 'W': true, 'w': true,
	'f': true, 'N': true, 'M': true, 'S': true, 'O': true, 'n': true,
}

// ParseSSHArgs: 拆出目标主机, 以及值得复用给第二条连接的flag子集.
// 不在目标主机处停下解析: ssh会重排参数, 选项可以跟在主机后面 (`ssh host -p 2222`).
func ParseSSHArgs(args []string) (destination string, connFlags []string, err error) {
	found := false
	for i := 0; i < len(args); {
		a := args[i]

		if a == "--" {
			if i+1 >= len(args) {
				return "", nil, errors.New("ssh: no destination given")
			}
			if !found {
				destination, found = args[i+1], true
			}
			return destination, connFlags, nil
		}
		if a == "" || a == "-" || a[0] != '-' {
			if !found {
				destination, found = a, true
				i++
				continue
			}
			return destination, connFlags, nil
		}

		group := a[1:]
		consumedNext := false
		for j := 0; j < len(group); j++ {
			c := group[j]
			keep := !sshFlagDroppedForQuery[c]

			if !sshFlagTakesValue[c] {
				if keep {
					connFlags = append(connFlags, "-"+string(c))
				}
				continue
			}
			if attached := group[j+1:]; attached != "" {
				if keep {
					connFlags = append(connFlags, "-"+string(c)+attached)
				}
			} else {
				consumedNext = true
				if keep && i+1 < len(args) {
					connFlags = append(connFlags, "-"+string(c), args[i+1])
				}
			}
			break
		}
		if consumedNext {
			i += 2
			continue
		}
		i++
	}
	if !found {
		return "", nil, errors.New("ssh: no destination given")
	}
	return destination, connFlags, nil
}

// parseRemoteSocketOutput: 只接受唯一的绝对路径.
// 登录横幅或shell报错会混进`gpgconf --list-dirs agent-socket`的输出,
// 挑错路径会让gpg用上远端自己的agent, 静默地用错误密钥签名.
func parseRemoteSocketOutput(out string) (string, error) {
	var found []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			continue
		}
		if strings.ContainsAny(line, " \t") {
			continue // 此处路径不会含空白字符
		}
		found = append(found, line)
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("remote host did not report an agent socket path")
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("remote host reported %d candidate socket paths: %v", len(found), found)
	}
}

type SSHQueryRunner func(args []string) (string, error)

// 向远端询问agent socket路径,不假定uid或目录布局
func DiscoverRemoteSocket(sshArgs []string, run SSHQueryRunner) (string, error) {
	destination, connFlags, err := ParseSSHArgs(sshArgs)
	if err != nil {
		return "", err
	}
	args := make([]string, 0, len(connFlags)+3)
	args = append(args, connFlags...)
	args = append(args, destination, "gpgconf --list-dirs agent-socket")

	out, err := run(args)
	if err != nil {
		return "", fmt.Errorf("querying the remote host for its agent socket: %w", err)
	}
	return parseRemoteSocketOutput(out)
}

type SSHCommandRunner func(sshArgs []string, remoteCommand string) (string, error)

// 单引号是唯一无法出现在单引号串内的字符,只能闭合,转义,再重开
func shellQuoteSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// 判定标记按整行匹配而非子串搜索:登录banner可能恰好含present这样的词
const (
	socketPresentMarker = "gpg-agent-forward-socket-present"
	socketAbsentMarker  = "gpg-agent-forward-socket-absent"
)

// 该路径是gpg找agent的地方,活socket属于远端自己的gpg-agent:
// 转发时sshd的`StreamLocalBindUnlink`会顶掉它占位,gpg便静默连上别的agent,
// 故拒绝覆盖;路径不存在才是正常情况.
func CheckRemoteSocketFree(sshArgs []string, remoteSocket string, run SSHCommandRunner) error {
	// 路径要到达远端shell,必须转义:含引号时原样插值会提前结束引号并执行其后的内容.
	cmd := fmt.Sprintf("test -e %s && echo %s || echo %s",
		shellQuoteSingle(remoteSocket), socketPresentMarker, socketAbsentMarker)
	out, err := run(sshArgs, cmd)
	if err != nil {
		return fmt.Errorf("checking whether %s already exists on the remote host: %w", remoteSocket, err)
	}
	if socketExists(out) {
		return fmt.Errorf(
			"%s already exists on the remote host, so it is in use by that host's own gpg-agent.\n"+
				"  Forwarding onto it would make gpg talk to the remote agent instead of the Windows one.\n"+
				"  Stop the remote agent first:\n"+
				"      gpgconf --kill gpg-agent\n"+
				"      echo no-autostart >> ~/.gnupg/gpg.conf\n"+
				"  (and remove the leftover socket if it survives: rm -f %s)\n"+
				"  Pass --remote-socket PATH to use a different path instead.",
			remoteSocket, shellQuoteSingle(remoteSocket))
	}
	return nil
}

func socketExists(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == socketPresentMarker {
			return true
		}
	}
	return false
}

func runSSHCommand(sshArgs []string, remoteCommand string) (string, error) {
	destination, connFlags, err := ParseSSHArgs(sshArgs)
	if err != nil {
		return "", err
	}
	args := make([]string, 0, len(connFlags)+3)
	args = append(args, connFlags...)
	args = append(args, destination, remoteCommand)
	return runSSHQuery(args)
}

func runSSHQuery(args []string) (string, error) {
	cmd := exec.Command("ssh", args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return stdout.String(), nil
}
