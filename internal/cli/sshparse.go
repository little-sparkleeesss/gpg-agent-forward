package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
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
	args, err := sshCommandArgs(sshArgs, "gpgconf --list-dirs agent-socket")
	if err != nil {
		return "", err
	}
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

// 探针的判定标记按整行匹配, 不按子串: 登录横幅里可能出现"present"这类普通词.
const (
	socketAbsentMarker     = "gpg-agent-forward-socket-absent"
	socketReclaimedMarker  = "gpg-agent-forward-socket-reclaimed"
	socketLiveMarker       = "gpg-agent-forward-socket-live"
	socketNotASocketMarker = "gpg-agent-forward-socket-notasocket"
	socketStuckMarker      = "gpg-agent-forward-socket-stuck"
	socketUnknownMarker    = "gpg-agent-forward-socket-unknown"
	socketSymlinkMarker    = "gpg-agent-forward-socket-symlink"
)

type remoteSocketState int

const (
	socketFree        remoteSocketState = iota // 路径上什么都没有
	socketReclaimed                            // 死socket已被删除
	socketLive                                 // 有东西在监听
	socketNotASocket                           // 挡路的是非socket文件
	socketStuck                                // 死socket还在, 删不掉
	socketUnjudgeable                          // 主机无法判定
	socketUnreported                           // 探针没有报出任何判定
	socketSymlink                              // 路径是符号链接
)

// procNetUnixPath: 探针读的第二份独立证据, 内核的unix socket表.
// 写成常量是为了让测试能替换这个名字: 绝对路径`/proc/net/unix`没法被unmount或改成不可读.
const procNetUnixPath = "/proc/net/unix"

// remoteSocketProbe: 一条远端命令报告path处是什么, 判定为死socket时就地删除.
// 判定与删除同行: 只有主机能分辨死socket与活socket; 检查与rm之间的竞态无锁可拿, 明知而接受.
// 命令必须是一行: sshd先把整串交给远端用户的登录shell, csh/tcsh拒绝跨行的引号词 (Unmatched '),
// 于是什么都不跑; sh -c只为if/elif给出已知解释器, 不解析外层; 删除只做能正面排除的情况:
// 活socket永不删; ss是程序, 可能过滤行或被沙箱掐掉回答却仍打印表头, 单凭它说"没有"不算数;
// 要`ss -xl`和`/proc/net/unix`两个独立来源都说已死才删; 读不到的不算数; 内核表按路径而非inode匹配.
func remoteSocketProbe(path string) string {
	// 分片拼接只为可读;这条远程命令必须保持单行
	script := strings.Join([]string{
		"p=" + shellQuoteSingle(path) + ";",
		"if [ -L \"$p\" ]; then echo " + socketSymlinkMarker + ";",
		"elif [ -e \"$p\" ]; then",
		"if [ -S \"$p\" ]; then",
		// 先读内核表:单凭它就能判路径被占用,没`ss`的主机也报得出活socket,
		// 否则用户会去开`--skip-remote-check`.表展平后与`ss`一样匹配,
		// 一个" $p "模式覆盖每行,行末路径也算.
		"procflat=;",
		"if [ -r " + procNetUnixPath + " ]; then procflat=$(tr '\\n' ' ' < " + procNetUnixPath + " 2>/dev/null); fi;",
		// 表头按两个相邻列名匹配而非整行:内核用成串空格补齐,模式里没有"一个或多个".
		// 这两个词是文件真被读到的证据:可读却永不应答的占位文件不能当作省略该路径的表.
		"proc_table=no; case \" $procflat \" in *\"RefCount Protocol \"*) proc_table=yes;; esac;",
		"proc_live=no; case \" $procflat \" in *\" $p \"*) proc_live=yes;; esac;",
		"if [ \"$proc_live\" = yes ]; then echo " + socketLiveMarker + ";",
		"elif command -v ss >/dev/null 2>&1; then",
		"out=$(LC_ALL=C ss -xl 2>/dev/null); st=$?;",
		// 先看`ss`自己的退出状态再读输出:管道只报最后一条命令的状态,
		// 跑起来却失败的`ss`什么都不打印,与"无人监听"长得一模一样.
		"if [ \"$st\" -ne 0 ]; then echo " + socketUnknownMarker + ";",
		"else flat=$(printf '%s' \"$out\" | tr '\\n' ' ');",
		"has_table=no; case \" $flat \" in *\" Netid State\"*) has_table=yes;; esac;",
		"live=no; case \" $flat \" in *\" $p \"*) live=yes;; esac;",
		"if [ \"$live\" = yes ]; then echo " + socketLiveMarker + ";",
		"elif [ \"$has_table\" = no ] || [ \"$proc_table\" = no ]; then echo " + socketUnknownMarker + ";",
		"elif rm -f -- \"$p\"; then echo " + socketReclaimedMarker + ";",
		"else echo " + socketStuckMarker + "; fi; fi;",
		"else echo " + socketUnknownMarker + "; fi;",
		"else echo " + socketNotASocketMarker + "; fi;",
		"else echo " + socketAbsentMarker + "; fi",
	}, " ")
	return "sh -c " + shellQuoteSingle(script)
}

// 无人绑定的socket是结束会话的遗留,删;活socket(远端agent或他人同路径)与非socket文件不碰.
// 判明需要两路证据,缺一路,失败或答的不是表都算没答;一路为何不够详见`remoteSocketProbe`.
// 状态仅在error为nil时有意义:判不出来一律返回`socketUnjudgeable`,忽略错误者即拒绝.
func probeRemoteSocket(sshArgs []string, remoteSocket string, run SSHCommandRunner) (remoteSocketState, error) {
	out, err := run(sshArgs, remoteSocketProbe(remoteSocket))
	if err != nil {
		// 原样返回:调用方各自会加上自己的语境,在此包装会文不对题
		return socketUnjudgeable, err
	}
	for _, line := range strings.Split(out, "\n") {
		switch strings.TrimSpace(line) {
		case socketAbsentMarker:
			return socketFree, nil
		case socketReclaimedMarker:
			return socketReclaimed, nil
		case socketLiveMarker:
			return socketLive, nil
		case socketNotASocketMarker:
			return socketNotASocket, nil
		case socketStuckMarker:
			return socketStuck, nil
		case socketUnknownMarker:
			return socketUnjudgeable, nil
		case socketSymlinkMarker:
			return socketSymlink, nil
		}
	}
	// 一行判定都没有:探针没按预期跑起来(无`sh`,登录shell解析不了,输出被过滤).
	// 没删东西但也没查东西,是独立判定而非"free",由调用方定夺,详见`CheckRemoteSocketFree`.
	return socketUnreported, nil
}

// 让sshd即将绑定的远端路径可用,不可用则说明原因.
// 活socket属于远端gpg-agent:转发时sshd的`StreamLocalBindUnlink`会顶掉它占位,
// gpg便静默连上别的agent,故拒绝覆盖;无人监听的遗留则删除放行,路径不存在是健康的.
// 仅error为nil才放行;判不出来的状态一律拒绝,错误里带`--skip-remote-check`;有明确判定则不给.
func CheckRemoteSocketFree(sshArgs []string, remoteSocket string, run SSHCommandRunner) (remoteSocketState, error) {
	state, err := probeRemoteSocket(sshArgs, remoteSocket, run)
	if err != nil {
		return state, fmt.Errorf("checking what is at %s on the remote host: %w", remoteSocket, err)
	}
	switch state {
	case socketFree, socketReclaimed:
		return state, nil
	case socketUnreported:
		return state, fmt.Errorf(
			"could not check what is at %s on the remote host: the probe there reported nothing.\n"+
				"  A host with no sh, a login shell that cannot run the probe, and a session whose output is filtered all look like this.\n"+
				"  Starting without the check would let sshd bind over a live gpg-agent socket, and gpg would then follow the wrong agent.\n"+
				"  Pass --skip-remote-check to start the session anyway, or --remote-socket PATH to use a different path.",
			remoteSocket)
	case socketLive:
		return state, fmt.Errorf(
			"%s already exists on the remote host, so it is in use by that host's own gpg-agent.\n"+
				"  Forwarding onto it would make gpg talk to the remote agent instead of the Windows one.\n"+
				"  Stop the remote agent first:\n"+
				"      gpgconf --kill gpg-agent\n"+
				"      echo no-autostart >> ~/.gnupg/gpg.conf\n"+
				"  (and remove the leftover socket if it survives: rm -f %s)\n"+
				"  Pass --remote-socket PATH to use a different path instead.",
			remoteSocket, shellQuoteSingle(remoteSocket))
	case socketNotASocket:
		return state, fmt.Errorf(
			"%s exists on the remote host and is not a socket, so it is not a leftover agent socket.\n"+
				"  Refusing to remove it. Move it out of the way, or pass --remote-socket PATH to use a different path.",
			remoteSocket)
	case socketStuck:
		return state, fmt.Errorf(
			"a socket nothing is listening on is left at %s on the remote host, and it could not be removed.\n"+
				"  Remove it there, or pass --remote-socket PATH to use a different path.",
			remoteSocket)
	case socketSymlink:
		return state, fmt.Errorf(
			"%s on the remote host is a symbolic link, so whether a live agent socket is behind it cannot be told from here.\n"+
				"  Refusing to remove the link or to bind over it. Point --remote-socket PATH at the real path instead.",
			remoteSocket)
	default: // socketUnjudgeable:两路证据都没答
		return state, fmt.Errorf(
			"could not tell whether %s on the remote host is in use: the host could not read both of its socket tables.\n"+
				"  This is the verdict when ss is missing, fails, or prints something that is not a socket table,\n"+
				"  and when the kernel's /proc/net/unix cannot be read there. Nothing was removed.\n"+
				"  Remove the file there if nothing should be using it, pass --remote-socket PATH to use a different path,\n"+
				"  or pass --skip-remote-check to start without the check and accept that sshd may bind over a live agent socket.",
			remoteSocket)
	}
}

// `sshWaitDelay`:ssh进程消失后Wait最多再等多久它的输出管道.ssh启动的命令可能比它活得久
// (`ProxyCommand`,wrapper,sshd认证后fork的守护进程),后代持有继承的stdout,复制管道的
// goroutine要等最后一个持有者退出;不设它超时杀不掉等待,等于没有超时.
const sshWaitDelay = 200 * time.Millisecond

// `sshQueryTimeout`:一次性查询的时限,覆盖整次调用(含ssh自己的连接),发现连接与每个探针.
// 远端只跑几条shell命令:探针读两张socket表.余量留给负载高的主机,
// 20秒足够放弃完全不答的主机.预检跑在信号处理安装之前,不返回的查询无法被中断.
// 会话自己的ssh不受此限,它持续到会话结束.
const sshQueryTimeout = 20 * time.Second

// 构造跑remoteCommand的ssh参数,丢掉会阻止远端命令运行的选项
func sshCommandArgs(sshArgs []string, remoteCommand string) ([]string, error) {
	destination, connFlags, err := ParseSSHArgs(sshArgs)
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, len(connFlags)+2)
	args = append(args, connFlags...)
	args = append(args, destination, remoteCommand)
	return args, nil
}

// remoteCommand的runner,超时同`runSSHQuery`的`sshQueryTimeout`:`run.go`的ssh子命令把它交给
// `CheckRemoteSocketFree`作探针的runner,不返回的探针不能挂住整个调用;不限时用`runSSHQueryContext`.
func runSSHCommand(sshArgs []string, remoteCommand string) (string, error) {
	args, err := sshCommandArgs(sshArgs, remoteCommand)
	if err != nil {
		return "", err
	}
	return runSSHQuery(args)
}

func runSSHQuery(args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sshQueryTimeout)
	defer cancel()
	return runSSHQueryContext(ctx, args)
}

// 一次性远端命令只有这里启动ssh,超时与等待延迟都在这一处施加.
// WaitDelay截断的等待不是失败的查询:只有ssh成功退出而它留下的进程仍持有输出管道时
// 才报`ErrWaitDelay`,已收集的输出就是ssh的回答;无判定行不等于判定,两个调用方都拒绝.
// 两个流都走有界缓冲(同中继日志),话痨主机撑不大本进程;缓冲留尾部,而答案恰在尾部.
func runSSHQueryContext(ctx context.Context, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.WaitDelay = sshWaitDelay
	var stdout, stderr boundedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		// 超时的截止时间先以信号到达这里:Wait优先报被杀进程的退出状态而非ctx的错误,
		// 死于信号的进程没有退出码(-1);"signal: killed"本身不说明原因,故并列ctx错误;
		// 保持包装,调用方能分辨这是超时而非ssh自己的判定.
		var exitErr *exec.ExitError
		if ctxErr := ctx.Err(); ctxErr != nil && errors.As(err, &exitErr) && exitErr.ExitCode() == -1 {
			err = fmt.Errorf("%w: %w", err, ctxErr)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return stdout.String(), nil
}
