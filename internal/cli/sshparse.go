package cli

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path"
	"strconv"
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

// sshFlagDroppedForQuery: 不能带进探测连接的单字母选项.
// `-N`和`-f`会让远端命令跑不起来, `-t`会索要pty把回答变成交互输出,
// 控制类选项会改变连接的建立方式, 转发会与中继自己的`-R`撞车.
// `-o`的长拼写不在这里判断, 详见 `sshOptionDroppedForQuery`.
var sshFlagDroppedForQuery = map[byte]bool{
	'B': true, 'b': true, 'D': true, 'L': true, 'R': true, 'W': true, 'w': true,
	'f': true, 'N': true, 'M': true, 'S': true, 'O': true, 'n': true, 't': true,
}

// sshOptionDroppedForQuery: 表里的关键字用ssh比较时的小写拼写.
// 转发类关键字是`-R`/`-L`/`-D`的另一条路: 探测连接自己建转发会绑上正要检查的路径, 查询就把
// 主机判成忙, 于是每次都被拒绝.
// 丢弃而非覆盖: ssh对标量取先读到的值, 本包后写的挤不掉; 清理由sshCommandArgs写在用户参数之前
// (详见 `sshCommandArgs`), 用户的`-o ClearAllForwardings=no`盖不过它; forward逐条追加, 后加的
// 也挤不掉; 其余关键字改变连接做什么: 用户的命令, `ForkAfterAuthentication`, 强制tty.
var sshOptionDroppedForQuery = map[string]bool{
	"remoteforward":           true,
	"localforward":            true,
	"dynamicforward":          true,
	"forkafterauthentication": true,
	"remotecommand":           true,
	"clearallforwardings":     true,
	"requesttty":              true,
}

// sshOptionKey: 取出`-o`参数设置的关键字, 小写.
// ssh不要求"Key=Value"拼写: 关键字前依次跳过空白, 一个等号和空白, 关键字在第一个等号或空白处结束,
// 所以`-o "RemoteForward /a:/b"`与`-o "=RemoteForward=/a:/b"`都等价于`-o RemoteForward=/a:/b`.
// 只跳一个等号: 两个时ssh什么都不设, 这里返回空关键字, 原样放过.
func sshOptionKey(option string) string {
	option = strings.TrimLeft(option, sshOptionWhitespace)
	option = strings.TrimPrefix(option, "=")
	option = strings.TrimLeft(option, sshOptionWhitespace)
	if i := strings.IndexFunc(option, func(r rune) bool {
		return r == '=' || strings.ContainsRune(sshOptionWhitespace, r)
	}); i >= 0 {
		option = option[:i]
	}
	return strings.ToLower(option)
}

// sshOptionWhitespace: ssh自己的选项解析器按C locale的`isspace()`读的空白, 只有这六个字符.
const sshOptionWhitespace = " \t\n\v\f\r"

// sshClearAllForwardings: 排在最前, 连配置文件里的转发一起清, 兼作过滤器认不出的拼写的兜底.
const sshClearAllForwardings = "ClearAllForwardings=yes"

// ParseSSHArgs: 拆出目标主机, 以及值得复用给第二条连接的flag子集.
// 不在目标主机处停下解析: ssh会重排参数, 选项可以跟在主机后面 (`ssh host -p 2222`).
// 一种选项的每种拼写都丢掉: 表里的字母, `-o`设的关键字 (附着/分开/带前导`=`都算), 以及`--option`.
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

		// `--option`是`-o`的GNU式拼写 (ssh自己会拒掉它), 这里照样读它的值:
		// 关键字要和其他选项一样被过滤, 更要紧的是别让`--option K=V host`把K=V当成主机.
		if a == "--option" || strings.HasPrefix(a, "--option=") {
			separate := a == "--option"
			value := strings.TrimPrefix(a, "--option=")
			if separate && i+1 < len(args) {
				value = args[i+1]
			}
			if !sshOptionDroppedForQuery[sshOptionKey(value)] {
				connFlags = append(connFlags, a)
				if separate && i+1 < len(args) {
					connFlags = append(connFlags, value)
				}
			}
			if separate {
				i += 2
				continue
			}
			i++
			continue
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
			attached := group[j+1:]
			// `-o`按它设置的关键字取舍, 不按字母.
			if c == 'o' {
				value := attached
				if value == "" && i+1 < len(args) {
					value = args[i+1]
				}
				if sshOptionDroppedForQuery[sshOptionKey(value)] {
					keep = false
				}
			}
			if attached != "" {
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

// octalEscapes: 把s的每个字节变成三位八进制转义, 结果里没有s的任何字节, 用作远端printf的格式串;
// 用八进制不用\xHH, 因为远端printf按POSIX读回\NNN.
// 远端用户的登录shell在sh之前解析命令行, 而csh/tcsh连单引号内也做历史展开: 路径里的"!"会让
// 命令报"Event not found"而什么都不跑; 引号救不了 (美元符号, 反引号, 波浪号同样是特殊字符,
// 也都是路径的合法字节), 只能不让路径的字节上命令行; 也让ssh对`-R`的百分号展开无事可做.
func octalEscapes(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 4)
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, `\%03o`, s[i])
	}
	return b.String()
}

// 远端socket预检问一件事: sshd将要绑定的路径上有没有东西在监听; 判成"没有"判错会删掉在用的socket.
// 证据是主机自己对路径发起的连接, 不是读socket表: 表只描述一个网络命名空间, 别的命名空间里的
// 监听者 (如共享目录的容器agent) 两边都不出现, 会被当成残留删掉.
// 三步只有第三步可能删除: 1) 问路径上是什么 (只用shell内建), 不可写就拒绝: 写权限是连接socket
// 说得出话的前提, 没有它"被拒的连接"与"没人监听"就是同一个答案; 2) 阳性对照: 让主机连自建socket,
// 不然stream-local转发的拒绝与没人监听无异; 3) 连接保持=监听者, 立刻结束才尝试删除; 判不了即拒绝.
const (
	// socketAbsentMarker: 路径上什么都没有; 标记都按整行匹配, 登录横幅里的普通词不算判定.
	socketAbsentMarker = "gpg-agent-forward-socket-absent"
	// socketUnwritableMarker: 有东西在, 本用户不可写.
	socketUnwritableMarker = "gpg-agent-forward-socket-unwritable"
	// socketNotASocketMarker: 可写但不是socket.
	socketNotASocketMarker = "gpg-agent-forward-socket-notasocket"
	// socketSocketMarker: 可写的socket在; 有没有东西应答, 由分类那步的连接去问.
	socketSocketMarker = "gpg-agent-forward-socket-socket"
	// socketUnknownMarker: 主机答了, 但没有可用的判定行.
	socketUnknownMarker = "gpg-agent-forward-socket-unknown"
	// socketReclaimedMarker和socketStuckMarker: 删除的两种结果, 文件已删掉或还在.
	socketReclaimedMarker = "gpg-agent-forward-socket-reclaimed"
	socketStuckMarker     = "gpg-agent-forward-socket-stuck"
)

// remoteSocketForm: 一条远端命令, 只用shell自己的测试报告path上是什么.
// 用内建测试而不依赖程序: 没有stat, ls, grep的主机答得一样好, 而这个答案决定删不删.
// 答案的含义: 不存在是健康情况 (指向不存在目标的符号链接同理, 会话的bind会替掉链接); 不可写,
// 非socket都拒绝且不动; 可写的socket才交给连接去分类.
// 路径在脚本里解码, 不上命令行: 远端登录shell先解析, csh/tcsh连单引号内也做历史展开,
// 详见 octalEscapes; 也让ssh对-L/-R的百分号展开无事可做 (详见 `percentEscape`); 解码先证明再信任.
func remoteSocketForm(path string) string {
	script := strings.Join([]string{
		`[ "$(printf '\134')" = '\' ] || { echo ` + socketUnknownMarker + `; exit 0; };`,
		"p=$(printf " + shellQuoteSingle(octalEscapes(path)) + ");",
		`[ -n "$p" ] || { echo ` + socketUnknownMarker + `; exit 0; };`,
		`if [ ! -e "$p" ]; then echo ` + socketAbsentMarker + `;`,
		`elif [ ! -w "$p" ]; then echo ` + socketUnwritableMarker + `;`,
		`elif [ ! -S "$p" ]; then echo ` + socketNotASocketMarker + `;`,
		`else echo ` + socketSocketMarker + `; fi`,
	}, " ")
	// sh -c只保证脚本体的解释器: 外层命令sshd已交给登录shell, 可能是csh.
	return "sh -c " + shellQuoteSingle(script)
}

// remoteSocketRemove: 一条远端命令删掉path并报告结果.
// 判定就是rm自己的状态: rm -f成功即文件已不在, 失败即删不掉, 不必再看一次路径.
func remoteSocketRemove(path string) string {
	script := strings.Join([]string{
		`[ "$(printf '\134')" = '\' ] || { echo ` + socketUnknownMarker + `; exit 0; };`,
		"p=$(printf " + shellQuoteSingle(octalEscapes(path)) + ");",
		`[ -n "$p" ] || { echo ` + socketUnknownMarker + `; exit 0; };`,
		`if rm -f -- "$p" 2>/dev/null; then echo ` + socketReclaimedMarker + `; else echo ` + socketStuckMarker + `; fi`,
	}, " ")
	return "sh -c " + shellQuoteSingle(script)
}

// socketForm: 一次性远端命令在路径上看到的结果.
type socketForm int

const (
	// formUnknown: 主机答了, 但没有可用的判定行; 路径仍属未知, 不能删.
	formUnknown socketForm = iota
	// formAbsent: 路径上什么都没有.
	formAbsent
	// formUnwritable: 路径上有东西, 本用户不可写.
	formUnwritable
	// formNotASocket: 路径上可写但不是socket.
	formNotASocket
	// formSocket: 路径上是可写的socket; 有没有应答由分类决定.
	formSocket
)

// parseSocketForm: 读form命令打出的那一行判定.
// 不是任何标记的内容 (没有输出, 横幅, 主机跑了别的) 都算formUnknown.
func parseSocketForm(out string) socketForm {
	for _, line := range strings.Split(out, "\n") {
		switch strings.TrimSpace(line) {
		case socketAbsentMarker:
			return formAbsent
		case socketUnwritableMarker:
			return formUnwritable
		case socketNotASocketMarker:
			return formNotASocket
		case socketSocketMarker:
			return formSocket
		case socketUnknownMarker:
			return formUnknown
		}
	}
	return formUnknown
}

// remoteSocketState: 检查在远端路径上看到什么, 又做了什么; 零值就是允许起会话的状态.
type remoteSocketState int

const (
	socketFree        remoteSocketState = iota // 路径上什么都没有
	socketReclaimed                            // 遗留socket已被删除
	socketLive                                 // 有东西在监听
	socketNotASocket                           // 挡路的是非socket文件
	socketStuck                                // 遗留socket还在, 删不掉
	socketUnjudgeable                          // 主机问不到, 或没有回答
	socketUnwritable                           // 有东西在, 本用户不可写
)

// String: 让失败信息读作`socketUnjudgeable`而不是`state 5`.
func (s remoteSocketState) String() string {
	switch s {
	case socketFree:
		return "socketFree"
	case socketReclaimed:
		return "socketReclaimed"
	case socketLive:
		return "socketLive"
	case socketNotASocket:
		return "socketNotASocket"
	case socketStuck:
		return "socketStuck"
	case socketUnjudgeable:
		return "socketUnjudgeable"
	case socketUnwritable:
		return "socketUnwritable"
	}
	return fmt.Sprintf("remoteSocketState(%d)", s)
}

// maySkipRemoteCheck: `--skip-remote-check`能否从这个状态起会话.
// 规则看状态是怎么来的, 不看是哪个状态: 只覆盖"检查根本做不成" (主机问不到, 或没有回答),
// 路径自身给出的判定不由该flag推翻: 有监听者, 非socket文件, 删不掉的残留都是;
// 不可写是另一种出路的问题 (换个路径), 因为写权限正是连接socket这个判定成立的前提.
func (s remoteSocketState) maySkipRemoteCheck() bool {
	return s == socketUnjudgeable
}

// probeRemoteSocketForm: 问远端remoteSocket处有什么; 只有错误为nil时状态才有意义.
func probeRemoteSocketForm(sshArgs []string, remoteSocket string, run SSHCommandRunner) (socketForm, error) {
	out, err := run(sshArgs, remoteSocketForm(remoteSocket))
	if err != nil {
		// 原样返回: 调用方用自己的措辞描述这个失败, 包一层只会重复.
		return formUnknown, err
	}
	return parseSocketForm(out), nil
}

// 分类连接用的`ClearAllForwardings`取值,刻意与一次性查询连接相反:该项全有全无,
// 置yes会把本连接所需的`-R`和两个`-L`一起清掉;置no只留下配置文件给该主机的转发,本就属于本次会话.
const sshKeepForwardings = "ClearAllForwardings=no"

type socketForwardSpec struct {
	// sshd连到`controlPath`时发布的本地端口,承载正向控制
	controlPort int
	// 本检查自建自管的远端socket路径,控制只碰它,绝不是被测路径
	controlPath string
	// sshd连到`targetPath`时发布的本地端口,承载分类判定
	targetPort int
	targetPath string
	// 控制socket回连的本地端口:接受并保持连接才算完成控制
	holdPort int
}

// 分类连接的ssh参数:沿用调用方的连接参数到达同一主机,另加三个转发
// (`-R`控制socket归远端,`-L`让sshd连到它,`-L`被测路径).
// 路径位于`-L`/`-R`规格内,ssh会展开其中的%记号,故先转义,详见`percentEscape`.
// 加`-N`是因为本连接只有转发;`ClearAllForwardings=no`的理由详见`sshKeepForwardings`.
func sshForwardArgs(sshArgs []string, spec socketForwardSpec) ([]string, error) {
	destination, connFlags, err := ParseSSHArgs(sshArgs)
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, len(connFlags)+12)
	args = append(args, "-o", sshKeepForwardings, "-N")
	args = append(args, connFlags...)
	args = append(args,
		"-R", percentEscape(spec.controlPath)+":127.0.0.1:"+strconv.Itoa(spec.holdPort),
		"-L", "127.0.0.1:"+strconv.Itoa(spec.controlPort)+":"+percentEscape(spec.controlPath),
		"-L", "127.0.0.1:"+strconv.Itoa(spec.targetPort)+":"+percentEscape(spec.targetPath),
	)
	args = append(args, destination)
	return args, nil
}

// 正向控制的socket名前缀:要短,因得挤在被测路径旁,后者本身可能已接近
// unix socket路径107字节的上限;又要有辨识度,免得被当成别人的socket.
const controlSocketPrefix = ".gpg-agent-forward-"

// 正向控制所用socket的远端路径:放在被测路径所在目录旁,sshd要绑该路径,
// 该目录本就必须可写,于是问题值得问的场景里控制也一定绑得上.
// 名字唯一,不会与被测路径或别的检查撞;结果不可用时报错而非截断:
// 旁放不下控制socket的路径判不了,是拒绝,不是删除.
func controlSocketPath(remoteSocket string) (string, error) {
	suffix, err := randomHex(6)
	if err != nil {
		return "", err
	}
	dir := path.Dir(remoteSocket)
	if dir == "" || dir == "." {
		dir = "/"
	}
	p := path.Join(dir, controlSocketPrefix+suffix)
	if p == remoteSocket {
		return "", fmt.Errorf("the control socket would be the path under test (%s)", p)
	}
	if err := ValidateRemoteSocket(p); err != nil {
		return "", fmt.Errorf("the control socket for %s: %w", remoteSocket, err)
	}
	return p, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := cryptorand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type socketForwardVerdict int

const (
	// forwardUnjudgeable:控制未通过或连接没做成,此判定下什么都不能删
	forwardUnjudgeable socketForwardVerdict = iota
	// forwardLive:有东西应答并保持连接
	forwardLive
	// forwardDead:连接没答话就结束了
	forwardDead
)

type localConnKind int

const (
	// localUnclassifiable:连不上或ssh已退出,由此得不出关于远端路径的判定
	localUnclassifiable localConnKind = iota
	// localHeld:已连接,既无话语也不关闭
	localHeld
	// localClosed:已连接,连接没答话就结束了
	localClosed
)

// 分类等待ssh发布本地端口的时限:覆盖ssh自身的连接,故给得宽;
// 预检发生在安装信号处理之前,答得慢的主机也要分类得出而非放弃.
const socketProbeDialTimeout = 6 * time.Second

// 连接保持沉默多久算被持有:无人监听的socket会立刻结束连接,所以这不是耐心,
// 而是答案可靠的那一半:沉默这么久仍开着的连接已被不说话的进程接受(gpg-agent即是).
// 留的疑问朝安全方向:慢到连不上都要这么久的远端读作live,检查即拒绝.
const socketProbeReadTimeout = 1200 * time.Millisecond

// 让远端主机自己连remoteSocket,据此报告那里有什么.
// 答案不可信者(控制未通过或连接没做成)一律返回`forwardUnjudgeable`:
// 无控制则无判定,详见`remoteSocketForm`.
func classifyRemoteSocket(sshArgs []string, remoteSocket, controlPath string) (socketForwardVerdict, error) {
	// 控制`-R`转发的本地端:sshd连上远端控制socket并把连接隧道到这里,
	// 接受并保持它才算走完控制所证明的那条链.
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return forwardUnjudgeable, err
	}
	defer hold.Close()
	acceptAndHold(hold)

	controlPort, err := freeLoopbackPort()
	if err != nil {
		return forwardUnjudgeable, err
	}
	targetPort, err := freeLoopbackPort()
	if err != nil {
		return forwardUnjudgeable, err
	}

	args, err := sshForwardArgs(sshArgs, socketForwardSpec{
		controlPort: controlPort,
		controlPath: controlPath,
		targetPort:  targetPort,
		targetPath:  remoteSocket,
		holdPort:    hold.Addr().(*net.TCPAddr).Port,
	})
	if err != nil {
		return forwardUnjudgeable, err
	}

	cmd := exec.Command("ssh", args...)
	// 保留ssh关于被拒转发的输出:它指出该看哪一侧;用与查询连接相同的有界缓冲,话痨主机撑不大进程
	var stderr boundedBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return forwardUnjudgeable, err
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	// 每条路径上都杀ssh,成功路径也一样:那时连接已给出答案,不再需要它
	defer func() {
		_ = cmd.Process.Kill()
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
		}
	}()

	if kind := classifyLocalPort(controlPort, exited); kind != localHeld {
		// 控制没走通:本地端口关闭或缺失说明不了远端路径什么,sshd拒绝stream-local连接
		// 与无人监听的socket长得一模一样;ssh有话时附在后面.
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			detail = "; ssh said: " + lastLine(detail)
		}
		return forwardUnjudgeable, fmt.Errorf(
			"the control connection through %s was not established (%v)%s", controlPath, kind, detail)
	}
	switch classifyLocalPort(targetPort, exited) {
	case localHeld:
		return forwardLive, nil
	case localClosed:
		return forwardDead, nil
	default:
		return forwardUnjudgeable, fmt.Errorf(
			"nothing answered on the local port %s was to be connected through; ssh said: %s",
			remoteSocket, lastLine(strings.TrimSpace(stderr.String())))
	}
}

// ssh把结束原因放在最后一行
func lastLine(s string) string {
	if s == "" {
		return "(nothing)"
	}
	lines := strings.Split(s, "\n")
	return lines[len(lines)-1]
}

// 端口是等来的而非假定:ssh在自身连接建立后才发布它,认证未完时什么都还没发布;
// ssh已退出则提前结束等待,没发布过的端口不会再有.
func classifyLocalPort(port int, exited <-chan struct{}) localConnKind {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(socketProbeDialTimeout)
	var conn net.Conn
	for {
		c, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			conn = c
			break
		}
		select {
		case <-exited:
			return localUnclassifiable
		default:
		}
		if !time.Now().Before(deadline) {
			return localUnclassifiable
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer conn.Close()

	// 连接结束:无字节且无超时;连接被持有:读以超时告终.字节是第三种结果,也是独立答案:
	// 对面有东西可对话,即为活路径.
	if err := conn.SetReadDeadline(time.Now().Add(socketProbeReadTimeout)); err != nil {
		return localUnclassifiable
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if n > 0 {
		return localHeld
	}
	if err == nil {
		return localClosed
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return localHeld
	}
	return localClosed
}

// 接受l上的连接并一直保持,直到l关闭;这是控制`-R`转发的本地落点:连接保持即证据,
// 有意不说话,让控制与目标用同一种读法(持有或结束).
func acceptAndHold(l net.Listener) {
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				c.Close()
			}
		}()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
}

// 返回一个无人监听的loopback端口;返回前已关闭,存在被别人抢走的窗口.
// 不能用`ssh -L`的0端口绕开:ssh拒绝零本地端口("Bad local forwarding specification").
// 窗口代价有界且朝安全方向:绑不上时ssh报错退出,等端口落空,分类做不成,检查拒绝.
func freeLoopbackPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		return 0, err
	}
	return port, nil
}

// 预检用的分类函数;做成变量便于测试替换判定,无需假ssh即可覆盖调用方各分支;
// 连接本身在`remote_probe_test.go`里用真绑定真连接的假ssh端到端覆盖.
var classifyRemoteSocketForward = classifyRemoteSocket

// 删除远端remoteSocket并报告是否已消失;两种结果都没报算删除失败,不算成功
func removeRemoteSocket(sshArgs []string, remoteSocket string, run SSHCommandRunner) (bool, error) {
	out, err := run(sshArgs, remoteSocketRemove(remoteSocket))
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(out, "\n") {
		switch strings.TrimSpace(line) {
		case socketReclaimedMarker:
			return true, nil
		case socketStuckMarker:
			return false, nil
		}
	}
	return false, nil
}

// 让sshd即将绑定的远端路径可用,不可用则说明原因.
// 该路径是gpg找agent的地方:转发到它时,sshd的`StreamLocalBindUnlink`会顶掉那里的活socket占位,
// gpg便静默连到别的agent,故活socket不覆盖;无人监听的遗留经正向控制确认无人应答后才删.
// 仅error为nil才放行:`socketReclaimed`是已删遗留,`socketUnjudgeable`与`socketUnwritable`亦拒绝;
// 哪些状态可被`--skip-remote-check`放行的规则详见`maySkipRemoteCheck`.
func CheckRemoteSocketFree(sshArgs []string, remoteSocket string, run SSHCommandRunner) (remoteSocketState, error) {
	form, err := probeRemoteSocketForm(sshArgs, remoteSocket, run)
	if err != nil {
		return socketUnjudgeable, fmt.Errorf("could not check what is at %s on the remote host: %w", remoteSocket, err)
	}
	switch form {
	case formAbsent:
		return socketFree, nil
	case formUnwritable:
		return socketUnwritable, fmt.Errorf(
			"%s on the remote host cannot be written by your user there, so whether anything is listening on it cannot be told from here.\n"+
				"  Connecting to a socket needs write permission on it, and a refused connect reaches this side as a\n"+
				"  connection that ended - the same thing a socket nothing is listening on looks like. Without the\n"+
				"  permission the two cannot be told apart, so this tool refuses rather than guess.\n"+
				"  Do not delete it yourself to get past this: something may be listening on it, and protecting exactly\n"+
				"  that is why this check exists. First see what is there and who owns it (ls -l %s), and make sure no\n"+
				"  agent is using it.\n"+
				"  Pass --remote-socket PATH to use a different path.",
			remoteSocket, shellQuoteSingle(remoteSocket))
	case formNotASocket:
		return socketNotASocket, fmt.Errorf(
			"%s exists on the remote host and is not a socket, so it is not a leftover agent socket.\n"+
				"  Refusing to remove it. Move it out of the way, or pass --remote-socket PATH to use a different path.",
			remoteSocket)
	case formUnknown:
		return socketUnjudgeable, fmt.Errorf(
			"could not check what is at %s on the remote host: the host did not answer.\n"+
				"  A host with no sh, a login shell that cannot run the command, a shell whose printf does not read the \\NNN\n"+
				"  escapes the path travels as, and a session whose output is filtered all look like this.\n"+
				"  Starting without the check would let sshd bind over a live gpg-agent socket, and gpg would then follow the wrong agent.\n"+
				"  Pass --skip-remote-check to start the session anyway, or --remote-socket PATH to use a different path.",
			remoteSocket)
	}

	control, err := controlSocketPath(remoteSocket)
	if err != nil {
		return socketUnjudgeable, fmt.Errorf("could not tell whether %s on the remote host is in use: %w", remoteSocket, err)
	}
	verdict, err := classifyRemoteSocketForward(sshArgs, remoteSocket, control)
	// 控制socket是本检查在远端的自有临时资源,无论分类结论如何都删;删除失败不报:
	// 留下的只是无人监听的socket,正是下次预检会回收的东西.
	removeRemoteSocketBestEffort(sshArgs, control, run)
	if err != nil {
		return socketUnjudgeable, fmt.Errorf(
			"could not tell whether %s on the remote host is in use: %v.\n"+
				"  The check works by having that host connect to the path, through a socket it creates next to it and then\n"+
				"  removes; that connection is what could not be made. It needs stream-local forwarding in both directions - a\n"+
				"  socket the host creates next to the path on that host, and a connect the host makes - so an sshd\n"+
				"  that restricts it (AllowStreamLocalForwarding no, local or remote, or PermitOpen limits on the\n"+
				"  connect) refuses one of them, and a refusal is indistinguishable from a socket nothing is listening\n"+
				"  on, so nothing was removed.\n"+
				"  Pass --skip-remote-check to start the session anyway, or --remote-socket PATH to use a different path.",
			remoteSocket, err)
	}
	switch verdict {
	case forwardLive:
		return socketLive, fmt.Errorf(
			"%s already exists on the remote host, so it is in use by that host's own gpg-agent.\n"+
				"  Forwarding onto it would make gpg talk to the remote agent instead of the Windows one.\n"+
				"  Stop the remote agent first:\n"+
				"      gpgconf --kill gpg-agent\n"+
				"      echo no-autostart >> ~/.gnupg/gpg.conf\n"+
				"  (and remove the leftover socket if it survives: rm -f -- %s)\n"+
				"  Pass --remote-socket PATH to use a different path instead.",
			remoteSocket, shellQuoteSingle(remoteSocket))
	case forwardDead:
		removed, err := removeRemoteSocket(sshArgs, remoteSocket, run)
		if err != nil {
			return socketStuck, fmt.Errorf(
				"a socket nothing is listening on is left at %s on the remote host, and removing it failed: %v.\n"+
					"  Remove it there, or pass --remote-socket PATH to use a different path.",
				remoteSocket, err)
		}
		if !removed {
			return socketStuck, fmt.Errorf(
				"a socket nothing is listening on is left at %s on the remote host, and it could not be removed.\n"+
					"  Remove it there, or pass --remote-socket PATH to use a different path.",
				remoteSocket)
		}
		return socketReclaimed, nil
	default: // forwardUnjudgeable:没有得到关于该路径的判定
		return socketUnjudgeable, fmt.Errorf(
			"could not tell whether %s on the remote host is in use: the check could not make its connection.\n"+
				"  Nothing was removed.\n"+
				"  Pass --skip-remote-check to start the session anyway, or --remote-socket PATH to use a different path.",
			remoteSocket)
	}
}

// 删除path并丢弃判定与失败;用于控制socket,它是本检查自己的资源,不是判定的对象:
// 删除失败留下的只是无人监听的socket,正是下次预检会回收的.
func removeRemoteSocketBestEffort(sshArgs []string, path string, run SSHCommandRunner) {
	_, _ = removeRemoteSocket(sshArgs, path, run)
}

// `sshWaitDelay`:ssh进程消失后Wait最多再等多久它的输出管道.ssh启动的命令可能比它活得久
// (`ProxyCommand`,wrapper,sshd认证后fork的守护进程),后代持有继承的stdout,复制管道的
// goroutine要等最后一个持有者退出;不设它超时杀不掉等待,等于没有超时.
const sshWaitDelay = 200 * time.Millisecond

// `sshQueryTimeout`:一次性查询的时限,覆盖整次调用(含ssh自己的连接),发现连接与每个探针.
// 远端只跑几条shell内建命令,工作量很小.余量留给负载高的主机,20秒足够,
// 又不至于久等完全不答的主机.预检跑在信号处理安装之前,不返回的查询无法被中断.
// 会话自己的ssh不受此限,它持续到会话结束.
const sshQueryTimeout = 20 * time.Second

// 构造一次性查询的ssh参数:丢掉会阻止远端命令运行的选项,并清掉会改变主机面貌的转发.
// `ClearAllForwardings`放最前:取舍详见`sshClearAllForwardings`,首值详见`sshOptionDroppedForQuery`.
func sshCommandArgs(sshArgs []string, remoteCommand string) ([]string, error) {
	destination, connFlags, err := ParseSSHArgs(sshArgs)
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, len(connFlags)+4)
	args = append(args, "-o", sshClearAllForwardings)
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
