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
// 主机判成忙, 于是每次都被拒绝; 丢弃而非覆盖: ssh对标量取先读到的值, 本包后写的挤不掉;
// 清空值由`sshCommandArgs`写在用户参数之前, 用户的`-o ClearAllForwardings=no`盖不过它;
// forward逐条追加, 后加的也挤不掉; 其余关键字改变连接做什么: 用户的命令会顶掉查询的,
// `ForkAfterAuthentication`让查询进后台而没有回答可读, 强制tty会变成交互输出.
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

// 探针的判定标记按整行匹配, 不按子串: 登录横幅里可能出现"present"这类普通词.
const (
	socketAbsentMarker     = "gpg-agent-forward-socket-absent"
	socketReclaimedMarker  = "gpg-agent-forward-socket-reclaimed"
	socketLiveMarker       = "gpg-agent-forward-socket-live"
	socketNotASocketMarker = "gpg-agent-forward-socket-notasocket"
	socketStaleMarker      = "gpg-agent-forward-socket-stale"
	socketStuckMarker      = "gpg-agent-forward-socket-stuck"
	socketUnknownMarker    = "gpg-agent-forward-socket-unknown"
	socketUnresolvedMarker = "gpg-agent-forward-socket-unresolved"
	socketSymlinkMarker    = "gpg-agent-forward-socket-symlink"
)

type remoteSocketState int

const (
	socketFree        remoteSocketState = iota // 路径上什么都没有
	socketReclaimed                            // 死socket已被删除
	socketStale                                // 死socket还在, 没有动它
	socketLive                                 // 有东西在监听
	socketNotASocket                           // 挡路的是非socket文件
	socketStuck                                // 死socket还在, 删不掉
	socketUnjudgeable                          // 主机无法判定
	socketUnreported                           // 探针没有报出任何判定
	socketUnresolved                           // 路径在主机上无法解析
	socketSymlink                              // 路径是符号链接
)

// reclaimPolicy: 调用方允许探针对没东西绑定的socket做什么.
// 用具名类型而不是bool: 两个策略差在是否删除远端文件, keepLeftover是零值, 忘了选也安全.
type reclaimPolicy bool

const (
	// keepLeftover: 只报告, 不动文件, 也是默认值. 已死的证据只覆盖本网络命名空间,
	// 别的命名空间里的监听者两个来源都不出现 (详见 `remoteSocketProbe`).
	keepLeftover reclaimPolicy = false
	// reclaimLeftover: 删除它, 调用方以此接受来源排除不了别的命名空间里的监听者.
	reclaimLeftover reclaimPolicy = true
)

// procNetUnixPath: 探针读的第二份独立证据, 内核的unix socket表.
// 写成常量是为了让测试能替换这个名字: 绝对路径`/proc/net/unix`没法被unmount或改成不可读.
const procNetUnixPath = "/proc/net/unix"

// ssStatusTag: 探针在ss的表后面打的那行, 带ss的退出状态.
// 状态随它所属的输出一起回来, 一次ss运行就同时回答"ss说了什么"和"ss到底跑没跑".
const ssStatusTag = "gpg-agent-forward-ss-status"

// remoteSocketProbe: 构建报告path处情况的远端命令, 只在reclaim允许时删除死socket.
// 判定与删除同行: 只有主机能分辨死socket与活socket; 检查与rm之间仍有竞态, 远端无锁可拿.
// 命令必须是一行: sshd先把整串交给远端用户的登录shell, csh/tcsh拒绝跨行的引号词 (Unmatched '),
// 于是什么都不跑; sh -c只为脚本体给出已知解释器; 删除只做能正面排除的情况: 活socket永不删;
// ss是程序, 可能过滤行或出错, 单凭它不算数; 要`ss -xl`与`/proc/net/unix`两个独立来源都说路径已死,
// 读不到的来源不算"没有"; 内核表按路径而非inode匹配; 解码先经证明 (\134读回与反斜杠比较).
func remoteSocketProbe(path string, reclaim reclaimPolicy) string {
	// 两个来源都否认时:删除是对远端的改动,仅在调用方要求时做,默认只报状态
	leftoverArm := "else echo " + socketStaleMarker + "; fi;"
	if reclaim == reclaimLeftover {
		// 删除用解析后的拼写,不用用户输入的那个:检查过表的是解析后的拼写,
		// 目录组件在检查与删除之间换了指向时,删除不得改到表从未查过的文件上.
		leftoverArm = "elif rm -f -- \"$np\"; then echo " + socketReclaimedMarker + "; else echo " + socketStuckMarker + "; fi;"
	}

	// 分片拼接只为可读;这条远程命令必须保持单行
	script := strings.Join([]string{
		// 路径在脚本内解码而非写进命令:一个字节也不能上命令行,原因详见`octalEscapes`.
		// 解码取决于宿主机的`printf`:POSIX要求它读`\NNN`,不支持的实现会把转义原样打印,
		// 那样的`p`既非空也非路径,每项检查都答"否",会报成路径不存在,正是本探针要避免的判定.
		// 故先验证解码:用`\134`(反斜杠的转义)检验`printf`;这是对`printf`的检验,不是对路径的限制.
		`[ "$(printf '\134')" = '\' ] || { echo ` + socketUnknownMarker + `; exit 0; };`,
		"p=$(printf " + shellQuoteSingle(octalEscapes(path)) + ");",
		// 解码的另一种失败:`printf`不存在或对格式什么都不打印,得到空路径;
		// 空`p`不是文件,每项检查都会对没查过的路径答"否",与`printf`把转义原样打印时是同一种误读.
		"[ -n \"$p\" ] || { echo " + socketUnknownMarker + "; exit 0; };",
		// cand PATH OTHERPATH [GREP ARGS...]:留下表里提到任一path的行,
		// 以及调用方模式选中的行,每行补一个尾随空格.OTHERPATH可为空,表示没有第二种拼写.
		// 表本身不进shell变量:几十万socket的表有几十MB,shell得先吃下全部才能看;
		// `grep`流式读,只留提到路径的少数行.
		// 行尾空格让整字段判定可行:shell模式锚不住行尾,否则行末路径会像更长名字的前缀.
		"cand() { q=$1; r=$2; shift 2; if [ -n \"$r\" ]; then grep -F -e \" $q\" -e \" $r\" \"$@\" | sed 's/$/ /'; else grep -F -e \" $q\" \"$@\" | sed 's/$/ /'; fi; };",
		"if [ -L \"$p\" ]; then echo " + socketSymlinkMarker + ";",
		"elif [ -e \"$p\" ]; then",
		"if [ -S \"$p\" ]; then",
		// 向表询问的是解析后的拼写,未必是用户写的那个:内核按监听者绑定的拼写记录,
		// 经符号链接,".."或重复斜杠到达的路径,对按用户拼写的搜索不可见,
		// 而"两个表都不可见"正是删除的依据.
		// 只解析目录,最后一段保持原样,路径本身是符号链接时仍判不了.
		// `readlink -f`是解析目录的办法,没有它时用`realpath`;仅在指向同一文件时才采用其结果.
		"np=;",
		"case $p in */*) nd=${p%/*}; ns=${p##*/};; *) nd=.; ns=$p;; esac;",
		"[ -n \"$nd\" ] || nd=/;",
		"rp=$(readlink -f -- \"$nd\" 2>/dev/null) || rp=;",
		"[ -n \"$rp\" ] || rp=$(realpath -- \"$nd\" 2>/dev/null) || rp=;",
		"if [ -n \"$rp\" ]; then case $rp in */) np=$rp$ns;; *) np=$rp/$ns;; esac; fi;",
		"if [ -n \"$np\" ] && [ \"$p\" -ef \"$np\" ] 2>/dev/null; then :; else np=; fi;",
		// 含控制字符的路径无法按整字段搜索:搜索的单位是行,名字里有换行就成了两个字段.
		// 只有符号链接的目标能造出这种路径,它使"没有绑定到该路径"不可证.
		"case $np in *[[:cntrl:]]*) np=;; esac;",
		// 先读内核表:单凭它就能判路径被占用,没`ss`的主机也报得出活agent socket,
		// 否则这类主机上用户会去开`--skip-remote-check`.
		"proc_table=no; proc_live=no;",
		"if [ -r " + procNetUnixPath + " ]; then",
		// 表头按两个相邻列名匹配而非整行:内核用成串空格补齐,模式里没有"一个或多个".
		// 这两个词是文件真被读到的证据:可读却永不应答的占位文件不能当作省略该路径的表.
		// 表头在第一行,查到此即停.
		"grep -F -q -e 'RefCount Protocol ' < " + procNetUnixPath + " 2>/dev/null && proc_table=yes;",
		"proc_cand=$(cand \"$p\" \"$np\" < " + procNetUnixPath + " 2>/dev/null);",
		"case \"$proc_cand\" in *\" $p \"*) proc_live=yes;; esac;",
		"if [ \"$proc_live\" = no ] && [ -n \"$np\" ] && [ \"$np\" != \"$p\" ]; then case \"$proc_cand\" in *\" $np \"*) proc_live=yes;; esac; fi;",
		"fi;",
		"if [ \"$proc_live\" = yes ]; then echo " + socketLiveMarker + ";",
		"elif command -v ss >/dev/null 2>&1; then",
		// `ss`的退出状态随其输出一起带回而非存进变量:管道只报最后一条命令的状态,
		// 要单独拿`ss`的状态就得先存下整张表;探针把状态作为表后一行打印,与表一起被`grep`捞出.
		"ss_cand=$( { LC_ALL=C ss -xl 2>/dev/null; printf '\\n%s=%s\\n' " + ssStatusTag + " \"$?\"; } " +
			"| cand \"$p\" \"$np\" -e '" + ssStatusTag + "=' -e 'Netid State ' );",
		"ss_ok=no; case \"$ss_cand\" in *\"" + ssStatusTag + "=0 \") ss_ok=yes;; esac;",
		"ss_table=no; case \"$ss_cand\" in *'Netid State '*) ss_table=yes;; esac;",
		"ss_live=no; case \"$ss_cand\" in *\" $p \"*) ss_live=yes;; esac;",
		"if [ \"$ss_live\" = no ] && [ -n \"$np\" ] && [ \"$np\" != \"$p\" ]; then case \"$ss_cand\" in *\" $np \"*) ss_live=yes;; esac; fi;",
		"if [ \"$ss_live\" = yes ]; then echo " + socketLiveMarker + ";",
		"elif [ -z \"$np\" ]; then echo " + socketUnresolvedMarker + ";",
		"elif [ \"$ss_ok\" = no ] || [ \"$ss_table\" = no ] || [ \"$proc_table\" = no ]; then echo " + socketUnknownMarker + ";",
		leftoverArm,
		"else echo " + socketUnknownMarker + "; fi;",
		"else echo " + socketNotASocketMarker + "; fi;",
		"else echo " + socketAbsentMarker + "; fi",
	}, " ")
	return "sh -c " + shellQuoteSingle(script)
}

// 询问远端path处有什么并按reclaim的限度行动.
// 活socket(远端agent或他人同路径)与非socket文件不碰;判明需两路证据,
// 缺一路,失败或答的不是表都算没答.一路为何不够,遗留为何默认只报不删,详见`remoteSocketProbe`.
// 状态仅在error为nil时有意义:判不出来返回`socketUnjudgeable`.
func probeRemoteSocket(sshArgs []string, remoteSocket string, reclaim reclaimPolicy, run SSHCommandRunner) (remoteSocketState, error) {
	out, err := run(sshArgs, remoteSocketProbe(remoteSocket, reclaim))
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
		case socketStaleMarker:
			return socketStale, nil
		case socketLiveMarker:
			return socketLive, nil
		case socketNotASocketMarker:
			return socketNotASocket, nil
		case socketStuckMarker:
			return socketStuck, nil
		case socketUnknownMarker:
			return socketUnjudgeable, nil
		case socketUnresolvedMarker:
			return socketUnresolved, nil
		case socketSymlinkMarker:
			return socketSymlink, nil
		}
	}
	// 一行判定都没有:探针没按预期跑起来(无`sh`,登录shell解析不了,输出被过滤).
	// 没删东西但也没查东西,是独立判定而非"free",由调用方定夺,详见`CheckRemoteSocketFree`.
	return socketUnreported, nil
}

// 让sshd即将绑定的远端路径可用,不可用则说明原因.
// 活socket属于远端自己的gpg-agent:转发时sshd的`StreamLocalBindUnlink`会顶掉它占位,
// gpg便静默连上别的agent,故拒绝覆盖.无人监听的遗留由调用方(reclaim)决定删不删:
// 证据只管一个网络命名空间,默认`keepLeftover`停下引导,`reclaimLeftover`删除后放行.
// 仅error为nil才放行;判不出来(问不到,解不了路径,读不了表)一律拒绝并带`--skip-remote-check`.
func CheckRemoteSocketFree(sshArgs []string, remoteSocket string, reclaim reclaimPolicy, run SSHCommandRunner) (remoteSocketState, error) {
	state, err := probeRemoteSocket(sshArgs, remoteSocket, reclaim, run)
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
	case socketStale:
		return state, fmt.Errorf(
			"a socket nothing is listening on is left at %s on the remote host, and it is not removed unless you ask for that.\n"+
				"  The evidence that it is dead comes from that host's own socket tables, and those describe one network\n"+
				"  namespace: an agent in a container that shares the directory is absent from both of them, so removing\n"+
				"  the file would take a socket that is in use away from it.\n"+
				"  Remove it there if nothing else is using it:\n"+
				"      rm -f -- %s\n"+
				"  or pass --reclaim-remote-socket to have gpg-agent-forward remove it and start the session.",
			remoteSocket, shellQuoteSingle(remoteSocket))
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
	case socketUnresolved:
		return state, fmt.Errorf(
			"could not work out what %s on the remote host resolves to, so whether the path is in use cannot be told there.\n"+
				"  The path is matched under the spelling its listener would have bound as well as the one given, and the\n"+
				"  host could not do that resolution: readlink -f and realpath both failed on the directory, or answered\n"+
				"  something that is not the same file. Nothing was removed.\n"+
				"  Pass --remote-socket PATH to use a different path, or --skip-remote-check to start without the check\n"+
				"  and accept that sshd may bind over a live agent socket.",
			remoteSocket)
	default: // socketUnjudgeable:远端没回答本检查所问的问题
		return state, fmt.Errorf(
			"could not tell whether %s on the remote host is in use: the host could not answer the questions the check turns on.\n"+
				"  This is the verdict when ss is missing, fails, or prints something that is not a socket table,\n"+
				"  when the kernel's /proc/net/unix cannot be read there - the probe reads those tables with grep\n"+
				"  and sed, so a host without them answers the same way - and when the host's printf does not read\n"+
				"  the \\NNN escapes the path travels as, which leaves the probe with no path to ask about.\n"+
				"  Nothing was removed.\n"+
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
