package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gpg-agent-forward/internal/nonce"
	"gpg-agent-forward/internal/relay"
	"gpg-agent-forward/internal/relaylock"
)

const (
	exitOK    = 0
	exitError = 1
)

// `args`不含程序名.
func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("no command given")
	}
	switch args[0] {
	case "--help", "-h", "help":
		printUsage(stdout)
		return nil
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "ssh":
		return runSSH(args[1:], stdout, stderr)
	case "ensure":
		return runEnsure(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr)
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `gpg-agent-forward - use a Windows gpg-agent (YubiKey) from a remote Linux host

Usage:
  gpg-agent-forward serve  [options]      run the relay (started on demand, exits when idle)
  gpg-agent-forward ssh    [ssh args...]  run ssh with the agent forwarding enabled
  gpg-agent-forward ensure [options]      start the relay only if it is not already running
  gpg-agent-forward doctor [options]      check the agent socket and the peer check

Common options:
  --socket-file PATH   Windows gpg-agent socket file
                       (default %LOCALAPPDATA%\gnupg\S.gpg-agent.extra)
  --port N             loopback port used between the relay and ssh
                       (default 29173)
  --idle DURATION      serve/ensure: exit after this long with no connection
                       (default 15m; 0 disables)
                       ssh accepts this option and ignores it: a relay used by
                       an ssh session is always started with the idle timeout
                       disabled, and its lifetime is tied to the session
  --remote-socket PATH ssh only: socket path to create on the remote host
                       (default: whatever gpgconf --list-dirs agent-socket reports)
  --skip-remote-check  ssh only: start the session even when the remote host
                       could not be asked about that path

The relay exposes the agent's *extra* socket, which GnuPG documents for
exactly this remote-forwarding case. It permits signing and decryption, and
refuses key import, export, deletion and generation, passphrase presetting,
and trust or event queries. Passphrase prompts and any card touch confirmation
still appear on the Windows desktop, so a PIN never crosses the SSH link.

A socket that nothing is listening on at the remote path is a leftover from a
finished session, and it blocks the next one. gpg-agent-forward removes it before the
session starts, so a finished session does not have to be cleaned up by hand.

What it asks before removing anything is the remote host itself, not its socket
tables. The check creates a socket next to the path and has the host connect to
it, twice: once on a socket the check owns, to prove that this host on this
connection permits such a connection at all, and once on the path itself. A
connection that stays open and silent is a live listener, and the session
stops: the path belongs to that host's own agent, and forwarding onto it would
make gpg follow the wrong agent. A connection that closes without an answer,
with that control in hand, is a leftover, and it is removed. The path is never
removed when it cannot be written, when it is not a socket, or when the host
cannot be asked or cannot answer - those all stop the session, and each error
carries the way to deal with it. --skip-remote-check is how a session starts
anyway when the host could not be asked or could not answer; it is no answer to
a path your user there cannot write, where a refused connect and a socket
nothing is listening on read the same, and the point is to stop rather than
guess. Do not clear such a path by hand: something may be listening on it.
`)
}

type serveOptions struct {
	socketFile string
	port       int
	idle       time.Duration
}

func addServeFlags(fs *flag.FlagSet, opts *serveOptions) {
	fs.StringVar(&opts.socketFile, "socket-file", defaultSocketFile(), "Windows gpg-agent socket file")
	fs.IntVar(&opts.port, "port", DefaultRelayPort, "loopback port for ssh to dial")
	fs.DurationVar(&opts.idle, "idle", 15*time.Minute, "exit after this long with no connection; 0 disables")
}

func runServe(args []string, stdout, stderr io.Writer) error {
	var opts serveOptions
	fs := newFlagSet("serve", stderr)
	addServeFlags(fs, &opts)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := ValidatePort(opts.port); err != nil {
		return err
	}
	if opts.socketFile == "" {
		return errors.New("--socket-file is required")
	}
	// 启动时解析socket文件而非只stat: 格式错误立刻报错而不是拖到每次连接;
	// 连不到agent的relay会让ssh转发看似正常, 每次签名却都失败.
	if err := validateSocketFile(opts.socketFile); err != nil {
		return err
	}

	r, err := relay.New(relay.Config{
		ListenAddr:  fmt.Sprintf("127.0.0.1:%d", opts.port),
		SocketFile:  opts.socketFile,
		IdleTimeout: opts.idle,
		AllowPeer:   allowPeer,
		Logger:      newLogger(stderr),
	})
	if err != nil {
		return err
	}
	defer r.Close()

	fmt.Fprintf(stdout, "listening on %s, agent socket %s\n", r.Addr(), opts.socketFile)
	err = r.Serve()
	if errors.Is(err, relay.ErrIdle) {
		fmt.Fprintln(stdout, "idle timeout reached, exiting")
		return nil
	}
	return err
}

func runEnsure(args []string, stdout, stderr io.Writer) error {
	var opts serveOptions
	fs := newFlagSet("ensure", stderr)
	addServeFlags(fs, &opts)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := ValidatePort(opts.port); err != nil {
		return err
	}
	_, err := EnsureRelay(selfExe(), opts.socketFile, opts.port, opts.idle)
	return err
}

func runSSH(args []string, stdout, stderr io.Writer) error {
	own, sshArgs := SplitSSHArgs(args)

	fs := newFlagSet("ssh", stderr)
	socketFile := fs.String("socket-file", defaultSocketFile(), "Windows gpg-agent socket file")
	port := fs.Int("port", DefaultRelayPort, "loopback port for ssh to dial")
	remoteSocket := fs.String("remote-socket", "",
		"socket path to create on the remote host (default: ask the remote for `gpgconf --list-dirs agent-socket`)")
	skipRemoteCheck := fs.Bool("skip-remote-check", false,
		"start the session even when the remote host could not be checked for a live socket at that path")
	// idle选项被接受但忽略: ssh会话用的relay总是禁用idle, 因为relay无法感知
	// 会话结束; 这里必须消费掉它, 否则会透传给ssh而被它拒绝, 会话根本起不来.
	fs.Duration("idle", 0,
		"accepted and ignored: a relay serving an ssh session is always started with the idle timeout disabled")
	if err := fs.Parse(own); err != nil {
		return err
	}
	if err := ValidatePort(*port); err != nil {
		return err
	}
	if len(sshArgs) == 0 {
		return errors.New("ssh: no destination given (use: gpg-agent-forward ssh [ssh args] host)")
	}

	// 远端agent socket路径要问不要猜: 取决于远端uid和非默认homedir, 猜错让gpg用远端密钥签名却像是成功.
	// 本命令多开的两条连接都在跑之前往stderr打一行: ssh的主机密钥确认与口令提示写到/dev/tty.
	// 提示不落在被捕获的流里, 出现时没有别的迹象说明是谁在问.
	// 这些写未加锁, 只在这里安全: watchdog要到relay才起, 信号转发更晚.
	if *remoteSocket == "" {
		fmt.Fprintf(stderr, "gpg-agent-forward: asking the remote host where its agent socket is (ssh may prompt; the check gives up after %s)\n", sshQueryTimeout)
		discovered, err := DiscoverRemoteSocket(sshArgs, runSSHQuery)
		if err != nil {
			return err
		}
		*remoteSocket = discovered
	}
	if err := ValidateRemoteSocket(*remoteSocket); err != nil {
		return err
	}

	// 拒绝覆盖远端主机自己的agent socket: 否则首次连接会顺带启动那个agent, gpg会静默用远端密钥签名.
	// 无人监听的socket是残留, 挡着bind又没服务, 这里删掉会话才能起.
	// 判据是远端主机本身: 回连无应答且有对照连接证明这类连接被允许才算残留 (详见classifyRemoteSocket).
	// 问不到或答不了就拒绝, 不检查正像sshd那样覆盖活动agent socket; `--skip-remote-check`明知风险放行.
	fmt.Fprintf(stderr, "gpg-agent-forward: checking what is at %s on the remote host (ssh may prompt; the check gives up after %s)\n", *remoteSocket, sshQueryTimeout)
	remoteState, err := CheckRemoteSocketFree(sshArgs, *remoteSocket, runSSHCommand)
	if err != nil {
		// 该flag只覆盖没能做成的检查: 已经给出结论的状态, flag说什么都拒绝.
		if !(*skipRemoteCheck && remoteState.maySkipRemoteCheck()) {
			return err
		}
		// 检查没能定论的东西正是用户判断要不要继续所需的, 所以打印出来而不是被flag吞掉.
		fmt.Fprintf(stderr, "gpg-agent-forward: --skip-remote-check: starting without a verdict:\n  %v\n", err)
	} else if remoteState == socketReclaimed {
		fmt.Fprintf(stderr, "gpg-agent-forward: removed a leftover socket nothing was listening on at %s on the remote host\n", *remoteSocket)
	}

	// 从这里起的诊断 (下面这行, ssh的stderr, watchdog) 都走同一把锁,
	// 调用方传入的writer不必自己保证并发安全.
	errOut := &syncWriter{w: stderr}

	stopRelay, err := EnsureRelay(selfExe(), *socketFile, *port, 0)
	if err != nil {
		return err
	}
	// relay无法感知ssh何时退出, 把它的生命周期绑到本次会话, 免得留下指向空的远端socket.
	// 复用的relay不归本次调用停 (stopRelay为nil), 但会话全程都需要本端口有监听;
	// 复用的relay可能按自己的idle超时退出, 所以watchdog会重启它并接管它启动的那个.
	keepAlive := newRelayKeepAlive(selfExe(), *socketFile, *port, stopRelay, errOut)
	keepAlive.start()
	defer keepAlive.shutdown()

	cmd := exec.Command("ssh", BuildSSHArgs(sshArgs, *remoteSocket, *port)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, errOut
	// ssh消失后限制等其输出管道的时间: 否则持有管道的ssh后代 (ProxyCommand,
	// wrapper, sshd fork的守护进程) 会决定会话何时结束, 收尾得等它.
	// 值与一次性远端命令相同 (详见sshWaitDelay), 代价也一样: 超出该时间的后代输出会丢.
	cmd.WaitDelay = sshWaitDelay
	fmt.Fprintf(errOut, "gpg-agent-forward: remote socket %s -> 127.0.0.1:%d\n", *remoteSocket, *port)

	// 把终止信号转发给ssh, 否则信号下deferred keepAlive.shutdown不执行, relay会残留.
	// handler先于ssh启动装好, 进程一存在就交给它 (详见signalForwarder).
	// 装晚了, 窗口里的信号会按默认动作结束本进程并留下relay和ssh; 交早了则会读到Start正在写的东西.
	signals := forwardSignals()
	defer signals.stop()
	sessionErr := runSessionSSH(cmd, signals)

	// 会话结束, 为它动作的这两样随之收摊, 而不是留给deferred调用.
	// watchdog会为没人要的会话补起relay, 之后只有deferred shutdown能再杀掉它.
	// 信号转发未撤: 已消费SIGINT/SIGTERM/SIGHUP而ssh已退出, teardown期间的kill会被吞掉; 两者幂等.
	signals.stop()
	keepAlive.shutdown()

	return sessionErr
}

// 跑会话的ssh命令, 把进程交给信号转发, 返回会话结果 (正常结束为nil, 否则ssh的错误).
// 分启动和等待两步而不是`cmd.Run`, 是为了进程一存在就交给转发者: 让它自己读`Process`
// 字段是在读`Start`正写的东西 (数据竞争), 还可能读早了丢掉窗口里的信号.
func runSessionSSH(cmd *exec.Cmd, signals signalForwarder) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	signals.attach(cmd.Process)

	err := cmd.Wait()
	// ssh退0, 但它的后代仍占着exec为ssh建的stderr管道, Wait在WaitDelay后关掉
	// 管道并以ErrWaitDelay代替状态; 退0的会话是正常结束的, 活过它的后代不是会话本身.
	// 报成失败会给成功的会话打错误并让CLI非零退出; ErrWaitDelay只代替成功状态, 不掩盖真实失败.
	if errors.Is(err, exec.ErrWaitDelay) {
		return nil
	}
	return err
}

func validateSocketFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("socket file %s: %w", path, err)
	}
	if _, err := nonce.Parse(data); err != nil {
		return fmt.Errorf("socket file %s: %w", path, err)
	}
	return nil
}

// 接受条件: 身份锁被持有且元数据记的正是本次要的socket文件 (详见relayForSocketFile).
// stop为nil即复用relay, 不归本次停; 同socket文件就复用, 有限idle由watchdog补 (详见relayKeepAlive).
// idle原样传给relay: ssh传0 (relay无法感知会话结束), ensure用用户的`--idle`.
func EnsureRelay(exePath, socketFile string, port int, idle time.Duration) (func(), error) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	reusable, err := relayForSocketFile(addr, socketFile)
	if err != nil {
		return nil, err
	}
	if reusable {
		return nil, nil
	}
	if socketFile == "" {
		return nil, errors.New("socket file path is required to start the relay")
	}
	args := []string{
		"serve",
		"--socket-file", socketFile,
		"--port", fmt.Sprint(port),
		"--idle", idle.String(),
	}
	cmd := startDetached(exePath, args)
	// 限制Wait阻塞在子进程输出管道上的时间, 免得收尾被拖到下面的兜底超时:
	// relay (或它派生的进程) 若继承并抓着stdout/stderr不放, Wait等的就是它而不是relay.
	cmd.WaitDelay = 200 * time.Millisecond
	// 捕获子进程输出, 让启动失败可诊断而不是无迹可寻.
	// 必须有界: relay可能多活数小时且每连接一行日志, 无上限会一直涨.
	var childOut boundedBuffer
	cmd.Stdout = &childOut
	cmd.Stderr = &childOut
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start relay: %w", err)
	}

	// 只起一个`Wait` goroutine管子进程一生: `ProcessState`只有`Wait`才填充,
	// 它兼顾发现提前退出与回收被杀进程; 调用两次`Wait`会竞争.
	exited := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(exited)
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			if cmd.Process == nil {
				return
			}
			_ = cmd.Process.Kill()
			// 通常WaitDelay远早于下面的兜底结束等待; 兜底只覆盖Wait永不返回.
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
			}
			// 给OS一点时间释放端口, 让立刻重连能重新绑定; 上限远低于上面的Wait超时:
			// 端口若还被残留reader占着, 多等只是拖住已经用完这个relay的调用方.
			deadline := time.Now().Add(500 * time.Millisecond)
			for time.Now().Before(deadline) {
				if !Probe(addr) {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}

	for i := 0; i < 100; i++ {
		// 子进程一退出就返回, 让relay自己的校验失败立刻带自己的消息上报,
		// 而不是等满超时再报误导性的未开始监听.
		select {
		case <-exited:
			stop()
			// 子进程抢端口失败时, 端口可能已被一个正为这个socket文件服务的relay拿走;
			// 那正是本次调用想要的, 直接复用而不是报错让调用方再重试.
			if adoptIfAppeared(addr, socketFile) {
				return nil, nil
			}
			return nil, relayStartError(addr, filepath.Base(exePath), childOut.String(), waitErr)
		default:
		}
		// 子进程算作已启动的条件与复用relay相同: 有应答, 锁被持有, 元数据记的正是本次要的socket文件.
		// 若只认监听加锁, 就会在端口被别的调用抢走时转发到别的agent的socket, 并在结束时杀掉那个relay.
		// 元数据在子进程写入期间短暂不可读, 所以锁不可读只是推迟接受而不是立刻失败.
		if reusable, _ := relayForSocketFile(addr, socketFile); reusable {
			return stop, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-exited:
		stop()
		if adoptIfAppeared(addr, socketFile) {
			return nil, nil
		}
		return nil, relayStartError(addr, filepath.Base(exePath), childOut.String(), waitErr)
	default:
	}
	stop()
	return nil, fmt.Errorf("relay did not begin listening on %s", addr)
}

// 判断`addr`上监听的是不是relay本身; 身份锁是唯一证据, 锁不在就不是我们的.
func relayRunning(addr string) bool {
	return Probe(addr) && relaylock.Held(addr)
}

// 身份锁无人持有时不报错也不复用: 端口要么空闲要么被占, 起自己的relay是调用方的事.
// 复用条件与子进程启动后的等待故意相同: 有应答不够, 它可能是别的调用为别的agent起的relay.
func relayForSocketFile(addr, socketFile string) (bool, error) {
	if !relayRunning(addr) {
		return false, nil
	}
	info, ok := relaylock.ReadInfo(addr)
	if !ok {
		// 锁被持有但不可读: relay在, 但没说它转发到哪个agent, 复用它就是猜.
		return false, fmt.Errorf(
			"a relay is listening on %s but its identity lock carries no readable metadata; stop it before starting another",
			addr)
	}
	if !sameSocketFile(info.SocketFile, socketFile) {
		return false, fmt.Errorf(
			"a relay is listening on %s for socket file %s, not %s; stop it before starting another",
			addr, info.SocketFile, socketFile)
	}
	return true, nil
}

// 看`socketFile`的relay现在是否已在`addr`上监听, 并短暂等待尚在抢占身份锁的那个.
// 覆盖的竞态: 本次子进程抢端口失败, 但抢到的可能正是为这个socket文件服务的
// relay, 那正是调用方想要的; 等待有上限, 通常到这里时它已认领完锁.
func adoptIfAppeared(addr, socketFile string) bool {
	deadline := time.Now().Add(400 * time.Millisecond)
	for {
		if reusable, _ := relayForSocketFile(addr, socketFile); reusable {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// 故意不解析符号链接: 经链接到达同一文件的两个路径保持不同,
// 否则会悄悄接受一个转发到别的文件的relay.
func cleanSocketFile(p string) string {
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return filepath.Clean(p)
}

// 作为变量是为了测试不必等真实间隔.
var relayWatchInterval = 3 * time.Second

// 会话有两条goroutine同时写诊断 (watchdog与复制ssh stderr的那条),
// 而`Run`接受任意`io.Writer`, 调用方的writer不保证并发安全.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// ssh会话全程在远端发布着relay的端口, 监听者不能中途消失: 本次启动的relay
// 已禁用idle, 而复用的那个可能来自带有限idle的`serve`或`ensure`, 到期退出会让
// 远端socket指向空; 这里盯着端口, 一消失就补一个 (idle禁用).
type relayKeepAlive struct {
	exe        string
	socketFile string
	port       int
	warn       io.Writer

	mu sync.Mutex
	// 本会话启动的relay的stop函数, 会话结束时必须停它; 用别人的relay时为nil.
	owned func()

	doneOnce sync.Once
	done     chan struct{}
	wg       sync.WaitGroup
}

func newRelayKeepAlive(exePath, socketFile string, port int, owned func(), warn io.Writer) *relayKeepAlive {
	return &relayKeepAlive{
		exe:        exePath,
		socketFile: socketFile,
		port:       port,
		warn:       warn,
		owned:      owned,
		done:       make(chan struct{}),
	}
}

func (k *relayKeepAlive) start() {
	k.wg.Add(1)
	go func() {
		defer k.wg.Done()
		ticker := time.NewTicker(relayWatchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-k.done:
				return
			case <-ticker.C:
				k.replaceRelayIfGone()
			}
		}
	}()
}

// 停掉watchdog, 再停本会话启动的那个relay; 复用的不动 (不归本次停).
// 幂等, 恰好停一次.
func (k *relayKeepAlive) shutdown() {
	k.doneOnce.Do(func() { close(k.done) })
	k.wg.Wait()
	k.mu.Lock()
	stop := k.owned
	k.owned = nil
	k.mu.Unlock()
	if stop != nil {
		stop()
	}
}

func (k *relayKeepAlive) replaceRelayIfGone() {
	select {
	case <-k.done:
		// 会话正在结束, 不要再给它起relay.
		return
	default:
	}
	addr := fmt.Sprintf("127.0.0.1:%d", k.port)
	if relayRunning(addr) {
		return
	}
	fmt.Fprintf(k.warn, "gpg-agent-forward: relay is no longer listening on %s, starting a replacement with the idle timeout disabled\n", addr)
	stop, err := EnsureRelay(k.exe, k.socketFile, k.port, 0)
	if err != nil {
		// 端口可能只是暂时不可用, 下一次轮询再试.
		fmt.Fprintf(k.warn, "gpg-agent-forward: could not restart the relay on %s: %v\n", addr, err)
		return
	}
	if stop == nil {
		// 别的调用的relay在这期间占了端口并被复用, 不归本次停.
		return
	}
	select {
	case <-k.done:
		// 替换relay启动期间会话结束了, 这个relay白起了, 就地停掉别留下.
		stop()
		return
	default:
	}
	k.mu.Lock()
	k.owned = stop
	k.mu.Unlock()
}

// 只保留最近的字节: relay可能跑数小时后才死, 死因在后几行而不是开头.
const maxRelayLogBytes = 8 << 10

// 收集writer输出到固定上限, 超出后丢弃最旧的, 长命子进程不会撑大本进程.
// 可并发写: exec分两个goroutine复制stdout和stderr.
type boundedBuffer struct {
	mu     sync.Mutex
	buf    []byte
	cutoff bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > maxRelayLogBytes {
		b.cutoff = true
		// 取尾部时新建切片而非reslice, 一次大写入才不会把整块旧缓冲区一起吊住.
		kept := make([]byte, maxRelayLogBytes)
		copy(kept, b.buf[len(b.buf)-maxRelayLogBytes:])
		b.buf = kept
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.cutoff {
		return string(b.buf)
	}
	return "[earlier output truncated]\n" + string(b.buf)
}

// 带上wait错误, 让被信号杀死的进程与干净退出的可区分.
func relayStartError(addr, exeName, output string, waitErr error) error {
	status := ""
	if waitErr != nil {
		status = fmt.Sprintf(" (%v)", waitErr)
	}
	msg := strings.TrimSpace(output)
	if msg == "" {
		return fmt.Errorf("relay exited before listening on %s%s; run %q to see why",
			addr, status, exeName+" serve")
	}
	return fmt.Errorf("relay exited before listening on %s%s: %s", addr, status, msg)
}

func Probe(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

var (
	// 这两个变量是接缝, 便于测试替换peer检查与子进程启动.
	allowPeerHook = func(net.Conn) error { return nil }
	startHook     = func(exePath string, args []string) *exec.Cmd {
		return exec.Command(exePath, args...)
	}
)

// 交给relay的peer检查; Windows上由平台实现在init时替换.
func allowPeer(c net.Conn) error { return allowPeerHook(c) }

// 启动子进程, 使其在本进程退出后仍存活.
func startDetached(exePath string, args []string) *exec.Cmd { return startHook(exePath, args) }

func selfExe() string {
	p, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return p
}

// 信号转发器: handler先装好, 进程存在后再交给它, 顺序不能反.
// 装晚了, 信号按默认动作直接结束本进程, 刚起的relay和ssh被留下, 远端还指着没人应答的socket.
// 交早了 (会话从前这么做) 是读`Process`与`Start`写它的数据竞争, 还会丢掉窗口里要求结束会话的信号.
type signalForwarder interface {
	// 把调用方已启动的会话进程交给转发器: 此前到达的信号会立刻补投, 使ssh启动期间
	// 落下的信号与晚一点到达的效果相同.必须在stop前调用一次, 传Start成功返回的进程.
	attach(p *os.Process)
	// 结束转发, 让信号恢复默认动作, 不在转发目标已消失时被吞掉;
	// 幂等, 会话收尾可以显式调用, deferred的调用仍可跟在后面.
	stop()
}

// 安装终止信号的handler并返回其转发器; 平台没有信号时返回no-op.
func forwardSignals() signalForwarder { return forwardSignalsImpl() }
