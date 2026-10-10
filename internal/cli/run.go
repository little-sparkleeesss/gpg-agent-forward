package cli

import (
	"bytes"
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
  --idle DURATION      serve only: exit after this long with no connection
                       (default 15m; 0 disables)
  --remote-socket PATH ssh only: socket path to create on the remote host
                       (default: whatever gpgconf --list-dirs agent-socket reports)

The relay exposes the agent's *extra* socket, which GnuPG documents for
exactly this remote-forwarding case. It permits signing and decryption, and
refuses key import, export, deletion and generation, passphrase presetting,
and trust or event queries. Passphrase prompts and any card touch confirmation
still appear on the Windows desktop, so a PIN never crosses the SSH link.
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
	if err := fs.Parse(own); err != nil {
		return err
	}
	if err := ValidatePort(*port); err != nil {
		return err
	}
	if len(sshArgs) == 0 {
		return errors.New("ssh: no destination given (use: gpg-agent-forward ssh [ssh args] host)")
	}

	// 远端agent socket路径要问出来而不是猜: 它取决于远端uid和是否用非默认
	// homedir; 猜错会让gpg走远端自己的agent, 拿远端密钥签名却像是成功.
	if *remoteSocket == "" {
		discovered, err := DiscoverRemoteSocket(sshArgs, runSSHQuery)
		if err != nil {
			return err
		}
		*remoteSocket = discovered
	}
	if err := ValidateRemoteSocket(*remoteSocket); err != nil {
		return err
	}

	// 拒绝覆盖远端主机自己的agent socket: 否则首次连接会顺带启动那个agent,
	// 再替换其活动socket, gpg会静默用远端密钥签名.
	if err := CheckRemoteSocketFree(sshArgs, *remoteSocket, runSSHCommand); err != nil {
		return err
	}

	stopRelay, err := EnsureRelay(selfExe(), *socketFile, *port, 0)
	if err != nil {
		return err
	}
	// relay无法感知ssh何时退出, 把它的生命周期绑到本次会话:
	// 活过会话的relay会留下指向空的远端socket.
	if stopRelay != nil {
		defer stopRelay()
	}

	cmd := exec.Command("ssh", BuildSSHArgs(sshArgs, *remoteSocket, *port)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, stderr
	fmt.Fprintf(stderr, "gpg-agent-forward: remote socket %s -> 127.0.0.1:%d\n", *remoteSocket, *port)

	// 把终止信号转发给ssh, 否则信号下deferred stopRelay不执行, relay会残留.
	stopSignals := forwardSignals(cmd)
	defer stopSignals()
	return cmd.Run()
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

// 端口有监听不等于relay在运行: 还要身份锁被持有 (详见relaylock), 否则会把陌生进程当成relay.
// stop为nil即复用了已有relay, 不归本次停.
// idle原样传给relay: ssh传0 (relay无法感知ssh会话何时结束), ensure用用户的`--idle`.
func EnsureRelay(exePath, socketFile string, port int, idle time.Duration) (func(), error) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	// 身份锁能否使用是机器的属性而非每次轮询的属性, 所以只探测一次.
	canLock := relaylock.CanLock()
	if relayRunning(addr, canLock) {
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
	// 捕获子进程输出, 让relay没能开始监听成为可诊断的错误而不是死路.
	var childOut bytes.Buffer
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
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
			}
		})
		// 给OS一点时间释放端口, 让立刻重连能重新绑定.
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if !Probe(addr) {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	for i := 0; i < 100; i++ {
		if relayRunning(addr, canLock) {
			return stop, nil
		}
		// 子进程一退出就返回, 让relay自己的校验失败立刻带自己的消息上报,
		// 而不是等满超时再报误导性的未开始监听.
		select {
		case <-exited:
			stop()
			return nil, relayStartError(addr, filepath.Base(exePath), childOut.String(), waitErr)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-exited:
		stop()
		return nil, relayStartError(addr, filepath.Base(exePath), childOut.String(), waitErr)
	default:
	}
	stop()
	return nil, fmt.Errorf("relay did not begin listening on %s", addr)
}

// 判断addr上监听的是不是relay本身, 而不只是占着端口的东西.
// `canLock`为假时退化成只dial: 平台不支持身份锁就拒绝启动会废掉工具.
func relayRunning(addr string, canLock bool) bool {
	if !Probe(addr) {
		return false
	}
	return relaylock.Held(addr) || !canLock
}

func relayStartError(addr, exeName, output string, waitErr error) error {
	msg := strings.TrimSpace(output)
	if msg == "" {
		if waitErr != nil {
			return fmt.Errorf("relay exited before listening on %s: %v", addr, waitErr)
		}
		return fmt.Errorf("relay exited immediately; run %q to see why", exeName+" serve")
	}
	return fmt.Errorf("relay exited before listening on %s: %s", addr, msg)
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

// 平台没有信号时返回no-op.
func forwardSignals(cmd *exec.Cmd) func() {
	return forwardSignalsImpl(cmd)
}
