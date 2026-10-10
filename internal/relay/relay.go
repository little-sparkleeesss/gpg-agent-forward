// Package `relay`把loopback TCP监听桥接到Windows `gpg-agent`: libassuan的nonce模拟与文件格式
// 详见`nonce`. SSH远端转发只能拨TCP host:port, 无法做nonce握手, 到不了agent.
// 监听地址取自调用方配置, 每个连接都重读socket文件, 拨号agent并重放nonce, 再双向原样拷贝字节.
package relay

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"gpg-agent-forward/internal/nonce"
	"gpg-agent-forward/internal/relaylock"
)

type Config struct {
	// SSH拨号的地址, 必须为字面loopback: relay拒绝把agent暴露到其他接口.
	ListenAddr string
	// Windows `gpg-agent`socket文件: 内含当前loopback端口与nonce, 例如
	// `%LOCALAPPDATA%\gnupg\S.gpg-agent.extra`.
	SocketFile string
	// 非nil时在nonce读写前审查每个连接, 返回错误即断开. Windows上用它要求
	// 对端是同一用户的`ssh.exe`, 补偿入口点丢失的文件系统权限.
	AllowPeer func(net.Conn) error
	// 正数时: 空闲(无连接在飞)超过该时长, `Serve`返回`ErrIdle`; 0禁用.
	// tunnel按需启动而非登录时起, 不应闲置不退.
	IdleTimeout time.Duration
	Logger      *log.Logger
}

// relay因闲置(超`Config.IdleTimeout`)关闭时由`Serve`返回; 对调用方不是错误.
var ErrIdle = errors.New("relay: idle timeout reached")

type Relay struct {
	cfg     Config
	ln      net.Listener
	log     *log.Logger
	once    sync.Once
	release func() // 释放身份锁; 锁不可用时为nil

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	// 最后转为全空闲的时刻(并非最后活跃时刻).
	lastActive time.Time
}

// `New`在`ListenAddr`不是字面loopback时返回: 否则agent会暴露给其他主机.
var ErrNotLoopback = errors.New("relay: listen address must be a literal loopback address")

// 创建时立刻绑定监听器: 端口冲突当场报给调用方, 而不是留到之后才发现.
func New(cfg Config) (*Relay, error) {
	if err := checkLoopback(cfg.ListenAddr); err != nil {
		return nil, err
	}
	if cfg.SocketFile == "" {
		return nil, errors.New("relay: SocketFile is required")
	}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("relay: listen on %s: %w", cfg.ListenAddr, err)
	}
	// 以实际绑定地址为键取身份锁: 供调用方区分本relay与冒名占端口者;
	// 拿不到锁不致命, relay照常服务, 只是无法与冒名者区分.
	release, ok := relaylock.TryLock(ln.Addr().String())
	if !ok {
		release = nil
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &Relay{
		cfg:        cfg,
		ln:         ln,
		log:        logger,
		release:    release,
		conns:      make(map[net.Conn]struct{}),
		lastActive: time.Now(),
	}, nil
}

// 只接受字面loopback IP; 有意拒绝主机名: 解析会让绑定地址取决于resolver,
// 被篡改的hosts文件可把agent入口点挪出本机.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrNotLoopback, addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: %s", ErrNotLoopback, addr)
	}
	return nil
}

func (r *Relay) Addr() net.Addr { return r.ln.Addr() }

func (r *Relay) Serve() error {
	// 给监听器设deadline把`Accept`变成轮询, 以便定期复查闲置条件.
	if r.cfg.IdleTimeout > 0 {
		interval := r.cfg.IdleTimeout / 4
		if interval <= 0 {
			interval = r.cfg.IdleTimeout
		}
		if err := r.ln.(*net.TCPListener).SetDeadline(time.Now().Add(interval)); err != nil {
			return fmt.Errorf("relay: set accept deadline: %w", err)
		}
	}

	for {
		c, err := r.ln.Accept()
		if err != nil {
			if r.isClosed() {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if r.idleExpired() {
					r.Close()
					return ErrIdle
				}
				if r.cfg.IdleTimeout > 0 {
					interval := r.cfg.IdleTimeout / 4
					if interval <= 0 {
						interval = r.cfg.IdleTimeout
					}
					r.ln.(*net.TCPListener).SetDeadline(time.Now().Add(interval))
				}
				continue
			}
			return fmt.Errorf("relay: accept: %w", err)
		}
		if !r.track(c) {
			c.Close()
			return nil
		}
		go func() {
			defer r.untrack(c)
			r.handle(c)
		}()
	}
}

func (r *Relay) idleExpired() bool {
	if r.cfg.IdleTimeout <= 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns) == 0 && time.Since(r.lastActive) >= r.cfg.IdleTimeout
}

func (r *Relay) Close() error {
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		conns := make([]net.Conn, 0, len(r.conns))
		for c := range r.conns {
			conns = append(conns, c)
		}
		r.mu.Unlock()

		r.ln.Close()
		if r.release != nil {
			r.release()
		}
		for _, c := range conns {
			c.Close()
		}
	})
	return nil
}

func (r *Relay) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func (r *Relay) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

func (r *Relay) untrack(c net.Conn) {
	r.mu.Lock()
	c.Close()
	delete(r.conns, c)
	if len(r.conns) == 0 {
		// 连接清空时重启闲置时钟: 短连接突发保持tunnel存活, 真正空闲才退出.
		r.lastActive = time.Now()
	}
	r.mu.Unlock()
}

// 服务单个客户端; 失败靠关连接上报, 这是agent不可达时gpg期望的行为.
func (r *Relay) handle(client net.Conn) {
	defer client.Close()

	if r.cfg.AllowPeer != nil {
		if err := r.cfg.AllowPeer(client); err != nil {
			r.log.Printf("rejected connection from %s: %v", client.RemoteAddr(), err)
			return
		}
	}

	agent, err := r.dialAgent()
	if err != nil {
		r.log.Printf("agent unreachable: %v", err)
		return
	}
	defer agent.Close()

	// 双向拷贝, 两个方向都结束才收工: 只等第一个会让defer的`Close`拆对,
	// 截断另一方向仍在回传的字节(客户端半关写端不应掐掉回包).
	done := make(chan struct{}, 2)
	go func() { copyAndClose(agent, client); done <- struct{}{} }()
	go func() { copyAndClose(client, agent); done <- struct{}{} }()
	<-done
	<-done
}

// 每连接重读socket文件并重放nonce: agent重启会换端口和nonce, 重读才能存活.
func (r *Relay) dialAgent() (net.Conn, error) {
	data, err := os.ReadFile(r.cfg.SocketFile)
	if err != nil {
		return nil, fmt.Errorf("read socket file %s: %w", r.cfg.SocketFile, err)
	}
	info, err := nonce.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse socket file %s: %w", r.cfg.SocketFile, err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", info.Port)
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial agent at %s: %w", addr, err)
	}
	if _, err := c.Write(info.Nonce[:]); err != nil {
		c.Close()
		return nil, fmt.Errorf("send nonce to agent: %w", err)
	}
	return c, nil
}

// 拷完后半关`dst`, 让对端看到干净的流结束而不是挂住.
func copyAndClose(dst, src net.Conn) {
	io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	dst.Close()
}
