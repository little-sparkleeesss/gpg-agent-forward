package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"gpg-agent-forward/internal/nonce"
	"gpg-agent-forward/internal/winpeer"
)

// `ProbeAgent`用与relay相同的路径完成agent握手并返回Assuan greeting, 不需要gpg和远端
// 主机. 失败消息说明哪一步失败: 是agent没在跑, 还是socket文件已过期.
func ProbeAgent(socketFile string) (string, error) {
	data, err := os.ReadFile(socketFile)
	if err != nil {
		return "", fmt.Errorf("reading socket file: %w", err)
	}
	info, err := nonce.Parse(data)
	if err != nil {
		return "", err
	}

	addr := fmt.Sprintf("127.0.0.1:%d", info.Port)
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("connecting to agent at %s: %w", addr, err)
	}
	defer c.Close()

	if _, err := c.Write(info.Nonce[:]); err != nil {
		return "", fmt.Errorf("sending nonce: %w", err)
	}
	// nonce不对时agent直接断开不吭声, 这里读失败即握手被拒.
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", err
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if n > 0 {
		return string(buf[:n]), nil
	}
	if err != nil {
		return "", fmt.Errorf("agent did not answer after the nonce: %w "+
			"(the socket file may be stale; restarting gpg-agent regenerates it)", err)
	}
	return "", errors.New("agent closed the connection without a greeting")
}

// `DescribeSocketFile`摘要socket文件, 不泄露nonce.
func DescribeSocketFile(socketFile string) (string, error) {
	data, err := os.ReadFile(socketFile)
	if err != nil {
		return "", fmt.Errorf("reading socket file: %w", err)
	}
	info, err := nonce.Parse(data)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s: %d bytes, agent port %d, nonce present (%d bytes)",
		socketFile, len(data), info.Port, len(info.Nonce)), nil
}

// `runDoctor`报告relay会看到什么, 让Windows专属部分能在实际运行的机器上诊断.
func runDoctor(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("doctor", stderr)
	socketFile := fs.String("socket-file", defaultSocketFile(), "Windows gpg-agent socket file")
	port := fs.Int("port", DefaultRelayPort, "loopback port the relay would use")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ok := true
	report := func(label string, err error, detail string) {
		if err != nil {
			ok = false
			fmt.Fprintf(stdout, "  FAIL  %s: %v\n", label, err)
			return
		}
		fmt.Fprintf(stdout, "  ok    %s%s\n", label, detail)
	}

	fmt.Fprintln(stdout, "socket file defaults")
	fmt.Fprintf(stdout, "  LOCALAPPDATA = %q\n", os.Getenv("LOCALAPPDATA"))
	fmt.Fprintf(stdout, "  socket file  = %s\n", *socketFile)

	fmt.Fprintln(stdout, "checks")
	desc, err := DescribeSocketFile(*socketFile)
	report("socket file parses", err, " ("+desc+")")
	if err == nil {
		greeting, gErr := ProbeAgent(*socketFile)
		report("agent handshake", gErr, " ("+trimGreeting(greeting)+")")
	}

	// peer策略只存在于Windows relay, 非Windows报n/a: 否则等于说没测过的策略已验证.
	if peerCheckSupported() {
		policyErr, liveErr := selfPeerCheck()
		report("peer check", policyErr, "")
		// live腿只证明检查能在真实连接上跑; 得不出结论 (如TCP表瞬时缺条目) 只是note, 不是
		// FAIL: 能证明策略坏掉的只有策略检查本身.
		if liveErr != nil {
			fmt.Fprintf(stdout, "  note  peer check on a live connection reached no verdict: %v\n", liveErr)
		}
	} else {
		fmt.Fprintln(stdout, "  n/a   peer check (Windows only)")
	}

	if *port > 0 {
		addr := fmt.Sprintf("127.0.0.1:%d", *port)
		if relayProbe := Probe(addr); relayProbe {
			fmt.Fprintf(stdout, "  note  something is already listening on %s\n", addr)
		} else {
			fmt.Fprintf(stdout, "  note  %s is free for the relay\n", addr)
		}
	}

	if !ok {
		return errors.New("doctor found problems (see above)")
	}
	fmt.Fprintln(stdout, "all checks passed")
	return nil
}

func trimGreeting(s string) string {
	s = trimTrailingNewline(s)
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

func trimTrailingNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// `selfPeerCheck`返回策略检查的错误 (必须让doctor失败) 和live腿的错误 (仅供参考).
// 策略对合成peer检查, 因为活体探测证明不了它: 本进程自己的连接按设计总是放行,
// 无论比较是否写反都返回nil.
func selfPeerCheck() (policyErr, liveErr error) {
	if err := peerPolicyCheck(); err != nil {
		return err, nil
	}
	// 再在真实连接上端到端确认机制能跑: 本机查询失败只报note, 不当成策略坏掉的证据.
	return nil, selfPeerCheckConn()
}

// `selfPeerCheckConn`对本进程自连的连接跑peer检查, 只有得不出结论才报错.
func selfPeerCheckConn() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()
		errCh <- selfPeerCheckResult(allowPeer(c))
	}()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()

	select {
	case err := <-errCh:
		return err
	case <-time.After(5 * time.Second):
		return errors.New("peer check did not return")
	}
}

// `selfPeerCheckResult`: 有结论 (`nil`放行, `ErrPeerNotAllowed`识别后拒绝) 返回nil;
// 其他错误即没结论 (查询或身份失败), 交doctor报note.
func selfPeerCheckResult(err error) error {
	if err == nil || errors.Is(err, winpeer.ErrPeerNotAllowed) {
		return nil
	}
	return err
}
