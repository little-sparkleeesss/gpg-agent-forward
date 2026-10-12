package cli

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// unix socket归绑定它的进程所在的network namespace所有: 别的namespace里的listener
// 不在内核的socket表里也不在`ss`里, 但文件在共享的mount namespace中, 且它会应答连接.
// 预检因此看连接而非socket表, 这样的listener永不会被删.

const (
	// 传给re-exec的测试二进制: 绑到哪里, 以及在哪里写下已绑好.
	netnsHelperSocket = "GPG_AGENT_FORWARD_TEST_NETNS_SOCKET"
	netnsHelperReady  = "GPG_AGENT_FORWARD_TEST_NETNS_READY"
)

// TestNetnsSocketHelper不是独立测试: 它是下面各测试的子进程一半, 在`unshare`下re-exec,
// 使它的listener归属socket表看不到的network namespace; 命名socket的变量缺失时直接跳过.
func TestNetnsSocketHelper(t *testing.T) {
	socket := os.Getenv(netnsHelperSocket)
	if socket == "" {
		t.Skip("not the netns helper invocation")
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("bind %s in this namespace: %v", socket, err)
	}
	defer l.Close()
	if err := os.WriteFile(os.Getenv(netnsHelperReady), []byte("ready"), 0o644); err != nil {
		t.Fatalf("report that %s is bound: %v", socket, err)
	}
	// 持有socket并接受连接, 直到父进程杀掉本进程: 预检读的是被接受且挂住的连接.
	// 从不`accept`的连接留在内核backlog里也同样开着, 但`accept`才是真实agent的行为.
	accepted := make(chan struct{}, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(time.Hour)
			}(c)
		}
	}()
	for {
		select {
		case <-accepted:
		case <-time.After(time.Hour):
		}
	}
}

func startSocketInAnotherNamespace(t *testing.T, socket string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("network namespaces are a Linux feature")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skipf("unshare is not on PATH, so no socket can be bound elsewhere: %v", err)
	}
	if err := exec.Command(unshare, "-rn", "true").Run(); err != nil {
		t.Skipf("unshare -rn does not work here, so no socket can be bound elsewhere: %v", err)
	}

	ready := filepath.Join(filepath.Dir(socket), "ready")
	var childOut bytes.Buffer
	child := exec.Command(unshare, "-rn", selfExe(), "-test.run=^TestNetnsSocketHelper$")
	child.Env = append(os.Environ(),
		netnsHelperSocket+"="+socket,
		netnsHelperReady+"="+ready,
	)
	child.Stdout, child.Stderr = &childOut, &childOut
	if err := child.Start(); err != nil {
		t.Fatalf("start the helper under unshare: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	t.Cleanup(func() {
		_ = child.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	for i := 0; i < 1000; i++ {
		if _, err := os.Stat(ready); err == nil {
			return
		}
		select {
		case err := <-done:
			// 子进程已退出, 输出不会再被写入, 所以能安全地把它带上作为失败原因.
			t.Fatalf("the helper exited before binding a socket: %v, output %q", err, childOut.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = child.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	t.Fatalf("the helper never reported a socket bound: output %q", childOut.String())
}

// 断言另一network namespace里的listener会被判为在用且文件不被删除: socket表给不出
// 这个结论, 只凭表判定删除会把文件从在用进程手里拿走.
func TestClassifyRemoteSocketFindsASocketInAnotherNamespace(t *testing.T) {
	requireShell(t)
	socket := filepath.Join(shortTempDir(t), "S.gpg-agent")
	startSocketInAnotherNamespace(t, socket)

	// 这里的判定走真实连接路径, 把本机当作远端主机去连另一个namespace里的socket.
	verdict, err := classifyUnixSocketLocally(t, socket)
	if err != nil {
		t.Fatalf("classifyUnixSocketLocally(%s) error = %v", socket, err)
	}
	if verdict != forwardLive {
		t.Fatalf("verdict = %v, want forwardLive: a socket bound in another namespace answered the connection", verdict)
	}
	if !socketFileExists(t, socket) {
		t.Fatalf("%s was removed: a socket bound in another namespace lost its file", socket)
	}
}

// 同一性质, 但不依赖namespace, 因此任何主机都能跑: 接受连接且保持沉默的listener
// 就是live, 与其权限如何无关.
func TestClassifyRemoteSocketFindsALiveListener(t *testing.T) {
	requireShell(t)
	socket := filepath.Join(shortTempDir(t), "S.gpg-agent")
	l := liveSocketAt(t, socket)
	defer l.Close()

	verdict, err := classifyUnixSocketLocally(t, socket)
	if err != nil {
		t.Fatalf("classifyUnixSocketLocally(%s) error = %v", socket, err)
	}
	if verdict != forwardLive {
		t.Errorf("verdict = %v, want forwardLive for a listener that accepts and says nothing", verdict)
	}
	if !socketFileExists(t, socket) {
		t.Error("a live socket was removed")
	}
}

// 无人监听的socket文件不接受连接, 连接立即结束, 这正是删除针对的情形.
func TestClassifyRemoteSocketFindsALeftover(t *testing.T) {
	requireShell(t)
	socket := filepath.Join(shortTempDir(t), "S.gpg-agent")
	deadSocketAt(t, socket)

	verdict, err := classifyUnixSocketLocally(t, socket)
	if err != nil {
		t.Fatalf("classifyUnixSocketLocally(%s) error = %v", socket, err)
	}
	if verdict != forwardDead {
		t.Errorf("verdict = %v, want forwardDead for a socket nothing is listening on", verdict)
	}
}

// 权限判定之门: 连socket需要写权限, 被拒时调用方看到的连接结束与无人监听无法区分,
// 所以form命令先在主机上正面试写权限; 本测试钉住的就是连接本身分不开这两者.
func TestClassifyRemoteSocketFindsNoListenerBehindAnUnwritablePath(t *testing.T) {
	requireShell(t)
	if os.Geteuid() == 0 {
		t.Skip("running as root, which bypasses the permission the test turns on")
	}
	socket := filepath.Join(t.TempDir(), "S.gpg-agent")
	l := liveSocketAt(t, socket)
	defer l.Close()
	if err := os.Chmod(socket, 0); err != nil {
		t.Skipf("cannot chmod the socket: %v", err)
	}

	verdict, err := classifyUnixSocketLocally(t, socket)
	if err != nil {
		t.Fatalf("classifyUnixSocketLocally(%s) error = %v", socket, err)
	}
	if verdict != forwardDead {
		t.Fatalf("verdict = %v, want forwardDead: this is the ambiguity the form command's write test exists to catch", verdict)
	}
	// form命令在此兜住: 同一路径报不可写, 不会走到删除.
	form, err := probeRemoteSocketForm([]string{"host"}, socket, localProbeRunner(os.Getenv("PATH")))
	if err != nil {
		t.Fatalf("probeRemoteSocketForm() error = %v", err)
	}
	if form != formUnwritable {
		t.Errorf("form = %v, want formUnwritable: the connection says %v, and only the write test says why", form, verdict)
	}
	if !socketFileExists(t, socket) {
		t.Error("the socket was removed on a connection reading that could not tell it apart from a leftover")
	}
}

// 在本机路径上跑真实判定: 替身ssh绑定本地端口, 再按远端主机的做法连接该路径,
// 详见`remote_probe_test.go`.
func classifyUnixSocketLocally(t *testing.T, path string) (socketForwardVerdict, error) {
	t.Helper()
	forwardStandInSSH(t)
	control, err := controlSocketPath(path)
	if err != nil {
		return forwardUnjudgeable, err
	}
	return classifyRemoteSocket([]string{"host"}, path, control)
}
