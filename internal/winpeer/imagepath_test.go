package winpeer

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// 造一个`LookPath`会接受的文件: Windows只看存在, Unix还看可执行位.
func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestResolveImagePathLooksUpBareNamesOnPATH(t *testing.T) {
	// 断言裸名走`PATH`查找而非工作目录: 否则同名诱饵胜出, 对不上对端路径, 自身探针豁免永不生效.
	const name = "gpg-agent-forward-windows-amd64.exe"

	tools := t.TempDir()
	onPath := filepath.Join(tools, name)
	writeExecutable(t, onPath)
	t.Setenv("PATH", tools)

	if runtime.GOOS != "windows" {
		// 工作目录里的同名诱饵不许胜出.
		// Windows上不种这个诱饵: CreateProcess先搜工作目录, 那里的副本才会被启动, 解析到它是对的.
		cwd := t.TempDir()
		writeExecutable(t, filepath.Join(cwd, name))
		t.Chdir(cwd)
	}

	if got := resolveImagePath(name); got != onPath {
		t.Errorf("resolveImagePath(%q) = %q, want the PATH entry %q", name, got, onPath)
	}
}

func TestResolveImagePathResolvesARelativePathAgainstTheWorkingDirectory(t *testing.T) {
	// 含目录的相对路径不是`PATH`查找, 就是相对于进程启动时的工作目录.
	dir := t.TempDir()
	t.Chdir(dir)
	rel := filepath.Join("bin", "gpg-agent-forward-windows-amd64.exe")
	writeExecutable(t, filepath.Join(dir, rel))

	want := filepath.Join(dir, rel)
	if got := resolveImagePath(rel); got != want {
		t.Errorf("resolveImagePath(%q) = %q, want %q", rel, got, want)
	}
}

func TestResolveImagePathKeepsASymlinkSpelling(t *testing.T) {
	// 保留链接的原写法: `QueryFullProcessImageName`报告的是镜像加载路径, 不是reparse目标.
	dir := t.TempDir()
	target := filepath.Join(dir, "gpg-agent-forward-windows-amd64.exe")
	link := filepath.Join(dir, "gpg-agent-forward-current.exe")
	writeExecutable(t, target)
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}

	if got := resolveImagePath(link); got != link {
		t.Errorf("resolveImagePath(%q) = %q, want the link itself", link, got)
	}
}

func TestResolveImagePathStaysBestEffortWhenLookupFails(t *testing.T) {
	// 空名必须保持为空: `filepath.Abs("")`是工作目录, 会把未知冒充成自身镜像.
	if got := resolveImagePath(""); got != "" {
		t.Errorf("resolveImagePath(%q) = %q, want %q", "", got, "")
	}

	// 不在任何`PATH`里的名字也要绝对化, 调用方拿到的值不比传入的差.
	t.Chdir(t.TempDir())
	t.Setenv("PATH", t.TempDir())
	name := "no-such-program-anywhere.exe"
	if got := resolveImagePath(name); !filepath.IsAbs(got) {
		t.Errorf("resolveImagePath(%q) = %q, want an absolute path", name, got)
	}
}
