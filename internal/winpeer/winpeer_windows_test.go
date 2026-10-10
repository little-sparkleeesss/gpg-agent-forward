//go:build windows

package winpeer

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestSelfImageMatchesTheImageThePeerLookupReports(t *testing.T) {
	// 自身镜像只用于一件事: 交给`sameImagePath`去和`QueryFullProcessImageName`报的对端路径比对,
	// 并用同一API问本进程要求一致: 自身探针豁免依赖它, 不一致`Verify`会拒掉中继自身的存活探测.
	// 路径字符串(短名, junction等)推不出结论, 只能直接问API.
	self, err := selfInfo()
	if err != nil {
		t.Fatalf("selfInfo() error = %v", err)
	}
	if self.ImagePath == "" {
		t.Fatal("selfInfo() returned an empty image path")
	}

	h, err := windows.OpenProcess(processQueryLimitedIn, false, windows.GetCurrentProcessId())
	if err != nil {
		t.Fatalf("OpenProcess(self) error = %v", err)
	}
	defer windows.CloseHandle(h)

	reported, err := processImagePath(h)
	if err != nil {
		t.Fatalf("processImagePath(self) error = %v", err)
	}
	if !sameImagePath(reported, self.ImagePath) {
		t.Errorf("self image is %q but the peer lookup reports %q for this process; the self-probe exemption cannot match",
			self.ImagePath, reported)
	}
}
