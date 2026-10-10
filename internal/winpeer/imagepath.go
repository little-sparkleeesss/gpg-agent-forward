package winpeer

import (
	"os/exec"
	"path/filepath"
)

// 解析为`QueryFullProcessImageName`报告的完整路径, 只用于识别自身探针, 失败保留原值.
// 裸名必须查`PATH`而非拼工作目录: 否则对不上对端路径, 探针豁免永不生效.
// 不解析符号链接和8.3名: 它报告的是加载路径而非reparse目标, 单方改写会破坏匹配.
func resolveImagePath(name string) string {
	if name == "" {
		return name
	}
	// `LookPath`带分隔符的输入原样通过, 它的错只表示没找到, 不能因此丢弃已是绝对路径的值.
	if found, err := exec.LookPath(name); err == nil {
		name = found
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return name
	}
	return abs
}
