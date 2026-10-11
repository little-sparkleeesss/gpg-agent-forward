//go:build !windows

package cli

import (
	"io"
	"log"
	"os"
)

// 非Windows上没有真实的agent socket文件, 这里照Windows布局取值
// 只为能在Linux上开发调试, 实际要用`--socket-file`指定路径.
func defaultSocketFile() string {
	return DefaultSocketFile(os.Getenv("LOCALAPPDATA"), os.Getenv("HOME"))
}

func newLogger(w io.Writer) *log.Logger {
	return log.New(w, "gpg-agent-forward: ", 0)
}

// 非Windows上没有对端用户可比, relay的对端策略不存在, 这里只能是no-op.
func peerPolicyCheck() error { return nil }

// 非Windows上无对端策略, doctor必须报n/a而不是声称通过.
// 声明为变量是为了测试能走doctor对端检查里只有策略存在时才有的分支.
var peerCheckSupported = func() bool { return false }

// 两种拼写指向同一文件时须视为同一路径, 否则按一种拼写记录的relay无法被另一种拼写复用.
// POSIX路径区分大小写, 清洗后比较即可; 归一化范围详见`cleanSocketFile`.
func sameSocketFile(a, b string) bool {
	return cleanSocketFile(a) == cleanSocketFile(b)
}
