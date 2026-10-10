package winpeer

import (
	"errors"
	"fmt"
)

// 表持续增长时的重试上限: 表永不稳定也不能死转.
const maxTableAttempts = 4

// 取大小与读表是两次调用, 表会在其间增长: 再次`ERROR_INSUFFICIENT_BUFFER`不是失败,
// 用刚写回的`size`重试; `fetch`可注入, 便于测这个增长路径.
func readTable(fetch func(buf []byte, size *uint32) error, parse func([]byte) ([]Conn4, error)) ([]Conn4, error) {
	var size uint32
	if err := fetch(nil, &size); err != nil && !errors.Is(err, errInsufficientBuffer) {
		return nil, fmt.Errorf("winpeer: size of TCP table: %w", err)
	}
	if size == 0 {
		return nil, nil
	}

	for attempt := 0; attempt < maxTableAttempts; attempt++ {
		buf := make([]byte, size)
		if err := fetch(buf, &size); err != nil {
			if errors.Is(err, errInsufficientBuffer) {
				continue // 表增长了, `size`已是所需长度.
			}
			return nil, fmt.Errorf("winpeer: read TCP table: %w", err)
		}
		return parse(buf)
	}
	return nil, errors.New("winpeer: TCP table kept growing between the size probe and the read")
}
