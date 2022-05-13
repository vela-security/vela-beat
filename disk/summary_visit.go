package disk

import (
	"runtime"
	"strings"
)

func (sum *summary) LookupDevice(name string) *Disk {
	n := len(sum.dev)
	if n == 0 {
		return nil
	}

	if runtime.GOOS == "windows" {
		name = strings.ToLower(name) + ":"
	}

	for i := 0; i < n; i++ {
		dev := sum.dev[i]
		if dev.EqualByName(name) {
			return dev
		}
	}

	return nil
}
