package cpu

import (
	"github.com/shirou/gopsutil/cpu"
	"runtime"
	"strings"
)

type snapshot struct {
	time int64
	data Stat
}

type summary struct {
	Arch      string
	Num       int
	PCnt      int //physical
	Vendor    string
	ModelName string
	Info      []cpu.InfoStat
	Err       error
	snap      snapshot
}

func New() *summary {
	sum := &summary{Arch: runtime.GOARCH, Num: runtime.NumCPU()}
	return sum

	return sum
}

func (sum *summary) updateModeName(name string) {
	if sum.ModelName == "" {
		sum.ModelName = name
		return
	}

	if !strings.Contains(sum.ModelName, name) {
		sum.ModelName = sum.ModelName + "," + name
	}
}

func (sum *summary) updateVendor(name string) {
	if sum.Vendor == "" {
		sum.Vendor = name
		return
	}

	if !strings.Contains(sum.Vendor, name) {
		sum.Vendor = sum.Vendor + "," + name
	}
}

func (sum *summary) updateCnt() bool {
	cnt, err := cpu.Counts(false)
	if err != nil {
		sum.Err = err
		return false
	}

	sum.PCnt = cnt
	return true
}
