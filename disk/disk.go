package disk

import (
	"github.com/shirou/gopsutil/disk"
	"strings"
)

type Disk struct {
	partition disk.PartitionStat
	Usage     disk.UsageStat
	IO        disk.IOCountersStat
}

func (di *Disk) EqualByName(name string) bool {
	if strings.ToLower(di.partition.Device) == name {
		return true
	}
	return false
}
