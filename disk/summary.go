package disk

import (
	"fmt"
	"github.com/shirou/gopsutil/disk"
	"github.com/vela-security/vela-public/catch"
	"time"
)

type snapshot struct {
	time int64
	dev  []*Disk
}

type summary struct {
	fail *catch.Cause
	dev  []*Disk
	snap snapshot
}

func New() *summary {
	return &summary{fail: catch.New()}
}

func (sum *summary) partition() {
	stat, err := disk.Partitions(true)
	if err != nil {
		sum.fail.Try("disk partition", err)
		return
	}

	n := len(stat)
	sum.dev = make([]*Disk, n)
	for i := 0; i < n; i++ {
		sum.dev[i] = &Disk{
			partition: stat[i],
		}
	}

	xEnv.Info("disk find partition over.")
}

func (sum *summary) DevById(idx int) string {
	return sum.dev[idx].partition.Device
}

func (sum *summary) usage() {
	n := len(sum.dev)
	for i := 0; i < n; i++ {
		dev := sum.DevById(i)
		usage, err := disk.Usage(dev)
		if err != nil {
			sum.fail.Try(dev, err)
			//xEnv.Errorf("%s disk partition got usage fail %v", dev, err)
			continue
		}
		sum.dev[i].Usage = *usage
	}
}

func (sum *summary) io() {
	n := len(sum.dev)
	for i := 0; i < n; i++ {
		dev := sum.DevById(i)
		ret, err := disk.IOCounters(dev)
		if err != nil {
			sum.fail.Try(dev, fmt.Errorf("%s got io counter fail %v", dev, err))
			//xEnv.Errorf("%s disk partition got usage fail %v", dev, err)
			continue
		}
		sum.dev[i].IO = ret[dev]
	}

}

func (sum *summary) Update() {
	now := time.Now().Unix()
	if now-sum.snap.time < 5 {
		return
	}

	sum.fail = catch.New()
	sum.snap.time = now
	sum.partition()
	sum.usage()
	sum.io()
}
