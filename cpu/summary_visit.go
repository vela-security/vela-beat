package cpu

import (
	"github.com/shirou/gopsutil/cpu"
	"time"
)

func (sum *summary) Ok() bool {
	return sum.Err == nil
}

func (sum *summary) Update() {
	if !sum.updateCnt() {
		return
	}

	info, err := cpu.Info()
	if err != nil {
		sum.Err = err
		return
	}

	n := len(info)
	if n == 0 {
		return
	}

	for i := 0; i < n; i++ {
		cpu := info[i]
		sum.updateModeName(cpu.ModelName)
		sum.updateVendor(cpu.VendorID)
	}

	sum.Info = info
}

func (sum *summary) time() (ct Stat) {
	cts, err := cpu.Times(false)
	if err != nil {
		xEnv.Errorf("got cpu time total fail %v", err)
		return
	}

	ct = Stat(cts[0])
	return

}

func (sum *summary) Time() (ct Stat) {
	ct = sum.time()
	sum.snap.time = time.Now().Unix()
	sum.snap.data = ct

	return ct
}

func (sum *summary) LoadAverage() Stat {
	now := time.Now().Unix()

	if sum.snap.data.Total() == 0 {
		sum.Time()
	}

	if now-sum.snap.time < 1 {
		time.Sleep(time.Second)
	}

	now = time.Now().Unix()
	ct := sum.time()
	if ct.IsNULL() {
		return ct
	}

	dv := ct.Dela(sum.snap.data)

	return dv.Average(now - sum.snap.time)
}
