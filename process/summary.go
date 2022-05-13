package process

import (
	"github.com/elastic/gosigar"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
)

type summary struct {
	Idle     uint32 `json:"idle"`
	Running  uint32 `json:"running"`
	Sleeping uint32 `json:"sleeping"`
	Stopped  uint32 `json:"stopped"`
	Total    uint32 `json:"total"`
	Unknown  uint32 `json:"unknown"`
	Zombie   uint32 `json:"zombie"`

	Process []*Process       `json:"process"`
	Sigar   gosigar.ProcList `json:"-"`
	Error   error
}

func (sum *summary) List() []int {
	return sum.Sigar.List
}

func (sum *summary) append(pv *Process) {
	switch pv.State {
	case "sleeping":
		sum.Sleeping++
	case "running":
		sum.Running++
	case "idle":
		sum.Idle++
	case "stopped":
		sum.Stopped++
	case "zombie":
		sum.Zombie++
	default:
		sum.Unknown++
	}
	sum.Total++
	sum.Process = append(sum.Process, pv)
}

func (sum *summary) init() {
	sigar := gosigar.ProcList{}
	sum.Error = sigar.Get()
	sum.Sigar = sigar
}

func (sum *summary) ToLValue() lua.LValue {
	return lua.NewAnyData(sum)
}

func (sum *summary) ok() bool {
	return sum.Error == nil
}

func (sum *summary) name(match func(string) bool) {
	if sum.init(); !sum.ok() {
		return
	}

	sum.view(func(pv *Process) bool {
		return match(pv.Name)
	})

	return
}

func (sum *summary) cmd(match func(string) bool) {
	if sum.init(); !sum.ok() {
		return
	}

	sum.view(func(pv *Process) bool {
		return match(pv.Cmdline)
	})
	return
}

func (sum *summary) exe(match func(string) bool) {
	if sum.init(); !sum.ok() {
		return
	}

	sum.view(func(pv *Process) bool {
		return match(pv.Executable)
	})
	return
}

func (sum *summary) args(match func(string) bool) {
	if sum.init(); !sum.ok() {
		return
	}

	sum.view(func(pv *Process) bool {
		for _, item := range pv.Args {
			if match(item) {
				return true
			}
		}
		return false
	})
	return
}

func (sum *summary) user(match func(string) bool) {
	if sum.init(); !sum.ok() {
		return
	}

	sum.view(func(pv *Process) bool {
		return match(pv.Username)
	})
	return
}

func (sum *summary) cwd(match func(string) bool) {
	if sum.init(); !sum.ok() {
		return
	}

	sum.view(func(pv *Process) bool {
		return match(pv.Cwd)
	})
}

func (sum *summary) ppid(match func(string) bool) {
	if sum.init(); !sum.ok() {
		return
	}

	sum.view(func(pv *Process) bool {
		return match(auxlib.ToString(pv.Ppid))
	})
}

func (sum *summary) view(match func(*Process) bool) {
	list := sum.List()
	n := len(list)
	if n == 0 {
		return
	}

	for i := 0; i < n; i++ {
		pid := list[i]
		pv, err := Pid(pid)
		if err != nil {
			continue
		}

		if !match(pv) {
			continue
		}
		sum.append(pv)
	}
}
