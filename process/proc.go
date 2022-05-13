package process

import (
	"github.com/elastic/gosigar"
	"github.com/vela-security/vela-public/grep"
)

type Process struct {
	Name       string   `json:"name"`
	State      string   `json:"state"`
	Pid        int      `json:"pid"`
	Ppid       int      `json:"ppid"`
	Pgid       uint32   `json:"pgid"`
	Cmdline    string   `json:"cmdline"`
	Username   string   `json:"username"`
	Cwd        string   `json:"cwd"`
	Executable string   `json:"executable"` // linux
	Args       []string `json:"args"`

	//CPU，单位 毫秒
	UserTicks    uint64  `json:"user_ticks"`
	TotalPct     float64 `json:"total_pct"`
	TotalNormPct float64 `json:"total_norm_pct"`
	SystemTicks  uint64  `json:"system_ticks"`
	TotalTicks   uint64  `json:"total_ticks"`
	StartTime    string  `json:"start_time"`

	//Memory
	MemSize  uint64  `json:"mem_size"`
	RssBytes uint64  `json:"rss_bytes"`
	RssPct   float64 `json:"rss_pct"`
	Share    uint64  `json:"share"`

	err error
}

func state(b byte) string {
	switch b {
	case 'S':
		return "sleeping"
	case 'R':
		return "running"
	case 'D':
		return "idle"
	case 'T':
		return "stopped"
	case 'Z':
		return "zombie"
	}
	return "unknown"
}

func Pid(pid int) (*Process, error) {
	var err error

	st := gosigar.ProcState{}
	err = st.Get(pid)
	if err != nil {
		return nil, err
	}

	proc := &Process{
		Name:     st.Name,
		State:    state(byte(st.State)),
		Pid:      pid,
		Ppid:     st.Ppid,
		Pgid:     uint32(st.Pgid),
		Username: st.Username,
	}

	exe := gosigar.ProcExe{}
	_ = exe.Get(pid)
	proc.Cwd = exe.Cwd
	proc.Executable = exe.Name

	return proc, nil
}

func Name(pattern string) *summary {
	sum := &summary{}
	sum.name(grep.New(pattern))
	return sum
}
