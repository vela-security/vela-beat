package process

import (
	"github.com/vela-security/vela-public/grep"
	"github.com/vela-security/vela-public/kind"
	"strings"
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

func (proc *Process) Byte() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("name", proc.Name)
	enc.KV("state", proc.State)
	enc.KV("pid", proc.Pid)
	enc.KV("ppid", proc.Ppid)
	enc.KV("pgid", proc.Pgid)
	enc.KV("cmdline", proc.Cmdline)
	enc.KV("username", proc.Username)
	enc.KV("cwd", proc.Cwd)
	enc.KV("executable", proc.Executable)
	enc.KV("args", strings.Join(proc.Args, " "))

	enc.KV("user_ticks", proc.UserTicks)
	enc.KV("total_pct", proc.TotalPct)
	enc.KV("total_norm_pct", proc.TotalNormPct)
	enc.KV("system_ticks", proc.SystemTicks)
	enc.KV("total_ticks", proc.TotalTicks)
	enc.KV("start_time", proc.StartTime)

	enc.KV("mem_size", proc.MemSize)
	enc.KV("rss_bytes", proc.RssBytes)
	enc.KV("rss_pct", proc.RssPct)
	enc.KV("share", proc.Share)
	enc.End("}")
	return enc.Bytes()
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
	proc := &Process{Pid: pid}
	err := proc.Lookup()
	return proc, err
}

func Name(pattern string) *summary {
	sum := &summary{}
	sum.name(grep.New(pattern))
	return sum
}
