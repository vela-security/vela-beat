package cpu

import (
	"github.com/shirou/gopsutil/cpu"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
	"runtime"
)

//type Stat struct {
//	CPU       string  `json:"cpu"`
//	User      float64 `json:"user"`
//	System    float64 `json:"system"`
//	Idle      float64 `json:"idle"`
//	Nice      float64 `json:"nice"`
//	Iowait    float64 `json:"iowait"`
//	Irq       float64 `json:"irq"`
//	Softirq   float64 `json:"softirq"`
//	Steal     float64 `json:"steal"`
//	Guest     float64 `json:"guest"`
//	GuestNice float64 `json:"guestNice"`
//}
//
//func NewStat(s cpu.TimesStat) Stat {
//	return Stat{
//		s.CPU,
//		s.User,
//		s.System,
//		s.Idle,
//		s.Nice,
//		s.Nice,
//		s.Iowait,
//		s.Softirq,
//		s.Steal,
//		s.Guest,
//		s.GuestNice,
//	}
//}

type Stat cpu.TimesStat

func (s Stat) String() string                         { return auxlib.B2S(s.Byte()) }
func (s Stat) Type() lua.LValueType                   { return lua.LTObject }
func (s Stat) AssertFloat64() (float64, bool)         { return 0, false }
func (s Stat) AssertString() (string, bool)           { return "", false }
func (s Stat) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (s Stat) Peek() lua.LValue                       { return s }

func (s Stat) Total() float64 {
	return s.Idle + s.User + s.System + s.Iowait + s.Nice + s.Irq + s.Softirq + s.Guest + s.GuestNice
}

func (s Stat) IsNULL() bool {
	return s.Total() == 0
}

func (s Stat) Pct() Stat {
	total := s.Total()
	return Stat{
		CPU:       "cpu-total-average",
		User:      s.User / total,
		System:    s.System / total,
		Idle:      s.Idle / total,
		Nice:      s.Nice / total,
		Iowait:    s.Iowait / total,
		Irq:       s.Irq / total,
		Softirq:   s.Softirq / total,
		Steal:     s.Steal / total,
		Guest:     s.Guest / total,
		GuestNice: s.GuestNice / total,
	}
}

func (s Stat) Dela(ct Stat) Stat {

	return Stat{
		CPU:       "cpu-total-dela",
		User:      s.User - ct.User,
		System:    s.System - ct.System,
		Idle:      s.Idle - ct.Idle,
		Nice:      s.Nice - ct.Nice,
		Iowait:    s.Iowait - ct.Iowait,
		Irq:       s.Irq - ct.Irq,
		Softirq:   s.Softirq - ct.Softirq,
		Steal:     s.Steal - ct.Steal,
		Guest:     s.Guest - ct.Guest,
		GuestNice: s.GuestNice - ct.GuestNice,
	}
}

func (s Stat) Average(div int64) Stat {
	return Stat{
		CPU:       "cpu-total-average",
		User:      s.User / float64(div),
		System:    s.System / float64(div),
		Idle:      s.Idle / float64(div),
		Nice:      s.Nice / float64(div),
		Iowait:    s.Iowait / float64(div),
		Irq:       s.Irq / float64(div),
		Softirq:   s.Softirq / float64(div),
		Steal:     s.Steal / float64(div),
		Guest:     s.Guest / float64(div),
		GuestNice: s.GuestNice / float64(div),
	}
}

func (s Stat) Byte() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("arch", runtime.GOARCH)
	enc.KV("core_num", runtime.NumCPU())
	enc.KV("user", s.User)
	enc.KV("system", s.System)
	enc.KV("idle", s.Idle)
	enc.KV("io_wait", s.Iowait)
	enc.KV("irq", s.Irq)
	enc.KV("nice", s.Nice)
	enc.KV("softirq", s.Softirq)
	enc.KV("stolen", s.Steal)
	enc.KV("total", s.Total())
	enc.End("}")
	return enc.Bytes()
}

func (s Stat) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "name":
		return lua.S2L(s.CPU)
	case "total":
		return lua.LNumber(s.Total())
	case "user":
		return lua.LNumber(s.User)
	case "system":
		return lua.LNumber(s.System)
	case "idle":
		return lua.LNumber(s.Idle)
	case "nice":
		return lua.LNumber(s.Nice)
	case "io_wait":
		return lua.LNumber(s.Iowait)
	case "irq":
		return lua.LNumber(s.Irq)
	case "soft_irq":
		return lua.LNumber(s.Softirq)
	case "steal":
		return lua.LNumber(s.Steal)
	case "guest":
		return lua.LNumber(s.Guest)
	case "guest_nice":
		return lua.LNumber(s.GuestNice)

	default:
		return lua.LNumber(0)

	}

}
