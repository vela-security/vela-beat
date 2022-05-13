package process

import (
	"github.com/vela-security/vela-public/lua"
	"strings"
)

func (proc *Process) ToLValue() lua.LValue {
	return lua.NewAnyData(proc)
}

func (proc *Process) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "name":
		return lua.S2L(proc.Name)

	case "pid":
		return lua.LInt(proc.Pid)

	case "ppid":
		return lua.LInt(proc.Ppid)

	case "pgid":
		return lua.LInt(proc.Pgid)

	case "cmd":
		return lua.S2L(proc.Cmdline)

	case "cwd":
		return lua.S2L(proc.Cwd)

	case "exe":
		return lua.S2L(proc.Executable)

	case "state":
		return lua.S2L(proc.State)

	case "args":
		return lua.S2L(strings.Join(proc.Args, " "))

	case "memory":
		return lua.LNumber(proc.MemSize)
	case "rss":
		return lua.LNumber(proc.RssBytes)

	case "rss_pct":
		return lua.LNumber(proc.RssPct)
	case "share":
		return lua.LNumber(proc.Share)

	case "stime":
		return lua.S2L(proc.StartTime)
	}

	return lua.LNil
}
