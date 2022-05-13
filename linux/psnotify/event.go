//go:build darwin || freebsd || netbsd || openbsd || linux
// +build darwin freebsd netbsd openbsd linux

package psnotify

import (
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-beat/process"
)

const (
	FORKL = lua.LString("fork")
	EXECL = lua.LString("exec")
	EXITL = lua.LString("exit")
	NULLL = lua.LString("null")
)

type event struct {
	eType uint32
	ppid  int
	pid   int
	proc  *process.Process
}

func newEv(ppid, pid int, et uint32) *event {
	return &event{pid: pid, ppid: ppid, eType: et}
}

func (ev *event) ToLValue() lua.LValue {
	return lua.NewAnyData(ev)
}

func (ev *event) Proc() *process.Process {
	if ev.proc != nil {
		return ev.proc
	}

	var proc *process.Process
	var err error
	if ev.ppid == -1 {
		proc, err = process.Pid(ev.pid)
	} else {
		proc, err = process.Pid(ev.ppid)
	}

	if err != nil {
		return nil
	}

	ev.proc = proc
	return proc
}

func (ev *event) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "type":
		switch ev.eType {
		case PROC_EVENT_FORK:
			return FORKL
		case PROC_EVENT_EXEC:
			return EXECL
		case PROC_EVENT_EXIT:
			return EXITL
		default:
			return NULLL
		}
		return lua.LInt(ev.eType)
	case "pid":
		return lua.LInt(ev.pid)
	case "ppid":
		return lua.LInt(ev.ppid)
	case "proc":
		if p := ev.Proc(); p == nil {
			return lua.LNil
		} else {
			return lua.NewAnyData(p)
		}
	}
	return lua.LNil
}
