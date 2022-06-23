//go:build darwin || freebsd || netbsd || openbsd || linux
// +build darwin freebsd netbsd openbsd linux

package psnotify

import (
	"github.com/vela-security/vela-public/lua"
)

func (nt *notify) pipeL(L *lua.LState) int {
	n := L.GetTop()
	if n <= 0 {
		return 0
	}
	for i := 1; i <= n; i++ {
		nt.cfg.pipe.Check(L, i)
	}
	return 0
}

func (nt *notify) startL(L *lua.LState) int {
	xEnv.Start(L, nt).From(nt.Code()).Do()
	return 0
}

func (nt *notify) allL(L *lua.LState) int {
	nt.cfg.watch.All = true

	n := L.GetTop()
	if n <= 0 {
		nt.cfg.watch.Entry = PROC_EVENT_ALL
		return 0
	}

	for i := 1; i <= n; i++ {
		nt.cfg.watch.Entry |= uint32(L.CheckInt(i))
	}

	return 0
}

func (nt *notify) Index(L *lua.LState, key string) lua.LValue {
	switch key {

	case "FORK":
		return lua.LInt(PROC_EVENT_FORK)

	case "EXEC":
		return lua.LInt(PROC_EVENT_EXEC)

	case "EXIT":
		return lua.LInt(PROC_EVENT_EXIT)

	case "pipe":
		return lua.NewFunction(nt.pipeL)

	case "start":
		return lua.NewFunction(nt.startL)

	case "all":
		return lua.NewFunction(nt.allL)
	}

	return lua.LNil
}
