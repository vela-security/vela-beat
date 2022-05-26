package process

import (
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	"time"
)

func (snt *snapshot) deleteL(L *lua.LState) int {
	snt.onDelete.CheckMany(L, pipe.Seek(0))
	return 0
}

func (snt *snapshot) createL(L *lua.LState) int {
	snt.onCreate.CheckMany(L, pipe.Seek(0))
	return 0
}

func (snt *snapshot) updateL(L *lua.LState) int {
	snt.onUpdate.CheckMany(L, pipe.Seek(0))
	return 0
}

func (snt *snapshot) bucketL(L *lua.LState) int {
	n := L.GetTop()
	if n == 0 {
		return 0
	}

	var bkt []string

	for i := 1; i <= n; i++ {
		bkt = append(bkt, L.CheckString(i))
	}

	snt.bkt = bkt
	return 0
}

func (snt *snapshot) runL(L *lua.LState) int {
	snt.V(lua.PTRun, time.Now())
	snt.run()
	snt.V(lua.PTMode, time.Now())
	return 0
}

func (snt *snapshot) pollL(L *lua.LState) int {
	delay := L.IsInt(1)
	if delay < 1 {
		delay = 30
	}

	snt.tk = time.NewTicker(time.Duration(delay) * time.Second)
	xEnv.Spawn(10, func() {
		for range snt.tk.C {
			snt.run()
		}
	})
	snt.V(lua.PTRun, time.Now())
	return 0
}

func (snt *snapshot) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "run":
		return lua.NewFunction(snt.runL)
	case "poll":
		return lua.NewFunction(snt.pollL)
	case "bucket":
		return lua.NewFunction(snt.bucketL)

	case "on_create":
		return lua.NewFunction(snt.createL)
	case "on_delete":
		return lua.NewFunction(snt.deleteL)
	case "on_update":
		return lua.NewFunction(snt.updateL)
	}

	return lua.LNil
}
