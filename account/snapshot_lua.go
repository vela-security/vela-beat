package account

import (
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	"reflect"
	"time"
)

var (
	subscript uint32 = 0
	typeof    string = reflect.TypeOf((*snapshot)(nil)).String()
)

func (snap *snapshot) runL(L *lua.LState) int {
	snap.run()
	return 0
}

func (snap *snapshot) pollL(L *lua.LState) int {
	n := L.IsInt(1)
	var dt time.Duration
	if n < 1 {
		dt = 3
	} else {
		dt = time.Duration(n)
	}
	snap.ticker = time.NewTicker(dt)

	xEnv.Spawn(0, func() {
		for range snap.ticker.C {
			snap.run()
		}
	})
	return 0
}

func (snap *snapshot) syncL(L *lua.LState) int {
	snap.sync()
	return 0
}

func (snap *snapshot) onCreateL(L *lua.LState) int {
	snap.onCreate = pipe.NewByLua(L, pipe.Seek(0), pipe.Env(xEnv))
	return 0
}

func (snap *snapshot) onUpdateL(L *lua.LState) int {
	snap.onUpdate = pipe.NewByLua(L, pipe.Seek(0), pipe.Env(xEnv))
	return 0
}

func (snap *snapshot) onDeleteL(L *lua.LState) int {
	snap.onDelete = pipe.NewByLua(L, pipe.Seek(0), pipe.Env(xEnv))
	return 0
}

func (snap *snapshot) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "run":
		return lua.NewFunction(snap.runL)
	case "sync":
		return lua.NewFunction(snap.syncL)
	case "poll":
		return lua.NewFunction(snap.pollL)
	case "on_create":
		return lua.NewFunction(snap.onCreateL)
	case "on_delete":
		return lua.NewFunction(snap.onDeleteL)
	case "on_update":
		return lua.NewFunction(snap.onUpdateL)
	}

	return lua.LNil
}
