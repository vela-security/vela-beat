package ss

import (
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	"reflect"
	"time"
)

var (
	lnTypeof  = reflect.TypeOf((*ListenSnap)(nil)).String()
	subscript = 0
)

func (snap *ListenSnap) runL(L *lua.LState) int {
	snap.do(snap.enable)
	return 0
}

func (snap *ListenSnap) pollL(L *lua.LState) int {
	n := L.IsInt(1)
	var interval time.Duration
	if n < 5 {
		interval = 5 * time.Second
	} else {
		interval = time.Duration(n) * time.Second
	}
	snap.ticker = time.NewTicker(interval)
	xEnv.Spawn(0, func() {
		for range snap.ticker.C {
			snap.do(snap.enable) //report diff
		}
	})

	snap.V(lua.PTRun, time.Now())
	return 0
}

func (snap *ListenSnap) syncL(L *lua.LState) int {
	snap.do(false)
	return 0
}

func (snap *ListenSnap) onCreateL(L *lua.LState) int {
	snap.onCreate.CheckMany(L, pipe.Env(xEnv), pipe.Seek(0))
	return 0
}

func (snap *ListenSnap) onUpdateL(L *lua.LState) int {
	snap.onUpdate.CheckMany(L, pipe.Env(xEnv), pipe.Seek(0))
	return 0
}

func (snap *ListenSnap) onDeleteL(L *lua.LState) int {
	snap.onDelete.CheckMany(L, pipe.Env(xEnv), pipe.Seek(0))
	return 0
}

func (snap *ListenSnap) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "run":
		return lua.NewFunction(snap.runL)
	case "poll":
		return lua.NewFunction(snap.pollL)
	case "sync":
		return lua.NewFunction(snap.syncL)
	case "on_create":
		return lua.NewFunction(snap.onCreateL)
	case "on_update":
		return lua.NewFunction(snap.onUpdateL)
	case "on_delete":
		return lua.NewFunction(snap.onUpdateL)
	}

	return lua.LNil
}

func newListenSnapshot(L *lua.LState) *ListenSnap {
	return &ListenSnap{
		enable:   L.IsTrue(1),
		co:       xEnv.Clone(L),
		bkt:      []string{"vela", "listen", "snapshot"},
		onCreate: pipe.New(),
		onDelete: pipe.New(),
		onUpdate: pipe.New(),
		current:  make(map[string]*listen, 64),
		update:   make(map[string]*listen, 64),
		delete:   make(map[string]interface{}, 64),
		report:   &report{},
	}
}
