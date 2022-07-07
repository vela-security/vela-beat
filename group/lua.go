package group

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

var xEnv assert.Environment

func allL(L *lua.LState) int {
	snap := newSnapshot()
	snap.init()
	proc := L.NewProc(snap.Name(), typeof)
	proc.Set(snap)
	L.Push(proc)
	return 1
}

func snapshotL(L *lua.LState) int {
	enable := L.IsTrue(1)
	snap := newSnapshot()
	snap.co = xEnv.Clone(L)
	snap.enable = enable
	proc := L.NewProc(snap.Name(), typeof)
	proc.Set(snap)
	L.Push(proc)
	return 1
}

func WithEnv(env assert.Environment) {
	xEnv = env
	kv := lua.NewUserKV()
	kv.Set("all", lua.NewFunction(allL))
	kv.Set("snapshot", lua.NewFunction(snapshotL))
	xEnv.Set("group", kv)

	xEnv.Mime(Group{}, encode, decode)
}
