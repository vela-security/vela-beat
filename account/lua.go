package account

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
	"os/user"
)

var xEnv assert.Environment

/*
	local v = vela.account.all(cnd)
	local u = vela.account.current()
	local g = vela.group.all(cnd)
	local l = vela.account.lookup("")

	local snap = vela.account.snapshot(true)
	snap.sync()
	snap.on_delete()
	snap.on_create()
	snap.on_update()
	snap.poll(5)
*/

func allL(L *lua.LState) int {
	snap := newSnapshot()
	snap.init()
	proc := L.NewProc(snap.Name(), typeof)
	proc.Set(snap)
	L.Push(proc)
	return 1
}

func currentL(L *lua.LState) int {
	u, err := user.Current()
	if err != nil {
		L.RaiseError("got current user fail %v", err)
		return 0
	}

	L.Push(&Account{
		GID:    u.Gid,
		UID:    u.Uid,
		Name:   u.Name,
		Home:   u.HomeDir,
		Status: "OK",
	})

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
	kv.Set("current", lua.NewFunction(currentL))
	kv.Set("snapshot", lua.NewFunction(snapshotL))
	xEnv.Set("account", kv)

	xEnv.Mime(Account{}, encode, decode)
}
