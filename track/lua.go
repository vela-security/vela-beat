package track

import (
	"github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

var xEnv assert.Environment

func newLuaTrackPidL(L *lua.LState) int {
	pid := L.IsInt(1)
	cnd := cond.CheckMany(L, cond.Seek(1))
	L.Push(newTrackByPid(int32(pid), cnd))
	return 1
}

func newLuaTrackAllL(L *lua.LState) int {
	tka := newLuaTrackALL(L)
	L.Push(tka)
	return 1
}

func newLuaTrackKwL(L *lua.LState) int {
	L.Push(newTracksKeyWold(L))
	return 1
}

func newLuaTrackNameL(L *lua.LState) int {
	L.Push(newTrackName(L))
	return 1
}

/*
	local v = vela.track.pid()
	local s = vela.track.all(100,"type eq file").pipe(_() end)
*/

func WithEnv(env assert.Environment) {
	xEnv = env
	kv := lua.NewUserKV()
	kv.Set("pid", lua.NewFunction(newLuaTrackPidL))
	kv.Set("all", lua.NewFunction(newLuaTrackAllL))
	kv.Set("kw", lua.NewFunction(newLuaTrackKwL))
	kv.Set("name", lua.NewFunction(newLuaTrackNameL))
	xEnv.Set("track", kv)
}
