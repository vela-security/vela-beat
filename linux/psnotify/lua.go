//go:build darwin || freebsd || netbsd || openbsd || linux
// +build darwin freebsd netbsd openbsd linux

package psnotify

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

var xEnv assert.Environment

func constructor(L *lua.LState) int {
	cfg := newConfig(L)

	proc := L.NewProc(cfg.name, typeof)
	if proc.IsNil() {
		proc.Set(newNotify(cfg))
	} else {
		nty := proc.Data.(*notify)
		xEnv.Free(nty.cfg.co)
		nty.cfg = cfg
	}

	L.Push(proc)
	return 1
}

func WithEnv(env assert.Environment, x lua.UserKV) {
	xEnv = env
	x.Set("psnotify", lua.NewFunction(constructor))
}
