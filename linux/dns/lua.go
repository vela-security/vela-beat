package dns

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

var xEnv assert.Environment

func (m *monitor) pipeL(L *lua.LState) int {
	m.cfg.pipe = pipe.NewByLua(L,
		pipe.Env(xEnv),
		pipe.Seek(0))

	return 0
}

func (m *monitor) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "pipe":
		return L.NewFunction(m.pipeL)
	}
	return lua.LNil
}

func constructor(L *lua.LState) int {
	cfg := newConfig(L)
	proc := L.NewProc(cfg.name, typeof)
	if proc.IsNil() {
		proc.Set(newM(cfg))
	} else {
		m := proc.Data.(*monitor)
		xEnv.Free(m.cfg.co)

		m.cfg = cfg
	}

	L.Push(proc)
	return 1
}

/*
	local dns = linux.dns{
		name = "monitor_dns",
		bind = "udp://0.0.0.0:53",
    }
	dns.pipe(_(tx) end)


*/

func WithEnv(env assert.Environment, x lua.UserKV) {
	xEnv = env
	x.Set("dns", lua.NewFunction(constructor))
}
