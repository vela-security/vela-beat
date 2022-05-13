package service

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

var xEnv assert.Environment

func lookupL(L *lua.LState) int {
	pattern := L.IsString(1)
	filter := newFilter(pattern)
	su := New()
	su.collect(filter)
	L.Push(su)
	return 1
}

func WithEnv(env assert.Environment) {
	xEnv = env
	xEnv.Set("service", lua.NewFunction(lookupL))
}
