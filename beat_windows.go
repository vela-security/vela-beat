package beat

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-beat/windows/event"
	"github.com/vela-security/vela-beat/windows/registry"
	"github.com/vela-security/vela-beat/windows/wmi"
)

func otherByEnv(env assert.Environment) {
	win := lua.NewUserKV()
	event.Inject(env, win)
	wmi.Inject(env, win)
	registry.Inject(env, win)

	env.Global("win", win)
}
