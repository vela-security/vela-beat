package beat

import (
	"github.com/vela-security/vela-beat/linux/dns"
	"github.com/vela-security/vela-beat/linux/psnotify"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

func otherByEnv(env assert.Environment) {
	linux := lua.NewUserKV()
	dns.WithEnv(env, linux)
	psnotify.WithEnv(env, linux)
	env.Global("linux", linux)
}
