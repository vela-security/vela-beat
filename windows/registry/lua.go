package registry

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

//rock.registry.LOCAL_MACHINE.create("SOFTWARE\\Hello Go" , "ALL_ACCESS")

var xEnv assert.Environment

func Inject(env assert.Environment, win lua.UserKV) {
	xEnv = env

	r := lua.NewUserKV()
	r.Set("USERS", registryL("USERS"))
	r.Set("LOCAL_MACHINE", registryL("LOCAL_MACHINE"))
	r.Set("CLASSES_ROOT", registryL("CLASSES_ROOT"))
	r.Set("CURRENT_CONFIG", registryL("CURRENT_CONFIG"))
	r.Set("CURRENT_USER", registryL("CURRENT_USER"))
	r.Set("PERFORMANCE_DATA", registryL("PERFORMANCE_DATA"))
	win.Set("registry", r)
}
