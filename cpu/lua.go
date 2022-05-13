package cpu

import (
	"github.com/vela-security/vela-public/assert"
)

var (
	xEnv assert.Environment
)

func WithEnv(env assert.Environment) {
	xEnv = env
	sum := New()
	sum.Update()
	//mt := lua.NewUserKV()
	//mt.Set("cnt", lua.NewFunction(LookupCpuCntL))
	//mt.Set("info", lua.NewFunction(LookupCpuInfoL))
	xEnv.Set("cpu", sum)
}
