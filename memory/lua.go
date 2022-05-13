package memory

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
	xEnv.Set("memory", sum)
}
