package disk

import (
	"github.com/vela-security/vela-public/assert"
)

var (
	xEnv assert.Environment
)

/*
	local disk = vela.disk.C

*/

func WithEnv(env assert.Environment) {
	xEnv = env
	sum := New()
	xEnv.Set("disk", sum)
}
