package host

import (
	"fmt"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

var xEnv assert.Environment

func (h *Host) String() string                         { return fmt.Sprintf("%p", h) }
func (h *Host) Type() lua.LValueType                   { return lua.LTObject }
func (h *Host) AssertFloat64() (float64, bool)         { return 0, false }
func (h *Host) AssertString() (string, bool)           { return "", false }
func (h *Host) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (h *Host) Peek() lua.LValue                       { return h }

func WithEnv(env assert.Environment) {
	xEnv = env
	env.Set("host", &Host{})
}
