package process

import (
	"fmt"
	"github.com/vela-security/vela-public/grep"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

func (sum *summary) String() string                         { return fmt.Sprintf("%p", sum) }
func (sum *summary) Type() lua.LValueType                   { return lua.LTObject }
func (sum *summary) AssertFloat64() (float64, bool)         { return 0, false }
func (sum *summary) AssertString() (string, bool)           { return "", false }
func (sum *summary) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (sum *summary) Peek() lua.LValue                       { return sum }

func (sum *summary) pipeL(L *lua.LState) int {
	filter := fuzzy(grep.New(L.IsString(1)))
	pp := pipe.NewByLua(L, pipe.Seek(1))
	var i uint32 = 0

	for ; i < sum.Total; i++ {
		pv := sum.Process[i]
		if !filter(pv) {
			continue
		}
		pp.Do(pv, L, func(err error) {
			xEnv.Errorf("sum process pipe fail %v", err)
		})
	}
	return 0
}

func (sum *summary) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "total":
		return lua.LInt(sum.Total)

	case "run":
		return lua.LInt(sum.Running)

	case "sleep":
		return lua.LInt(sum.Sleeping)

	case "stop":
		return lua.LInt(sum.Stopped)

	case "idle":
		return lua.LInt(sum.Idle)

	case "pipe":
		return lua.NewFunction(sum.pipeL)
	}

	return lua.LNil
}
