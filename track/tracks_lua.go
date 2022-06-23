package track

import (
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

func (tks *tracks) String() string                         { return "vela.track.all" }
func (tks *tracks) Type() lua.LValueType                   { return lua.LTObject }
func (tks *tracks) AssertFloat64() (float64, bool)         { return 0, false }
func (tks *tracks) AssertString() (string, bool)           { return "", false }
func (tks *tracks) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (tks *tracks) Peek() lua.LValue                       { return tks }

func (tks *tracks) pipeL(L *lua.LState) int {
	pip := pipe.NewByLua(L, pipe.Env(xEnv), pipe.Seek(0))
	co := xEnv.Clone(L)
	defer xEnv.Free(co)

	for _, sec := range tks.data {
		pip.Do(&sec, co, func(err error) {
			xEnv.Errorf("tracks pipe fail %v", err)
		})
	}

	return 0
}

func (tks *tracks) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "size":
		return lua.LNumber(len(tks.data))
	case "pipe":
		return lua.NewFunction(tks.pipeL)

	}

	return lua.LNil
}
