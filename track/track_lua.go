package track

import (
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

func (tk *track) String() string                         { return "vela.track" }
func (tk *track) Type() lua.LValueType                   { return lua.LTObject }
func (tk *track) AssertFloat64() (float64, bool)         { return 0, false }
func (tk *track) AssertString() (string, bool)           { return "", false }
func (tk *track) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (tk *track) Peek() lua.LValue                       { return tk }

func (tk *track) pipe(co *lua.LState, pip *pipe.Px) int {
	n := len(tk.data)
	if n == 0 {
		return 0
	}

	for i := 0; i < n; i++ {
		pip.Do(&tk.data[i], co, func(err error) {
			xEnv.Errorf("vela track pipe fail %v", err)
		})
	}

	return 0
}

func (tk *track) pipeL(L *lua.LState) int {
	pip := pipe.NewByLua(L, pipe.Env(xEnv), pipe.Seek(0))
	co := xEnv.Clone(L)
	defer xEnv.Free(co)

	return tk.pipe(co, pip)
}

func (tk *track) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "ok":
		return lua.LBool(tk.ok())
	case "exe":
		return lua.S2L(tk.exe)
	case "size":
		return lua.LInt(len(tk.data))
	case "pipe":
		return lua.NewFunction(tk.pipeL)

	}

	return lua.LNil
}
