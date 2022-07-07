package group

import (
	"github.com/vela-security/vela-public/lua"
)

func (g *Group) String() string                         { return lua.B2S(g.Byte()) }
func (g *Group) Type() lua.LValueType                   { return lua.LTObject }
func (g *Group) AssertFloat64() (float64, bool)         { return 0, false }
func (g *Group) AssertString() (string, bool)           { return "", false }
func (g *Group) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (g *Group) Peek() lua.LValue                       { return g }

func (g *Group) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "name":
		return lua.S2L(g.Name)
	case "gid":
		return lua.S2L(g.GID)
	case "description":
		return lua.S2L(g.Description)
	}

	return lua.LNil
}
