package disk

import (
	"fmt"
	"github.com/vela-security/vela-public/lua"
	"strings"
)

func (sum *summary) String() string                         { return fmt.Sprintf("%p", sum) }
func (sum *summary) Type() lua.LValueType                   { return lua.LTObject }
func (sum *summary) AssertFloat64() (float64, bool)         { return 0, false }
func (sum *summary) AssertString() (string, bool)           { return "", false }
func (sum *summary) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (sum *summary) Peek() lua.LValue                       { return sum }

func (sum *summary) check(L *lua.LState) {
	sum.Update()
	err := sum.fail.Wrap()
	if err != nil {
		L.RaiseError("disk info got fail %v", err)
		return
	}
}

func (sum *summary) Index(L *lua.LState, key string) lua.LValue {

	sum.check(L)

	if strings.HasPrefix(key, "dev_") {
		return sum.devL(key[4:])
	}

	return lua.LNil
}

func (sum *summary) devL(name string) lua.LValue {
	dev := sum.LookupDevice(name)
	if dev == nil {
		return lua.LNil
	}
	return dev
}
