package psnotify

import (
	"github.com/vela-security/vela-beat/process"
	"github.com/vela-security/vela-public/lua"
)

func (ev *event) String() string                         { return lua.B2S(ev.Byte()) }
func (ev *event) Type() lua.LValueType                   { return lua.LTObject }
func (ev *event) AssertFloat64() (float64, bool)         { return 0, false }
func (ev *event) AssertString() (string, bool)           { return "", false }
func (ev *event) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (ev *event) Peek() lua.LValue                       { return ev }

func (ev *event) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "type":
		return lua.S2L(ev.eTypeToString())
	case "pid":
		return lua.LInt(ev.pid)
	case "ppid":
		return lua.LInt(ev.ppid)
	case "p_name":
		return lua.S2L(ev.ps().Name)
	case "p_exe":
		return lua.S2L(ev.ps().Executable)
	case "p_cwd":
		return lua.S2L(ev.ps().Cwd)
	case "p_cmdline":
		return lua.S2L(ev.ps().Cmdline)
	case "p_args":
		return lua.S2L(ev.ps().ArgsToString())
	case "p_user":
		return lua.S2L(ev.ps().Username)
	case "info":
		return lua.B2L(ev.info())

	case "p":
		if ev.proc.IsNull() {
			ev.proc, _ = process.Pid(ev.pid)
		}
		return ev.proc
	}
	return lua.LNil
}
