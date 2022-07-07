package psnotify

import (
	"github.com/vela-security/vela-beat/process"
	"github.com/vela-security/vela-beat/ss"
	"github.com/vela-security/vela-beat/track"
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-public/lua"
	"strconv"
)

func (ev *event) String() string                         { return lua.B2S(ev.Byte()) }
func (ev *event) Type() lua.LValueType                   { return lua.LTObject }
func (ev *event) AssertFloat64() (float64, bool)         { return 0, false }
func (ev *event) AssertString() (string, bool)           { return "", false }
func (ev *event) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (ev *event) Peek() lua.LValue                       { return ev }

func (ev *event) ss(L *lua.LState) int {
	proto := L.CheckString(1)

	var cnd *cond.Cond
	if n := L.GetTop(); n <= 1 {
		cnd = cond.New("pid = " + strconv.Itoa(ev.pid))
	} else {
		cnd = cond.CheckMany(L, cond.Seek(1))
	}
	L.Push(ss.By(proto, cnd))
	return 1
}

func (ev *event) track(L *lua.LState) int {
	cnd := cond.CheckMany(L)
	L.Push(track.ByPid(int32(ev.pid), cnd))
	return 1
}

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

	case "ps":
		if ev.proc.IsNull() {
			ev.proc, _ = process.Pid(ev.pid)
		}
		return ev.proc

	case "ss":
		return lua.NewFunction(ev.ss)

	case "track":
		return lua.NewFunction(ev.track)
	}
	return lua.LNil
}
