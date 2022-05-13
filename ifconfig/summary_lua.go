package ifconfig

import (
	"fmt"
	"github.com/vela-security/vela-public/grep"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	"github.com/vela-security/vela-public/worker"
	"gopkg.in/tomb.v2"
	"time"
)

func (sum *summary) String() string                         { return fmt.Sprintf("%p", sum) }
func (sum *summary) Type() lua.LValueType                   { return lua.LTObject }
func (sum *summary) AssertFloat64() (float64, bool)         { return 0, false }
func (sum *summary) AssertString() (string, bool)           { return "", false }
func (sum *summary) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (sum *summary) Peek() lua.LValue                       { return sum }

func (sum *summary) Meta(L *lua.LState, key lua.LValue) lua.LValue {
	switch key.Type() {

	case lua.LTInt:
		return sum.r(int(key.(lua.LInt)))

	case lua.LTNumber:
		return sum.r(int(key.(lua.LNumber)))

	case lua.LTString:
		return sum.Index(L, key.String())
	}

	return lua.LNil
}

func (sum *summary) r(idx int) lua.LValue {
	n := len(sum.iFace)
	if n == 0 {
		return lua.LNil
	}

	if idx-1 > n || idx-1 < 0 {
		return lua.LNil
	}

	return sum.iFace[idx-1].ToLValue()
}

func (sum *summary) pipeL(L *lua.LState) int {
	pp := pipe.NewByLua(L, pipe.Env(xEnv))

	n := sum.Len()
	if n == 0 {
		return 0
	}

	for i := 0; i < n; i++ {
		vx := sum.iFace[i]
		pp.Do(&vx, L, func(err error) {
			xEnv.Errorf("rock interface pipe fail %v", err)
		})
	}
	return 0
}

func (sum *summary) updateL(L *lua.LState) int {
	sum.update()
	return 0
}

func (sum *summary) searchL(filter func(i Interface) bool) lua.Slice {
	if sum.Err != nil {
		return lua.NewSlice(0)
	}

	n := sum.Len()
	if n == 0 {
		return lua.NewSlice(0)
	}

	s := make([]lua.LValue, n)
	k := 0
	for i := 0; i < n; i++ {
		ifi := sum.iFace[i]
		if filter(sum.iFace[i]) {
			s[k] = ifi.ToLValue()
			k++
		}
	}

	return s[:k]
}

func (sum *summary) macL(L *lua.LState) int {
	match := grep.New(L.IsString(1))
	s := sum.searchL(func(i Interface) bool {
		if match(i.face.HardwareAddr.String()) {
			return true
		}
		return false
	})
	L.Push(s)
	return 0
}

func (sum *summary) ipL(L *lua.LState) int {
	match := grep.New(L.IsString(1))
	s := sum.searchL(func(i Interface) bool {
		if filterByAddr(i, match) {
			return true
		}
		return false
	})
	L.Push(s)
	return 1
}

func (sum *summary) nameL(L *lua.LState) int {
	match := grep.New(L.IsString(1))
	s := sum.searchL(func(i Interface) bool {
		if match(i.face.Name) {
			return true
		}
		return false
	})
	L.Push(s)

	return 0
}

func (sum *summary) flowL(L *lua.LState) int {
	tt := L.IsInt(1)
	pp := pipe.NewByLua(L, pipe.Seek(1))
	co := xEnv.Clone(L)

	if tt <= 0 {
		tt = 1000
	}

	tom := new(tomb.Tomb)
	task := func() {
		tk := time.NewTicker(time.Duration(tt) * time.Millisecond)
		defer tk.Stop()

		for {
			select {

			case <-tom.Dying():
				xEnv.Error("rock.interface.flow thread exit")
				return

			case <-tk.C:
				sum.flow(pp, co)
			}
		}
	}

	kill := func() {
		tom.Kill(fmt.Errorf("over"))
	}

	w := worker.New(L, "rock.interface.flow")
	w.Task(task).Kill(kill).Start()
	return 0
}

func (sum *summary) Index(L *lua.LState, key string) lua.LValue {
	switch key {

	case "update":
		return L.NewFunction(sum.updateL)

	case "pipe":
		return L.NewFunction(sum.pipeL)

	case "ip":
		return L.NewFunction(sum.ipL)

	case "name":
		return L.NewFunction(sum.nameL)

	case "mac":
		return L.NewFunction(sum.macL)

	case "flow":
		return L.NewFunction(sum.flowL)
	}

	return lua.LNil
}
