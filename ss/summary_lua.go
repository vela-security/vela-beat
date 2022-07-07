package ss

import (
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

func (sum *summary) String() string                         { return lua.B2S(sum.Byte()) }
func (sum *summary) Type() lua.LValueType                   { return lua.LTObject }
func (sum *summary) AssertFloat64() (float64, bool)         { return 0, false }
func (sum *summary) AssertString() (string, bool)           { return "", false }
func (sum *summary) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (sum *summary) Peek() lua.LValue                       { return sum }

func (sum *summary) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "closed":
		return lua.LInt(sum.CLOSED)
	case "listen":
		return lua.LInt(sum.LISTEN)
	case "syn_sent":
		return lua.LInt(sum.SYN_SENT)
	case "syn_rcvd":
		return lua.LInt(sum.SYN_RCVD)
	case "estab":
		return lua.LInt(sum.ESTABLISHED)
	case "fin_wait_1":
		return lua.LInt(sum.FIN_WAIT1)
	case "fin_wait_2":
		return lua.LInt(sum.FIN_WAIT2)
	case "close_wait":
		return lua.LInt(sum.CLOSE_WAIT)
	case "closing":
		return lua.LInt(sum.CLOSING)
	case "last_ack":
		return lua.LInt(sum.LAST_ACK)
	case "time_wait":
		return lua.LInt(sum.TIME_WAIT)
	case "delete_tcb":
		return lua.LInt(sum.DELETE_TCB)
	case "total":
		return lua.LInt(sum.Total)

	case "err":
		if sum.Err == nil {
			return lua.LNil
		}
		return lua.S2L(sum.Err.Error())

	case "pipe":
		return lua.NewFunction(sum.pipeL)

	}

	return lua.LNil
}

func (sum *summary) pipeL(L *lua.LState) int {
	n := len(sum.Sockets)
	if n == 0 {
		return 0
	}
	pp := pipe.NewByLua(L, pipe.Env(xEnv))
	for i := 0; i < n; i++ {
		pp.Do(sum.Sockets[i], L, func(err error) {
			xEnv.Errorf("socket summary pipe call fail %v", err)
		})
	}
	return 0
}
