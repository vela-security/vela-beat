package socket

import (
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

var xEnv assert.Environment

/*
	local s = rock.ss("tcp" , "stat == LISTEN")
	s.pipe(_(sock)
		sock.pid
		sock.pid
		sock.local_addr
		sock.remote_port
		sock.remote_addr
		sock.path
		sock.proc.name
	end)
*/

func ssL(L *lua.LState) int {
	proto := L.IsString(1)
	sum := &summary{}
	cnd := cond.CheckMany(L, cond.Seek(1))

	switch proto {
	case "tcp":
		sum.tcp(cnd)
	case "udp":
		sum.udp(cnd)

	case "unix":
		sum.unix(cnd)

	case "all", "*":
		sum.tcp(cnd)
		sum.udp(cnd)
		sum.unix(cnd)

	default:
		L.RaiseError("invalid socket protocol , got %s", proto)
		return 0

	}

	L.Push(sum)
	return 1
}

func WithEnv(env assert.Environment) {
	xEnv = env
	//kv := lua.NewUserKV()
	//kv.Set("pid", lua.NewFunction(pidL))
	//kv.Set("all", lua.NewFunction(allL))
	//kv.Set("tcp", lua.NewFunction(tcpL))
	//kv.Set("udp", lua.NewFunction(udpL))
	//kv.Set("unix", lua.NewFunction(unixL))
	//kv.Set("not", lua.NewFunction(notL))
	//kv.Set("listen", lua.NewFunction(listenL))

	env.Set("ss", lua.NewFunction(ssL))
}
