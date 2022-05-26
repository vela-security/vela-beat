package socket

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/grep"
	"github.com/vela-security/vela-public/lua"
)

var xEnv assert.Environment

func pidL(L *lua.LState) int {
	pid := L.CheckInt(1)
	sum := &summary{}
	sum.all(func(s *Socket) bool {
		return s.Pid == uint32(pid)
	})
	L.PushAny(sum)
	return 1
}

func tcpL(L *lua.LState) int {
	sum := &summary{}
	sum.tcp(fuzzy(grep.New(L.IsString(1))))
	L.PushAny(sum)
	return 1
}

func udpL(L *lua.LState) int {
	sum := &summary{}
	sum.udp(fuzzy(grep.New(L.IsString(1))))
	L.PushAny(sum)
	return 1
}

func unixL(L *lua.LState) int {
	sum := &summary{}
	sum.unix(fuzzy(grep.New(L.IsString(1))))
	L.PushAny(sum)
	return 1
}

func allL(L *lua.LState) int {
	sum := &summary{}
	match := fuzzy(grep.New(L.IsString(1)))
	sum.all(match)
	L.PushAny(sum)
	return 1
}

func listenL(L *lua.LState) int {
	sum := &summary{}
	match := fuzzy(grep.New(L.IsString(1)))
	sum.all(func(sock *Socket) bool {
		if sock.State != "LISTEN" {
			return false
		}
		return match(sock)
	})
	L.PushAny(sum)
	return 1
}

func notL(L *lua.LState) int {
	sum := &summary{}
	match := fuzzy(grep.New(L.IsString(1)))
	sum.all(func(sock *Socket) bool {
		return !match(sock)
	})
	L.PushAny(sum)
	return 1

}

/*
	local s = rock.ss.all("*tcp")
	local s = rock.ss.tcp("x")
	local s = rock.ss.udp("x")
	local s = rock.ss.unix("*sock*")
	local s = rock.ss.listen()
	local s = rock.ss.not("127.0.0.1")


	s.pipe(_(sock)
		sock.pid
		sock.pid
		sock.local_address
		sock.remote_port
		sock.remote_addr
		sock.path
		sock.proc.name
	end)



*/

func WithEnv(env assert.Environment) {
	xEnv = env
	kv := lua.NewUserKV()
	kv.Set("pid", lua.NewFunction(pidL))
	kv.Set("all", lua.NewFunction(allL))
	kv.Set("tcp", lua.NewFunction(tcpL))
	kv.Set("udp", lua.NewFunction(udpL))
	kv.Set("unix", lua.NewFunction(unixL))
	kv.Set("not", lua.NewFunction(notL))
	kv.Set("listen", lua.NewFunction(listenL))

	env.Set("ss", kv)
}
