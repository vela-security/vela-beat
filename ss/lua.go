package ss

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
	cnd := cond.CheckMany(L, cond.Seek(1))

	sum := By(proto, cnd)
	if sum == nil {
		L.RaiseError("invalid socket protocol , got %s", proto)
		return 0
	}

	L.Push(sum)
	return 1
}

func newListenSnapshotL(L *lua.LState) int {
	snap := newListenSnapshot(L)
	proc := L.NewProc(snap.Name(), lnTypeof)
	proc.Set(snap)
	L.Push(proc)
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
	env.Set("ss_listen_snapshot", lua.NewFunction(newListenSnapshotL))
	xEnv.Mime(&listen{}, encode, decode)
}
