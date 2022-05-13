package socket

import (
	"github.com/vela-security/vela-public/lua"
	"syscall"
)

func (sock *Socket) Index(L *lua.LState, key string) lua.LValue {
	switch key {

	case "pid":
		return lua.LInt(sock.Pid)
	case "family":
		return lua.LInt(sock.Family)
	case "protocol":
		switch sock.Protocol {
		case syscall.IPPROTO_TCP:
			return lua.LString("tcp")
		case syscall.IPPROTO_UDP:
			return lua.LString("udp")
		default:
			return lua.LString("")
		}

	case "local_addr":
		return lua.S2L(sock.LocalIP)
	case "local_port":
		return lua.LInt(sock.LocalPort)
	case "remote_addr":
		return lua.S2L(sock.RemoteIP)
	case "remote_port":
		return lua.LInt(sock.RemotePort)

	case "path":
		return lua.S2L(sock.Path)

	case "state":
		return lua.S2L(sock.State)

	case "process":
		return lua.S2L(sock.Process)

	case "user":
		return lua.S2L(sock.Username)
	}

	return lua.LNil

}
