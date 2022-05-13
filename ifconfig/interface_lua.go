package ifconfig

import (
	"bytes"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
	"net"
)

func (ifi *Interface) addrL(L *lua.LState) int {
	n := L.CheckInt(1)

	addr, err := ifi.face.Addrs()
	if err != nil {
		return 0
	}

	if n >= len(addr) {
		return 0
	}
	ip := addr[n].(*net.IPNet)

	L.Push(lua.S2L(ip.IP.String()))
	L.Push(lua.S2L(ip.Mask.String()))
	return 2
}

func (ifi *Interface) helper(match func(string) bool) string {
	addr, err := ifi.face.Addrs()
	if err != nil {
		return ""
	}

	n := len(addr)
	if n == 0 {
		return ""
	}

	var buf bytes.Buffer
	k := 0
	for i := 0; i < n; i++ {
		ip := addr[i].(*net.IPNet).IP.String()

		if !match(ip) {
			continue
		}

		if k > 0 {
			buf.WriteByte(',')
		}
		k++

		buf.WriteString(ip)
	}
	return buf.String()
}

func (ifi *Interface) ipv4L() string {
	return ifi.helper(auxlib.Ipv4)
}

func (ifi *Interface) ipv6L() string {
	return ifi.helper(auxlib.Ipv6)
}

func (ifi *Interface) Index(L *lua.LState, key string) lua.LValue {

	switch key {

	case "name":
		return lua.S2L(ifi.face.Name)

	case "flag":
		return lua.S2L(ifi.face.Flags.String())

	case "index":
		return lua.LInt(ifi.face.Index)

	case "mac":
		return lua.S2L(ifi.Mac())

	case "mtu":
		return lua.LInt(ifi.face.MTU)

	case "addr":
		return lua.NewFunction(ifi.addrL)

	case "ipv4":
		return lua.S2L(ifi.ipv4L())

	case "ipv6":
		return lua.S2L(ifi.ipv6L())

	}

	return lua.LNil

}
