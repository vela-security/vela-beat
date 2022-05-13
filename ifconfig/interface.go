package ifconfig

import (
	"github.com/vela-security/vela-public/lua"
	"net"
	"time"
)

type Interface struct {
	face net.Interface
	flow *flow
	last time.Time
}

func (ifi *Interface) ToLValue() lua.LValue {
	return lua.NewAnyData(ifi)
}

func (ifi *Interface) Name() string {
	return ifi.face.Name
}

func (ifi *Interface) Addr() []net.Addr {
	addrs, err := ifi.face.Addrs()
	if err != nil {
		xEnv.Errorf("network interface lookup fail %v", err)
		return nil
	}
	return addrs
}

func (ifi *Interface) Mac() string {
	if ifi.face.HardwareAddr == nil {
		return ""
	}

	return ifi.face.HardwareAddr.String()
}
