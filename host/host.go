package host

import (
	"github.com/shirou/gopsutil/host"
	"github.com/vela-security/vela-public/lua"
	"time"
)

type Host struct {
	id       string
	platform string
	family   string
	version  string
	hostname string
	kernel   string

	time        int64
	proc        uint64
	uptime      uint64
	bootTime    uint64
	virtual     string
	virtualRole string
}

func (h *Host) Update() {
	now := time.Now().Unix()

	if now-h.time < 30 {
		return
	}

	info, err := host.Info()
	if err != nil {
		xEnv.Errorf("got system host info fail %v", err)
		return
	}
	h.id = info.HostID
	h.platform = info.Platform
	h.family = info.PlatformFamily
	h.version = info.PlatformVersion
	h.uptime = info.Uptime
	h.bootTime = info.BootTime
	h.hostname = info.Hostname
	h.kernel = info.KernelVersion
	h.virtual = info.VirtualizationSystem
	h.virtualRole = info.VirtualizationRole
	h.time = now

}

func (h *Host) Index(L *lua.LState, key string) lua.LValue {
	h.Update()

	switch key {
	case "id":
		return lua.S2L(h.id)
	case "name":
		return lua.S2L(h.hostname)
	case "platform":
		return lua.S2L(h.platform)
	case "family":
		return lua.S2L(h.family)
	case "version":
		return lua.S2L(h.version)
	case "kernel":
		return lua.S2L(h.kernel)
	case "uptime":
		return lua.LNumber(h.uptime)
	case "boot_time":
		return lua.LNumber(h.bootTime)
	case "virtual":
		return lua.S2L(h.virtual)
	case "virtual_role":
		return lua.S2L(h.virtualRole)
	case "proc_number":
		return lua.LInt(h.proc)
	}

	return lua.LNil
}
