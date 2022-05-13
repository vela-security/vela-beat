package ifconfig

import "net"

func noop(p Interface) bool {
	return true
}

func fuzzy(match func(string) bool) func(Interface) bool {
	return func(i Interface) bool {
		if match(i.face.Name) {
			return true
		}

		if match(i.face.HardwareAddr.String()) {
			return true
		}

		if match(i.face.Flags.String()) {
			return true
		}

		if filterByAddr(i, match) {
			return true
		}

		return false
	}
}

func filterByAddr(ifi Interface, match func(string) bool) bool {
	addr := ifi.Addr()
	n := len(addr)
	if n == 0 {
		return false
	}

	for i := 0; i < n; i++ {
		if match(addr[i].(*net.IPNet).IP.String()) {
			return true
		}
	}

	return false
}
