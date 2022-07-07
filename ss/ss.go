package ss

import (
	cond "github.com/vela-security/vela-cond"
)

func By(proto string, cnd *cond.Cond) *summary {
	sum := &summary{}

	switch proto {
	case "tcp":
		sum.tcp4(cnd)
		sum.tcp6(cnd)
	case "udp":
		sum.udp4(cnd)
		sum.udp6(cnd)
	case "tcp4":
		sum.tcp4(cnd)
	case "udp4":
		sum.udp4(cnd)
	case "tcp6":
		sum.tcp6(cnd)
	case "udp6":
		sum.udp6(cnd)

	case "unix":
		sum.unix(cnd)

	case "all", "*":
		sum.tcp4(cnd)
		sum.udp4(cnd)
		sum.tcp6(cnd)
		sum.udp6(cnd)
		sum.unix(cnd)
	default:
		return nil
		//sum.Err = fmt.Errorf("not found %s proto", proto)
	}

	return sum
}
