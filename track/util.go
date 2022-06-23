package track

import (
	"encoding/binary"
	"math/big"
	"net"
)

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func ipv6ToInt(IPv6Addr net.IP) *big.Int {
	IPv6Int := big.NewInt(0)
	IPv6Int.SetBytes(IPv6Addr)
	return IPv6Int
}

func IntToIpv6(v6 *big.Int) net.IP {
	ip := v6.Bytes()
	var a net.IP = ip
	return a
}
