//go:build windows
// +build windows

package ss

import (
	cond "github.com/vela-security/vela-cond"
	"syscall"
)

func (sum *summary) udp4(cnd *cond.Cond) {
	tbl, err := GetUDPTableOwnerPID(true)
	if err != nil {
		sum.Err = err
		return
	}

	snp, err := CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		sum.Err = err
		return
	}
	defer snp.Close()

	s := tbl.Rows()
	for i := range s {
		sock := toSocket(&s[i], snp)
		sock.Protocol = syscall.IPPROTO_UDP
		sock.Family = syscall.IPPROTO_IP
		if cnd.Match(sock) {
			sum.append(sock)
		}
	}
}

func (sum *summary) udp6(cnd *cond.Cond) {
	tbl, err := GetUDP6TableOwnerPID(true)
	if err != nil {
		sum.Err = err
		return
	}

	snp, err := CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		sum.Err = err
		return
	}
	defer snp.Close()

	s := tbl.Rows()
	for i := range s {
		sock := toSocket(&s[i], snp)
		sock.Protocol = syscall.IPPROTO_UDP
		sock.Family = syscall.IPPROTO_IPV6
		if cnd.Match(sock) {
			sum.append(sock)
		}
	}
}

func (sum *summary) udp(cnd *cond.Cond) {
	sum.udp4(cnd)
	sum.udp6(cnd)
}
