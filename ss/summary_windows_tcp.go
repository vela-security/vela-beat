//go:build windows
// +build windows

package ss

import (
	cond "github.com/vela-security/vela-cond"
	"syscall"
)

func (sum *summary) tcp4(cnd *cond.Cond) {
	tbl, err := GetTCPTable2(true)
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
		sock.Protocol = syscall.IPPROTO_TCP
		sock.Family = syscall.IPPROTO_IP
		if cnd.Match(sock) {
			sum.append(sock)
		}
	}
}

func (sum *summary) tcp6(cnd *cond.Cond) {
	tbl, err := GetTCP6Table2(true)
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
		sock.Protocol = syscall.IPPROTO_TCP
		sock.Family = syscall.IPPROTO_IPV6
		if cnd.Match(sock) {
			sum.append(sock)
		}
	}
}

func (sum *summary) tcp(cnd *cond.Cond) {
	sum.tcp4(cnd)
	sum.tcp6(cnd)
}
