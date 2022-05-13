//go:build windows
// +build windows

package socket

import "syscall"

func (sum *summary) tcp4(filter func(*Socket) bool) {
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
		if filter(sock) {
			sum.append(sock)
		}
	}
}

func (sum *summary) tcp6(filter func(*Socket) bool) {
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
		if filter(sock) {
			sum.append(sock)
		}
	}
}

func (sum *summary) tcp(filter func(*Socket) bool) {
	sum.tcp4(filter)
	sum.tcp6(filter)
}
