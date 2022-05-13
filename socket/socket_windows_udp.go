//go:build windows
// +build windows

package socket

import "syscall"

func (sum *summary) udp4(filter func(*Socket) bool ) {
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
		sock := toSocket(&s[i] , snp)
		sock.Protocol = syscall.IPPROTO_UDP
		sock.Family = syscall.IPPROTO_IP
		if filter(sock) {
			sum.append(sock)
		}
	}
}

func (sum *summary) udp6(filter func(*Socket) bool) {
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
		sock := toSocket(&s[i] , snp)
		sock.Protocol = syscall.IPPROTO_UDP
		sock.Family = syscall.IPPROTO_IPV6
		if filter(sock) {
			sum.append(sock)
		}
	}
}

func (sum *summary) udp(filter func(*Socket) bool) {
	sum.udp4(filter)
	sum.udp6(filter)
}

