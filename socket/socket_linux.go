package socket

import (
	"github.com/vela-security/vela-beat/process"
	"syscall"
)

func (sum *summary) handle(sock *Socket, filter func(*Socket) bool) {
	if sock.Pid != 0 {
		p, er := process.Pid(int(sock.Pid))
		if er != nil {
			sock.Process = ""
		}
		sock.Process = p.Executable
		sock.Username = p.Username
	}

	if filter(sock) {
		sum.append(sock)
	}
}

func (sum *summary) tcp(filter func(*Socket) bool) {
	sst.R()
	//刷新缓存

	handle := func(item *InetDiagMsg) {
		sock := toSocket(item)
		sock.State = TCPState(item.State).String()
		sock.Protocol = syscall.IPPROTO_TCP
		sum.handle(sock, filter)
	}

	err := connect(syscall.IPPROTO_TCP, handle)
	if err != nil {
		sum.Err = err
	}
}

func (sum *summary) udp(filter func(*Socket) bool) {
	//刷新缓存
	sst.R()

	handle := func(item *InetDiagMsg) {
		sock := toSocket(item)
		sock.Protocol = syscall.IPPROTO_UDP
		sum.handle(sock, filter)
	}

	err := connect(syscall.IPPROTO_UDP, handle)
	if err != nil {
		sum.Err = err
		return
	}
}
