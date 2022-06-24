package socket

import (
	"github.com/vela-security/vela-beat/process"
	cond "github.com/vela-security/vela-cond"
	"syscall"
)

func (sum *summary) handle(sock *Socket, cnd *cond.Cond) {
	if sock.Pid != 0 {
		p, er := process.Pid(int(sock.Pid))
		if er != nil {
			sock.Process = ""
		}
		sock.Process = p.Executable
		sock.Username = p.Username
	}

	if cnd.Match(sock) {
		sum.append(sock)
	}
}

func (sum *summary) tcp(cnd *cond.Cond) {
	sst.R()
	//刷新缓存

	handle := func(item *InetDiagMsg) {
		sock := toSocket(item)
		sock.State = TCPState(item.State).String()
		sock.Protocol = syscall.IPPROTO_TCP
		sum.handle(sock, cnd)
	}

	err := connect(syscall.IPPROTO_TCP, handle)
	if err != nil {
		sum.Err = err
	}
}

func (sum *summary) udp(cnd *cond.Cond) {
	//刷新缓存
	sst.R()

	handle := func(item *InetDiagMsg) {
		sock := toSocket(item)
		sock.Protocol = syscall.IPPROTO_UDP
		sum.handle(sock, cnd)
	}

	err := connect(syscall.IPPROTO_UDP, handle)
	if err != nil {
		sum.Err = err
		return
	}
}
