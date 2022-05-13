package socket

import "github.com/vela-security/vela-public/auxlib"

func fuzzy(match func(string) bool) func(*Socket) bool {
	return func(sock *Socket) bool {
		if match(sock.State) || match(sock.LocalIP) || match(sock.RemoteIP) {
			return true
		}

		if sock.Process != "" && match(sock.Process) {
			return true
		}

		if match(auxlib.ToString(sock.LocalPort)) || match(auxlib.ToString(sock.RemotePort)) {
			return true
		}

		return false
	}
}
