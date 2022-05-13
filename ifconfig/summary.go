package ifconfig

import (
	"net"
	"time"
)

type summary struct {
	iFace []Interface
	Err   error
}

func (sum *summary) Len() int {
	return len(sum.iFace)
}

func (sum *summary) append(vi Interface) {
	sum.iFace = append(sum.iFace, vi)
}

func (sum *summary) update() {
	face, err := net.Interfaces()
	if err != nil {
		sum.Err = err
		return
	}

	n := len(face)
	now := time.Now()

	for i := 0; i < n; i++ {
		ifc := Interface{face: face[i], last: now}
		sum.iFace = append(sum.iFace, ifc)
	}
}

func (sum *summary) ok() bool {
	if sum.Err != nil {
		return false
	}

	return true
}
