package track

import (
	"github.com/vela-security/vela-beat/process"
	cond "github.com/vela-security/vela-cond"
)

func ByPid(pid int32, cnd *cond.Cond) *track {
	return newTrackByPid(pid, cnd)
}

func ByProcess(p *process.Process, cnd *cond.Cond) *track {
	return newTrackByPid(int32(p.Pid), cnd)
}

func ByName(name string, cnd *cond.Cond) *tracks {
	return newTrackByName(name, cnd)
}
