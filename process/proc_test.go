package process

import (
	"github.com/shirou/gopsutil/process"
	"testing"
)

func TestPid(T *testing.T) {

	p, err := process.NewProcess(22920)
	if err != nil {
		T.Log(err)
	}
	path, _ := p.Exe()
	T.Logf("%v", path)

}
