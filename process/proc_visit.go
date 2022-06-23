package process

import (
	"github.com/elastic/gosigar"
)

func (proc *Process) LookupState() error {
	st := gosigar.ProcState{}

	err := st.Get(proc.Pid)
	if err != nil {
		return err
	}

	proc.Name = st.Name
	proc.State = state(byte(st.State))
	proc.Ppid = st.Ppid
	proc.Pgid = uint32(st.Pgid)
	proc.Username = st.Username
	proc.LookupExec()

	return nil
}

func (proc *Process) Lookup() error {
	return proc.LookupState()
}

func (proc *Process) IsNull() bool {
	return proc == nil || proc.Pid == -1
}
