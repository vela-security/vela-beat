package process

import "github.com/elastic/gosigar"

func (proc *Process) LookupExec() error {
	exe := gosigar.ProcExe{}
	err := exe.Get(proc.Pid)
	if err != nil {
		return err
	}

	proc.Cwd = exe.Cwd
	proc.Executable = exe.Name

	arg := gosigar.ProcArgs{}
	err = arg.Get(proc.Pid)
	if err != nil {
		return err
	}

	proc.Args = arg.List
	return nil
}

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
