//go:build linux || darwin
// +build linux darwin

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
