package service

import (
	"github.com/shirou/gopsutil/winservices"
	"golang.org/x/sys/windows"
)

func (su *Summary) collect(filter match) {
	ssv, err := winservices.ListServices()
	if err != nil {
		xEnv.Errorf("collect service fail %v", err)
		return
	}

	n := len(ssv)
	if n == 0 {
		return
	}

	for i := 0; i < n; i++ {
		ms := ssv[i]
		s, er := winservices.NewService(ms.Name)
		if er != nil {
			xEnv.Errorf("got %v service fail %v", ms.Name, er)
			continue
		}

		er = s.GetServiceDetail()
		if er != nil {
			xEnv.Errorf("got %v service detail fail %v", ms.Name, er)
			continue
		}

		sv := s2s(s)
		if !filter(sv) {
			continue
		}

		su.append(s2s(s))
	}

}

func s2s(s *winservices.Service) *Service {
	return &Service{
		Name:        s.Name,
		StartType:   assertStartType(s.Config.StartType),
		ExecPath:    s.Config.BinaryPathName,
		DisplayName: s.Config.DisplayName,
		Description: s.Config.Description,
		State:       assertStateType(uint32(s.Status.State)),
		Pid:         s.Status.Pid,
		ExitCode:    s.Status.Win32ExitCode,
	}
}

func assertStartType(t uint32) string {
	switch t {
	case windows.SERVICE_AUTO_START:
		return "auto_start"
	case windows.SERVICE_BOOT_START:
		return "boot_start"
	case windows.SERVICE_DEMAND_START:
		return "demand_start"
	case windows.SERVICE_DISABLED:
		return "disabled"
	default:
		return "unknown"
	}
}

func assertStateType(et uint32) string {
	switch et {
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "start_pending"
	case windows.SERVICE_STOP_PENDING:
		return "stop_pending"
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_CONTINUE_PENDING:
		return "continue_pending"
	case windows.SERVICE_PAUSE_PENDING:
		return "pause_pending"
	case windows.SERVICE_PAUSED:
		return "paused"
	default:
		return "unknown"
	}
}
