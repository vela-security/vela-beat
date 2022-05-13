package service

import (
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/grep"
)

type match func(*Service) bool

func newFilter(pattern string) match {
	fn := grep.New(pattern)
	if fn == nil {
		return func(_ *Service) bool {
			return true
		}
	}

	return func(s *Service) bool {
		return fn(s.Name) ||
			fn(s.DisplayName) ||
			fn(s.ExecPath) ||
			fn(s.State) ||
			fn(s.StartType) ||
			fn(auxlib.ToString(s.Pid)) ||
			fn(auxlib.ToString(s.ExitCode))

	}

}
