package track

import (
	cond "github.com/vela-security/vela-cond"
)

type tracks struct {
	data []Section
	cnd  *cond.Cond
}

func (tks *tracks) append(v ...Section) {
	tks.data = append(tks.data, v...)
}

func (tks *tracks) Visit(handle func(Section)) {
	n := len(tks.data)
	if n == 0 {
		return
	}

	for i := 0; i < n; i++ {
		handle(tks.data[i])
	}
}

func (tks *tracks) Reset() {
	tks.data = nil
}
