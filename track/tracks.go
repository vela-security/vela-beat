package track

import (
	cond "github.com/vela-security/vela-cond"
)

type tracks struct {
	data []section
	cnd  *cond.Cond
}

func (tks *tracks) append(v ...section) {
	tks.data = append(tks.data, v...)
}
