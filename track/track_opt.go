package track

import cond "github.com/vela-security/vela-cond"

func withPid(v int32) func(*track) {
	return func(tk *track) {
		tk.pid = v
	}
}

func withCnd(cnd *cond.Cond) func(*track) {
	return func(tk *track) {
		tk.cnd = cnd
	}
}
