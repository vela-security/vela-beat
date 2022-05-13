//go:build darwin || freebsd || netbsd || openbsd || linux
// +build darwin freebsd netbsd openbsd linux

package psnotify

import (
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

type config struct {
	name  string
	pipe  *pipe.Px
	co    *lua.LState
	watch *Watcher
}

func newConfig(L *lua.LState) *config {
	val := L.Get(1)
	cfg := &config{
		co:   xEnv.Clone(L),
		pipe: pipe.New(pipe.Env(xEnv)),
	}

	switch val.Type() {
	case lua.LTString:
		cfg.name = val.String()

	case lua.LTTable:
		tab := val.(*lua.LTable)
		tab.Range(func(key string, val lua.LValue) {
			cfg.NewIndex(L, key, val)
		})
	}

	if e := cfg.valid(); e != nil {
		L.RaiseError("%v", e)
		return nil
	}

	return cfg
}

func (cfg *config) NewIndex(L *lua.LState, key string, val lua.LValue) {
	switch key {
	case "name":
		cfg.name = val.String()

	default:
		//todo
	}
}

func (cfg *config) valid() error {
	if e := auxlib.Name(cfg.name); e != nil {
		return e
	}

	wer, err := NewWatcher()
	if err != nil {
		return err
	}

	cfg.watch = wer
	return nil
}
