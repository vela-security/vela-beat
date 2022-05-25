package process

import (
	audit "github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	"reflect"
	"time"
)

var (
	snapshotTypeof = reflect.TypeOf((*snapshot)(nil)).String()
)

/*
	664    {"name": "123" , "cwd": "123"}
	665    {"name": "123" , "cwd": "123"}
	667    {"name": "123" , "cwd": "123"}
*/

type snapshot struct {
	lua.ProcEx
	co       *lua.LState
	onDelete *pipe.Px
	onUpdate *pipe.Px
	tk       time.Ticker
	bkt      []string
	current  map[int]bool
	delete   map[string]interface{}
	update   map[string]interface{}
}

func newSnapshot(L *lua.LState) *snapshot {
	sum := &summary{}
	if sum.init(); !sum.ok() {
		return nil
	}

	snt := &snapshot{
		bkt:      []string{"vela", "process", "snapshot"},
		co:       xEnv.Clone(L),
		onDelete: pipe.New(pipe.Env(xEnv)),
		onUpdate: pipe.New(pipe.Env(xEnv)),
		current:  sum.Map(),
		update:   make(map[string]interface{}, 128),
		delete:   make(map[string]interface{}, 128),
	}
	snt.V(lua.PTInit)

	return snt
}

func (snt *snapshot) Name() string {
	return "process.snapshot"
}

func (snt *snapshot) Type() string {
	return snapshotTypeof
}

func (snt *snapshot) Start() error {
	return nil
}

func (snt *snapshot) Close() error {
	return nil
}

func (snt *snapshot) diff(key string, v interface{}) {
	pid, err := auxlib.ToIntE(key)
	if err != nil {
		xEnv.Errorf("got invalid pid %v", err)
		snt.delete[key] = v
		return
	}

	old, ok := v.(*simple)
	if !ok {
		xEnv.Errorf("invalid process simple %v", v)
		snt.delete[key] = v
		return
	}

	if _, ok := snt.current[pid]; !ok {
		snt.delete[key] = v
		return
	}
	delete(snt.current, pid)

	sim := simple{}
	err = sim.by(pid)
	if err != nil {
		xEnv.Errorf("not found pid:%d process", pid)
		snt.delete[key] = v
		return
	}

	if !sim.Equal(old) {
		snt.update[key] = sim
	}
}

func (snt *snapshot) sync() {
	for pid, _ := range snt.current {
		sim := &simple{}
		if err := sim.by(pid); err != nil {
			xEnv.Errorf("not found pid:%d process %v", pid, err)
			continue
		}
		snt.update[auxlib.ToString(pid)] = sim
	}
}

func (snt *snapshot) Delete(bkt assert.Bucket) {
	for pid, val := range snt.delete {
		bkt.Delete(pid)
		snt.onDelete.Do(val, snt.co, func(err error) {
			audit.Errorf("%s process snapshot delete fail %v", snt.Name(), err).From(snt.co.CodeVM()).Put()
		})
	}
}

func (snt *snapshot) Update(bkt assert.Bucket) {
	for pid, val := range snt.update {
		bkt.Store(pid, val, 0)
		snt.onUpdate.Do(val, snt.co, func(err error) {
			audit.Errorf("%s process snapshot update fail %v", snt.Name(), err).From(snt.co.CodeVM()).Put()
		})
	}
}

func (snt *snapshot) run() {
	bkt := xEnv.Bucket(snt.bkt...)
	bkt.Range(snt.diff)
	snt.sync()
	snt.Delete(bkt)
	snt.Update(bkt)
}
