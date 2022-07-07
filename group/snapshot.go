package group

import (
	"fmt"
	opcode "github.com/vela-security/vela-opcode"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	"sync/atomic"
	"time"
)

type snapshot struct {
	lua.ProcEx
	name     string
	err      error
	bkt      []string
	data     []Group
	onCreate *pipe.Px
	onDelete *pipe.Px
	onUpdate *pipe.Px
	ticker   *time.Ticker
	co       *lua.LState
	current  map[string]Group
	create   map[string]Group
	delete   map[string]Group
	update   map[string]Group
	enable   bool
	report   *report
}

func newSnapshot() *snapshot {
	sub := atomic.AddUint32(&subscript, 1)

	snap := &snapshot{
		name:     fmt.Sprintf("vela.group.snapshot.%d", sub),
		bkt:      []string{"vela", "group", "snapshot"},
		onCreate: pipe.New(),
		onDelete: pipe.New(),
		onUpdate: pipe.New(),
	}
	return snap
}

func (snap *snapshot) init() {
	snap.data, snap.err = List()
	snap.current = make(map[string]Group, 5)
	snap.create = make(map[string]Group, 5)
	snap.delete = make(map[string]Group, 5)
	snap.update = make(map[string]Group, 5)
	snap.report = &report{}
}

func (snap *snapshot) Start() error {
	return nil
}

func (snap *snapshot) Close() error {
	if snap.ticker != nil {
		snap.ticker.Stop()
	}

	return nil
}

func (snap *snapshot) Name() string {
	return snap.name
}

func (snap *snapshot) Type() string {
	return typeof
}

func (snap *snapshot) ok() bool {
	return snap.err == nil
}

func (snap *snapshot) Map() {
	n := len(snap.data)
	if n == 0 {
		return
	}

	for i := 0; i < n; i++ {
		a := snap.data[i]
		snap.current[a.Name] = a
	}
}

func (snap *snapshot) find(name string) (Group, bool) {
	var a Group
	n := len(snap.data)
	if n == 0 {
		return a, false
	}

	for i := 0; i < n; i++ {
		if snap.data[i].Name == name {
			return snap.data[i], true
		}
	}
	return a, false
}

func (snap *snapshot) diff(name string, v interface{}) {
	old, ok := v.(Group)
	if !ok {
		snap.delete[name] = Group{Name: name}
		return
	}

	a, ok := snap.current[name]
	if !ok {
		snap.delete[name] = old
		return
	}
	delete(snap.current, name)

	if a.equal(old) {
		return
	}

	snap.update[name] = a
}

func (snap *snapshot) reset() {
	snap.current = make(map[string]Group, 6)
	snap.create = make(map[string]Group, 6)
	snap.delete = make(map[string]Group, 6)
	snap.update = make(map[string]Group, 6)
	snap.report = &report{}
}

func (snap *snapshot) do(enable bool) {
	snap.init()
	if !snap.ok() {
		xEnv.Errorf("init account snapshot fail %v", snap.err)
		return
	}

	snap.Map()
	bkt := xEnv.Bucket(snap.bkt...)
	bkt.Range(snap.diff)
	snap.Create(bkt)
	snap.Update(bkt)
	snap.Delete(bkt)

	if !enable {
		xEnv.TnlSend(opcode.OpGroupFull, snap.data)
		snap.reset()
		return
	}

	snap.Report()
}
