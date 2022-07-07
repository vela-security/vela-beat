package process

import (
	"fmt"
	audit "github.com/vela-security/vela-audit"
	opcode "github.com/vela-security/vela-opcode"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	"reflect"
	"sync/atomic"
	"time"
)

var (
	snapshotTypeof = reflect.TypeOf((*snapshot)(nil)).String()
)

const (
	SYNC Model = iota + 1
	WORK
)

type Model uint8

func (m Model) String() string {
	switch m {
	case SYNC:
		return "sync"
	case WORK:
		return "work"
	default:
		return ""
	}
}

/*
	664    {"name": "123" , "cwd": "123"}
	665    {"name": "123" , "cwd": "123"}
	667    {"name": "123" , "cwd": "123"}
*/

type snapshot struct {
	lua.ProcEx
	state    uint32
	flag     Model
	co       *lua.LState
	onCreate *pipe.Px
	onDelete *pipe.Px
	onUpdate *pipe.Px
	by       func(int) (*Process, error)
	store    func(assert.Bucket)

	tk      *time.Ticker
	bkt     []string
	current map[int]*Process
	delete  map[string]interface{}
	update  map[string]*Process
	report  *report

	//report enable
	enable bool

	//report opcode
	opcode int
}

func newSnapshot(L *lua.LState) *snapshot {
	snt := &snapshot{
		state:    0, //init
		enable:   L.IsTrue(1),
		bkt:      []string{"vela", "process", "snapshot"},
		co:       xEnv.Clone(L),
		onCreate: pipe.New(pipe.Env(xEnv)),
		onDelete: pipe.New(pipe.Env(xEnv)),
		onUpdate: pipe.New(pipe.Env(xEnv)),
	}
	snt.V(lua.PTInit)

	return snt
}

func (snt *snapshot) reset() {
	snt.update = nil
	snt.delete = nil
	snt.report = nil
	snt.current = nil
	snt.flag = 0
}

func (snt *snapshot) withProcess(ps []*Process) {
	n := len(ps)
	if n == 0 {
		return
	}

	if e := xEnv.TnlSend(opcode.OpProcessFull, ps); e != nil {
		xEnv.Errorf("process snapshot sync push fail %v", e)
	}

	//map fast match
	snt.current = make(map[int]*Process, n)
	for i := 0; i < n; i++ {
		p := ps[i]
		snt.current[p.Pid] = p
	}

	//by pid find proc
	snt.by = func(pid int) (*Process, error) {
		proc, ok := snt.current[pid]
		if ok {
			delete(snt.current, pid)
			return proc, nil
		}
		return nil, fmt.Errorf("not found %d process", pid)
	}

}

func (snt *snapshot) withList(list []int) {
	n := len(list)
	p := &Process{Pid: -1}
	snt.current = make(map[int]*Process, n)
	for i := 0; i < n; i++ {
		pid := list[i]
		snt.current[pid] = p
	}

	snt.by = func(pid int) (*Process, error) {
		delete(snt.current, pid)
		return Pid(pid)
	}
}

func (snt *snapshot) constructor(flag Model) bool {
	snt.flag = flag
	snt.update = make(map[string]*Process, 128)
	snt.delete = make(map[string]interface{}, 128)
	snt.report = &report{}

	sum := &summary{}
	if sum.init(); !sum.ok() {
		return false
	}

	switch flag {
	case SYNC:
		sum.view(func(_ *Process) bool { return true })
		snt.withProcess(sum.Process)
		return true

	case WORK:
		snt.withList(sum.List())
		return true

	default:
		return false
	}
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
	if snt.tk != nil {
		snt.tk.Stop()
	}
	return nil
}

func (snt *snapshot) diff(key string, v interface{}) {
	pid, err := auxlib.ToIntE(key)
	if err != nil {
		xEnv.Infof("got invalid pid %v", err)
		snt.delete[key] = v
		snt.report.OnDelete(pid)
		return
	}

	old, ok := v.(*simple)
	if !ok {
		xEnv.Infof("invalid process simple %v", v)
		snt.delete[key] = v
		snt.report.OnDelete(pid)
		return
	}

	if _, exist := snt.current[pid]; !exist {
		snt.delete[key] = v
		snt.report.OnDelete(pid)
		return
	}
	p, er := snt.by(pid)
	if er != nil {
		xEnv.Errorf("not found pid:%d process %v", pid, err)
		snt.delete[key] = v
		snt.report.OnDelete(pid)
		return
	}

	sim := &simple{}
	sim.with(p)
	if !sim.Equal(old) {
		snt.update[key] = p
		snt.report.OnUpdate(p)
	}
}

func (snt *snapshot) IsRun() bool {
	return atomic.AddUint32(&snt.state, 1) > 1
}

func (snt *snapshot) End() {
	atomic.StoreUint32(&snt.state, 0)
}

func (snt *snapshot) run() {
	if snt.IsRun() {
		xEnv.Errorf("process running by %s", snt.flag.String())
		return
	}

	defer snt.End()

	if !snt.constructor(WORK) {
		audit.Errorf("%s process reset snapshot fail", snt.Name()).From(snt.co.CodeVM()).Put()
		return
	}

	bkt := xEnv.Bucket(snt.bkt...)
	bkt.Range(snt.diff)
	snt.Create(bkt)
	snt.Delete(bkt)
	snt.Update(bkt)
	snt.doReport()

	snt.reset()
}

func (snt *snapshot) sync() {
	if snt.IsRun() {
		xEnv.Errorf("process running by %s", snt.flag.String())
		return
	}
	defer snt.End()

	if !snt.constructor(SYNC) {
		audit.Errorf("%s process reset snapshot fail", snt.Name()).From(snt.co.CodeVM()).Put()
		return
	}

	bkt := xEnv.Bucket(snt.bkt...)
	bkt.Range(snt.diff)
	snt.Create(bkt)
	snt.Delete(bkt)
	snt.Update(bkt)
	snt.reset()
}
