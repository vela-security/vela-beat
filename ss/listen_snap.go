package ss

import (
	cond "github.com/vela-security/vela-cond"
	opcode "github.com/vela-security/vela-opcode"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	"sync/atomic"
	"time"
)

type ListenSnap struct {
	lua.ProcEx
	sign     uint32
	name     string
	err      error
	bkt      []string
	data     []*listen
	onCreate *pipe.Px
	onDelete *pipe.Px
	onUpdate *pipe.Px
	ticker   *time.Ticker
	co       *lua.LState
	current  map[string]*listen
	create   map[string]*listen
	delete   map[string]interface{}
	update   map[string]*listen
	enable   bool
	report   *report
}

func convert(sock *Socket) *listen {
	ln := &listen{
		Pid:       sock.Pid,
		Family:    sock.Family,
		Protocol:  sock.Protocol,
		LocalIP:   sock.LocalIP,
		LocalPort: sock.LocalPort,
		Path:      sock.Path,
		Process:   sock.Process,
		Username:  sock.Username,
	}

	ln.md5()

	return ln
}

func (snap *ListenSnap) Name() string {
	return snap.name
}

func (snap *ListenSnap) Type() string {
	return lnTypeof
}

func (snap *ListenSnap) Start() error {
	return nil
}

func (snap *ListenSnap) Close() error {
	if snap.ticker == nil {
		return nil
	}

	snap.ticker.Stop()
	return nil
}

func (snap *ListenSnap) add(sock *Socket) {
	ln := convert(sock)
	snap.current[ln.RecordID] = ln
	snap.data = append(snap.data, ln)
}

func (snap *ListenSnap) reset() {
	snap.current = make(map[string]*listen, 64)
	snap.create = make(map[string]*listen, 64)
	snap.delete = make(map[string]interface{}, 64)
	snap.update = make(map[string]*listen, 64)
	snap.report = &report{}
	snap.data = nil
}

func (snap *ListenSnap) Create(bkt assert.Bucket) {
	for name, item := range snap.current {
		bkt.Store(name, item, 0)
		snap.report.doCreate(item)
		snap.onCreate.Do(item, snap.co, func(err error) {
			xEnv.Errorf("account snapshot create pipe call fail %v", err)
		})
	}
}

func (snap *ListenSnap) Update(bkt assert.Bucket) {
	for name, item := range snap.update {
		bkt.Store(name, item, 0)
		snap.report.doUpdate(item)
		snap.onUpdate.Do(item, snap.co, func(err error) {
			xEnv.Errorf("account snapshot update pipe call fail %v", err)
		})
	}

}

func (snap *ListenSnap) Delete(bkt assert.Bucket) {
	for name, item := range snap.delete {
		bkt.Delete(name)
		snap.report.doDelete(name)
		snap.onDelete.Do(&item, snap.co, func(err error) {
			xEnv.Errorf("account snapshot delete pipe call fail %v", err)
		})
	}
}

func (snap *ListenSnap) diff(key string, v interface{}) {
	old, ok := v.(*listen)
	if !ok {
		snap.delete[key] = v
		return
	}

	cur, ok := snap.current[key]
	if !ok {
		snap.delete[key] = old
		return
	}
	delete(snap.current, key)

	if cur.equal(old) {
		return
	}

	snap.update[key] = cur

}

func (snap *ListenSnap) IsRun() bool {
	c := atomic.AddUint32(&snap.sign, 1)
	return c > 1
}

func (snap *ListenSnap) over() {
	atomic.StoreUint32(&snap.sign, 0)
}

func (snap *ListenSnap) do(enable bool) {
	if snap.IsRun() {
		xEnv.Infof("last listen snapshot not over")
		return
	}
	defer snap.over()

	cnd := cond.New("state = LISTEN")
	sum := By("all", cnd)
	if sum.Err != nil {
		xEnv.Errorf("Listen got fail %v", sum.Err)
		return
	}

	for _, sock := range sum.Sockets {
		snap.add(sock)
	}

	bkt := xEnv.Bucket(snap.bkt...)
	bkt.Range(snap.diff)
	snap.Create(bkt)
	snap.Update(bkt)
	snap.Delete(bkt)

	if !enable {
		xEnv.TnlSend(opcode.OpListenFull, snap.data)
		snap.reset()
		return
	}

	if snap.report.len() > 0 {
		xEnv.TnlSend(opcode.OpListenDiff, snap.report)
		snap.reset()
	}
}
