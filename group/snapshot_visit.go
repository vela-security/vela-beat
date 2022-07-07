package group

import (
	opcode "github.com/vela-security/vela-opcode"
	"github.com/vela-security/vela-public/assert"
)

func (snap *snapshot) Create(bkt assert.Bucket) {
	for name, item := range snap.current {
		bkt.Store(name, item, 0)
		snap.report.doCreate(item)
		snap.onCreate.Do(&item, snap.co, func(err error) {
			xEnv.Errorf("account snapshot create pipe call fail %v", err)
		})
	}

}

func (snap *snapshot) Update(bkt assert.Bucket) {
	for name, item := range snap.update {
		bkt.Store(name, item, 0)
		snap.report.doUpdate(item)
		snap.onUpdate.Do(&item, snap.co, func(err error) {
			xEnv.Errorf("account snapshot update pipe call fail %v", err)
		})
	}

}

func (snap *snapshot) Delete(bkt assert.Bucket) {
	for name, item := range snap.delete {
		bkt.Delete(name)
		snap.report.doDelete(name)
		snap.onDelete.Do(&item, snap.co, func(err error) {
			xEnv.Errorf("account snapshot delete pipe call fail %v", err)
		})
	}
}

func (snap *snapshot) Report() {
	if snap.enable && snap.report.len() > 0 {
		xEnv.TnlSend(opcode.OpGroupDiff, snap.report)
	}
}
