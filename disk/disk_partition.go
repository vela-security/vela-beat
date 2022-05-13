package disk

import (
	"fmt"
	"github.com/shirou/gopsutil/disk"
	"github.com/vela-security/vela-public/lua"
)

type PartitionStat disk.PartitionStat

func (ps PartitionStat) String() string                         { return fmt.Sprintf("%p", &ps) }
func (ps PartitionStat) Type() lua.LValueType                   { return lua.LTObject }
func (ps PartitionStat) AssertFloat64() (float64, bool)         { return 0, false }
func (ps PartitionStat) AssertString() (string, bool)           { return "", false }
func (ps PartitionStat) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (ps PartitionStat) Peek() lua.LValue                       { return ps }

func (ps PartitionStat) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "device":
		return lua.S2L(ps.Device)
	case "mount_point":
		return lua.S2L(ps.Mountpoint)
	case "type":
		return lua.S2L(ps.Fstype)
	case "opts":
		return lua.S2L(ps.Opts)

	}

	return lua.LNil
}
