package disk

import (
	"fmt"
	"github.com/shirou/gopsutil/disk"
	"github.com/vela-security/vela-public/lua"
)

type UsageStat disk.UsageStat

func (us UsageStat) String() string                         { return fmt.Sprintf("%p", &us) }
func (us UsageStat) Type() lua.LValueType                   { return lua.LTObject }
func (us UsageStat) AssertFloat64() (float64, bool)         { return 0, false }
func (us UsageStat) AssertString() (string, bool)           { return "", false }
func (us UsageStat) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (us UsageStat) Peek() lua.LValue                       { return us }

func (us UsageStat) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "total":
		return lua.LNumber(us.Total)
	case "free":
		return lua.LNumber(us.Free)
	case "used":
		return lua.LNumber(us.Used)
	case "used_pct":
		return lua.LNumber(us.UsedPercent)
	case "inode_total":
		return lua.LNumber(us.InodesTotal)
	case "inode_used":
		return lua.LNumber(us.InodesUsed)
	case "inode_used_pct":
		return lua.LNumber(us.InodesUsedPercent)

	}

	return lua.LNil
}
