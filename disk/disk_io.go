package disk

import (
	"fmt"
	"github.com/shirou/gopsutil/disk"
	"github.com/vela-security/vela-public/lua"
)

type IOCountersStat disk.IOCountersStat

func (it IOCountersStat) String() string                         { return fmt.Sprintf("%p", &it) }
func (it IOCountersStat) Type() lua.LValueType                   { return lua.LTObject }
func (it IOCountersStat) AssertFloat64() (float64, bool)         { return 0, false }
func (it IOCountersStat) AssertString() (string, bool)           { return "", false }
func (it IOCountersStat) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (it IOCountersStat) Peek() lua.LValue                       { return it }

func (it IOCountersStat) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "read_count":
		return lua.LNumber(it.ReadCount)
	case "merge_read_count":
		return lua.LNumber(it.MergedReadCount)
	case "read_bytes":
		return lua.LNumber(it.ReadBytes)
	case "read_time":
		return lua.LNumber(it.ReadTime)
	case "write_count":
		return lua.LNumber(it.WriteCount)
	case "merge_write_count":
		return lua.LNumber(it.MergedWriteCount)
	case "write_bytes":
		return lua.LNumber(it.WriteBytes)
	case "write_time":
		return lua.LNumber(it.WriteTime)
	case "time":
		return lua.LNumber(it.IoTime)
	case "weighted":
		return lua.LNumber(it.WeightedIO)
	case "label":
		return lua.S2L(it.Label)
	case "serial":
		return lua.S2L(it.SerialNumber)
	}
	return lua.LNil
}
