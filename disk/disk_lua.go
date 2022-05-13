package disk

import (
	"fmt"
	"github.com/vela-security/vela-public/lua"
)

func (di *Disk) String() string                         { return fmt.Sprintf("%p", di) }
func (di *Disk) Type() lua.LValueType                   { return lua.LTObject }
func (di *Disk) AssertFloat64() (float64, bool)         { return 0, false }
func (di *Disk) AssertString() (string, bool)           { return "", false }
func (di *Disk) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (di *Disk) Peek() lua.LValue                       { return di }

func (di *Disk) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "partition":
		return PartitionStat(di.partition)
	case "usage":
		return UsageStat(di.Usage)
	case "io_stat":
		return IOCountersStat(di.IO)

	case "name":
		return lua.S2L(di.partition.Device)
	case "mount":
		return lua.S2L(di.partition.Mountpoint)
	case "fstype":
		return lua.S2L(di.partition.Fstype)
	case "opts":
		return lua.S2L(di.partition.Opts)
	case "path":
		return lua.S2L(di.Usage.Path)
	case "total":
		return lua.LNumber(di.Usage.Total)
	case "free":
		return lua.LNumber(di.Usage.Free)
	case "used":
		return lua.LNumber(di.Usage.Used)
	case "used_pct":
		return lua.LNumber(di.Usage.UsedPercent)
	case "inodes":
		return lua.LNumber(di.Usage.InodesTotal)
	case "used_inode":
		return lua.LNumber(di.Usage.InodesUsed)
	case "used_inode_pct":
		return lua.LNumber(di.Usage.InodesUsedPercent)
	case "read_bytes":
		return lua.LNumber(di.IO.ReadBytes)
	case "read_count":
		return lua.LNumber(di.IO.ReadCount)
	case "read_time":
		return lua.LNumber(di.IO.ReadTime)
	case "write_bytes":
		return lua.LNumber(di.IO.WriteBytes)
	case "write_count":
		return lua.LNumber(di.IO.WriteCount)
	case "write_time":
		return lua.LNumber(di.IO.WriteTime)
	case "serialNumber":
		return lua.S2L(di.IO.SerialNumber)
	case "label":
		return lua.S2L(di.IO.Label)

	}
	return lua.LNil
}
