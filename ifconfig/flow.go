package ifconfig

import (
	"github.com/vela-security/vela-public/lua"
)

type flow struct {
	InBytes         uint64
	InPackets       uint64
	InError         uint64
	InDropped       uint64
	InBytesPerSec   float64
	InPacketsPerSec float64

	OutBytes         uint64
	OutPackets       uint64
	OutError         uint64
	OutDropped       uint64
	OutBytesPerSec   float64
	OutPacketsPerSec float64
}

func (f *flow) ToLValue() lua.LValue {
	return lua.NewAnyData(f)
}

func (f *flow) clone() *flow {
	return &flow{
		InBytes:          f.InBytes,
		InPackets:        f.InPackets,
		InError:          f.InError,
		InDropped:        f.InDropped,
		InBytesPerSec:    f.InBytesPerSec,
		InPacketsPerSec:  f.InPacketsPerSec,
		OutBytes:         f.OutBytes,
		OutPackets:       f.OutPackets,
		OutError:         f.OutError,
		OutDropped:       f.OutDropped,
		OutBytesPerSec:   f.OutBytesPerSec,
		OutPacketsPerSec: f.OutPacketsPerSec,
	}
}
