package memory

import (
	"github.com/vela-security/vela-public/lua"
)

func (sum *summary) String() string                         { return lua.B2S(sum.Byte()) }
func (sum *summary) Type() lua.LValueType                   { return lua.LTObject }
func (sum *summary) AssertFloat64() (float64, bool)         { return 0, false }
func (sum *summary) AssertString() (string, bool)           { return "", false }
func (sum *summary) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (sum *summary) Peek() lua.LValue                       { return sum }

func (sum *summary) Index(L *lua.LState, key string) lua.LValue {
	sum.Update()
	switch key {
	case "total":
		return lua.LNumber(sum.Total)
	case "free":
		return lua.LNumber(sum.Free)
	case "used_pct":
		return lua.LNumber(sum.UsedPct)
	case "swap_total":
		return lua.LNumber(sum.SwapTotal)
	case "swap_free":
		return lua.LNumber(sum.SwapTotal)
	case "swap_in_pages":
		return lua.LNumber(sum.SwapInPages)
	case "swap_out_pages":
		return lua.LNumber(sum.SwapOutPages)
	case "swap_used_pct":
		return lua.LNumber(sum.SwapUsedPct)
	default:
		return lua.LNumber(0)
	}
}
