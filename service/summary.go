package service

import (
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
	"strings"
)

type Summary struct {
	ssv    []*Service
	uptime uint64
}

func New() *Summary {
	return &Summary{}
}

func (su *Summary) String() string                         { return lua.B2S(su.Byte()) }
func (su *Summary) Type() lua.LValueType                   { return lua.LTObject }
func (su *Summary) AssertFloat64() (float64, bool)         { return 0, false }
func (su *Summary) AssertString() (string, bool)           { return "", false }
func (su *Summary) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (su *Summary) Peek() lua.LValue                       { return su }

func (su *Summary) Byte() []byte {
	buf := kind.NewJsonEncoder()
	buf.Arr("")

	for _, item := range su.ssv {
		buf.Tab("")
		buf.KV("name", item.Name)
		buf.KV("start_type", item.StartType)
		buf.KV("exec_path", strings.Trim(item.ExecPath, "\""))
		buf.KV("display_name", item.DisplayName)
		buf.KV("description", item.Description)
		buf.KV("state", item.State)
		buf.KV("pid", item.Pid)
		buf.KV("exit_code", item.ExitCode)
		buf.End("},")
	}

	buf.End("]")
	return buf.Bytes()
}

func (su *Summary) append(v *Service) {
	if v == nil {
		return
	}

	su.ssv = append(su.ssv, v)
}
