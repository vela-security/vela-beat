package ss

import (
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
)

func (ln *listen) String() string                         { return lua.B2S(ln.Byte()) }
func (ln *listen) Type() lua.LValueType                   { return lua.LTObject }
func (ln *listen) AssertFloat64() (float64, bool)         { return 0, false }
func (ln *listen) AssertString() (string, bool)           { return "", false }
func (ln *listen) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (ln *listen) Peek() lua.LValue                       { return ln }

func (ln *listen) Byte() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("record_id", ln.RecordID)
	enc.KV("pid", ln.Pid)
	enc.KV("family", ln.Family)
	enc.KV("protocol", ln.Protocol)
	enc.KV("local_ip", ln.LocalIP)
	enc.KV("local_port", ln.LocalPort)
	enc.KV("path", ln.Path)
	enc.KV("process", ln.Process)
	enc.KV("username", ln.Username)
	enc.KV("fd", ln.fd)
	enc.End("}")
	return enc.Bytes()
}
