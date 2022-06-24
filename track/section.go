package track

import (
	"bytes"
	"fmt"
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
	"path/filepath"
	"strconv"
)

type section struct {
	Pid   int32
	User  string
	Exe   string
	Typ   string
	Value string
}

func (s *section) String() string                         { return lua.B2S(s.Byte()) }
func (s *section) Type() lua.LValueType                   { return lua.LTObject }
func (s *section) AssertFloat64() (float64, bool)         { return 0, false }
func (s *section) AssertString() (string, bool)           { return "", false }
func (s *section) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (s *section) Peek() lua.LValue                       { return s }

func (s *section) Byte() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("pid", s.Pid)
	enc.KV("type", s.Typ)
	enc.KV("value", s.Value)
	enc.KV("name", s.Name())
	enc.KV("exe", s.Exe)
	enc.End("}")
	return enc.Bytes()
}

func (s *section) Name() string {
	if s.Exe == "" {
		return ""
	}
	return filepath.Base(s.Exe)
}

func (s *section) Raw() string {
	var buf bytes.Buffer
	buf.WriteString(strconv.Itoa(int(s.Pid)))
	buf.WriteByte(' ')
	buf.WriteString(s.Value)
	buf.WriteByte(' ')
	buf.WriteString(s.User)
	buf.WriteByte(' ')
	buf.WriteString(s.Exe)
	buf.WriteByte(' ')
	buf.WriteString(s.Typ)
	return buf.String()
}

func (s *section) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "type":
		return lua.S2L(s.Typ)
	case "value":
		return lua.S2L(s.Value)
	case "pid":
		return lua.LNumber(s.Pid)
	case "exe":
		return lua.LString(s.Exe)
	case "name":
		return lua.LString(s.Name())
	case "ext":
		return lua.LString(filepath.Ext(s.Exe))
	case "info":
		return lua.S2L(fmt.Sprintf("pid:%d name:%s type:%s value:%s", s.Pid, s.Name(), s.Typ, s.Value))
	case "raw":
		return lua.LString(s.Raw())
	}

	return lua.LNil
}
