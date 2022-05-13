package socket

import (
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
)

type Socket struct {
	Pid        uint32 `json:"pid"`
	Family     uint8  `json:"family"`
	Protocol   uint8  `json:"protocol"`
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	Path       string `json:"path"`
	State      string `json:"state"`
	Process    string `json:"process"`
	Username   string `json:"username"`
}

func (s *Socket) Marshal(enc *kind.JsonEncoder) {
	enc.Tab("")

	enc.KV("state", s.State)
	enc.KV("local_ip", s.LocalIP)
	enc.KV("local_port", s.LocalPort)
	enc.KV("remote_ip", s.RemoteIP)
	enc.KV("remote_port", s.RemotePort)
	enc.KV("pid", s.Pid)
	enc.KV("process_name", s.Process)
	enc.KV("user_name", s.Username)

	enc.End("},")
}

func (s *Socket) Byte() []byte {
	buf := kind.NewJsonEncoder()
	s.Marshal(buf)
	buf.End("")
	return buf.Bytes()
}

func (s *Socket) String() string {
	return lua.B2S(s.Byte())
}
