package socket

import (
	"github.com/vela-security/vela-public/kind"
)

type summary struct {
	CLOSED      int       `json:"closed"`
	LISTEN      int       `json:"listen"`
	SYN_SENT    int       `json:"syn_sent"`
	SYN_RCVD    int       `json:"syn_rcvd"`
	ESTABLISHED int       `json:"established"`
	FIN_WAIT1   int       `json:"fin_wait1"`
	FIN_WAIT2   int       `json:"fin_wait2"`
	CLOSE_WAIT  int       `json:"close_wait"`
	CLOSING     int       `json:"closing"`
	LAST_ACK    int       `json:"last_ack"`
	TIME_WAIT   int       `json:"time_wait"`
	DELETE_TCB  int       `json:"delete_tcb, omitempty"`
	Total       int       `json:"total"`
	Sockets     []*Socket `json:"sockets"`
	Err         error     `json:"-"`
}

func (sum *summary) append(s *Socket) {
	switch s.State {

	case "ESTAB":
		sum.ESTABLISHED++
	case "SYN-SENT":
		sum.SYN_SENT++
	case "SYN-RCVD":
		sum.SYN_RCVD++
	case "FIN-WAIT-1":
		sum.FIN_WAIT1++
	case "FIN-WAIT-2":
		sum.FIN_WAIT2++
	case "TIME-WAIT":
		sum.TIME_WAIT++
	case "CLOSED":
		sum.CLOSED++
	case "CLOSE-WAIT":
		sum.CLOSE_WAIT++
	case "LAST-ACK":
		sum.LAST_ACK++
	case "LISTEN":
		sum.LISTEN++
	case "CLOSING":
		sum.CLOSING++

	}
	sum.Total++
	sum.Sockets = append(sum.Sockets, s)
}

func (sum *summary) Byte() []byte {
	buf := kind.NewJsonEncoder()
	buf.Tab("")
	buf.KV("closed", sum.CLOSED)
	buf.KV("listen", sum.LISTEN)
	buf.KV("syn_sent", sum.SYN_SENT)
	buf.KV("syn_rcvd", sum.SYN_RCVD)
	buf.KV("established", sum.ESTABLISHED)
	buf.KV("fin_wait1", sum.FIN_WAIT1)
	buf.KV("fin_wait2", sum.FIN_WAIT2)
	buf.KV("close_wait", sum.CLOSE_WAIT)
	buf.KV("closing", sum.CLOSING)
	buf.KV("last_ack", sum.LAST_ACK)
	buf.KV("time_wait", sum.TIME_WAIT)
	buf.KV("delete_tcb", sum.DELETE_TCB)
	buf.Arr("sockets")

	for _, item := range sum.Sockets {
		item.Marshal(buf)
	}
	buf.End("]}")

	return buf.Bytes()
}

//func (sum *summary) all(filter func(*Socket) bool) {
//	sum.tcp(filter)
//	sum.udp(filter)
//	sum.unix(filter)
//}
