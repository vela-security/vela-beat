//go:build linux
// +build linux

package ss

import (
	"bytes"
	"encoding/binary"
	"syscall"
)

func connect(protocol uint8, handle func(*InetDiagMsg)) error {
	hdr := syscall.NlMsghdr{
		Type:  uint16(SOCK_DIAG_BY_FAMILY),
		Flags: uint16(syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST),
		Pid:   uint32(0),
	}
	req := InetDiagReqV2{
		Family:   uint8(AF_INET),
		Protocol: protocol,
		States:   AllTCPStates,
	}

	byteOrder2 := GetEndian()
	buf := bytes.NewBuffer(make([]byte, sizeofInetDiagReqV2))
	buf.Reset()
	if err := binary.Write(buf, byteOrder2, req); err != nil {
		// This never returns an error.
		return err
	}
	b := buf.Bytes()
	req2 := syscall.NetlinkMessage{Header: hdr, Data: b}
	return NetlinkInetDiag(req2, handle)
}

func connect6(protocol uint8, handle func(*InetDiagMsg)) error {
	hdr := syscall.NlMsghdr{
		Type:  uint16(SOCK_DIAG_BY_FAMILY),
		Flags: uint16(syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST),
		Pid:   uint32(0),
	}
	req := InetDiagReqV2{
		Family:   uint8(AF_INET6),
		Protocol: protocol,
		States:   AllTCPStates,
	}

	byteOrder2 := GetEndian()
	buf := bytes.NewBuffer(make([]byte, sizeofInetDiagReqV2))
	buf.Reset()
	if err := binary.Write(buf, byteOrder2, req); err != nil {
		// This never returns an error.
		return err
	}
	b := buf.Bytes()
	req2 := syscall.NetlinkMessage{Header: hdr, Data: b}
	return NetlinkInetDiag(req2, handle)
}
