package process

import (
	"bytes"
	"encoding/gob"
)

type null struct{}

var NULL = null{}

type simple struct {
	Name       string   `json:"name"`
	State      string   `json:"state"`
	Pid        int      `json:"pid"`
	PPid       int      `json:"ppid"`
	PGid       uint32   `json:"pgid"`
	Cmdline    string   `json:"cmdline"`
	Username   string   `json:"username"`
	Cwd        string   `json:"cwd"`
	Executable string   `json:"executable"` // linux
	Args       []string `json:"args"`
}

func (s *simple) by(pid int) error {
	proc, err := Pid(pid)
	if err != nil {
		return err
	}

	s.Name = proc.Name
	s.State = proc.State
	s.Pid = proc.Pid
	s.PPid = proc.Ppid
	s.PGid = proc.Pgid
	s.Cmdline = proc.Cmdline
	s.Username = proc.Username
	s.Cwd = proc.Cwd
	s.Executable = proc.Executable
	s.Args = proc.Args
	return nil
}

func (s *simple) binary() string {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(s)
	if err != nil {
		return ""
		xEnv.Errorf("pid:%d name:%s gob encode fail %v", s.Pid, s.Name, err)
		//return ""
	}

	return buf.String()
}

func (s *simple) Equal(old *simple) bool {
	return s.binary() == old.binary()
}

func encode(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(v)
	if err != nil {
		return nil, err
		//xEnv.Errorf("pid:%d name:%s gob encode fail %v", s.Pid, s.Name, err)
		//return ""
	}
	return buf.Bytes(), nil
}

func decode(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var s simple
	dec := gob.NewDecoder(bytes.NewReader(data))
	err := dec.Decode(&s)
	return &s, err
}
