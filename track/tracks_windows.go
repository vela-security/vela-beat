package track

import (
	"bufio"
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
	"io"
	"regexp"
	"strings"
)

var re2 = regexp.MustCompile(`(.*?)\s+pid\:\s+(\d{1,5})\s+type\:\s+(\w+)\s+[A-Z0-9]+\:\s+(.*)\s$`)

func trim2(line string, s *section) bool { // trim name output
	m := re2.FindStringSubmatch(line)
	if len(m) != 5 {
		return false
	}
	s.Exe = m[1]
	s.Pid = auxlib.ToInt32(m[2])
	s.Typ = strings.ToLower(m[3])
	s.Value = m[4]
	return true
}

var reUser = regexp.MustCompile(`(.*?)\s*pid\:\s*(\d+)\s*(.*)\r$`)

func trimUser(line string) (int32, string, bool) {
	m := reUser.FindStringSubmatch(line)
	if len(m) != 4 {
		return 0, "", false
	}

	name := m[1]
	pid := auxlib.ToInt32(m[2])
	return pid, name, true
}

func isBorder(line string) bool {
	return "------------------------------------------------------------------------------\r" == line
}

func (tks *tracks) dumpKw(out io.ReadCloser) {
	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		sec := section{}
		if !trim2(line, &sec) {
			goto next
		}
		if tks.cnd.Match(&sec) {
			tks.data = append(tks.data, sec)
		}
	next:
		if er := scanner.Err(); er != nil {
			xEnv.Errorf("track handle.exe scan fail %v", er)
			return
		}
	}
}
func (tks *tracks) dumpByName(out io.ReadCloser) {
	scanner := bufio.NewScanner(out)
	stat := 0 //0: start 1: broder  2:User 3:line

	var pid int32
	var name string
	for scanner.Scan() {
		line := scanner.Text()

		if isBorder(line) {
			pid = 0
			name = ""
			stat = 1
			continue
		}

		stat++
		switch stat {
		case 2: //user
			pid, name, _ = trimUser(line)

		default:
			sec := section{}
			if !trim(line, &sec) {
				continue
			}
			sec.Pid = pid
			sec.Exe = name
			if tks.cnd.Match(&sec) {
				tks.data = append(tks.data, sec)
			}
		}

		if er := scanner.Err(); er != nil {
			xEnv.Errorf("track handle.exe scan fail %v", er)
			return
		}
	}

}

func (tks *tracks) forkExecByKw(keywold string) error {
	if e := auxlib.Checksum(cmm.exe, cmm.hash); e != nil {
		return e
	}

	tk := newTrack(withCnd(tks.cnd))
	cmd := tk.Command(keywold, "-nobanner")
	tk.forkExec(cmd, tks.dumpKw)
	return nil
}

func (tks *tracks) forkExecByName(name string) error {
	if e := auxlib.Checksum(cmm.exe, cmm.hash); e != nil {
		return e
	}

	tk := newTrack(withCnd(tks.cnd))
	cmd := tk.Command("-p", name, "-nobanner")
	tk.forkExec(cmd, tks.dumpByName)
	return nil
}

func newTracksKeyWold(L *lua.LState) *tracks {
	name := L.CheckString(1)
	tks := &tracks{cnd: cond.CheckMany(L, cond.Seek(1))}
	if !protective(name) {
		L.RaiseError("protective key world got %s", name)
		return tks
	}

	tks.forkExecByKw(name)

	return tks
}

func newTrackName(L *lua.LState) *tracks {
	name := L.CheckString(1)
	tks := &tracks{cnd: cond.CheckMany(L, cond.Seek(1))}
	if !protective(name) {
		L.RaiseError("protective name got %s", name)
		return tks
	}
	tks.forkExecByName(name)
	return tks
}
