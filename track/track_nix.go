//go:build linux || plan9 || freebsd || solaris
// +build linux plan9 freebsd solaris

package track

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (tk *track) filepath(pid int32) string {
	return filepath.Join("/proc", strconv.Itoa(int(pid)), "fd")
}

func (tk *track) readdir(pid int32) ([]string, error) {
	path := tk.filepath(pid)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open dir %s", path)
	}
	defer f.Close()

	return f.Readdirnames(-1)
}

func (tk *track) readlink(dir, fd string) (string, error) {
	return os.Readlink(filepath.Join(dir, fd))
}

func (tk *track) Pid() ([]section, error) {
	sym, err := tk.readdir(tk.pid)
	if err != nil {
		return nil, err
	}

	var data []section
	dir := filepath.Join("/proc", tk.pid2str(), "fd")
	tk.total = int32(len(sym))

	for _, fd := range sym {
		p, e := tk.readlink(dir, fd)
		if e != nil {
			continue
		}
		switch {
		case p == "/dev/null":
			continue
		case strings.HasPrefix(p, "anon_inode:"):
			//tk.append(section{"inode", p[12 : len(p)-1]})
			continue

		case strings.HasPrefix(p, "socket:"):
			//tk.append(section{"socket", p[8 : len(p)-1]})
			continue
		case strings.HasPrefix(p, "pipe:"):
			//tk.append(section{"socket", p[8 : len(p)-1]})
			continue

		default:
			tk.append(section{
				Pid:   tk.pid,
				Exe:   tk.exe,
				Typ:   "file",
				Value: p,
			})
		}
	}

	return data, nil
}
