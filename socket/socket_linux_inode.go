//go:build linux
// +build linux

package socket

import (
	"github.com/elastic/gosigar"
	"os"
	"strconv"
	"strings"
	"sync"
)

type snapshot struct {
	mutex   sync.Mutex
	socket  map[uint32]int //socket inode snapshot
	collect map[int]int    //pid num inode number
}

var sst = &snapshot{}

func (sn *snapshot) Value(pid int, link string) {
	if !strings.HasPrefix(link, "socket:[") {
		return
	}

	node, err := strconv.ParseInt(link[8:len(link)-1], 10, 64)
	if err != nil {
		return
	}
	sn.socket[uint32(node)] = pid
}

func (sn *snapshot) read(pid int) {
	path := "/proc" + "/" + strconv.Itoa(pid) + "/fd/"
	d, err := os.Open(path)
	if err != nil {
		return
	}
	defer d.Close()

	names, err := d.Readdirnames(-1)
	if err != nil {
		return
	}

	for _, name := range names {
		pathLink := path + name
		target, er := os.Readlink(pathLink)
		if er != nil {
			continue
		}
		sn.Value(pid, target)
	}

	sn.collect[pid] = len(names)
}

func (sn *snapshot) R() error {
	sigar := gosigar.ProcList{}
	err := sigar.Get()
	if err != nil {
		return err
	}

	sn.mutex.Lock()
	defer sn.mutex.Unlock()

	sn.socket = make(map[uint32]int)
	sn.collect = make(map[int]int)
	n := len(sigar.List)
	for i := 0; i < n; i++ {
		sn.read(sigar.List[i])
	}
	return nil
}

func (sn *snapshot) GetPidByInode(idx uint32) int {
	sn.mutex.Lock()
	defer sn.mutex.Unlock()
	return sn.socket[idx]
}
