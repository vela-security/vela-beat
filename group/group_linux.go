package group

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var colon = ":"

func convert(line string, v *Group) bool {
	u := strings.Split(line, colon)
	if len(u) < 4 {
		xEnv.Errorf("not convert %s to linux group", string(line))
		return false
	}

	v.Name = u[0]
	v.GID = u[2]
	v.Description = line
	return true
}

func List() ([]Group, error) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return nil, fmt.Errorf("read /etc/group fail %v", err)
	}
	defer f.Close()

	var av []Group
	add := func(line string) {
		v := Group{}
		if convert(line, &v) {
			av = append(av, v)
		}
	}

	rd := bufio.NewScanner(f)
	for rd.Scan() {
		add(rd.Text())
		if e := rd.Err(); e != nil {
			return nil, err
		}
	}

	return av, nil
}
