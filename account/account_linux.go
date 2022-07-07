package account

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var colon = ":"

func convert(line string, v *Account) bool {
	u := strings.Split(line, colon)
	if len(u) < 7 {
		xEnv.Errorf("not convert %s to linux account", string(line))
		return false
	}

	v.Name = u[0]
	v.UID = u[2]
	v.GID = u[3]
	v.FullName = u[4]
	v.Home = u[5]
	v.Description = u[6]
	v.Status = "OK"
	return true
}

func List() ([]Account, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("read /etc/passwd fail %v", err)
	}
	defer f.Close()

	var av []Account
	add := func(line string) {
		v := Account{}
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
