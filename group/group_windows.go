package group

import "github.com/StackExchange/wmi"

type WinGroup struct {
	Caption     string
	Description string
	Domain      string
	Name        string
	SID         string
	SIDType     uint8
	Status      string
}

func convert(ua []WinGroup) []Group {
	var av []Group
	n := len(ua)
	if n == 0 {
		return av
	}

	add := func(w WinGroup) {
		item := Group{
			Name:        w.Name,
			Description: w.Description,
			GID:         w.SID,
		}
		av = append(av, item)
	}

	for i := 0; i < n; i++ {
		add(ua[i])
	}

	return av
}

func List() ([]Group, error) {
	var dst []WinGroup
	err := wmi.Query("SELECT * FROM Win32_Group where LocalAccount=TRUE", &dst)
	if err != nil {
		return nil, err
	}

	return convert(dst), nil
}
