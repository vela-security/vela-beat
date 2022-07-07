package group

import "encoding/json"

func encode(v interface{}) ([]byte, error) {
	a := v.(Group)
	return a.Byte(), nil
}

func decode(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var v Group
	err := json.Unmarshal(data, &v)
	return v, err
}
