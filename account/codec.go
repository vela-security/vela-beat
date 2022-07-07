package account

import "encoding/json"

func encode(v interface{}) ([]byte, error) {
	a := v.(Account)
	return a.Byte(), nil
}

func decode(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var v Account
	err := json.Unmarshal(data, &v)
	return v, err
}
