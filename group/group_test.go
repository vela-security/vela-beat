package group

import "testing"

func TestGroup(t *testing.T) {
	list, err := List()
	if err != nil {
		t.Log(err)
		return
	}

	t.Logf("%v", list)
}
