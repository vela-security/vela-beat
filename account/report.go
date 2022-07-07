package account

type report struct {
	Deletes []string  `json:"deletes"`
	Updates []Account `json:"updates"`
	Creates []Account `json:"creates"`
}

func (r *report) doDelete(name string) {
	r.Deletes = append(r.Deletes, name)
}

func (r *report) doUpdate(a Account) {
	r.Updates = append(r.Updates, a)
}

func (r *report) doCreate(a Account) {
	r.Creates = append(r.Creates, a)
}

func (r *report) len() int {
	return len(r.Deletes) + len(r.Updates) + len(r.Creates)
}
