package group

type report struct {
	Deletes []string `json:"deletes"`
	Updates []Group  `json:"updates"`
	Creates []Group  `json:"creates"`
}

func (r *report) doDelete(name string) {
	r.Deletes = append(r.Deletes, name)
}

func (r *report) doUpdate(a Group) {
	r.Updates = append(r.Updates, a)
}

func (r *report) doCreate(a Group) {
	r.Creates = append(r.Creates, a)
}

func (r *report) len() int {
	return len(r.Deletes) + len(r.Updates) + len(r.Creates)
}
