package group

import "github.com/vela-security/vela-public/kind"

type Group struct {
	Name        string `json:"name"`
	GID         string `json:"gid"`
	Description string `json:"description"`
}

func (g *Group) Byte() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("name", g.Name)
	enc.KV("gid", g.GID)
	enc.KV("description", g.Description)
	enc.End("}")
	return enc.Bytes()
}

func (g *Group) equal(old Group) bool {
	if g.Name != old.Name {
		return false
	}

	if g.GID != old.GID {
		return false
	}

	if g.Description != old.Description {
		return false
	}

	return true
}
