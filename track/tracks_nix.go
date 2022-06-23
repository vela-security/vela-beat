//go:build linux || plan9 || freebsd || solaris
// +build linux plan9 freebsd solaris

package track

import (
	"fmt"
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-public/lua"
)

func newTracksKeyWold(L *lua.LState) *tracks {
	world := L.CheckString(1)
	cnd := cond.New(fmt.Sprintf("raw cn *%s*", world))
	cnd.CheckMany(L, cond.Seek(1))

	tks := &tracks{cnd: cnd}
	tks.scan()
	return tks
}

func newTrackName(L *lua.LState) *tracks {
	name := L.CheckString(1)
	cnd := cond.New(fmt.Sprintf("name eq %s", name))
	cnd.CheckMany(L, cond.Seek(1))
	tks := &tracks{cnd: cnd}
	tks.scan()
	return tks
}
