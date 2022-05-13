package ifconfig

import (
	"github.com/vela-security/vela-public/assert"
	"sync"
)

var (
	xEnv assert.Environment
	once sync.Once
	_G   *summary
)

//func allL(L *lua.LState) int {
//	sum := &summary{}
//	sum.view(fuzzy(grep.New(L.IsString(1))))
//	L.Push(sum)
//	return 1
//}
//
//func ipL(L *lua.LState) int {
//	sum := &summary{}
//	sum.ip(grep.New(L.IsString(1)))
//	L.Push(sum)
//	return 1
//}
//
//func nameL(L *lua.LState) int {
//	sum := &summary{}
//	name := L.IsString(1)
//	sum.name(func(s string) bool {
//		return 	name == s
//	})
//
//	if len(sum.iFace) > 0 {
//		L.Push(sum.iFace[0])
//		return 1
//	}
//	return 0
//}

/*
	local sum  = vela.ifconfig.all()
	local mac  = vela.ifconfig.mac()
	local flow = vela.ifconfig.flow()
	local eth  = vela.ifconfig.ip()

	eth.mac
	eth.abb
	eth.acc
	eth.bcc

*/

func WithEnv(env assert.Environment) {
	xEnv = env
	_G = &summary{}
	_G.update()
	env.Set("ifconfig", _G)

	//kv := lua.NewUserKV()
	//kv.Set("all"  , lua.NewFunction(allL))
	//kv.Set("mac"  , lua.NewFunction(allL))
	//kv.Set("ip"   , lua.NewFunction(ipL))
	//kv.Set("name" , lua.NewFunction(nameL))
	//kv.Set("flow" , lua.NewFunction(flowL))

	//env.Set("interface", _G)
}
