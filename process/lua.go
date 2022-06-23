package process

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/grep"
	"github.com/vela-security/vela-public/lua"
)

var xEnv assert.Environment

func pidL(L *lua.LState) int {
	pid := L.IsInt(1)
	if pid == 0 {
		return 0
	}

	proc, err := Pid(pid)
	if err != nil {
		return 0
	}

	L.Push(lua.NewAnyData(proc))
	return 1
}

func nameL(L *lua.LState) int {
	sum := &summary{}
	sum.name(grep.New(L.IsString(1)))
	L.Push(sum)
	return 1
}

func cmdL(L *lua.LState) int {
	sum := &summary{}
	sum.cmd(grep.New(L.IsString(1)))
	L.Push(sum)
	return 1
}
func exeL(L *lua.LState) int {
	sum := &summary{}
	sum.exe(grep.New(L.IsString(1)))
	L.Push(sum)
	return 1
}

func userL(L *lua.LState) int {
	sum := &summary{}
	sum.user(grep.New(L.IsString(1)))
	L.Push(sum)
	return 1
}

func cwdL(L *lua.LState) int {
	sum := &summary{}
	sum.cwd(grep.New(L.IsString(1)))
	L.Push(sum)
	return 1
}

func ppidL(L *lua.LState) int {
	sum := &summary{}
	sum.ppid(grep.New(L.IsString(1)))
	L.Push(sum)
	return 1
}

func allL(L *lua.LState) int {
	sum := &summary{}
	sum.init()
	if !sum.ok() {
		goto done
	}

	sum.view(fuzzy(grep.New(L.IsString(1))))

done:
	L.Push(sum)
	return 1
}

func snapshotL(L *lua.LState) int {
	snt := newSnapshot(L)
	if snt == nil {
		L.RaiseError("new process snapshot fail")
		return 0
	}

	proc := L.NewProc(snt.Name(), snt.Type())
	if proc.IsNil() {
		proc.Set(snt)
	} else {
		old := proc.Data.(*snapshot)
		old.Close()
		proc.Set(snt)
	}

	L.Push(proc)
	return 1
}

/*
	local sum = rock.ps.all()
	local sum = rock.ps.name("*dlv*")

	sum.pipe(_(p)
		p.name
		p.cmd
		p.cwd
		p.exe
		p.ppid
	end)


	local p = rock.ps.pid(123)

	local snap = rock.ps.snapshot()

	snap.poll(5)
*/

func WithEnv(env assert.Environment) {
	xEnv = env
	kv := lua.NewUserKV()
	kv.Set("all", lua.NewFunction(allL))
	kv.Set("pid", lua.NewFunction(pidL))
	kv.Set("exe", lua.NewFunction(exeL))
	kv.Set("cmd", lua.NewFunction(cmdL))
	kv.Set("user", lua.NewFunction(userL))
	kv.Set("cwd", lua.NewFunction(cwdL))
	kv.Set("name", lua.NewFunction(nameL))
	kv.Set("ppid", lua.NewFunction(ppidL))
	kv.Set("snapshot", lua.NewFunction(snapshotL))
	env.Set("ps", kv)

	//注册加解密
	xEnv.Mime(simple{}, encode, decode)
}
