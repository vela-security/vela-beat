# linux
linux下常用的数据接口

## linux.dns
- 监听linux模式下dns的访问记录
- userdata = linux.dns{name , region , bind}
- userdata = linux.dns(name)
- [userdata.pipe(v)]()
- [userdata.start]()
```lua
    local d = linux.dns{
        name = "monitor",
        region = region.sdk(),
        bind = "udp://0.0.0.0:53", 
    }
    d.pipe(lua.writer)
    d.pipe(function(tx)  end)
    d.start()
```

## linux.psnotify(name)
- 构造一个linux 监控
- ps.all()
- ps.cond(condition)
- ps.pipe(pipe)
```lua
    --local cnd = vela.cond("type eq fork,exec" , "ppid > 0")
    local cnd = vela.cond("ppid > 0" , "info cn */etc/passwd/*,*/etc/shadow*,*cron*,*.ssh*")
    cnd.ok(function(ev)
        print(ev.info)
        vela.ss("tcp" , "pid = " .. tostring(ev.pid)).pipe(function(sock)
            print(sock)
        end)
    end)

    local pnt = linux.psnotify("psnotify")
    pnt.all()
    pnt.cond(cnd)
    pnt.start()

```

