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
```lua
    local cnd = vela.cond("type eq fork" , "pid > 0")
    
    cnd.ok(function()
            
    end)

    cnd.no(function()
            
    end)

    local pnt = linux.psnotify("psnotify")
    pnt.do(cnd)
```

