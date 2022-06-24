# vela-track
文件句柄跟踪插件 可以发现指定进程和指定名称的句柄 windows下可能需要信任一下handle.exe

## vela.track.all(condition , condition...)
- 查询所有的句柄信息 过滤条件为 condition 语法
```lua
    vela.track.all("type eq file").pipe(function(section)
        print(section.info)
        --todo
    end)
```

## vela.track.kw(keyword , condition...)
- 查询包含关键字的当前的文件句柄
- 查询当前的主机上说有打开的的文件句柄中包含 当前关键字的句柄
```lua
    vela.track.kw("java").pipe(function(section)
        print(section.info)
        --todo
    end)
```

## vela.track.name(name , condition...)
- 查询指定进程名称的文件正在打开的句柄
- 跟keyword的区别在于这里查询的是进程名称 然后关联说有的文件句柄信息
```lua
    vela.track.name("java").pipe(function(section)
        print(section.info)
        --todo
    end)
```


## section
- 相关查询结果的内容返回值信息
- type  类型
- value 句柄文件信息
- pid   进程pid
- exe   进程文件
- name  进程名称
- ext   句柄文件后缀
- info  整体信息
- raw   原始数据格式(JSON)
```lua
    vela.track.all("type eq file").pipe(function(section)
        print(section.type)
        print(section.value)
        print(section.pid)
        --todo
    end)
```