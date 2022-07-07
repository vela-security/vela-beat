# vela-beat/socket
- 查看主机网络信息

## summary = vela.ss(proto, condition...)
- 查看本地网路信息 proto:协议类型(tcp,udp,unix,all) condition:匹配条件
- pipe(pipe)
```lua
    vela.ss("tcp").pipe(function(sock) end)
    vela.ss("tcp" , "stat = ESTAB").pipe(function(sock) end)
    vela.ss("tcp" , "stat = LISTEN" , "pid > 10").pipe(function(sock) end)
    vela.ss("all" , "stat = LISTEN" , "pid > 10").pipe(function(sock) end)
```
## summary
- 查询后的的结果对象 后面返回的都是结果
- closed
- listen
- syn_sent
- syn_rcvd
- estab
- fin_wait_1
- fin_wait_2
- close_wait
- closing
- last_ack
- time_wait
- delete_tcb
- total
- err
- pipe(pipe)

## socket
- 内部变量
- pid
- family
- protocol
- local_addr
- local_port
- remote_addr
- remote_port
- path //unix
- state
- process
- user

## 状态值
- ESTAB
- SYN-SENT
- SYN-RECV
- FIN-WAIT-1
- FIN-WAIT-2
- TIME-WAIT
- CLOSED
- CLOSE-WAIT
- LAST-ACK
- LISTEN
- CLOSING