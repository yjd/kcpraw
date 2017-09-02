kcpraw
------

运行在伪造的 TCP 协议之上的 kcptun, 主要目的是避免 ISP 对 UDP 协议可能的 QOS.  
在三次握手后会进行 HTTP 握手, 将流量伪装成 HTTP 流量.  
kcptun 的具体参数与使用方法参见 [kcptun](https://github.com/xtaci/kcptun)  

Basic Usage 
-----------

为了使用原始套接字/使用 pcap 发送数据，服务端与客户端都需要 root 权限。  
在填写服务端监听地址时必须填写服务器的 ip 地址，省略 ip 地址是不行滴。

服务端  
```
./kcpraw_server_linux_amd64 -t "TARGET_IP:TARGET_PORT" -l "KCP_SERVER_IP:KCP_SERVER_PORT"
```  
客户端  
```
./kcpraw_client_darwin_amd64 -r "KCP_SERVER_IP:KCP_SERVER_PORT" -l ":LOCAL_PORT"  
```

Additional Parameters
---------------------

* host 
设置启用 HTTP 伪装时所使用的 Host，如果不设置默认为 www.bing.com  

* nohttp  
关闭 HTTP 伪装功能，~~在这一选项上客户端与服务端必须保持一致~~,现在服务端能够同时处理开启和关闭 HTTP 伪装的情况,服务端 nohttp 参数已经被废弃   

* usemul (server only)
使用 Mul 模式，当启用时能够将多个下层的数据流聚合为一个数据流，同时一条下层的数据流断开时不会影响到上层的连接  

* mulconn (client only)
当 mulconn 大于 0 时表示启用 Mul 模式，数值决定了发起多少个下层的连接，目前下层的连接可以是 UDP 或者 fake-TCP 连接   
客户端与服务端在是否启用 Mul 模式这一点上必须保持一致  

* udp  
使用 UDP 套接字收发数据  

Install & Build 
---------------

对于普通用户，直接下载 [releases](https://github.com/ccsexyz/kcpraw/releases) 中对应的预编译版本即可。windows 下依赖 [winpcap](http://www.winpcap.org/install/),需要手动安装。
  
如果需要自己编译，请自行解决 Go 环境问题，然后执行下面的命令。
```
go get -u -v github.com/ccsexyz/kcpraw/client  
go get -u -v github.com/ccsexyz/kcpraw/server  
```

windows 下编译依赖 [winpcap](http://www.winpcap.org/install/) 和 gcc 请自行解决环境问题    
对 windows10 使用者你可能需要参考这个链接 [stackoverflow](http://stackoverflow.com/questions/38047858/compile-gopacket-on-windows-64bit)　　

About RST
---------  

现在默认开启 ignrst 选项在应用层忽略掉 rst 报文。但是过滤 rst 报文仍然是有意义的，一小部分 ISP 可能会在收到 rst 报文后取消 NAT 映射。

1.Linux: 由程序自动增删 iptables 规则  

2.Windows: 参考 [windows firewall port exceptions](https://www.veritas.com/support/en_US/article.000085856) 链接中的方法为*所有端口*设置例外规则

3.Macos: 推荐通过设置 pf 规则来过滤 RST 报文 
```
# 在 /etc/pf.conf 文件后添加一行 
block drop proto tcp from any to <your kcp-server ip address> flags R/R
# 例如 block drop proto tcp from any to 45.88.75.23 flags R/R  
# 然后在终端下执行 
sudo pfctl -f /etc/pf.conf 
sudo pfctl -e 
```

