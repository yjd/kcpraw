Name 
====

kcpraw 

Synopsis
========  

```  
$ kcpraw_client_darwin_amd64 -l 127.0.0.1:1080 -r vps:80 --key secret --mode fast3 --mtu 1200 --ds 0 --ps 0 --nocomp --host www.zhihu.com   
# kcpraw_server_linux_amd64 -l vps:80 -t :10086 --key secret --mtu 1200 --mode fast2 --ds 0 --ps 0 --nocomp
```  

Features
========
* turn udp traffic to tcp traffic  
* http obfuscating  
* tls obfuscating  
* easy to install & build & use  
* provide socks5/socks4/socks4a/http & shadowsocks server at kcpraw/server   
* support socks5 udp-associate   
* provide additional tcp/udp tunnels  
* aggregate multiple underlying connections to one kcp connection   

Installation
============

It is highly recommended to use [kcpraw releases](https://github.com/ccsexyz/kcpraw/releases).  

Note for Windows Users   
kcpraw is dependent on winpcap.You should download and install it from [winpcap](https://www.winpcap.org/install/default.htm) first.   

Note for Linux Users  
kcpraw uses raw-socket to receive and send tcp packets. root permission is required.

Note for Macos Users  
kcpraw requires read permission for /dev/bpfx. so don't run kcpraw as nobody.   

Build
=====

Alternatively, you can manually compiled it from source:    
1.Download and install Go from https://golang.org/dl/ if you don't have go yet.   
2.Run go get or build.sh   

```  
$ go get -u -v github.com/ccsexyz/kcpraw/client
$ go get -u -v github.com/ccsexyz/kcpraw/server  

# or 
$ go get github.com/ccsexyz/kcpraw  
$ cd $GOPATH/src/github.com/ccsexyz/kcpraw  
$ ./build.sh  
```  

Note for Windows Users

If you're trying to compile 64-bit kcpraw(or google/gopacket) on 64-bit Windows, you might have to do the crazy hijinks detailed at [compile gopacket on windows](http://stackoverflow.com/questions/38047858/compile-gopacket-on-windows-64bit) 

Usage
=====

```
$ ./client -h
NAME:
   kcpraw - client(with SMUX)

USAGE:
   client [global options] command [command options] [arguments...]

VERSION:
   SELFBUILD

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --localaddr value, -l value      local listen address (default: ":12948")
   --remoteaddr value, -r value     kcp server address (default: "vps:29900")
   --key value                      pre-shared secret between client and server (default: "it's a secrect") [$KCPTUN_KEY]
   --crypt value                    aes, aes-128, aes-192, chacha20, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none (default: "aes")
   --mode value                     profiles: fast3, fast2, fast, normal, manual (default: "fast")
   --conn value                     set num of UDP connections to server (default: 1)
   --autoexpire value               set auto expiration time(in seconds) for a single UDP connection, 0 to disable (default: 0)
   --mtu value                      set maximum transmission unit for UDP packets (default: 1350)
   --sndwnd value                   set send window size(num of packets) (default: 128)
   --rcvwnd value                   set receive window size(num of packets) (default: 512)
   --datashard value, --ds value    set reed-solomon erasure coding - datashard (default: 10)
   --parityshard value, --ps value  set reed-solomon erasure coding - parityshard (default: 3)
   --dscp value                     set dscp(6bit) (default: 0)
   --nocomp                         disable compression
   --snmplog value                  collect snmp to file, aware of timeformat in golang, like: ./snmp-20060102.log
   --snmpperiod value               snmp collect period, in seconds (default: 60)
   --log value                      specify a log file to output, default goes to stderr
   -c value                         config from json file, which will override the command from shell
   --host value                     hostname for obfuscating (Experimental)
   --nohttp                         don't send http request after tcp 3-way handshake
   --scavengettl value              set how long an expired connection can live(in sec), -1 to disable (default: 600)
   --mulconn value                  use multiple underlying conns for one kcp connection, default is 0 (default: 0)
   --udp                            enable udp mode
   --pprof value                    set the listen address for pprof
   --nodummy                        don't use dummy socket
   --proxylist value                set the path of proxy list
   --chnroute value                 set the path of china route
   --proxy                          enable default proxy(socks4/socks4a/socks5/http)
   --udprelay                       enable socks5 udp relay
   --tunnels value                  provide additional tcp/udp tunnels, eg: udp,:10000,8.8.8.8:53;tcp,:10080,www.google.com:80
   --help, -h                       show help
   --version, -v                    print the version

$ ./server -h
NAME:
   kcpraw - server(with SMUX)

USAGE:
   server [global options] command [command options] [arguments...]

VERSION:
   SELFBUILD

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --listen value, -l value         kcp server listen address (default: ":29900")
   --target value, -t value         target server address (default: "127.0.0.1:12948")
   --key value                      pre-shared secret between client and server (default: "it's a secrect") [$KCPTUN_KEY]
   --crypt value                    aes, aes-128, aes-192, chacha20, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none (default: "aes")
   --mode value                     profiles: fast3, fast2, fast, normal, manual (default: "fast")
   --mtu value                      set maximum transmission unit for UDP packets (default: 1350)
   --sndwnd value                   set send window size(num of packets) (default: 1024)
   --rcvwnd value                   set receive window size(num of packets) (default: 1024)
   --datashard value, --ds value    set reed-solomon erasure coding - datashard (default: 10)
   --parityshard value, --ps value  set reed-solomon erasure coding - parityshard (default: 3)
   --dscp value                     set dscp(6bit) (default: 0)
   --nocomp                         disable compression
   --usemul                         use multiple underlying conns for one kcp connection
   --snmplog value                  collect snmp to file, aware of timeformat in golang, like: ./snmp-20060102.log
   --snmpperiod value               snmp collect period, in seconds (default: 60)
   --log value                      specify a log file to output, default goes to stderr
   -c value                         config from json file, which will override the command from shell
   --udp                            enable udp mode
   --pprof value                    set the listen address for pprof
   --proxy                          enable default proxy(socks4/socks4a/socks5/http)
   --ssproxy                        enable shadowsocks proxy
   --ssmethod value                 set the method of shadowsocks proxy (default: "multi")
   --sskey value                    set the password of shadowsocks proxy
   --help, -h                       show help
   --version, -v                    print the version
```

Report Bugs
===========

You're very welcom to report issues on GitHub: 

https://github.com/ccsexyz/kcpraw/issues  

Authors
=======

* xtaci   
* ccsexyz  
