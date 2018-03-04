package main

import (
	"encoding/csv"
	"fmt"
	"hash"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"os/signal"
	"syscall"

	"github.com/ccsexyz/kcp-go-raw"
	"github.com/ccsexyz/kcpraw/common"
	"github.com/ccsexyz/shadowsocks-go/redir"
	"github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/ccsexyz/smux"
	"github.com/ccsexyz/utils"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"github.com/xtaci/kcp-go"
)

var (
	// VERSION is injected by buildflags
	VERSION = "SELFBUILD"
	// SALT is use for pbkdf2 key expansion
	SALT = "kcp-go"
)

const (
	nonceSize  = 16
	udpBufSize = 2048
)

type udpConn struct {
	net.Conn
	block kcp.BlockCrypt
	mac   hash.Hash
	ok    bool
}

func (conn *udpConn) Read(b []byte) (n int, err error) {
AGAIN:
	n, err = conn.Conn.Read(b)
	if err != nil {
		return
	}
	if n < nonceSize {
		goto AGAIN
	}
	conn.block.Decrypt(b[:n], b[:n])
	n = copy(b, b[nonceSize:n])
	conn.ok = true
	return
}

func (conn *udpConn) Write(b []byte) (n int, err error) {
	macSize := conn.mac.Size()
	buf := utils.GetBuf(len(b) + nonceSize + macSize)
	defer utils.PutBuf(buf)
	utils.PutRandomBytes(buf[:nonceSize])
	copy(buf[nonceSize:], b)
	conn.block.Encrypt(buf[:nonceSize+len(b)], buf[:nonceSize+len(b)])
	if conn.ok {
		utils.PutRandomBytes(buf[nonceSize+len(b):])
	} else {
		conn.mac.Write(buf[:nonceSize+len(b)])
		mac := conn.mac.Sum(nil)
		conn.mac.Reset()
		copy(buf[nonceSize+len(b):], mac)
	}
	_, err = conn.Conn.Write(buf[:nonceSize+macSize+len(b)])
	if err != nil {
		return
	}
	n = len(b)
	return
}

func handleTunnelClient(sess *smux.Session, p1 net.Conn, host string, port int) {
	defer p1.Close()

	if len(host) == 0 || port == 0 {
		return
	}

	p2, err := sess.OpenStream()
	if err != nil {
		return
	}
	defer p2.Close()

	err = socks6HandShake(p2, host, port)
	if err != nil {
		return
	}

	log.Println("tcp tunnel opened", host, port)
	defer log.Println("tcp tunnel closed", host, port)

	pipe(p1, p2)
}

func handleProxyClient(sess *smux.Session, p1 net.Conn, cfg *Config) {
	defer func() {
		if p1 != nil {
			p1.Close()
		}
	}()

	p1 = cfg.proxyAcceptor(p1)
	if p1 == nil {
		return
	}

	ssconn, ok := p1.(ss.Conn)
	if !ok {
		return
	}
	target := ssconn.GetDst().String()

	host, port, err := utils.SplitHostAndPort(target)
	if err != nil {
		return
	}

	var direct bool
	ip := net.ParseIP(host)

	if ip != nil && cfg.chnRouteCtx != nil {
		direct = cfg.chnRouteCtx.testIP(ip)
	} else if cfg.autoProxyCtx != nil {
		direct = !cfg.autoProxyCtx.checkIfProxy(host)
	}

	var p2 net.Conn
	defer func() {
		if p2 != nil {
			p2.Close()
		}
	}()

	if direct {
		p2, err = net.Dial("tcp", target)
		if err != nil {
			log.Println(err)
			return
		}
	} else {
		p2, err = sess.OpenStream()
		if err != nil {
			return
		}
		if len(host) != 0 && port > 0 {
			err = socks6HandShake(p2, host, port)
			if err != nil {
				return
			}
		}
	}

	var directStr string
	if direct {
		directStr = "direct"
	}

	log.Println("stream opened", target, directStr)
	defer log.Println("stream closed", target, directStr)

	pipe(p1, p2)
}

func handleClient(sess *smux.Session, p1 net.Conn) {
	defer p1.Close()

	p2, err := sess.OpenStream()
	if err != nil {
		return
	}
	defer p2.Close()

	log.Println("stream opened")
	defer log.Println("stream closed")

	pipe(p1, p2)
}

func pipe(p1, p2 net.Conn) {
	b1 := utils.GetBuf(65535)
	defer utils.PutBuf(b1)
	b2 := utils.GetBuf(65535)
	defer utils.PutBuf(b2)
	common.Pipe(p1, p2, b1, b2)
}

func checkError(err error) {
	if err != nil {
		log.Printf("%+v\n", err)
		os.Exit(-1)
	}
}

func main() {
	rand.Seed(int64(time.Now().Nanosecond()))
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)
	myApp := cli.NewApp()
	myApp.Name = "kcpraw"
	myApp.Usage = "client(with SMUX)"
	myApp.Version = VERSION
	myApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "localaddr,l",
			Value: ":12948",
			Usage: "local listen address",
		},
		cli.StringFlag{
			Name:  "remoteaddr, r",
			Value: "vps:29900",
			Usage: "kcp server address",
		},
		cli.StringFlag{
			Name:   "key",
			Value:  "it's a secrect",
			Usage:  "pre-shared secret between client and server",
			EnvVar: "KCPTUN_KEY",
		},
		cli.StringFlag{
			Name:  "crypt",
			Value: "aes",
			Usage: "aes, aes-128, aes-192, chacha20, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none",
		},
		cli.StringFlag{
			Name:  "mode",
			Value: "fast",
			Usage: "profiles: fast3, fast2, fast, normal, manual",
		},
		cli.IntFlag{
			Name:  "conn",
			Value: 1,
			Usage: "set num of UDP connections to server",
		},
		cli.IntFlag{
			Name:  "autoexpire",
			Value: 0,
			Usage: "set auto expiration time(in seconds) for a single UDP connection, 0 to disable",
		},
		cli.IntFlag{
			Name:  "mtu",
			Value: 1350,
			Usage: "set maximum transmission unit for UDP packets",
		},
		cli.IntFlag{
			Name:  "sndwnd",
			Value: 128,
			Usage: "set send window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "rcvwnd",
			Value: 512,
			Usage: "set receive window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "datashard,ds",
			Value: 0,
			Usage: "set reed-solomon erasure coding - datashard",
		},
		cli.IntFlag{
			Name:  "parityshard,ps",
			Value: 0,
			Usage: "set reed-solomon erasure coding - parityshard",
		},
		cli.IntFlag{
			Name:  "udp_datashard,udp_ds",
			Value: 0,
			Usage: "set reed-solomon erasure coding - datashard",
		},
		cli.IntFlag{
			Name:  "udp_parityshard,udp_ps",
			Value: 0,
			Usage: "set reed-solomon erasure coding - parityshard",
		},
		cli.IntFlag{
			Name:  "dscp",
			Value: 0,
			Usage: "set dscp(6bit)",
		},
		cli.BoolFlag{
			Name:   "acknodelay",
			Usage:  "flush ack immediately when a packet is received",
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nodelay",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "interval",
			Value:  40,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "resend",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nc",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "sockbuf",
			Value:  4194304, // socket buffer size in bytes
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "keepalive",
			Value:  10, // nat keepalive interval in seconds
			Hidden: true,
		},
		cli.StringFlag{
			Name:  "snmplog",
			Value: "",
			Usage: "collect snmp to file, aware of timeformat in golang, like: ./snmp-20060102.log",
		},
		cli.IntFlag{
			Name:  "snmpperiod",
			Value: 60,
			Usage: "snmp collect period, in seconds",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
			Usage: "specify a log file to output, default goes to stderr",
		},
		cli.StringFlag{
			Name:  "c",
			Value: "", // when the value is not empty, the config path must exists
			Usage: "config from json file, which will override the command from shell",
		},
		cli.StringFlag{
			Name:  "host",
			Value: "",
			Usage: "hostname for obfuscating (Experimental)",
		},
		cli.StringFlag{
			Name:  "obfs",
			Usage: "obfuscating method, http/tls",
		},
		cli.IntFlag{
			Name:  "scavengettl",
			Value: 600,
			Usage: "set how long an expired connection can live(in sec), -1 to disable",
		},
		cli.IntFlag{
			Name:  "mulconn",
			Value: 0,
			Usage: "use multiple underlying conns for one kcp connection, default is 0",
		},
		cli.BoolFlag{
			Name:  "udp",
			Usage: "enable udp mode",
		},
		cli.StringFlag{
			Name:  "pprof",
			Usage: "set the listen address for pprof",
		},
		cli.BoolFlag{
			Name:  "nodummy",
			Usage: "don't use dummy socket",
		},
		cli.StringFlag{
			Name:  "proxylist",
			Usage: "set the path of proxy list",
		},
		cli.StringFlag{
			Name:  "chnroute",
			Usage: "set the path of china route",
		},
		cli.BoolFlag{
			Name:  "proxy",
			Usage: "enable default proxy(socks4/socks4a/socks5/http/shadowsocks)",
		},
		cli.BoolFlag{
			Name:  "udprelay",
			Usage: "enable socks5 udp relay",
		},
		cli.StringFlag{
			Name:  "tunnels",
			Usage: "provide additional tcp/udp tunnels, eg: udp,:10000,8.8.8.8:53;tcp,:10080,www.google.com:80",
		},
		cli.StringFlag{
			Name:  "salt",
			Value: SALT,
			Usage: "for pbkdf2 key derivation function",
		},
		cli.BoolFlag{
			Name:  "udpviakcp",
			Usage: "",
		},
		cli.IntFlag{
			Name:  "timeout",
			Value: 60,
			Usage: "",
		},
		cli.IntFlag{
			Name:  "udp_timeout",
			Value: 5,
			Usage: "",
		},
	}
	myApp.Action = func(c *cli.Context) error {
		config := Config{}
		config.LocalAddr = c.String("localaddr")
		config.RemoteAddr = c.String("remoteaddr")
		config.Key = c.String("key")
		config.Crypt = c.String("crypt")
		config.Mode = c.String("mode")
		config.Conn = c.Int("conn")
		config.AutoExpire = c.Int("autoexpire")
		config.MTU = c.Int("mtu")
		config.SndWnd = c.Int("sndwnd")
		config.RcvWnd = c.Int("rcvwnd")
		config.DataShard = c.Int("datashard")
		config.ParityShard = c.Int("parityshard")
		config.DSCP = c.Int("dscp")
		config.AckNodelay = c.Bool("acknodelay")
		config.NoDelay = c.Int("nodelay")
		config.Interval = c.Int("interval")
		config.Resend = c.Int("resend")
		config.NoCongestion = c.Int("nc")
		config.SockBuf = c.Int("sockbuf")
		config.KeepAlive = c.Int("keepalive")
		config.Log = c.String("log")
		config.SnmpLog = c.String("snmplog")
		config.SnmpPeriod = c.Int("snmpperiod")
		config.Obfs = c.String("obfs")
		config.Host = c.String("host")
		config.ScavengeTTL = c.Int("scavengettl")
		config.MulConn = c.Int("mulconn")
		config.UDP = c.Bool("udp")
		config.Pprof = c.String("pprof")
		config.NoDummpy = c.Bool("nodummy")
		config.ProxyList = c.String("proxylist")
		config.ChnRoute = c.String("chnroute")
		config.UDPRelay = c.Bool("udprelay")
		config.Proxy = c.Bool("proxy")
		config.Salt = c.String("salt")
		config.UDPViaKCP = c.Bool("udpviakcp")
		config.Timeout = c.Int("timeout")
		config.UDPTimeout = c.Int("udp_timeout")
		config.UDPDataShard = c.Int("udp_datashard")
		config.UDPParityShard = c.Int("udp_parityshard")
		tunnels := c.String("tunnels")

		if c.String("c") != "" {
			err := parseJSONConfig(&config, c.String("c"))
			checkError(err)
		}

		if config.UDPTimeout == 0 {
			config.UDPTimeout = config.Timeout
		}
		if config.UDPDataShard == 0 {
			config.UDPDataShard = config.DataShard
		}
		if config.UDPParityShard == 0 {
			config.UDPParityShard = config.ParityShard
		}

		// log redirect
		if config.Log != "" {
			f, err := os.OpenFile(config.Log, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			checkError(err)
			defer f.Close()
			log.SetOutput(f)
		}

		switch config.Mode {
		case "normal":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
		case "fast":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
		case "fast2":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
		case "fast3":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
		}

		log.Println("version:", VERSION)
		addr, err := net.ResolveTCPAddr("tcp", config.LocalAddr)
		checkError(err)
		listener, err := net.ListenTCP("tcp", addr)
		checkError(err)

		block := common.NewBlockCrypt([]byte(config.Key), []byte(config.Salt), config.Crypt)

		if len(config.Host) == 0 {
			config.Obfs = ""
		}

		if len(tunnels) != 0 {
			for _, t := range strings.Split(tunnels, ";") {
				tcs := strings.Split(t, ",")
				if len(tcs) != 3 || len(tcs[1]) == 0 || len(tcs[2]) == 0 {
					continue
				}
				config.Tunnels = append(config.Tunnels, &tunnelConfig{
					Type:       tcs[0],
					LocalAddr:  tcs[1],
					RemoteAddr: tcs[2],
				})
			}
		}

		if len(config.ProxyList) != 0 || len(config.ChnRoute) != 0 {
			config.Proxy = true
		}

		if config.UDPViaKCP && config.UDPRelay && !config.Proxy {
			config.Proxy = true
		}

		log.Println("listening on:", listener.Addr())
		log.Println("encryption:", config.Crypt)
		log.Println("nodelay parameters:", config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		log.Println("remote address:", config.RemoteAddr)
		log.Println("sndwnd:", config.SndWnd, "rcvwnd:", config.RcvWnd)
		log.Println("mtu:", config.MTU)
		log.Println("datashard:", config.DataShard, "parityshard:", config.ParityShard)
		log.Println("acknodelay:", config.AckNodelay)
		log.Println("dscp:", config.DSCP)
		log.Println("salt:", config.Salt)
		log.Println("sockbuf:", config.SockBuf)
		log.Println("keepalive:", config.KeepAlive)
		log.Println("conn:", config.Conn)
		log.Println("autoexpire:", config.AutoExpire)
		log.Println("snmplog:", config.SnmpLog)
		log.Println("snmpperiod:", config.SnmpPeriod)
		log.Println("scavengettl:", config.ScavengeTTL)
		log.Println("mulconn:", config.MulConn)
		log.Println("udp mode:", config.UDP)
		log.Println("pprof listen at:", config.Pprof)
		log.Println("dummpy:", !config.NoDummpy)
		log.Println("obfs:", config.Obfs)
		log.Println("httphost:", config.Host)
		log.Println("proxy:", config.Proxy)
		log.Println("proxylist:", config.ProxyList)
		log.Println("chnroute:", config.ChnRoute)
		log.Println("udprelay:", config.UDPRelay)

		if len(config.Pprof) != 0 {
			if utils.PprofEnabled() {
				log.Println("run pprof http server at", config.Pprof)
				go func() {
					utils.RunProfileHTTPServer(config.Pprof)
				}()
			} else {
				log.Println("set pprof but pprof isn't compiled")
			}
		}

		args := make(map[string]interface{})

		if config.UDPRelay {
			args["localaddr"] = config.LocalAddr
			args["udprelay"] = true
		}

		if len(config.ProxyList) != 0 {
			config.autoProxyCtx = newAutoProxy()
			config.autoProxyCtx.loadPorxyList(config.ProxyList)
		}

		if len(config.ChnRoute) != 0 {
			config.chnRouteCtx = new(chnRouteList)
			err := config.chnRouteCtx.load(config.ChnRoute)
			if err != nil {
				log.Println(err)
				config.chnRouteCtx = nil
			}
		}

		if config.Proxy {
			args["password"] = config.Key
			config.proxyAcceptor = ss.GetShadowAcceptor(args)
		}

		switch config.Obfs {
		case "tls":
			kcpraw.SetNoHTTP(true)
			kcpraw.SetTLS(true)
		case "http":
		default:
			kcpraw.SetNoHTTP(true)
		}
		kcpraw.SetHost(config.Host)
		kcpraw.SetDSCP(config.DSCP)
		kcpraw.SetIgnRST(true)
		kcpraw.SetDummy(!config.NoDummpy)

		smuxConfig := smux.DefaultConfig()
		smuxConfig.MaxReceiveBuffer = config.SockBuf
		smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second

		createConn := func() (*smux.Session, error) {
			kcpconn, err := kcpraw.DialWithOptions(config.RemoteAddr, block, config.DataShard, config.ParityShard, config.Key, config.MulConn, config.UDP)
			if err != nil {
				return nil, errors.Wrap(err, "createConn()")
			}
			kcpconn.SetStreamMode(true)
			kcpconn.SetWriteDelay(true)
			kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
			kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)

			mss := kcpraw.GetMSSByAddr(kcpconn.LocalAddr(), kcpconn.RemoteAddr())
			if mss > 0 && mss < config.MTU {
				kcpconn.SetMtu(mss)
			} else {
				kcpconn.SetMtu(config.MTU)
			}

			kcpconn.SetACKNoDelay(config.AckNodelay)

			// stream multiplex
			var session *smux.Session
			var conn io.ReadWriteCloser
			conn = kcpconn
			session, err = smux.Client(conn, smuxConfig)
			if err != nil {
				return nil, errors.Wrap(err, "createConn()")
			}
			log.Println("connection:", kcpconn.LocalAddr(), "->", kcpconn.RemoteAddr())
			return session, nil
		}

		// wait until a connection is ready
		waitConn := func() *smux.Session {
			for {
				if session, err := createConn(); err == nil {
					return session
				} else {
					time.Sleep(time.Second)
				}
			}
		}

		type muxSessInfo struct {
			session *smux.Session
			ttl     time.Time
		}
		var mmuxes [][]muxSessInfo

		sigch := make(chan os.Signal, 2)
		signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigch
			for _, muxes := range mmuxes {
				for _, m := range muxes {
					m.session.Close()
				}
			}
			os.Exit(1)
		}()

		go snmpLogger(config.SnmpLog, config.SnmpPeriod)

		newSessionDailer := func() func() *smux.Session {
			numconn := uint16(config.Conn)
			muxes := make([]muxSessInfo, numconn)
			mmuxes = append(mmuxes, muxes)

			for k := range muxes {
				sess, err := createConn()
				checkError(err)
				muxes[k].session = sess
				muxes[k].ttl = time.Now().Add(time.Duration(config.AutoExpire) * time.Second)
			}

			chScavenger := make(chan *smux.Session, 128)
			go scavenger(chScavenger, config.ScavengeTTL)
			rr := uint16(0)
			var rrLock sync.Mutex
			return func() *smux.Session {
				rrLock.Lock()
				defer rrLock.Unlock()

				idx := rr % numconn

				// do auto expiration && reconnection
				if muxes[idx].session.IsClosed() || (config.AutoExpire > 0 && time.Now().After(muxes[idx].ttl)) {
					chScavenger <- muxes[idx].session
					muxes[idx].session = waitConn()
					muxes[idx].ttl = time.Now().Add(time.Duration(config.AutoExpire) * time.Second)
				}
				rr++

				return muxes[idx].session
			}
		}

		dialSessionForTCP := newSessionDailer()
		var dialSessionForUDPImp func() *smux.Session
		var udpDialerOnce sync.Once
		dialSessionForUDP := func() *smux.Session {
			udpDialerOnce.Do(func() { dialSessionForUDPImp = newSessionDailer() })
			return dialSessionForUDPImp()
		}

		createConnForUDP := func() (conn net.Conn, err error) {
			if config.UDPViaKCP {
				session := dialSessionForUDP()
				if session == nil {
					return nil, fmt.Errorf("no available session")
				}
				conn, err = session.OpenStream()
				if err != nil {
					return
				}
				err = socks6HandShake(conn, "udprelay", 6666)
				if err != nil {
					return
				}
				conn = common.NewPktConn(conn)
			} else {
				conn, err = kcpraw.DialRAW(config.RemoteAddr, config.Key, config.MulConn, config.UDP, nil)
				if err != nil {
					return nil, err
				}
				mac := common.NewHMAC([]byte(config.Key), []byte(config.Salt))
				conn = &udpConn{Conn: conn, block: block, mac: mac}
				conn = utils.NewSliceConn(conn, config.MTU)
				if config.UDPDataShard > 0 && config.UDPParityShard > 0 {
					conn = utils.NewFecConn(conn, config.UDPDataShard, config.UDPParityShard)
				}
			}
			return conn, nil
		}

		handleUDPTunnel := func(p1 net.Conn, target string, data []byte) {
			p2, err := createConnForUDP()
			if err != nil {
				return
			}
			defer p2.Close()

			if config.UDPViaKCP {
				_, err = p2.Write(utils.StringToSlice(target))
				if err != nil {
					return
				}
			} else {
				p2 = common.NewAddrConn(p2, utils.StringToSlice(target), true)
			}

			if data != nil {
				_, err = p2.Write(data)
				if err != nil {
					return
				}
			}

			log.Println("udp tunnel opened", target)
			defer log.Println("udp tunnel closed", target)

			pipe(p1, p2)
		}

		handleUDPClient := func(p1 net.Conn) {
			defer p1.Close()

			buf := utils.GetBuf(udpBufSize)
			defer utils.PutBuf(buf)

			n, err := p1.Read(buf)
			if err != nil || n < 3 {
				return
			}

			addr, data, err := ss.ParseAddr(buf[3:n])
			if err != nil || addr == nil {
				return
			}

			header := utils.CopyBuffer(buf[:n-len(data)])
			p1 = common.NewHdrConn(p1, header)

			handleUDPTunnel(p1, addr.String(), data)
		}

		if config.UDPRelay {
			ctx := utils.UDPServerCtx{Expires: config.UDPTimeout, Mtu: config.MTU * 2}
			udpListener, err := utils.ListenSubUDPWithCtx("udp", config.LocalAddr, &ctx)
			if err != nil {
				log.Fatalln(err)
			}
			go func() {
				defer udpListener.Close()
				for {
					p1, err := udpListener.Accept()
					if err != nil {
						log.Fatalln(err)
					}
					p1 = common.NewTimeoutConn(p1, time.Second*time.Duration(config.UDPTimeout))
					go func(p1 net.Conn) {
						defer p1.Close()
						if config.Proxy {
							handleUDPClient(p1)
						} else {
							p2, err := createConnForUDP()
							if err != nil {
								return
							}
							defer p2.Close()
							log.Println("udp tunnel opened")
							defer log.Println("udp tunnel closed")
							pipe(p1, p2)
						}
					}(p1)
				}
			}()
		}

		runUDPTunnelListener := func(ctx *tunnelConfig) {
			if len(ctx.LocalAddr) == 0 || len(ctx.RemoteAddr) == 0 || len(ctx.RemoteAddr) > 256 || config.Proxy == false {
				return
			}
			log.Println("run udp tunnel:", ctx.LocalAddr, "->", ctx.RemoteAddr)
			udpCtx := utils.UDPServerCtx{Expires: config.UDPTimeout, Mtu: config.MTU * 2}
			udpListener, err := utils.ListenSubUDPWithCtx("udp", ctx.LocalAddr, &udpCtx)
			if err != nil {
				log.Fatalln(err)
			}
			defer udpListener.Close()
			for {
				p1, err := udpListener.Accept()
				if err != nil {
					log.Fatalln(err)
				}
				p1 = common.NewTimeoutConn(p1, time.Second*time.Duration(config.UDPTimeout))
				go handleUDPTunnel(p1, ctx.RemoteAddr, nil)
			}
		}

		runTCPTunnelListener := func(ctx *tunnelConfig) {
			if config.proxyAcceptor == nil {
				return
			}
			log.Println("run tcp tunnel:", ctx.LocalAddr, "->", ctx.RemoteAddr)
			tcpAddr, err := net.ResolveTCPAddr("tcp", ctx.LocalAddr)
			if err != nil {
				log.Fatalln(err)
			}
			tcpTunnelListener, err := net.ListenTCP("tcp", tcpAddr)
			checkError(err)
			defer tcpTunnelListener.Close()
			host, port, err := utils.SplitHostAndPort(ctx.RemoteAddr)
			if err != nil {
				log.Fatalln(err)
			}
			for {
				p1, err := tcpTunnelListener.Accept()
				if err != nil {
					log.Fatalln(err)
				}
				p1 = common.NewTimeoutConn(p1, time.Second*time.Duration(config.Timeout))
				go func(conn net.Conn) {
					session := dialSessionForTCP()
					if session == nil {
						conn.Close()
						return
					}
					handleTunnelClient(session, p1, host, port)
				}(p1)
			}
		}

		for _, tunnel := range config.Tunnels {
			if tunnel.Type == "udp" {
				if config.UDPRelay != true {
					continue
				}
				go runUDPTunnelListener(tunnel)
			} else {
				go runTCPTunnelListener(tunnel)
			}
		}
		for {
			p1, err := listener.AcceptTCP()
			if err != nil {
				log.Fatalln(err)
			}
			checkError(err)
			go func(conn net.Conn) {
				defer conn.Close()
				conn = common.NewTimeoutConn(conn, time.Second*time.Duration(config.Timeout))

				session := dialSessionForTCP()
				if session == nil {
					return
				}

				target, _ := redir.GetOrigDst(conn)
				if (len(target) != 0 && target == conn.LocalAddr().String()) ||
					config.proxyAcceptor == nil {
					target = ""
				}

				if len(target) > 0 {
					host, port, err := utils.SplitHostAndPort(target)
					if err != nil {
						return
					}
					handleTunnelClient(session, conn, host, port)
				} else if config.proxyAcceptor != nil {
					handleProxyClient(session, conn, &config)
				} else {
					handleClient(session, conn)
				}
			}(p1)
		}
	}
	myApp.Run(os.Args)
}

type scavengeSession struct {
	session *smux.Session
	ts      time.Time
}

func scavenger(ch chan *smux.Session, ttl int) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var sessionList []scavengeSession
	for {
		select {
		case sess := <-ch:
			sessionList = append(sessionList, scavengeSession{sess, time.Now()})
			log.Println("session marked as expired")
		case <-ticker.C:
			var newList []scavengeSession
			for k := range sessionList {
				s := sessionList[k]
				if s.session.NumStreams() == 0 || s.session.IsClosed() {
					log.Println("session normally closed")
					s.session.Close()
				} else if ttl >= 0 && time.Since(s.ts) >= time.Duration(ttl)*time.Second {
					log.Println("session reached scavenge ttl")
					s.session.Close()
				} else {
					newList = append(newList, sessionList[k])
				}
			}
			sessionList = newList
		}
	}
}

func snmpLogger(path string, interval int) {
	if path == "" || interval == 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			f, err := os.OpenFile(time.Now().Format(path), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			if err != nil {
				log.Println(err)
				return
			}
			w := csv.NewWriter(f)
			// write header in empty file
			if stat, err := f.Stat(); err == nil && stat.Size() == 0 {
				if err := w.Write(append([]string{"Unix"}, kcp.DefaultSnmp.Header()...)); err != nil {
					log.Println(err)
				}
			}
			if err := w.Write(append([]string{fmt.Sprint(time.Now().Unix())}, kcp.DefaultSnmp.ToSlice()...)); err != nil {
				log.Println(err)
			}
			kcp.DefaultSnmp.Reset()
			w.Flush()
			f.Close()
		}
	}
}
