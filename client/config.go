package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

// Config for client
type Config struct {
	LocalAddr      string `json:"localaddr"`
	RemoteAddr     string `json:"remoteaddr"`
	Key            string `json:"key"`
	Crypt          string `json:"crypt"`
	Mode           string `json:"mode"`
	Conn           int    `json:"conn"`
	AutoExpire     int    `json:"autoexpire"`
	MTU            int    `json:"mtu"`
	SndWnd         int    `json:"sndwnd"`
	RcvWnd         int    `json:"rcvwnd"`
	DataShard      int    `json:"datashard"`
	ParityShard    int    `json:"parityshard"`
	DSCP           int    `json:"dscp"`
	AckNodelay     bool   `json:"acknodelay"`
	NoDelay        int    `json:"nodelay"`
	Interval       int    `json:"interval"`
	Resend         int    `json:"resend"`
	NoCongestion   int    `json:"nc"`
	SockBuf        int    `json:"sockbuf"`
	KeepAlive      int    `json:"keepalive"`
	Log            string `json:"log"`
	SnmpLog        string `json:"snmplog"`
	SnmpPeriod     int    `json:"snmpperiod"`
	Obfs           string `json:"obfs"`
	Host           string `json:"host"`
	ScavengeTTL    int    `json:"scavengettl"`
	MulConn        int    `json:"mulconn"`
	UDP            bool   `json:"udp"`
	Pprof          string `json:"pprof"`
	NoDummpy       bool   `json:"nodummy"`
	ProxyList      string `json:"proxylist"`
	ChnRoute       string `json:"chnroute"`
	UDPRelay       bool   `json:"udprelay"`
	Proxy          bool   `json:"proxy"`
	Salt           string `json:"salt"`
	UDPViaKCP      bool   `json:"udpviakcp"`
	Timeout        int    `json:"timeout"`
	UDPTimeout     int    `json:"udp_timeout"`
	UDPDataShard   int    `json:"udp_datashard"`
	UDPParityShard int    `json:"udp_parityshard"`

	Tunnels []*tunnelConfig `json:"tunnels"`

	proxyAcceptor ss.Acceptor
	autoProxyCtx  *autoProxy
	chnRouteCtx   *chnRouteList
}

type tunnelConfig struct {
	Type       string `json:"type"` // tcp or udp
	LocalAddr  string `json:"localaddr"`
	RemoteAddr string `json:"remoteaddr"`
}

func parseJSONConfig(config *Config, path string) error {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(config)
}

func parsePluginOptionsFromEnv(config *Config) {
	pluginOptions := os.Getenv("SS_PLUGIN_OPTIONS")
	options := strings.Split(pluginOptions, ";")
	for _, option := range options {
		kv := strings.SplitN(option, "=", 2)
		k := kv[0]
		var v string
		if len(kv) > 1 {
			v = kv[1]
		}
		nv, _ := strconv.Atoi(v)
		switch k {
		case "localaddr":
			config.LocalAddr = v
		case "remoteaddr":
			config.RemoteAddr = v
		case "key":
			config.Key = v
		case "crypt":
			config.Crypt = v
		case "mode":
			config.Mode = v
		case "conn":
			config.Conn = nv
		case "autoexpire":
			config.AutoExpire = nv
		case "mtu":
			config.MTU = nv
		case "sndwnd":
			config.SndWnd = nv
		case "rcvwnd":
			config.RcvWnd = nv
		case "datashard":
			config.DataShard = nv
		case "parityshard":
			config.ParityShard = nv
		case "dscp":
			config.DSCP = nv
		case "acknodelay":
			config.AckNodelay = true
		case "nodelay":
			config.NoDelay = nv
		case "interval":
			config.Interval = nv
		case "resend":
			config.Resend = nv
		case "nc":
			config.NoCongestion = nv
		case "sockbuf":
			config.SockBuf = nv
		case "keepalive":
			config.KeepAlive = nv
		case "log":
			config.Log = v
		case "snmplog":
			config.SnmpLog = v
		case "snmpperiod":
			config.SnmpPeriod = nv
		case "obfs":
			config.Obfs = v
		case "host":
			config.Host = v
		case "scavengettl":
			config.ScavengeTTL = nv
		case "mulconn":
			config.MulConn = nv
		case "udp":
			config.UDP = true
		case "pprof":
			config.Pprof = v
		case "nodummy":
			config.NoDummpy = true
		case "proxylist":
			config.ProxyList = v
		case "chnroute":
			config.ChnRoute = v
		case "udprelay":
			config.UDPRelay = true
		case "proxy":
			config.Proxy = true
		case "salt":
			config.Salt = v
		case "udpviakcp":
			config.UDPViaKCP = true
		case "timeout":
			config.Timeout = nv
		case "udp_timeout":
			config.UDPTimeout = nv
		case "udp_datashard":
			config.UDPDataShard = nv
		case "udp_parityshard":
			config.ParityShard = nv
		}
	}
}

func parseConfigFromEnv(config *Config) {
	remoteHost := os.Getenv("SS_REMOTE_HOST")
	remotePort := os.Getenv("SS_REMOTE_PORT")
	localHost := os.Getenv("SS_LOCAL_HOST")
	localPort := os.Getenv("SS_LOCAL_PORT")
	if len(remoteHost) == 0 || len(remotePort) == 0 || len(localHost) == 0 || len(localPort) == 0 {
		return
	}
	config.LocalAddr = fmt.Sprintf("%v:%v", localHost, localPort)
	config.RemoteAddr = fmt.Sprintf("%v:%v", remoteHost, remotePort)
	parsePluginOptionsFromEnv(config)
}
