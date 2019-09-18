package common

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/ccsexyz/utils"
	kcp "github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

func NewBlockCrypt(key, salt []byte, method string) kcp.BlockCrypt {
	pass := pbkdf2.Key(key, salt, 4096, 32, sha1.New)
	var block kcp.BlockCrypt
	switch method {
	case "sm4":
		block, _ = kcp.NewSM4BlockCrypt(pass[:16])
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	case "chacha20":
		block, _ = utils.NewChaCha20BlockCrypt(pass)
	default:
		block, _ = kcp.NewAESBlockCrypt(pass)
	}
	return block
}

func NewHMAC(key, salt []byte) hash.Hash {
	key = append(key, salt...)
	key = append(key, []byte("udp")...)
	return hmac.New(md5.New, key)
}

type pktConn struct {
	net.Conn
}

func (conn *pktConn) Read(b []byte) (n int, err error) {
	var l [2]byte
	_, err = io.ReadFull(conn.Conn, l[:2])
	if err != nil {
		return
	}
	expectedLength := int(binary.BigEndian.Uint16(l[:]))
	if len(b) < expectedLength {
		buf := utils.GetBuf(expectedLength)
		defer utils.PutBuf(buf)
		_, err = io.ReadFull(conn.Conn, buf)
		if err != nil {
			return
		}
		n = copy(b, buf)
		return
	}
	b = b[:expectedLength]
	return io.ReadFull(conn.Conn, b)
}

func (conn *pktConn) Write(b []byte) (n int, err error) {
	if len(b) > 65535 {
		return 0, io.ErrShortBuffer
	}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(b)))
	_, err = conn.Conn.Write(l[:2])
	if err != nil {
		return
	}
	return conn.Conn.Write(b)
}

func NewPktConn(conn net.Conn) net.Conn {
	return &pktConn{Conn: conn}
}

type timeoutConn struct {
	net.Conn
	d time.Duration
}

func (conn *timeoutConn) Read(b []byte) (n int, err error) {
	err = conn.Conn.SetReadDeadline(time.Now().Add(conn.d))
	if err == nil {
		n, err = conn.Conn.Read(b)
	}
	return
}

func (conn *timeoutConn) Write(b []byte) (n int, err error) {
	err = conn.Conn.SetWriteDeadline(time.Now().Add(conn.d))
	if err == nil {
		n, err = conn.Conn.Write(b)
	}
	return
}

func NewTimeoutConn(c net.Conn, d time.Duration) net.Conn {
	return &timeoutConn{Conn: c, d: d}
}

type hdrConn struct {
	net.Conn
	hdr []byte
}

func (conn *hdrConn) Write(b []byte) (n int, err error) {
	if len(conn.hdr) == 0 {
		return conn.Conn.Write(b)
	}
	buf := utils.GetBuf(len(conn.hdr) + len(b))
	defer utils.PutBuf(buf)
	copy(buf, conn.hdr)
	n = copy(buf[len(conn.hdr):], b)
	_, err = conn.Conn.Write(buf)
	if err != nil {
		n = 0
	}
	return
}

func (conn *hdrConn) Read(b []byte) (n int, err error) {
	if len(conn.hdr) == 0 {
		return conn.Conn.Read(b)
	}
AGAIN:
	n, err = conn.Conn.Read(b)
	if err != nil {
		return
	}
	if n < len(conn.hdr) {
		goto AGAIN
	}
	n = copy(b, b[len(conn.hdr):n])
	return
}

func NewHdrConn(c net.Conn, hdr []byte) net.Conn {
	return &hdrConn{Conn: c, hdr: hdr}
}

type addrConn struct {
	net.Conn
	zero   [16]byte
	addr   []byte
	ok     bool
	random bool
}

func (conn *addrConn) Write(b []byte) (n int, err error) {
	n = len(b) + 1 + len(conn.addr)
	buf := utils.GetBuf(n)
	defer utils.PutBuf(buf)
	buf[0] = byte(len(conn.addr))
	copy(buf[1:], conn.addr)
	copy(buf[1+len(conn.addr):], b)
	_, err = conn.Conn.Write(buf[:n])
	if err != nil {
		n = 0
	}
	n = len(b)
	if conn.ok {
		if conn.random {
			r := rand.Intn(len(conn.zero))
			conn.addr = conn.zero[:r]
		} else {
			conn.addr = nil
		}
	}
	return
}

func (conn *addrConn) Read(b []byte) (n int, err error) {
	n, err = conn.Conn.Read(b)
	if err != nil || n == 0 {
		return
	}
	h := 1 + int(b[0])
	if n < h {
		err = io.ErrShortBuffer
		return
	}
	n = copy(b, b[h:n])
	conn.ok = true
	return
}

func NewAddrConn(c net.Conn, addr []byte, random bool) net.Conn {
	return &addrConn{Conn: c, addr: addr, random: random, ok: false}
}

func Pipe(p1, p2 net.Conn, b1, b2 []byte) {
	p1die := make(chan struct{})
	p2die := make(chan struct{})
	f := func(dst, src net.Conn, buf []byte, die chan struct{}) {
		var n, nw int
		var err error
		defer close(die)
		for err == nil {
			n, err = src.Read(buf)
			if n > 0 || err == nil {
				nw, err = dst.Write(buf[:n])
				if err == nil && nw != n {
					err = io.ErrShortWrite
				}
			}
		}
	}
	go f(p1, p2, b1, p1die)
	go f(p2, p1, b2, p2die)
	select {
	case <-p1die:
	case <-p2die:
	}
}
