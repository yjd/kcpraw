package main

import (
	"crypto/hmac"
	"fmt"
	"hash"
	"net"
	"sync"
	"time"

	"github.com/ccsexyz/utils"
	kcp "github.com/xtaci/kcp-go"
)

const (
	nonceSize = 16
)

type divSess struct {
	bypass  bool
	ts      time.Time
	addrstr string
}

type bpBuf struct {
	buf  []byte
	from net.Addr
}

type divConn struct {
	net.PacketConn
	die      chan struct{}
	lock     sync.Mutex
	sessions sync.Map
	bp       *bpConn
	mac      hash.Hash
	mtu      int
	lastsess *divSess
}

func newDivConn(p net.PacketConn, block kcp.BlockCrypt, mac hash.Hash, mtu int) *divConn {
	div := new(divConn)
	div.PacketConn = p
	div.die = make(chan struct{})
	div.mtu = mtu
	div.mac = mac
	bp := new(bpConn)
	bp.divConn = div
	div.bp = bp
	bp.packets = make(chan bpBuf, 1024)
	bp.block = block
	return div
}

func (div *divConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
AGAIN:
	n, addr, err = 0, nil, nil
	n, addr, err = div.PacketConn.ReadFrom(b)
	if err != nil {
		return
	}
	if n < div.mac.Size() {
		goto AGAIN
	}
	addrstr := addr.String()
	var sess *divSess
	if div.lastsess != nil && div.lastsess.addrstr == addrstr {
		sess = div.lastsess
	} else {
		v, ok := div.sessions.Load(addrstr)
		if ok {
			sess = v.(*divSess)
		} else {
			sess = &divSess{
				ts:      time.Now(),
				addrstr: addrstr,
			}
			_, ok := div.check(b[:n])
			if ok {
				sess.bypass = true
			} else {
				sess.bypass = false
			}
			div.sessions.Store(addrstr, sess)
		}
		div.lastsess = sess
	}
	if sess.bypass {
		msg := b[:n-div.mac.Size()]
		div.bp.input(msg, addr)
		goto AGAIN
	}
	return
}

func (div *divConn) check(b []byte) ([]byte, bool) {
	n := len(b)
	if n < div.mac.Size() {
		return nil, false
	}
	msg := b[:n-div.mac.Size()]
	msgMAC := b[n-div.mac.Size():]
	div.lock.Lock()
	div.mac.Write(msg)
	expectedMAC := div.mac.Sum(nil)
	div.mac.Reset()
	div.lock.Unlock()
	if hmac.Equal(msgMAC, expectedMAC) {
		return msg, true
	}
	return nil, false
}

func (div *divConn) Close() error {
	div.lock.Lock()
	defer div.lock.Unlock()
	select {
	case <-div.die:
	default:
		close(div.die)
	}
	return div.PacketConn.Close()
}

func (div *divConn) bypass() *bpConn {
	return div.bp
}

type bpConn struct {
	*divConn
	packets chan bpBuf
	rtimer  time.Timer
	block   kcp.BlockCrypt
}

func (bp *bpConn) input(b []byte, from net.Addr) {
	b2 := utils.CopyBuffer(b)
	select {
	case <-bp.divConn.die:
		utils.PutBuf(b2)
	case bp.packets <- bpBuf{buf: b2, from: from}:
	}
}

func (bp *bpConn) SetReadDeadline(t time.Time) (err error) {
	bp.rtimer.Reset(t.Sub(time.Now()))
	return nil
}

func (bp *bpConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	select {
	case buf := <-bp.packets:
		bp.block.Decrypt(buf.buf, buf.buf)
		n = copy(b, buf.buf[nonceSize:])
		addr = buf.from
		utils.PutBuf(buf.buf)
		return n, addr, nil
	case <-bp.die:
		return 0, nil, fmt.Errorf("read from closed bpConn")
	case <-bp.rtimer.C:
		return 0, nil, fmt.Errorf("bpConn timeout")
	}
}

func (bp *bpConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	buf := utils.GetBuf(len(b) + nonceSize)
	defer utils.PutBuf(buf)
	utils.PutRandomBytes(buf[:nonceSize])
	copy(buf[nonceSize:], b)
	bp.block.Encrypt(buf, buf)
	_, err = bp.PacketConn.WriteTo(buf, addr)
	if err != nil {
		return
	}
	n = len(b)
	return
}
