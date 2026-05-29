package xoren

import (
	"bytes"
	"crypto/subtle"
	"net"
)

// xorChunkSize is the maximum chunk passed to subtle.XORBytes in one call.
// 4KiB amortizes the per-call overhead while staying inside L1 on every
// platform we care about.
const xorChunkSize = 4096

// xorConn wraps a net.Conn and applies a streaming XOR with a repeating key
// on every byte read from or written to the underlying connection.
type xorConn struct {
	net.Conn
	keyLen   int
	extKey   []byte // key repeated so extKey[pos:pos+xorChunkSize] is always in range
	wbuf     []byte // scratch buffer for Write, grown on demand
	readPos  int    // [0, keyLen)
	writePos int    // [0, keyLen)
}

func newXorConn(c net.Conn, key []byte) net.Conn {
	if len(key) == 0 {
		return c
	}
	keyLen := len(key)
	// Repeat the key enough times that extKey[pos:pos+xorChunkSize] is valid
	// for any pos in [0, keyLen). The +1 covers the worst case where keyLen
	// does not divide xorChunkSize.
	reps := (xorChunkSize+keyLen-1)/keyLen + 1
	return &xorConn{
		Conn:   c,
		keyLen: keyLen,
		extKey: bytes.Repeat(key, reps),
	}
}

func (c *xorConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.readPos = c.xorStream(b[:n], b[:n], c.readPos)
	}
	return n, err
}

func (c *xorConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return c.Conn.Write(b)
	}
	if cap(c.wbuf) < len(b) {
		c.wbuf = make([]byte, len(b))
	} else {
		c.wbuf = c.wbuf[:len(b)]
	}
	startPos := c.writePos
	c.writePos = c.xorStream(c.wbuf, b, startPos)
	n, err := c.Conn.Write(c.wbuf)
	if n < len(b) {
		// Underlying conn accepted only n bytes. Roll the keystream back so it
		// stays in sync with the peer's reader; the caller will resend b[n:],
		// which will then be encoded starting at the right offset.
		c.writePos = (startPos + n) % c.keyLen
	}
	return n, err
}

// xorStream XORs src into dst using the keystream starting at pos and returns
// the next keystream offset modulo keyLen.
func (c *xorConn) xorStream(dst, src []byte, pos int) int {
	for len(src) > 0 {
		n := len(src)
		if n > xorChunkSize {
			n = xorChunkSize
		}
		subtle.XORBytes(dst[:n], src[:n], c.extKey[pos:pos+n])
		pos += n
		if pos >= c.keyLen {
			pos %= c.keyLen
		}
		src = src[n:]
		dst = dst[n:]
	}
	return pos
}
