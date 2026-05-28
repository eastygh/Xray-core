package xoren

import (
	"net"
)

// xorConn wraps a net.Conn and applies a streaming XOR with a repeating key
// on every byte read from or written to the underlying connection.
type xorConn struct {
	net.Conn
	key      []byte
	readPos  int
	writePos int
}

func newXorConn(c net.Conn, key []byte) net.Conn {
	if len(key) == 0 {
		return c
	}
	return &xorConn{Conn: c, key: key}
}

func (c *xorConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		k := c.key
		klen := len(k)
		pos := c.readPos
		for i := 0; i < n; i++ {
			b[i] ^= k[pos]
			pos++
			if pos == klen {
				pos = 0
			}
		}
		c.readPos = pos
	}
	return n, err
}

func (c *xorConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return c.Conn.Write(b)
	}
	buf := make([]byte, len(b))
	k := c.key
	klen := len(k)
	pos := c.writePos
	for i, v := range b {
		buf[i] = v ^ k[pos]
		pos++
		if pos == klen {
			pos = 0
		}
	}
	n, err := c.Conn.Write(buf)
	if n > 0 {
		c.writePos = (c.writePos + n) % klen
	}
	return n, err
}
