package xorex

import (
	"net"
	"time"
)

// Conn wraps a net.Conn and applies XOR to all bytes passing through.
type Conn struct {
	conn net.Conn
	key  []byte
}

func NewConn(conn net.Conn, key []byte) *Conn {
	return &Conn{
		conn: conn,
		key:  key,
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.conn.Read(b)
	if n > 0 {
		xorBytes(b[:n], c.key)
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	xored := make([]byte, len(b))
	copy(xored, b)
	xorBytes(xored, c.key)
	return c.conn.Write(xored)
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// xorBytes applies XOR with the given key cyclically.
func xorBytes(data, key []byte) {
	if len(key) == 0 {
		return
	}
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
}
