package xoren

import (
	"io"
	"net"
	"testing"
	"time"
)

// discardConn is a net.Conn whose Write succeeds without doing anything,
// so the benchmark measures only the XOR + buffer-management cost.
type discardConn struct{}

func (discardConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (discardConn) Write(b []byte) (int, error)      { return len(b), nil }
func (discardConn) Close() error                     { return nil }
func (discardConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (discardConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (discardConn) SetDeadline(time.Time) error      { return nil }
func (discardConn) SetReadDeadline(time.Time) error  { return nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }

func benchWrite(b *testing.B, size int) {
	key := []byte{0x01, 0x02, 0x03, 0xFF}
	c := newXorConn(discardConn{}, key)
	payload := make([]byte, size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWrite_1KB(b *testing.B)  { benchWrite(b, 1024) }
func BenchmarkWrite_16KB(b *testing.B) { benchWrite(b, 16*1024) }
func BenchmarkWrite_64KB(b *testing.B) { benchWrite(b, 64*1024) }
