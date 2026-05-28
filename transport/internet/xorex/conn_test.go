package xorex

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type testConn struct {
	net.Conn
	rbuf bytes.Buffer
	wbuf bytes.Buffer
}

func (c *testConn) Read(b []byte) (int, error)         { return c.rbuf.Read(b) }
func (c *testConn) Write(b []byte) (int, error)        { return c.wbuf.Write(b) }
func (c *testConn) Close() error                       { return nil }
func (c *testConn) LocalAddr() net.Addr                { return nil }
func (c *testConn) RemoteAddr() net.Addr               { return nil }
func (c *testConn) SetDeadline(t time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(t time.Time) error { return nil }

func TestXorBytes(t *testing.T) {
	key := []byte{0x55}
	data := []byte{0x00, 0xFF, 0xAA, 0x55}
	expected := []byte{0x55, 0xAA, 0xFF, 0x00}
	xorBytes(data, key)
	for i := range data {
		if data[i] != expected[i] {
			t.Errorf("byte %d: got %02x, want %02x", i, data[i], expected[i])
		}
	}
}

func TestXorBytesCycle(t *testing.T) {
	key := []byte{0xAA, 0x55}
	data := []byte{0x00, 0x00, 0x00, 0x00}
	expected := []byte{0xAA, 0x55, 0xAA, 0x55}
	xorBytes(data, key)
	for i := range data {
		if data[i] != expected[i] {
			t.Errorf("byte %d: got %02x, want %02x", i, data[i], expected[i])
		}
	}
}

func TestXorBytesDoubleXor(t *testing.T) {
	key := []byte{0x7F}
	original := []byte("Hello, World! This is a test.")
	data := make([]byte, len(original))
	copy(data, original)
	xorBytes(data, key)
	xorBytes(data, key)
	if !bytes.Equal(data, original) {
		t.Error("double XOR should return original")
	}
}

func TestConnRead(t *testing.T) {
	key := []byte{0x42}
	original := []byte("test data")
	encrypted := make([]byte, len(original))
	copy(encrypted, original)
	xorBytes(encrypted, key)

	tc := &testConn{}
	tc.rbuf.Write(encrypted)

	conn := NewConn(tc, key)
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], original) {
		t.Errorf("Read: got %v, want %v", buf[:n], original)
	}
}

func TestConnWrite(t *testing.T) {
	key := []byte{0x42}
	original := []byte("test data")

	tc := &testConn{}
	conn := NewConn(tc, key)
	_, err := conn.Write(original)
	if err != nil {
		t.Fatal(err)
	}

	expected := make([]byte, len(original))
	copy(expected, original)
	xorBytes(expected, key)

	if !bytes.Equal(tc.wbuf.Bytes(), expected) {
		t.Errorf("Write: got %v, want %v", tc.wbuf.Bytes(), expected)
	}
}

func TestConnReadWrite(t *testing.T) {
	key := []byte{0x99}
	original := []byte("Hello XOR transport!")

	// Simulate: client encrypts on write, server decrypts on read
	clientConn := &testConn{}
	serverConn := &testConn{}

	// Client writes (XOR applied on write)
	client := NewConn(clientConn, key)
	client.Write(original)

	// "Network" transfers bytes from client to server
	serverConn.rbuf.Write(clientConn.wbuf.Bytes())

	// Server reads (XOR applied on read)
	server := NewConn(serverConn, key)
	buf := make([]byte, 1024)
	n, _ := server.Read(buf)

	if !bytes.Equal(buf[:n], original) {
		t.Errorf("round trip: got %v, want %v", buf[:n], original)
	}
}
