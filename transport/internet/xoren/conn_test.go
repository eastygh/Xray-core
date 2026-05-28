package xoren

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestXorConnRoundTrip(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03, 0xFF}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	serverConn := newXorConn(server, key)
	clientConn := newXorConn(client, key)

	payload := []byte("hello, xoren! a longer-than-key payload to force key wraparound")

	errCh := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(payload)
		errCh <- err
	}()

	got := make([]byte, len(payload))
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("write: %v", err)
	}

	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch:\n got: %q\nwant: %q", got, payload)
	}
}

func TestXorConnNotPlaintextOnWire(t *testing.T) {
	key := []byte{0xAB, 0xCD}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	writer := newXorConn(a, key)
	payload := []byte{0x00, 0x00, 0x00, 0x00}

	go func() { writer.Write(payload) }()

	wire := make([]byte, len(payload))
	if err := b.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(b, wire); err != nil {
		t.Fatal(err)
	}

	want := []byte{0xAB, 0xCD, 0xAB, 0xCD}
	if !bytes.Equal(wire, want) {
		t.Fatalf("wire bytes: got % X, want % X", wire, want)
	}
}
