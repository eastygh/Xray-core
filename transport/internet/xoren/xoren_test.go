package xoren_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	. "github.com/xtls/xray-core/transport/internet/xoren"
)

func TestListenXORENAndDial(t *testing.T) {
	port := tcp.PickPort()
	key := []byte{0x01, 0x02, 0x03, 0xFF}

	listen, err := ListenXOREN(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName:     "xoren",
		ProtocolSettings: &Config{Key: key},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()
			var b [1024]byte
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := c.Read(b[:])
			if err != nil {
				return
			}
			if !bytes.Equal(b[:n], []byte("ping")) {
				t.Errorf("server got %q, want %q", b[:n], "ping")
				return
			}
			common.Must2(c.Write([]byte("pong")))
		}(conn)
	})
	common.Must(err)
	defer listen.Close()

	conn, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, port), &internet.MemoryStreamConfig{
		ProtocolName:     "xoren",
		ProtocolSettings: &Config{Key: key},
	})
	common.Must(err)
	defer conn.Close()

	common.Must2(conn.Write([]byte("ping")))

	var b [1024]byte
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "pong" {
		t.Fatalf("client got %q, want %q", b[:n], "pong")
	}
}

func TestDialFailsOnKeyMismatch(t *testing.T) {
	port := tcp.PickPort()

	listen, err := ListenXOREN(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName:     "xoren",
		ProtocolSettings: &Config{Key: []byte{0xAA}},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()
			var b [16]byte
			c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _ := c.Read(b[:])
			// Server XORs with 0xAA, client XORs with 0xBB:
			// "ping" -> wire bytes XORed with 0xBB -> server decodes with 0xAA -> garbage.
			if bytes.Equal(b[:n], []byte("ping")) {
				t.Errorf("server unexpectedly decoded plaintext with wrong key")
			}
		}(conn)
	})
	common.Must(err)
	defer listen.Close()

	conn, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, port), &internet.MemoryStreamConfig{
		ProtocolName:     "xoren",
		ProtocolSettings: &Config{Key: []byte{0xBB}},
	})
	common.Must(err)
	defer conn.Close()

	common.Must2(conn.Write([]byte("ping")))
	time.Sleep(100 * time.Millisecond)
}
