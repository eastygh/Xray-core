package peek_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/peek"
	"github.com/xtls/xray-core/common/protocol/tls"
)

// buildClientHello assembles a syntactically valid TLS ClientHello record
// carrying the given SNI. A TLS "padding" extension (RFC 7685, type 21) of
// padLen bytes is appended after server_name to inflate the record without
// affecting SNI parsing — useful for exercising large-ClientHello handling.
func buildClientHello(sni string, padLen int) []byte {
	name := []byte(sni)

	// server_name extension payload: list_len(2) + [type(1) + name_len(2) + name]
	entry := append([]byte{0x00, byte(len(name) >> 8), byte(len(name))}, name...)
	sniExtData := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)

	ext := append([]byte{0x00, 0x00, byte(len(sniExtData) >> 8), byte(len(sniExtData))}, sniExtData...)
	if padLen > 0 {
		ext = append(ext, 0x00, 0x15, byte(padLen>>8), byte(padLen))
		ext = append(ext, make([]byte, padLen)...)
	}

	var body []byte
	body = append(body, 0x03, 0x03)             // client_version TLS 1.2
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id length 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: len 2 + TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression_methods: len 1 + null
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec
}

// newPeekConn returns the server side of a loopback TCP connection that already
// has data buffered from the client, plus a cleanup func. A real socket (not
// net.Pipe) is required because peek relies on MSG_PEEK via SyscallConn.
func newPeekConn(t *testing.T, data []byte) (net.Conn, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialResult, 1)
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			_, err = c.Write(data)
		}
		ch <- dialResult{c, err}
	}()

	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("client setup failed: %v", r.err)
	}

	cleanup := func() {
		server.Close()
		if r.conn != nil {
			r.conn.Close()
		}
		ln.Close()
	}
	return server, cleanup
}

func TestSNIExtractsDomain(t *testing.T) {
	hello := buildClientHello("example.com", 0)
	conn, cleanup := newPeekConn(t, hello)
	defer cleanup()

	got, err := peek.SNI(conn, 16389, 5, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	h, err := tls.SniffTLS(got)
	if err != nil {
		t.Fatalf("SniffTLS failed: %v", err)
	}
	if h.Domain() != "example.com" {
		t.Fatalf("domain = %q, want example.com", h.Domain())
	}
}

// TestSNILargeClientHello is the regression test for the truncation bug:
// ClientHellos with post-quantum key shares exceed the old 2048 cap. With a
// buffer large enough for the full record the SNI is recovered; with a 2048
// cap the record is truncated and SniffTLS cannot find it — which is exactly
// why defaultReadSize was raised.
func TestSNILargeClientHello(t *testing.T) {
	hello := buildClientHello("pq.example.com", 3000) // record ~3 KB > 2048
	if len(hello) <= 2048 {
		t.Fatalf("test fixture too small: %d bytes", len(hello))
	}

	t.Run("large buffer recovers SNI", func(t *testing.T) {
		conn, cleanup := newPeekConn(t, hello)
		defer cleanup()

		got, err := peek.SNI(conn, 16389, 254, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		h, err := tls.SniffTLS(got)
		if err != nil {
			t.Fatalf("SniffTLS failed on full record: %v", err)
		}
		if h.Domain() != "pq.example.com" {
			t.Fatalf("domain = %q, want pq.example.com", h.Domain())
		}
	})

	t.Run("small buffer truncates", func(t *testing.T) {
		conn, cleanup := newPeekConn(t, hello)
		defer cleanup()

		got, err := peek.SNI(conn, 2048, 254, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) > 2048 {
			t.Fatalf("peek returned %d bytes, expected cap at 2048", len(got))
		}
		if _, err := tls.SniffTLS(got); err == nil {
			t.Fatal("expected SniffTLS to fail on a truncated record")
		}
	})
}

func TestSNIDoesNotConsume(t *testing.T) {
	hello := buildClientHello("keep.example.com", 0)
	conn, cleanup := newPeekConn(t, hello)
	defer cleanup()

	peeked, err := peek.SNI(conn, 16389, 5, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// A real read must still see the same bytes the peek observed.
	buf := make([]byte, len(peeked))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, peeked) {
		t.Fatal("bytes read after peek differ from peeked bytes")
	}
}

// TestSNINonTLS covers the non-TLS path (e.g. the xoren preamble): the record
// header detection never triggers, so peek collects up to minSize bytes and
// SniffTLS reports it is not a TLS handshake.
func TestSNINonTLS(t *testing.T) {
	data := bytes.Repeat([]byte{0xAB}, 300)
	conn, cleanup := newPeekConn(t, data)
	defer cleanup()

	got, err := peek.SNI(conn, 16389, 254, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 254 {
		t.Fatalf("peek returned %d bytes, want >= minSize 254", len(got))
	}
	if _, err := tls.SniffTLS(got); err == nil {
		t.Fatal("expected SniffTLS to reject non-TLS bytes")
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
