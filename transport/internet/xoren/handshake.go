package xoren

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// Handshake framing prepended to every xoren connection:
//
//	┌────────────┬──────────┬───────────────────────────────┐
//	│ nonce 8B   │ tag 8B   │ XOR stream (VLESS payload)     │
//	└────────────┴──────────┴───────────────────────────────┘
//
// tag and the per-connection stream key are both derived from a single
// HMAC-SHA256(key, nonce) (32B): tag = h[:8] is sent on the wire so a peer
// (xoren listener) or an upstream inbound (selector) holding the key can
// recognise the connection without forging it; streamKey = h[8:32] is the
// secret repeating-XOR key for the payload and is disjoint from the published
// tag, so revealing the tag never leaks keystream bytes.
//
// Because the nonce is random per connection, the first 16 bytes look like
// uniform noise and carry no static fingerprint, and the same VLESS header no
// longer produces an identical ciphertext prefix across connections.
const (
	nonceLen     = 8
	tagLen       = 8
	HandshakeLen = nonceLen + tagLen // bytes a peer must read/peek to authenticate
	streamKeyLen = sha256.Size - tagLen

	handshakeReadTimeout = 10 * time.Second
)

// deriveHandshake computes the wire tag and the per-connection stream key from
// key and nonce in a single HMAC pass.
func deriveHandshake(key, nonce []byte) (tag, streamKey []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	h := mac.Sum(nil) // 32B
	return h[:tagLen], h[tagLen : tagLen+streamKeyLen]
}

// clientHandshake generates a fresh nonce, writes the nonce||tag preamble to
// conn in the clear and returns the derived stream key for wrapping the rest of
// the connection.
func clientHandshake(conn net.Conn, key []byte) ([]byte, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("xoren: failed to generate nonce").Base(err)
	}
	tag, streamKey := deriveHandshake(key, nonce)

	preamble := make([]byte, 0, HandshakeLen)
	preamble = append(preamble, nonce...)
	preamble = append(preamble, tag...)
	if _, err := conn.Write(preamble); err != nil {
		return nil, errors.New("xoren: failed to write handshake").Base(err)
	}
	return streamKey, nil
}

// serverHandshake consumes the nonce||tag preamble from conn, authenticates it
// against key and returns the derived stream key. A mismatch (or any
// unauthenticated probe) yields an error so the caller can drop the connection.
func serverHandshake(conn net.Conn, key []byte) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeReadTimeout))
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, HandshakeLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, errors.New("xoren: failed to read handshake").Base(err)
	}
	wantTag, streamKey := deriveHandshake(key, buf[:nonceLen])
	if subtle.ConstantTimeCompare(buf[nonceLen:HandshakeLen], wantTag) != 1 {
		return nil, errors.New("xoren: handshake authentication failed")
	}
	return streamKey, nil
}

// VerifyHandshake reports whether peeked (the connection's first bytes, read
// non-destructively e.g. via MSG_PEEK) carries a valid xoren preamble for key.
// It is used by upstream inbounds such as the selector to detect xoren traffic
// without consuming any bytes.
func VerifyHandshake(peeked, key []byte) bool {
	if len(key) == 0 || len(peeked) < HandshakeLen {
		return false
	}
	wantTag, _ := deriveHandshake(key, peeked[:nonceLen])
	return subtle.ConstantTimeCompare(peeked[nonceLen:HandshakeLen], wantTag) == 1
}
