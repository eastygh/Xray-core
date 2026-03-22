package selector

import (
	"encoding/binary"
)

// DetectionResult holds the result of protocol detection on the first bytes of a connection.
type DetectionResult struct {
	IsTLS     bool
	HasECH    bool
	SNI       string
	IsMTProto bool
}

// Detect analyzes the first bytes of a connection and returns a DetectionResult.
func Detect(data []byte) DetectionResult {
	var result DetectionResult

	if len(data) == 0 {
		return result
	}

	// Check TLS: content type 0x16 (Handshake), valid version (3.x)
	if len(data) >= 5 && data[0] == 0x16 && data[1] == 3 {
		result.IsTLS = true
		headerLen := int(binary.BigEndian.Uint16(data[3:5]))
		if 5+headerLen <= len(data) {
			result.SNI, result.HasECH = parseClientHello(data[5 : 5+headerLen])
		} else if len(data) > 5 {
			// Partial ClientHello — parse what we have
			result.SNI, result.HasECH = parseClientHello(data[5:])
		}
		return result
	}

	// Check MTProto (heuristic): not TLS, not HTTP, >= 64 bytes, high entropy
	if len(data) >= 64 && !isHTTPMethod(data) && looksLikeMTProto(data) {
		result.IsMTProto = true
		return result
	}

	return result
}

// parseClientHello extracts SNI and detects ECH extension from a TLS ClientHello message.
// Based on common/protocol/tls/sniff.go but extended for ECH detection.
func parseClientHello(data []byte) (sni string, hasECH bool) {
	if len(data) < 42 {
		return
	}

	// data[0] = handshake type (1 = ClientHello)
	if data[0] != 1 {
		return
	}

	// Skip handshake header (4 bytes: type + length)
	// Skip client version (2 bytes) + random (32 bytes) = starts at offset 38
	if len(data) < 43 {
		return
	}

	sessionIDLen := int(data[38])
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		return
	}
	data = data[39+sessionIDLen:]

	if len(data) < 2 {
		return
	}

	// Cipher suites
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return
	}
	data = data[2+cipherSuiteLen:]

	if len(data) < 1 {
		return
	}

	// Compression methods
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return
	}
	data = data[1+compressionMethodsLen:]

	if len(data) < 2 {
		return
	}

	// Extensions
	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength > len(data) {
		extensionsLength = len(data)
	}
	data = data[:extensionsLength]

	for len(data) >= 4 {
		extType := uint16(data[0])<<8 | uint16(data[1])
		extLen := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if extLen > len(data) {
			break
		}

		switch extType {
		case 0x0000: // server_name (SNI)
			sni = parseSNI(data[:extLen])
		case 0xfe0d: // encrypted_client_hello (ECH)
			hasECH = true
		}

		data = data[extLen:]
	}

	return
}

// parseSNI extracts the hostname from a server_name extension.
func parseSNI(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	namesLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if namesLen > len(data) {
		namesLen = len(data)
	}
	data = data[:namesLen]

	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(data[1])<<8 | int(data[2])
		data = data[3:]
		if nameLen > len(data) {
			break
		}
		if nameType == 0 { // host_name
			return string(data[:nameLen])
		}
		data = data[nameLen:]
	}
	return ""
}

// isHTTPMethod checks if data starts with a common HTTP method.
func isHTTPMethod(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	// Check common HTTP methods
	switch {
	case len(data) >= 3 && string(data[:3]) == "GET":
		return true
	case len(data) >= 4 && string(data[:4]) == "POST":
		return true
	case len(data) >= 4 && string(data[:4]) == "HEAD":
		return true
	case len(data) >= 3 && string(data[:3]) == "PUT":
		return true
	case len(data) >= 6 && string(data[:6]) == "DELETE":
		return true
	case len(data) >= 7 && string(data[:7]) == "OPTIONS":
		return true
	case len(data) >= 7 && string(data[:7]) == "CONNECT":
		return true
	case len(data) >= 5 && string(data[:5]) == "PATCH":
		return true
	}
	return false
}

// looksLikeMTProto uses heuristics to detect MTProto obfuscated protocol.
// MTProto obfs2 sends 64 random-looking bytes as the initial handshake.
func looksLikeMTProto(data []byte) bool {
	if len(data) < 64 {
		return false
	}

	// Check that the first 56 bytes look random (high entropy).
	// Random data should not have many null bytes or long runs of the same byte.
	var nullCount int
	var maxRun int
	currentRun := 1

	for i := range 56 {
		if data[i] == 0 {
			nullCount++
		}
		if i > 0 && data[i] == data[i-1] {
			currentRun++
			if currentRun > maxRun {
				maxRun = currentRun
			}
		} else {
			currentRun = 1
		}
	}

	// Reject if too many null bytes or repeating patterns
	if nullCount > 8 {
		return false
	}
	if maxRun > 6 {
		return false
	}

	// MTProto header should not start with known protocol signatures
	// Already checked: not TLS (0x16), not HTTP methods
	// Additional check: not SOCKS5 (0x05), not SOCKS4 (0x04)
	if data[0] == 0x05 || data[0] == 0x04 {
		return false
	}

	return true
}
