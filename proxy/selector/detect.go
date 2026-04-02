package selector

import (
	"encoding/binary"
)

// DetectionResult holds protocol detection results.
type DetectionResult struct {
	IsTLS     bool
	HasECH    bool
	SNI       string
	IsMTProto bool
}

// Detect analyzes first bytes of a connection to identify the protocol.
func Detect(data []byte) DetectionResult {
	var result DetectionResult

	if len(data) == 0 {
		return result
	}

	// TLS: content type 0x16 (Handshake), version 3.x
	if len(data) >= 5 && data[0] == 0x16 && data[1] == 3 {
		result.IsTLS = true
		headerLen := int(binary.BigEndian.Uint16(data[3:5]))
		if 5+headerLen <= len(data) {
			result.SNI, result.HasECH = parseClientHello(data[5 : 5+headerLen])
		} else if len(data) > 5 {
			result.SNI, result.HasECH = parseClientHello(data[5:])
		}
		return result
	}

	// MTProto: not TLS, not HTTP, 64+ random-looking bytes
	if len(data) >= 64 && !isHTTPMethod(data) && looksLikeMTProto(data) {
		result.IsMTProto = true
		return result
	}

	return result
}

// parseClientHello extracts SNI and detects ECH from a TLS ClientHello.
func parseClientHello(data []byte) (sni string, hasECH bool) {
	if len(data) < 42 || data[0] != 1 {
		return
	}

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

	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return
	}
	data = data[2+cipherSuiteLen:]

	if len(data) < 1 {
		return
	}

	compressionLen := int(data[0])
	if len(data) < 1+compressionLen {
		return
	}
	data = data[1+compressionLen:]

	if len(data) < 2 {
		return
	}

	extLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extLen > len(data) {
		extLen = len(data)
	}
	data = data[:extLen]

	for len(data) >= 4 {
		extType := uint16(data[0])<<8 | uint16(data[1])
		extDataLen := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if extDataLen > len(data) {
			break
		}

		switch extType {
		case 0x0000: // server_name
			sni = parseSNI(data[:extDataLen])
		case 0xfe0d: // encrypted_client_hello
			hasECH = true
		}

		data = data[extDataLen:]
	}

	return
}

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
		if nameType == 0 {
			return string(data[:nameLen])
		}
		data = data[nameLen:]
	}
	return ""
}

func isHTTPMethod(data []byte) bool {
	if len(data) < 3 {
		return false
	}
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

// looksLikeMTProto uses heuristics to detect MTProto obfuscated handshake:
// 64 bytes of high-entropy data, no known protocol signature.
func looksLikeMTProto(data []byte) bool {
	if len(data) < 64 {
		return false
	}

	var nullCount, maxRun, currentRun int
	currentRun = 1

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

	if nullCount > 8 || maxRun > 6 {
		return false
	}

	// Not SOCKS4/5
	if data[0] == 0x05 || data[0] == 0x04 {
		return false
	}

	return true
}
