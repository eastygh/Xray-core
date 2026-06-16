// Package peek reads bytes from a TCP socket without consuming them, so the
// caller can inspect early protocol data (e.g. TLS ClientHello) and still hand
// the connection downstream unchanged. Uses MSG_PEEK on Unix and the Winsock
// equivalent on Windows.
package peek

import (
	"encoding/binary"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// SNI behaves like Bytes but, once a TLS record header has arrived, grows the
// target read size to cover the full ClientHello record so the SNI extension
// can be parsed without further reads.
func SNI(conn stat.Connection, maxSize int, minSize int, timeout time.Duration) ([]byte, error) {
	raw := stat.TryUnwrapStatsConn(conn)

	sc, ok := raw.(syscall.Conn)
	if !ok {
		return nil, errors.New("connection does not support SyscallConn")
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}

	raw.SetReadDeadline(time.Now().Add(timeout))
	defer raw.SetReadDeadline(time.Time{})

	buf := make([]byte, maxSize)
	var total int

	targetSize := minSize
	recordSized := false

	for {
		var n int
		var peekErr error

		err = rawConn.Read(func(fd uintptr) bool {
			n, peekErr = recvfromPeek(fd, buf)
			return !isRetryable(peekErr)
		})

		if n > total {
			total = n
		}

		// if we have a TLS record header, grow the target size to cover the full
		if total >= 5 && !recordSized {
			// check if this is a TLS ClientHello record (probably)
			if buf[0] == 0x16 && buf[1] == 3 {
				recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
				targetSize = min(5+recordLen, maxSize)
				recordSized = true
			}
		}

		if total >= targetSize {
			break
		}

		if err != nil || peekErr != nil {
			if total > 0 {
				break
			}
			if err != nil {
				return nil, errors.New("peek failed").Base(err)
			}
			return nil, errors.New("peek failed").Base(peekErr)
		}
		time.Sleep(5 * time.Millisecond)
	}

	return buf[:total], nil
}
