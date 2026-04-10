package selector

import (
	"encoding/binary"
	"net"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// peekBytes reads up to maxSize bytes from the socket buffer using MSG_PEEK
// without consuming them. Retries until at least minSize bytes arrive or
// timeout expires.
func peekBytes(conn stat.Connection, maxSize int, minSize int, timeout time.Duration) ([]byte, error) {
	raw := stat.TryUnwrapStatsConn(conn)

	sc, ok := raw.(syscall.Conn)
	if !ok {
		return nil, errors.New("connection does not support SyscallConn")
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}

	raw.(net.Conn).SetReadDeadline(time.Now().Add(timeout))
	defer raw.(net.Conn).SetReadDeadline(time.Time{})

	buf := make([]byte, maxSize)
	var total int

	for total < minSize {
		var n int
		var peekErr error

		err = rawConn.Read(func(fd uintptr) bool {
			n, peekErr = recvfromPeek(fd, buf)
			return !isRetryable(peekErr)
		})

		if n > total {
			total = n
		}
		if total >= minSize {
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

// peek bytes from TLS handshake while SNI is not available
// peekBytes reads up to maxSize bytes from the socket buffer using MSG_PEEK
// without consuming them. Retries until at least minSize bytes arrive or
// timeout expires.
func peekSNI(conn stat.Connection, maxSize int, minSize int, timeout time.Duration) ([]byte, error) {
	raw := stat.TryUnwrapStatsConn(conn)

	sc, ok := raw.(syscall.Conn)
	if !ok {
		return nil, errors.New("connection does not support SyscallConn")
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}

	raw.(net.Conn).SetReadDeadline(time.Now().Add(timeout))
	defer raw.(net.Conn).SetReadDeadline(time.Time{})

	buf := make([]byte, maxSize)
	var total int

	targetSize := minSize

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

		if total >= 5 && targetSize == minSize {
			if buf[0] == 0x16 && buf[1] == 3 {
				recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
				expectedTotal := 5 + recordLen

				if expectedTotal > targetSize && expectedTotal <= maxSize {
					targetSize = expectedTotal
				}
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
