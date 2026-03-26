package selector

import (
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// peekBytes reads bytes from the connection's socket buffer using MSG_PEEK,
// which does NOT consume the data. Retries until at least minSize bytes are
// available or timeout expires. Subsequent Read() calls on the connection
// will return the same bytes.
func peekBytes(conn stat.Connection, maxSize int, minSize int, timeout time.Duration) ([]byte, error) {
	raw := unwrapRawConn(conn)

	sc, ok := raw.(syscall.Conn)
	if !ok {
		return nil, errors.New("connection does not support SyscallConn for peek")
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}

	// Set deadline so we don't wait forever for slow/dead clients
	raw.SetReadDeadline(time.Now().Add(timeout))
	defer raw.SetReadDeadline(time.Time{}) // clear deadline after peek

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
		// Timeout or error — return what we have
		if err != nil || peekErr != nil {
			if total > 0 {
				break // got some bytes, proceed with partial detection
			}
			if err != nil {
				return nil, errors.New("peek failed").Base(err)
			}
			return nil, errors.New("peek failed").Base(peekErr)
		}
		// Brief pause before retrying — data might still be arriving
		time.Sleep(5 * time.Millisecond)
	}

	return buf[:total], nil
}
