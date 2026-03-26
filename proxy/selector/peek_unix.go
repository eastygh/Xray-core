//go:build !windows

package selector

import (
	"errors"
	"syscall"
)

// recvfromPeek performs a non-consuming peek read from the socket fd.
func recvfromPeek(fd uintptr, buf []byte) (int, error) {
	n, _, err := syscall.Recvfrom(int(fd), buf, syscall.MSG_PEEK)
	return n, err
}

// isRetryable returns true if the error indicates the socket has no data yet.
func isRetryable(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
}
