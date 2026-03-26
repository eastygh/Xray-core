//go:build windows

package selector

import "syscall"

const (
	msgPeek        = 0x2   // Winsock MSG_PEEK
	wsaeWouldBlock = 10035 // Winsock WSAEWOULDBLOCK
)

// recvfromPeek performs a non-consuming peek read from the socket fd.
func recvfromPeek(fd uintptr, buf []byte) (int, error) {
	n, _, err := syscall.Recvfrom(syscall.Handle(fd), buf, msgPeek)
	return n, err
}

// isRetryable returns true if the error indicates the socket has no data yet.
func isRetryable(err error) bool {
	return err == syscall.Errno(wsaeWouldBlock)
}
