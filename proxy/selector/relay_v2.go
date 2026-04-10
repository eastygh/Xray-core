package selector

import (
	"context"
	"io"
	"net"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func loopbackRelayV2(ctx context.Context, clientConn stat.Connection, targetAddr string, ppVersion uint32) error {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	serverConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return errors.New("failed to dial loopback ", targetAddr).Base(err)
	}
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	enableKeepAlive(serverConn)
	enableKeepAlive(clientConn)

	// PROXY protocol
	if ppVersion > 0 && ppVersion <= 2 {
		_ = serverConn.SetWriteDeadline(time.Now().Add(5 * time.Second))

		header := proxyproto.HeaderProxyFromAddrs(
			byte(ppVersion),
			clientConn.RemoteAddr(),
			clientConn.LocalAddr(),
		)

		if _, err := header.WriteTo(serverConn); err != nil {
			return errors.New("failed to write PROXY protocol v", ppVersion, " header").Base(err)
		}

		_ = serverConn.SetWriteDeadline(time.Time{}) // reset deadline
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	timer := signal.CancelAfterInactivity(ctx, cancel, relayIdleTimeout)

	requestDone := func() error {
		err := buf.Copy(
			buf.NewReader(clientConn),
			buf.NewWriter(serverConn),
			buf.UpdateActivity(timer),
		)

		if err != nil && err != io.EOF {
			return errors.New("failed to relay request").Base(err)
		}

		closeWrite(serverConn)
		return nil
	}

	responseDone := func() error {
		err := buf.Copy(
			buf.NewReader(serverConn),
			buf.NewWriter(clientConn),
			buf.UpdateActivity(timer),
		)

		if err != nil && err != io.EOF {
			return errors.New("failed to relay response").Base(err)
		}

		closeWrite(clientConn)
		return nil
	}

	if err := task.Run(ctx, requestDone, responseDone); err != nil {
		return errors.New("relay connection ends").Base(err)
	}

	return nil
}

func enableKeepAlive(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

func closeWrite(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}
