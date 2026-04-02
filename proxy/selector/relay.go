package selector

import (
	"context"
	"net"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const relayIdleTimeout = 5 * 60 // seconds

func loopbackRelay(ctx context.Context, clientConn stat.Connection, targetAddr string, ppVersion uint32) error {
	var d net.Dialer
	serverConn, err := d.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return errors.New("failed to dial loopback ", targetAddr).Base(err)
	}
	defer serverConn.Close()

	if ppVersion > 0 && ppVersion <= 2 {
		header := proxyproto.HeaderProxyFromAddrs(byte(ppVersion), clientConn.RemoteAddr(), clientConn.LocalAddr())
		if _, err := header.WriteTo(serverConn); err != nil {
			return errors.New("failed to write PROXY protocol v", ppVersion, " header").Base(err)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, relayIdleTimeout)

	requestDone := func() error {
		defer timer.SetTimeout(relayIdleTimeout)
		if err := buf.Copy(buf.NewReader(clientConn), buf.NewWriter(serverConn), buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to relay request").Base(err)
		}
		// Half-close: signal EOF to the target handler so it can finish its response
		if tc, ok := serverConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		return nil
	}
	responseDone := func() error {
		defer timer.SetTimeout(relayIdleTimeout)
		if err := buf.Copy(buf.NewReader(serverConn), buf.NewWriter(clientConn), buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to relay response").Base(err)
		}
		return nil
	}

	if err := task.Run(ctx, requestDone, responseDone); err != nil {
		return errors.New("relay connection ends").Base(err)
	}
	return nil
}
