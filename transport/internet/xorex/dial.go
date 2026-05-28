package xorex

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Dial dials a new TCP connection to the given destination and wraps it with XOR.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "xorex: dialing TCP to ", dest)
	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	if streamSettings.TcpmaskManager != nil {
		newConn, err := streamSettings.TcpmaskManager.WrapConnClient(conn)
		if err != nil {
			conn.Close()
			return nil, errors.New("mask err").Base(err)
		}
		conn = newConn
	}

	xorexSettings := streamSettings.ProtocolSettings.(*Config)
	if len(xorexSettings.Key) == 0 {
		return nil, errors.New("xorex key must not be empty").AtError()
	}

	return stat.Connection(NewConn(conn, xorexSettings.Key)), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
