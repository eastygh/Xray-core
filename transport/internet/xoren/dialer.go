package xoren

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Dial dials a new XOR-wrapped TCP connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "dialing XOREN to ", dest)
	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	xorenSettings, ok := streamSettings.ProtocolSettings.(*Config)
	if !ok {
		conn.Close()
		return nil, errors.New("xoren: invalid stream settings type")
	}
	if len(xorenSettings.Key) == 0 {
		conn.Close()
		return nil, errors.New("xoren: empty key")
	}

	streamKey, err := clientHandshake(conn, xorenSettings.Key)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return stat.Connection(newXorConn(conn, streamKey)), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
