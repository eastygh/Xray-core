package xoren

import (
	"context"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Listener is an internet.Listener that listens for XOR-wrapped TCP connections.
type Listener struct {
	listener net.Listener
	config   *Config
	addConn  internet.ConnHandler
}

// ListenXOREN creates a new Listener based on configurations.
func ListenXOREN(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	xorenSettings, ok := streamSettings.ProtocolSettings.(*Config)
	if !ok {
		return nil, errors.New("xoren: invalid stream settings type")
	}
	if len(xorenSettings.Key) == 0 {
		return nil, errors.New("xoren: empty key")
	}

	l := &Listener{
		addConn: handler,
		config:  xorenSettings,
	}

	if streamSettings.SocketSettings == nil {
		streamSettings.SocketSettings = &internet.SocketConfig{}
	}
	streamSettings.SocketSettings.AcceptProxyProtocol = xorenSettings.AcceptProxyProtocol || streamSettings.SocketSettings.AcceptProxyProtocol

	listener, err := internet.ListenSystem(ctx, &net.TCPAddr{
		IP:   address.IP(),
		Port: int(port),
	}, streamSettings.SocketSettings)
	if err != nil {
		return nil, errors.New("failed to listen XOREN on ", address, ":", port).Base(err)
	}
	errors.LogInfo(ctx, "listening XOREN on ", address, ":", port)

	if streamSettings.SocketSettings.AcceptProxyProtocol {
		errors.LogWarning(ctx, "accepting PROXY protocol")
	}

	l.listener = listener
	go l.keepAccepting()
	return l, nil
}

func (l *Listener) keepAccepting() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "closed") {
				break
			}
			errors.LogWarningInner(context.Background(), err, "failed to accept raw connections")
			if strings.Contains(errStr, "too many") {
				time.Sleep(time.Millisecond * 500)
			}
			continue
		}
		go func(c net.Conn) {
			streamKey, err := serverHandshake(c, l.config.Key)
			if err != nil {
				errors.LogDebug(context.Background(), "xoren: dropping connection: ", err)
				_ = c.Close()
				return
			}
			l.addConn(stat.Connection(newXorConn(c, streamKey)))
		}(conn)
	}
}

// Addr implements internet.Listener.Addr.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// Close implements internet.Listener.Close.
func (l *Listener) Close() error {
	return l.listener.Close()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenXOREN))
}
