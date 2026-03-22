package mtproto

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/9seconds/mtg/v2/essentials"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type xrayNetwork struct {
	dispatcher routing.Dispatcher
	mu         sync.Mutex
	currentCtx context.Context
}

func (n *xrayNetwork) setContext(ctx context.Context) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.currentCtx = ctx
}

func (n *xrayNetwork) clearContext() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.currentCtx = nil
}

func (n *xrayNetwork) getContext() context.Context {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.currentCtx != nil {
		return n.currentCtx
	}
	return context.Background()
}

func (n *xrayNetwork) Dial(network, address string) (essentials.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

func (n *xrayNetwork) DialContext(ctx context.Context, network, address string) (essentials.Conn, error) {
	dest := parseDestination(network, address)

	dispCtx := n.getContext()

	outbounds := session.OutboundsFromContext(dispCtx)
	if len(outbounds) > 0 {
		ob := outbounds[len(outbounds)-1]
		ob.Target = dest
	}

	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())

	err := n.dispatcher.DispatchLink(dispCtx, dest, &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	})
	if err != nil {
		return nil, err
	}

	conn := cnc.NewConnection(
		cnc.ConnectionInputMulti(uplinkWriter),
		cnc.ConnectionOutputMulti(downlinkReader),
		cnc.ConnectionRemoteAddr(&net.TCPAddr{IP: dest.Address.IP(), Port: int(dest.Port)}),
	)

	return essentials.WrapNetConn(conn), nil
}

func (n *xrayNetwork) MakeHTTPClient(dialFunc func(ctx context.Context, network, address string) (essentials.Conn, error)) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialFunc(ctx, network, address)
			},
		},
	}
}

func (n *xrayNetwork) NativeDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
	}
}

func parseDestination(network, address string) xnet.Destination {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		portStr = "443"
	}

	port, _ := strconv.Atoi(portStr)

	var xnetwork xnet.Network
	switch network {
	case "udp", "udp4", "udp6":
		xnetwork = xnet.Network_UDP
	default:
		xnetwork = xnet.Network_TCP
	}

	addr := xnet.ParseAddress(host)

	return xnet.Destination{
		Network: xnetwork,
		Address: addr,
		Port:    xnet.Port(port),
	}
}
