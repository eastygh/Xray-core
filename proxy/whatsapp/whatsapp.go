package whatsapp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/peek"
	"github.com/xtls/xray-core/common/protocol/tls"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	// Backends mirror the official WhatsApp proxy (github.com/WhatsApp/proxy,
	// proxy/src/proxy_config.cfg): chat/XMPP traffic goes to g.whatsapp.net:5222
	// with a PROXY-protocol v1 header (HAProxy "send-proxy"); media traffic goes
	// to whatsapp.net:443 with no header.
	defaultChatHost  = "g.whatsapp.net"
	defaultChatPort  = 5222
	defaultMediaHost = "whatsapp.net"
	defaultMediaPort = 443

	sniffReadSize    = 2048
	sniffMinPeekSize = 254
	sniffTimeout     = 5 * time.Second
)

var (
	defaultChatPorts  = []uint32{80, 443, 5222, 8080, 8222, 8443}
	defaultMediaPorts = []uint32{587, 7777}
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		h := &Handler{}
		h.init(config.(*Config))
		return h, nil
	}))
}

type Handler struct {
	chatDest  xnet.Destination
	mediaDest xnet.Destination

	chatPorts  map[uint32]struct{}
	mediaPorts map[uint32]struct{}

	sniffSNI      bool
	defaultTarget Target
}

func (h *Handler) init(c *Config) {
	chatHost := c.ChatHost
	if chatHost == "" {
		chatHost = defaultChatHost
	}
	chatPort := c.ChatPort
	if chatPort == 0 {
		chatPort = defaultChatPort
	}
	mediaHost := c.MediaHost
	if mediaHost == "" {
		mediaHost = defaultMediaHost
	}
	mediaPort := c.MediaPort
	if mediaPort == 0 {
		mediaPort = defaultMediaPort
	}

	h.chatDest = xnet.TCPDestination(xnet.ParseAddress(chatHost), xnet.Port(chatPort))
	h.mediaDest = xnet.TCPDestination(xnet.ParseAddress(mediaHost), xnet.Port(mediaPort))

	h.chatPorts = portSet(c.ChatPorts, defaultChatPorts)
	h.mediaPorts = portSet(c.MediaPorts, defaultMediaPorts)

	h.sniffSNI = c.SniffSni

	h.defaultTarget = c.DefaultTarget
	if h.defaultTarget == Target_TARGET_UNSPECIFIED {
		h.defaultTarget = Target_TARGET_CHAT
	}
}

func portSet(custom []uint32, def []uint32) map[uint32]struct{} {
	src := custom
	if len(src) == 0 {
		src = def
	}
	m := make(map[uint32]struct{}, len(src))
	for _, p := range src {
		m[p] = struct{}{}
	}
	return m
}

func (h *Handler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if ib := session.InboundFromContext(ctx); ib != nil {
		ib.Name = "whatsapp"
		ib.CanSpliceCopy = 3
	}

	localPort := localPortOf(conn)
	target := h.pickTarget(ctx, conn, localPort)
	dest := h.destFor(target)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "whatsapp:" + targetName(target),
	})
	errors.LogInfo(ctx, "whatsapp ", conn.RemoteAddr(), " -> ", dest, " (", targetName(target), ")")

	if ib := session.InboundFromContext(ctx); ib != nil {
		errors.LogInfo(ctx, "whatsapp debug: inbound.Tag=", ib.Tag, " inbound.Name=", ib.Name)
	}

	var reader buf.Reader = buf.NewReader(conn)
	// The chat/XMPP backend (g.whatsapp.net) is fronted by HAProxy "send-proxy":
	// it expects a PROXY-protocol v1 line as the very first bytes, carrying the
	// real client address. Without it the edge stalls parsing the Noise
	// handshake as a malformed header and the client hangs in "Connecting...".
	// Media (whatsapp.net:443) is a plain relay and must NOT receive a header.
	if target == Target_TARGET_CHAT {
		header := proxyProtocolHeaderV1(conn.RemoteAddr(), conn.LocalAddr())
		if header != nil {
			b := buf.New()
			b.Write(header)
			reader = &buf.BufferedReader{
				Reader: reader,
				Buffer: buf.MultiBuffer{b},
			}
		}
	}

	link := &transport.Link{
		Reader: reader,
		Writer: buf.NewWriter(conn),
	}
	if err := dispatcher.DispatchLink(ctx, dest, link); err != nil {
		return errors.New("failed to dispatch whatsapp link").Base(err)
	}
	return nil
}

// proxyProtocolHeaderV1 builds a PROXY-protocol v1 header line
// ("PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n") describing the
// client->proxy connection, matching HAProxy's "send-proxy". src is the real
// client (conn.RemoteAddr), dst is the local address the client connected to
// (conn.LocalAddr). When the addresses can't be expressed in a v1 line it falls
// back to the valid "PROXY UNKNOWN\r\n" line rather than nil: the edge still
// needs *some* header first, it just won't learn the real client IP.
func proxyProtocolHeaderV1(src, dst net.Addr) []byte {
	srcTCP, ok1 := src.(*net.TCPAddr)
	dstTCP, ok2 := dst.(*net.TCPAddr)
	if !ok1 || !ok2 {
		return []byte("PROXY UNKNOWN\r\n")
	}
	src4, dst4 := srcTCP.IP.To4(), dstTCP.IP.To4()
	switch {
	case src4 != nil && dst4 != nil:
		return fmt.Appendf(nil, "PROXY TCP4 %s %s %d %d\r\n",
			src4.String(), dst4.String(), srcTCP.Port, dstTCP.Port)
	case src4 == nil && dst4 == nil:
		return fmt.Appendf(nil, "PROXY TCP6 %s %s %d %d\r\n",
			srcTCP.IP.String(), dstTCP.IP.String(), srcTCP.Port, dstTCP.Port)
	default:
		// Mixed families can't be represented in a single v1 line.
		return []byte("PROXY UNKNOWN\r\n")
	}
}

// pickTarget decides chat vs media. Uses MSG_PEEK so the bytes inspected here
// are NOT consumed from the socket — the dispatched reader will still see them.
func (h *Handler) pickTarget(ctx context.Context, conn stat.Connection, port uint32) Target {
	if _, ok := h.mediaPorts[port]; ok {
		return Target_TARGET_MEDIA
	}
	_, isChatPort := h.chatPorts[port]
	if isChatPort && h.sniffSNI {
		sni, ok := session.SniffedSNIFromContext(ctx)
		if !ok {
			// No upstream inbound peeked this connection — do it ourselves.
			sni = peekSNI(ctx, conn)
		}
		if sni != "" && isMediaSNI(sni) {
			return Target_TARGET_MEDIA
		}
		return Target_TARGET_CHAT
	}
	if isChatPort {
		return Target_TARGET_CHAT
	}
	return h.defaultTarget
}

func peekSNI(ctx context.Context, conn stat.Connection) string {
	firstBytes, err := peek.SNI(conn, sniffReadSize, sniffMinPeekSize, sniffTimeout)
	if err != nil {
		errors.LogDebug(ctx, "whatsapp: peek failed: ", err)
		return ""
	}
	h, err := tls.SniffTLS(firstBytes)
	if err != nil {
		return ""
	}
	return h.Domain()
}

func (h *Handler) destFor(t Target) xnet.Destination {
	if t == Target_TARGET_MEDIA {
		return h.mediaDest
	}
	return h.chatDest
}

func isMediaSNI(sni string) bool {
	if sni == "" {
		return false
	}
	s := strings.ToLower(sni)
	// Media CDN hosts on WhatsApp typically end with ".cdn.whatsapp.net" or
	// "*.fna.whatsapp.net" and "mmg.*"-style media endpoints. Be permissive so
	// future host renames don't silently misroute.
	switch {
	case strings.HasSuffix(s, ".cdn.whatsapp.net"),
		strings.HasSuffix(s, ".fna.whatsapp.net"),
		strings.HasPrefix(s, "mmg."),
		strings.HasPrefix(s, "media."),
		strings.HasPrefix(s, "media-"):
		return true
	}
	return false
}

func targetName(t Target) string {
	if t == Target_TARGET_MEDIA {
		return "media"
	}
	return "chat"
}

func localPortOf(conn net.Conn) uint32 {
	la := conn.LocalAddr()
	if la == nil {
		return 0
	}
	if a, ok := la.(*net.TCPAddr); ok {
		return uint32(a.Port)
	}
	_, portStr, err := net.SplitHostPort(la.String())
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(portStr)
	return uint32(p)
}
