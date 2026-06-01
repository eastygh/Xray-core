package whatsapp

import (
	"context"
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
	defaultChatHost  = "chatd.whatsapp.net"
	defaultChatPort  = 5222
	defaultMediaHost = "mmg.whatsapp.net"
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

	link := &transport.Link{
		Reader: buf.NewReader(conn),
		Writer: buf.NewWriter(conn),
	}
	if err := dispatcher.DispatchLink(ctx, dest, link); err != nil {
		return errors.New("failed to dispatch whatsapp link").Base(err)
	}
	return nil
}

// pickTarget decides chat vs media. Uses MSG_PEEK so the bytes inspected here
// are NOT consumed from the socket — the dispatched reader will still see them.
func (h *Handler) pickTarget(ctx context.Context, conn stat.Connection, port uint32) Target {
	if _, ok := h.mediaPorts[port]; ok {
		return Target_TARGET_MEDIA
	}
	_, isChatPort := h.chatPorts[port]
	if isChatPort && h.sniffSNI {
		if sni := peekSNI(ctx, conn); sni != "" && isMediaSNI(sni) {
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
