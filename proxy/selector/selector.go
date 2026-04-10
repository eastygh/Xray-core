package selector

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		s := new(Selector)
		err := core.RequireFeatures(ctx, func(im inbound.Manager) error {
			return s.init(config.(*Config), im)
		})
		return s, err
	}))
}

const (
	defaultReadSize    = 2048
	defaultPeekTimeout = 5 * time.Second
	defaultMinPeekSize = 254
)

type compiledRule struct {
	sni           string         // exact match (if pattern is nil)
	pattern       *regexp.Regexp // regex match (if set)
	handlerTag    string
	loopbackAddr  string
	proxyProtocol uint32
}

func (r *compiledRule) matchSNI(sni string) bool {
	if r.pattern != nil {
		return r.pattern.MatchString(sni)
	}
	return r.sni == "" || r.sni == sni
}

// Selector implements proxy.Inbound.
// It peeks at the first bytes of a TLS connection, extracts the SNI,
// and routes to the appropriate inbound handler by tag.
type Selector struct {
	inboundManager inbound.Manager
	rules          []compiledRule
	readSize       int
	peekTimeout    time.Duration
	minPeekSize    int
}

func (s *Selector) init(config *Config, im inbound.Manager) error {
	s.inboundManager = im

	s.readSize = int(config.ReadSize)
	if s.readSize <= 0 {
		s.readSize = defaultReadSize
	}
	s.peekTimeout = time.Duration(config.PeekTimeoutMs) * time.Millisecond
	if s.peekTimeout <= 0 {
		s.peekTimeout = defaultPeekTimeout
	}
	s.minPeekSize = int(config.MinPeekSize)
	if s.minPeekSize <= 0 {
		s.minPeekSize = defaultMinPeekSize
	}

	s.rules = make([]compiledRule, 0, len(config.Rules))
	for _, r := range config.Rules {
		cr := compiledRule{
			sni:           r.Match,
			handlerTag:    r.HandlerTag,
			proxyProtocol: r.ProxyProtocol,
		}
		if r.Pattern != "" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				return errors.New("invalid regex in rule: ", r.Pattern).Base(err)
			}
			cr.pattern = re
			cr.sni = "" // pattern takes priority
		}
		if r.LoopbackAddr != "" {
			cr.loopbackAddr = r.LoopbackAddr
		} else {
			info := resolveHandlerInfo(im, cr.handlerTag)
			if info.hasSecurity {
				cr.loopbackAddr = info.addr
			}
			if cr.proxyProtocol > 0 && !info.acceptPP {
				cr.proxyProtocol = 0
			}
		}
		s.rules = append(s.rules, cr)
	}
	return nil
}

// Network implements proxy.Inbound.
func (s *Selector) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// Process implements proxy.Inbound.
func (s *Selector) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	firstBytes, err := peekSNI(conn, s.readSize, s.minPeekSize, s.peekTimeout)
	if err != nil {
		return errors.New("failed to peek first bytes").Base(err)
	}

	var sni string
	if h, err := tls.SniffTLS(firstBytes); err == nil {
		sni = h.Domain()
	}

	if sni == "" {
		errors.LogWarning(ctx, "No sni found in first bytes, route to default handler")
	}

	var rule *compiledRule
	for i := range s.rules {
		if s.rules[i].matchSNI(sni) {
			rule = &s.rules[i]
			break
		}
	}

	if rule == nil {
		return errors.New("no matching rule for sni=", sni)
	}

	errors.LogInfo(ctx, "routing to [", rule.handlerTag, "] sni=", sni,
		" loopback=", rule.loopbackAddr != "")

	handler, err := s.inboundManager.GetHandler(ctx, rule.handlerTag)
	if err != nil {
		return errors.New("handler not found: ", rule.handlerTag).Base(err)
	}

	if rule.loopbackAddr != "" {
		return loopbackRelayV2(ctx, conn, rule.loopbackAddr, rule.proxyProtocol)
	}

	if ib := session.InboundFromContext(ctx); ib != nil {
		ib.Tag = rule.handlerTag
	}

	gi, ok := handler.(proxy.GetInbound)
	if !ok {
		return errors.New("handler [", rule.handlerTag, "] does not implement GetInbound")
	}
	return gi.GetInbound().Process(ctx, network, conn, dispatcher)
}

type handlerInfo struct {
	addr        string
	hasSecurity bool
	acceptPP    bool
}

func resolveHandlerInfo(im inbound.Manager, tag string) handlerInfo {
	handler, err := im.GetHandler(context.Background(), tag)
	if err != nil {
		return handlerInfo{}
	}

	receiverMsg := handler.ReceiverSettings()
	if receiverMsg == nil {
		return handlerInfo{}
	}

	instance, err := receiverMsg.GetInstance()
	if err != nil {
		return handlerInfo{}
	}
	rc, ok := instance.(*proxyman.ReceiverConfig)
	if !ok {
		return handlerInfo{}
	}

	mss, err := internet.ToMemoryStreamConfig(rc.GetStreamSettings())
	if err != nil {
		return handlerInfo{}
	}
	hasSecurity := mss.SecurityType != ""
	acceptPP := mss.SocketSettings.GetAcceptProxyProtocol()

	pl := rc.GetPortList()
	if pl == nil || len(pl.GetRange()) == 0 {
		return handlerInfo{hasSecurity: hasSecurity, acceptPP: acceptPP}
	}

	addr := rc.Listen.AsAddress()
	if addr == nil {
		addr = xnet.LocalHostIP
	}

	return handlerInfo{
		addr:        net.JoinHostPort(addr.String(), fmt.Sprintf("%d", pl.GetRange()[0].From)),
		hasSecurity: hasSecurity,
		acceptPP:    acceptPP,
	}
}
