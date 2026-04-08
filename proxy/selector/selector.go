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
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
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
	match         string
	pattern       *regexp.Regexp
	handlerTag    string
	loopbackAddr  string // non-empty when handler requires loopback relay
	proxyProtocol uint32
}

// Selector implements proxy.Inbound.
// It peeks at the first bytes of a TCP connection to detect the protocol,
// then routes to the appropriate inbound handler by tag.
type Selector struct {
	config         *Config
	inboundManager inbound.Manager
	rules          []compiledRule
	readSize       int
	peekTimeout    time.Duration
	minPeekSize    int
}

func (s *Selector) init(config *Config, im inbound.Manager) error {
	s.config = config
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
			match:         r.Match,
			handlerTag:    r.HandlerTag,
			proxyProtocol: r.ProxyProtocol,
		}
		if r.Pattern != "" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				return errors.New("invalid regex in rule: ", r.Pattern).Base(err)
			}
			cr.pattern = re
		}
		// Determine loopback address.
		// Loopback is required when the target handler has transport security
		// (TLS/Reality) — the connection must go through the handler's TCP
		// listener so TLS handshake happens normally.
		if r.LoopbackAddr != "" {
			cr.loopbackAddr = r.LoopbackAddr
		} else {
			info := resolveHandlerInfo(im, cr.handlerTag)
			if info.hasSecurity {
				cr.loopbackAddr = info.addr
			}
			// Suppress PROXY protocol if handler doesn't accept it
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
	firstBytes, err := peekBytes(conn, s.readSize, s.minPeekSize, s.peekTimeout)
	if err != nil {
		return errors.New("failed to peek first bytes").Base(err)
	}

	result := Detect(firstBytes)
	rule := s.matchRules(result)

	if rule == nil {
		if s.config.DefaultHandlerTag == "" {
			return errors.New("no matching rule and no default handler")
		}
		// Build a default rule on demand. Resolve loopback only if needed.
		info := resolveHandlerInfo(s.inboundManager, s.config.DefaultHandlerTag)
		rule = &compiledRule{
			match:      "default",
			handlerTag: s.config.DefaultHandlerTag,
		}
		if info.hasSecurity {
			rule.loopbackAddr = info.addr
		}
	}

	useLoopback := rule.loopbackAddr != ""

	errors.LogInfo(ctx, "routing to [", rule.handlerTag, "] tls=", result.IsTLS,
		" sni=", result.SNI, " ech=", result.HasECH,
		" mtproto=", result.IsMTProto, " loopback=", useLoopback)

	handler, err := s.inboundManager.GetHandler(ctx, rule.handlerTag)
	if err != nil {
		return errors.New("handler not found: ", rule.handlerTag).Base(err)
	}

	if useLoopback {
		return loopbackRelay(ctx, conn, rule.loopbackAddr, rule.proxyProtocol)
	}

	// Direct call for handlers without transport security.
	// Rewrite inbound tag so downstream routing sees the target handler.
	if ib := session.InboundFromContext(ctx); ib != nil {
		ib.Tag = rule.handlerTag
	}

	gi, ok := handler.(proxy.GetInbound)
	if !ok {
		return errors.New("handler [", rule.handlerTag, "] does not implement GetInbound")
	}
	return gi.GetInbound().Process(ctx, network, conn, dispatcher)
}

func (s *Selector) matchRules(result DetectionResult) *compiledRule {
	for i := range s.rules {
		r := &s.rules[i]
		switch r.match {
		case "notls":
			if !result.IsTLS {
				return r
			}
		case "tls":
			if result.IsTLS {
				if r.pattern == nil || r.pattern.MatchString(result.SNI) {
					return r
				}
			}
		case "ech":
			if result.IsTLS && result.HasECH && result.SNI == "" {
				if r.pattern == nil || r.pattern.MatchString(result.SNI) {
					return r
				}
			}
		case "tls_default":
			if result.IsTLS {
				return r
			}
		case "mtproto":
			if result.IsMTProto {
				return r
			}
		case "unknown":
			if !result.IsTLS && !result.IsMTProto {
				return r
			}
		}
	}
	return nil
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

	ss := rc.GetStreamSettings()
	hasSecurity := ss != nil && ss.GetSecurityType() != ""
	acceptPP := ss != nil && ss.GetSocketSettings().GetAcceptProxyProtocol()

	pl := rc.GetPortList()
	if pl == nil || len(pl.GetRange()) == 0 {
		return handlerInfo{acceptPP: acceptPP}
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
