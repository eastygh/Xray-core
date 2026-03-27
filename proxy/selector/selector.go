package selector

import (
	"context"
	"net"
	"regexp"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	defaultReadSize    = 2048
	defaultPeekTimeout = 5 * time.Second
	defaultMinPeekSize = 16 // enough for TLS record header (5) + handshake type (1) + length (3) + version (2) + random start
)

// compiledRule is a pre-compiled routing rule.
type compiledRule struct {
	match      string
	pattern    *regexp.Regexp
	handlerTag string
}

// Selector implements proxy.Inbound. It reads the first bytes of a connection,
// detects the protocol (TLS/SNI/ECH/MTProto), and delegates to the appropriate
// inbound handler looked up by tag.
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
			match:      r.Match,
			handlerTag: r.HandlerTag,
		}
		if r.Pattern != "" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				return errors.New("invalid regex pattern in selector rule: ", r.Pattern).Base(err)
			}
			cr.pattern = re
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
	// 1. Peek at first bytes WITHOUT consuming them from the socket buffer.
	firstBytes, err := peekBytes(conn, s.readSize, s.minPeekSize, s.peekTimeout)
	if err != nil {
		return errors.New("failed to peek first bytes").Base(err)
	}

	// 2. Detect protocol
	result := Detect(firstBytes)

	// 3. Match rules
	handlerTag := s.matchRules(result)
	if handlerTag == "" {
		handlerTag = s.config.DefaultHandlerTag
	}
	if handlerTag == "" {
		return errors.New("no matching rule and no default handler configured")
	}

	errors.LogInfo(ctx, "selector: routing to handler [", handlerTag, "]",
		" tls=", result.IsTLS, " sni=", result.SNI, " ech=", result.HasECH,
		" mtproto=", result.IsMTProto, " peeked=", len(firstBytes))

	// 4. Get target handler
	handler, err := s.inboundManager.GetHandler(ctx, handlerTag)
	if err != nil {
		return errors.New("selector: handler not found: ", handlerTag).Base(err)
	}

	// 5. Inject the raw connection into the handler's listener pipeline.
	// The listener applies TLS/Reality using its own cached config objects,
	// then the worker callback runs synchronously with proper context.
	type connectionInjector interface {
		HandleConnection(net.Conn) bool
	}
	rawConn := unwrapRawConn(conn)
	if ci, ok := handler.(connectionInjector); ok {
		errors.LogInfo(ctx, "selector: handler [", handlerTag, "] supports HandleConnection, injecting")
		if ci.HandleConnection(rawConn) {
			return nil // handler took ownership — ran synchronously to completion
		}
		errors.LogWarning(ctx, "selector: handler [", handlerTag, "] HandleConnection returned false (no worker/listener?)")
	} else {
		errors.LogWarning(ctx, "selector: handler [", handlerTag, "] does not support HandleConnection, using fallback")
	}

	// 6. Fallback: handler has no listener — delegate to proxy directly.
	// NOTE: ctx here is the selector's context, not the target handler's.
	gi, ok := handler.(proxy.GetInbound)
	if !ok {
		return errors.New("selector: handler [", handlerTag, "] does not expose proxy.Inbound")
	}
	errors.LogWarning(ctx, "selector: fallback direct proxy.Process for [", handlerTag, "] — TLS will NOT be applied")
	return gi.GetInbound().Process(ctx, network, stat.Connection(rawConn), dispatcher)
}

// unwrapRawConn peels off stat.CounterConnection wrappers to get the raw
// net.Conn (typically *net.TCPConn) with native interface support.
func unwrapRawConn(conn stat.Connection) net.Conn {
	return stat.TryUnwrapStatsConn(conn)
}

// matchRules finds the first matching rule for the detection result.
func (s *Selector) matchRules(result DetectionResult) string {
	for _, r := range s.rules {
		switch r.match {
		case "notls":
			if !result.IsTLS {
				return r.handlerTag
			}
		case "tls":
			if result.IsTLS && !result.HasECH {
				if r.pattern == nil || r.pattern.MatchString(result.SNI) {
					return r.handlerTag
				}
			}
		case "ech":
			if result.IsTLS && result.HasECH {
				if r.pattern == nil || r.pattern.MatchString(result.SNI) {
					return r.handlerTag
				}
			}
		case "tls_default":
			if result.IsTLS {
				return r.handlerTag
			}
		case "mtproto":
			if result.IsMTProto {
				return r.handlerTag
			}
		case "unknown":
			if !result.IsTLS && !result.IsMTProto {
				return r.handlerTag
			}
		}
	}
	return ""
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		s := new(Selector)
		err := core.RequireFeatures(ctx, func(im inbound.Manager) error {
			return s.init(config.(*Config), im)
		})
		return s, err
	}))
}
