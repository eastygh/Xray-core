package selector

import (
	"bytes"
	"context"
	"io"
	"net"
	"regexp"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const defaultReadSize = 2048

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
}

func (s *Selector) init(config *Config, im inbound.Manager) error {
	s.config = config
	s.inboundManager = im
	s.readSize = int(config.ReadSize)
	if s.readSize <= 0 {
		s.readSize = defaultReadSize
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
	// 1. Read first bytes
	firstBuf := make([]byte, s.readSize)
	n, err := conn.Read(firstBuf)
	if err != nil {
		return errors.New("failed to read first bytes").Base(err)
	}
	firstBytes := firstBuf[:n]

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
		" tls=", result.IsTLS, " sni=", result.SNI, " ech=", result.HasECH, " mtproto=", result.IsMTProto)

	// 4. Get target handler
	handler, err := s.inboundManager.GetHandler(ctx, handlerTag)
	if err != nil {
		return errors.New("selector: handler not found: ", handlerTag).Base(err)
	}

	gi, ok := handler.(proxy.GetInbound)
	if !ok {
		return errors.New("selector: handler [", handlerTag, "] does not expose proxy.Inbound")
	}
	inboundProxy := gi.GetInbound()

	// 5. Wrap connection with buffered bytes
	wrappedConn := newBufferedConn(conn, firstBytes)

	// 6. Delegate to target handler
	return inboundProxy.Process(ctx, network, wrappedConn, dispatcher)
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

// bufferedConn wraps a net.Conn, prepending already-read bytes before the real connection.
type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func newBufferedConn(conn net.Conn, firstBytes []byte) stat.Connection {
	return &bufferedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(firstBytes), conn),
	}
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
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
