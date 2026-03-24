package selector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"sync"

	"github.com/xtls/xray-core/app/proxyman"
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

	// 5. Wrap connection to replay consumed bytes
	wrappedConn := newBufferedConn(conn, firstBytes)

	// 6. If the target handler has transport-layer security (TLS/Reality/etc.),
	// we cannot call proxy.Process() directly because that bypasses the transport
	// stack. Instead, pipe the raw connection to the handler's own listener so
	// the native transport code handles TLS/Reality/WS/gRPC/etc.
	if addr := getHandlerListenAddr(handler); addr != "" {
		errors.LogInfo(ctx, "selector: piping to handler listener at ", addr)
		return pipeToListener(wrappedConn, addr)
	}

	// 7. No transport security — delegate to proxy directly
	gi, ok := handler.(proxy.GetInbound)
	if !ok {
		return errors.New("selector: handler [", handlerTag, "] does not expose proxy.Inbound")
	}
	return gi.GetInbound().Process(ctx, network, wrappedConn, dispatcher)
}

// getHandlerListenAddr returns "host:port" of the handler's listener if it has
// transport-layer security configured. Returns "" if direct proxy.Process() is safe.
func getHandlerListenAddr(handler inbound.Handler) string {
	rs := handler.ReceiverSettings()
	if rs == nil {
		return ""
	}
	msg, err := rs.GetInstance()
	if err != nil {
		return ""
	}
	rc, ok := msg.(*proxyman.ReceiverConfig)
	if !ok {
		return ""
	}

	// Only pipe when there is transport security that the listener must handle
	if rc.StreamSettings == nil || !rc.StreamSettings.HasSecuritySettings() {
		return ""
	}

	// Need a port to connect to
	if rc.PortList == nil || len(rc.PortList.Range) == 0 {
		return ""
	}
	port := rc.PortList.Range[0].From

	addr := "127.0.0.1"
	if rc.Listen != nil {
		if a := rc.Listen.AsAddress(); a != nil {
			s := a.String()
			// If handler listens on 0.0.0.0 or ::, connect via loopback
			if s != "0.0.0.0" && s != "::" {
				addr = s
			}
		}
	}

	return fmt.Sprintf("%s:%d", addr, port)
}

// pipeToListener connects to the handler's actual listener and bidirectionally
// copies data. This lets the handler's full transport stack (TLS/Reality/WS/gRPC)
// process the connection natively — the same approach used by VLESS fallbacks.
func pipeToListener(clientConn stat.Connection, addr string) error {
	targetConn, err := net.Dial("tcp", addr)
	if err != nil {
		return errors.New("selector: failed to connect to handler listener at ", addr).Base(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// client → handler listener
	go func() {
		io.Copy(targetConn, clientConn)
		// Signal write-done to target so TLS knows the stream ended
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		wg.Done()
	}()

	// handler listener → client
	go func() {
		io.Copy(clientConn, targetConn)
		// Signal write-done to client
		if cw, ok := clientConn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		wg.Done()
	}()

	wg.Wait()
	targetConn.Close()
	return nil
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

// CloseWrite delegates half-close to the underlying connection.
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
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
