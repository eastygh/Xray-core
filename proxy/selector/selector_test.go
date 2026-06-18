package selector

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/inbound"
)

// stubManager is a minimal inbound.Manager whose GetHandler always fails, so
// resolveHandlerInfo falls back to empty handlerInfo. That keeps init() tests
// focused on rule compilation without standing up real inbound handlers.
type stubManager struct{}

func (stubManager) Type() interface{} { return inbound.ManagerType() }
func (stubManager) Start() error      { return nil }
func (stubManager) Close() error      { return nil }
func (stubManager) GetHandler(ctx context.Context, tag string) (inbound.Handler, error) {
	return nil, stderrors.New("no handler: " + tag)
}
func (stubManager) AddHandler(ctx context.Context, handler inbound.Handler) error { return nil }
func (stubManager) RemoveHandler(ctx context.Context, tag string) error           { return nil }
func (stubManager) ListHandlers(ctx context.Context) []inbound.Handler            { return nil }

var _ inbound.Manager = stubManager{}

func TestMatchSNI(t *testing.T) {
	cases := []struct {
		name string
		rule compiledRule
		sni  string
		want bool
	}{
		{"exact match", compiledRule{sni: "example.com"}, "example.com", true},
		{"exact mismatch", compiledRule{sni: "example.com"}, "other.com", false},
		{"empty is catch-all", compiledRule{sni: ""}, "anything.com", true},
		{"empty matches empty", compiledRule{sni: ""}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.rule.matchSNI(c.sni); got != c.want {
				t.Fatalf("matchSNI(%q) = %v, want %v", c.sni, got, c.want)
			}
		})
	}
}

func TestMatchSNIPattern(t *testing.T) {
	s := &Selector{}
	if err := s.init(&Config{
		Rules: []*Rule{{Pattern: `.*\.example\.com$`, HandlerTag: "h"}},
	}, stubManager{}); err != nil {
		t.Fatal(err)
	}

	r := &s.rules[0]
	if r.sni != "" {
		t.Fatalf("pattern rule should clear exact sni, got %q", r.sni)
	}
	if !r.matchSNI("a.example.com") {
		t.Error("expected a.example.com to match pattern")
	}
	if r.matchSNI("example.org") {
		t.Error("did not expect example.org to match pattern")
	}
}

func TestInitDefaults(t *testing.T) {
	s := &Selector{}
	if err := s.init(&Config{}, stubManager{}); err != nil {
		t.Fatal(err)
	}
	if s.readSize != defaultReadSize {
		t.Errorf("readSize = %d, want %d", s.readSize, defaultReadSize)
	}
	if s.peekTimeout != defaultPeekTimeout {
		t.Errorf("peekTimeout = %v, want %v", s.peekTimeout, defaultPeekTimeout)
	}
	if s.minPeekSize != defaultMinPeekSize {
		t.Errorf("minPeekSize = %d, want %d", s.minPeekSize, defaultMinPeekSize)
	}
}

func TestInitCustomValues(t *testing.T) {
	s := &Selector{}
	if err := s.init(&Config{
		ReadSize:      1000,
		PeekTimeoutMs: 200,
		MinPeekSize:   100,
	}, stubManager{}); err != nil {
		t.Fatal(err)
	}
	if s.readSize != 1000 {
		t.Errorf("readSize = %d, want 1000", s.readSize)
	}
	if s.peekTimeout != 200*time.Millisecond {
		t.Errorf("peekTimeout = %v, want 200ms", s.peekTimeout)
	}
	if s.minPeekSize != 100 {
		t.Errorf("minPeekSize = %d, want 100", s.minPeekSize)
	}
}

func TestInitInvalidRegex(t *testing.T) {
	s := &Selector{}
	err := s.init(&Config{
		Rules: []*Rule{{Pattern: "[", HandlerTag: "h"}},
	}, stubManager{})
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

func TestInitForwarderRule(t *testing.T) {
	s := &Selector{}
	if err := s.init(&Config{
		Rules: []*Rule{{
			Match:         "site.example.com",
			LoopbackAddr:  "127.0.0.1:8443",
			ProxyProtocol: 2,
		}},
	}, stubManager{}); err != nil {
		t.Fatal(err)
	}

	r := s.rules[0]
	if r.loopbackAddr != "127.0.0.1:8443" {
		t.Errorf("loopbackAddr = %q, want 127.0.0.1:8443", r.loopbackAddr)
	}
	// A forwarder rule carries no inbound handler, so proxyProtocol must be kept
	// verbatim (it is the operator's responsibility to point it at a PROXY-aware
	// target such as nginx).
	if r.proxyProtocol != 2 {
		t.Errorf("proxyProtocol = %d, want 2", r.proxyProtocol)
	}
	if !r.matchSNI("site.example.com") {
		t.Error("forwarder rule should match its SNI")
	}
}

func TestInitUnresolvableHandlerDropsProxyProtocol(t *testing.T) {
	// Without loopbackAddr the handler must accept PROXY protocol; the stub
	// manager resolves nothing, so proxyProtocol is disabled to avoid corrupting
	// a downstream that never agreed to it.
	s := &Selector{}
	if err := s.init(&Config{
		Rules: []*Rule{{Match: "x.com", HandlerTag: "missing", ProxyProtocol: 1}},
	}, stubManager{}); err != nil {
		t.Fatal(err)
	}
	if s.rules[0].proxyProtocol != 0 {
		t.Errorf("proxyProtocol = %d, want 0 (handler unresolved)", s.rules[0].proxyProtocol)
	}
	if s.rules[0].loopbackAddr != "" {
		t.Errorf("loopbackAddr = %q, want empty", s.rules[0].loopbackAddr)
	}
}

func TestNetwork(t *testing.T) {
	s := &Selector{}
	got := s.Network()
	if len(got) != 1 || got[0] != xnet.Network_TCP {
		t.Fatalf("Network() = %v, want [TCP]", got)
	}
}
