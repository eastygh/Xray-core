package inbound

import (
	"context"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

func getStatCounter(v *core.Instance, tag string) (stats.Counter, stats.Counter) {
	var uplinkCounter stats.Counter
	var downlinkCounter stats.Counter

	policy := v.GetFeature(policy.ManagerType()).(policy.Manager)
	if len(tag) > 0 && policy.ForSystem().Stats.InboundUplink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + tag + ">>>traffic>>>uplink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			uplinkCounter = c
		}
	}
	if len(tag) > 0 && policy.ForSystem().Stats.InboundDownlink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + tag + ">>>traffic>>>downlink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			downlinkCounter = c
		}
	}

	return uplinkCounter, downlinkCounter
}

type AlwaysOnInboundHandler struct {
	proxyConfig    interface{}
	receiverConfig *proxyman.ReceiverConfig
	proxy          proxy.Inbound
	workers        []worker
	mux            *mux.Server
	tag            string
	streamConfig   *internet.MemoryStreamConfig
}

func NewAlwaysOnInboundHandler(ctx context.Context, tag string, receiverConfig *proxyman.ReceiverConfig, proxyConfig interface{}) (*AlwaysOnInboundHandler, error) {
	// Set tag and sniffing config in context before creating proxy
	// This allows proxies like TUN to access these settings
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: tag})
	if receiverConfig.SniffingSettings != nil {
		ctx = session.ContextWithContent(ctx, &session.Content{
			SniffingRequest: session.SniffingRequest{
				Enabled:                        receiverConfig.SniffingSettings.Enabled,
				OverrideDestinationForProtocol: receiverConfig.SniffingSettings.DestinationOverride,
				ExcludeForDomain:               receiverConfig.SniffingSettings.DomainsExcluded,
				MetadataOnly:                   receiverConfig.SniffingSettings.MetadataOnly,
				RouteOnly:                      receiverConfig.SniffingSettings.RouteOnly,
			},
		})
	}
	rawProxy, err := common.CreateObject(ctx, proxyConfig)
	if err != nil {
		return nil, err
	}
	p, ok := rawProxy.(proxy.Inbound)
	if !ok {
		return nil, errors.New("not an inbound proxy.")
	}

	h := &AlwaysOnInboundHandler{
		receiverConfig: receiverConfig,
		proxyConfig:    proxyConfig,
		proxy:          p,
		mux:            mux.NewServer(ctx),
		tag:            tag,
	}

	uplinkCounter, downlinkCounter := getStatCounter(core.MustFromContext(ctx), tag)

	nl := p.Network()
	pl := receiverConfig.PortList
	address := receiverConfig.Listen.AsAddress()
	if address == nil {
		address = net.AnyIP
	}

	mss, err := internet.ToMemoryStreamConfig(receiverConfig.StreamSettings)
	if err != nil {
		return nil, errors.New("failed to parse stream config").Base(err).AtWarning()
	}
	h.streamConfig = mss

	if receiverConfig.ReceiveOriginalDestination {
		if mss.SocketSettings == nil {
			mss.SocketSettings = &internet.SocketConfig{}
		}
		if mss.SocketSettings.Tproxy == internet.SocketConfig_Off {
			mss.SocketSettings.Tproxy = internet.SocketConfig_Redirect
		}
		mss.SocketSettings.ReceiveOriginalDestAddress = true
	}
	if pl == nil {
		if net.HasNetwork(nl, net.Network_UNIX) {
			errors.LogDebug(ctx, "creating unix domain socket worker on ", address)

			worker := &dsWorker{
				address:         address,
				proxy:           p,
				stream:          mss,
				tag:             tag,
				dispatcher:      h.mux,
				sniffingConfig:  receiverConfig.SniffingSettings,
				uplinkCounter:   uplinkCounter,
				downlinkCounter: downlinkCounter,
				ctx:             ctx,
			}
			h.workers = append(h.workers, worker)
		}

		// Create a virtual tcpWorker (no port, no listener) so external
		// routing (e.g., from selector) can reuse the standard callback
		// pipeline: context setup → counters → proxy.Process.
		if net.HasNetwork(nl, net.Network_TCP) {
			h.workers = append(h.workers, &tcpWorker{
				address:         address,
				proxy:           p,
				stream:          mss,
				tag:             tag,
				dispatcher:      h.mux,
				sniffingConfig:  receiverConfig.SniffingSettings,
				uplinkCounter:   uplinkCounter,
				downlinkCounter: downlinkCounter,
				ctx:             ctx,
			})
		}
	}
	if pl != nil {
		for _, pr := range pl.Range {
			for port := pr.From; port <= pr.To; port++ {
				if net.HasNetwork(nl, net.Network_TCP) {
					errors.LogDebug(ctx, "creating stream worker on ", address, ":", port)

					worker := &tcpWorker{
						address:         address,
						port:            net.Port(port),
						proxy:           p,
						stream:          mss,
						recvOrigDest:    receiverConfig.ReceiveOriginalDestination,
						tag:             tag,
						dispatcher:      h.mux,
						sniffingConfig:  receiverConfig.SniffingSettings,
						uplinkCounter:   uplinkCounter,
						downlinkCounter: downlinkCounter,
						ctx:             ctx,
					}
					h.workers = append(h.workers, worker)
				}

				if net.HasNetwork(nl, net.Network_UDP) {
					worker := &udpWorker{
						tag:             tag,
						proxy:           p,
						address:         address,
						port:            net.Port(port),
						dispatcher:      h.mux,
						sniffingConfig:  receiverConfig.SniffingSettings,
						uplinkCounter:   uplinkCounter,
						downlinkCounter: downlinkCounter,
						stream:          mss,
						ctx:             ctx,
					}
					h.workers = append(h.workers, worker)
				}
			}
		}
	}

	return h, nil
}

// Start implements common.Runnable.
func (h *AlwaysOnInboundHandler) Start() error {
	for _, worker := range h.workers {
		if err := worker.Start(); err != nil {
			return err
		}
	}
	return nil
}

// Close implements common.Closable.
func (h *AlwaysOnInboundHandler) Close() error {
	var errs []error
	for _, worker := range h.workers {
		errs = append(errs, worker.Close())
	}
	errs = append(errs, h.mux.Close())
	if err := errors.Combine(errs...); err != nil {
		return errors.New("failed to close all resources").Base(err)
	}
	return nil
}

func (h *AlwaysOnInboundHandler) Tag() string {
	return h.tag
}

func (h *AlwaysOnInboundHandler) GetInbound() proxy.Inbound {
	return h.proxy
}

// ReceiverSettings implements inbound.Handler.
func (h *AlwaysOnInboundHandler) ReceiverSettings() *serial.TypedMessage {
	return serial.ToTypedMessage(h.receiverConfig)
}

// HandleConnection processes an externally-routed connection through the
// handler's standard tcpWorker callback pipeline. Applies transport security
// (TLS/Reality) from the handler's stream config, then delegates to the
// worker's callback which handles context setup, counters, and proxy.Process.
// Works for any protocol (VLESS, Shadowsocks, Trojan, etc.).
// Blocks until the proxy finishes processing.
func (h *AlwaysOnInboundHandler) HandleConnection(conn net.Conn) error {
	// 1. Apply transport-layer security from the handler's cached stream config.
	// This is the same logic as tcp.Listener.keepAccepting().
	if h.streamConfig != nil {
		if tlsConfig := tls.ConfigFromStreamSettings(h.streamConfig); tlsConfig != nil {
			conn = tls.Server(conn, tlsConfig.GetTLSConfig())
		} else if realityConfig := reality.ConfigFromStreamSettings(h.streamConfig); realityConfig != nil {
			var err error
			if conn, err = reality.Server(conn, realityConfig.GetREALITYConfig()); err != nil {
				return err
			}
		}
	}

	// 2. Find the tcpWorker and reuse its callback — no code duplication.
	// The callback builds proper context (tag, sniffing, counters, session)
	// and calls proxy.Process synchronously.
	for _, w := range h.workers {
		if tw, ok := w.(*tcpWorker); ok {
			tw.callback(stat.Connection(conn))
			return nil
		}
	}
	return errors.New("no TCP worker available for handler [", h.tag, "]")
}

// ProxySettings implements inbound.Handler.
func (h *AlwaysOnInboundHandler) ProxySettings() *serial.TypedMessage {
	if v, ok := h.proxyConfig.(proto.Message); ok {
		return serial.ToTypedMessage(v)
	}
	return nil
}
