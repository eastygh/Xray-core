package mtproto

import (
	"context"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/events"
	"github.com/9seconds/mtg/v2/ipblocklist"
	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		h := new(Handler)
		err := core.RequireFeatures(ctx, func(d routing.Dispatcher) error {
			return h.init(config.(*Config), d)
		})
		return h, err
	}))
}

type Handler struct {
	config  *Config
	proxy   *mtglib.Proxy
	xrayNet *xrayNetwork
}

func (h *Handler) init(config *Config, dispatcher routing.Dispatcher) error {
	h.config = config

	secret, err := mtglib.ParseSecret(config.Secret)
	if err != nil {
		return errors.New("failed to parse mtproto secret").Base(err)
	}

	h.xrayNet = &xrayNetwork{
		dispatcher: dispatcher,
	}

	var antiReplayCache mtglib.AntiReplayCache
	if config.AntiReplay {
		antiReplayCache = antireplay.NewStableBloomFilter(
			antireplay.DefaultStableBloomFilterMaxSize,
			antireplay.DefaultStableBloomFilterErrorRate,
		)
	} else {
		antiReplayCache = antireplay.NewNoop()
	}

	tolerateSkew := time.Duration(config.TolerateTimeSkewnessSeconds) * time.Second
	if tolerateSkew == 0 {
		tolerateSkew = mtglib.DefaultTolerateTimeSkewness
	}

	concurrency := uint(config.Concurrency)
	if concurrency == 0 {
		concurrency = mtglib.DefaultConcurrency
	}

	domainFrontingPort := uint(config.DomainFrontingPort)
	if domainFrontingPort == 0 {
		domainFrontingPort = mtglib.DefaultDomainFrontingPort
	}

	preferIP := config.PreferIp
	if preferIP == "" {
		preferIP = mtglib.DefaultPreferIP
	}

	opts := mtglib.ProxyOpts{
		Secret:                   secret,
		Network:                  h.xrayNet,
		AntiReplayCache:          antiReplayCache,
		IPBlocklist:              ipblocklist.NewNoop(),
		IPAllowlist:              ipblocklist.NewNoop(),
		EventStream:              events.NewNoopStream(),
		Logger:                   newXrayLogger(),
		Concurrency:              concurrency,
		TolerateTimeSkewness:     tolerateSkew,
		DomainFrontingPort:       domainFrontingPort,
		PreferIP:                 preferIP,
		AllowFallbackOnUnknownDC: config.AllowFallbackOnUnknownDc,
		AutoUpdate:               config.AutoUpdate,
	}

	proxy, err := mtglib.NewProxy(opts)
	if err != nil {
		return errors.New("failed to create mtproto proxy").Base(err)
	}

	h.proxy = proxy
	return nil
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.Name = "mtproto"
	}

	h.xrayNet.setContext(ctx)
	defer h.xrayNet.clearContext()

	h.proxy.ServeConn(essentials.WrapNetConn(conn))
	return nil
}
