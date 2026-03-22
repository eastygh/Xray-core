package conf

import (
	"github.com/xtls/xray-core/proxy/mtproto"
	"google.golang.org/protobuf/proto"
)

type MTProtoConfig struct {
	Secret                      string `json:"secret"`
	Concurrency                 uint32 `json:"concurrency"`
	AllowFallbackOnUnknownDC    bool   `json:"allowFallbackOnUnknownDC"`
	PreferIP                    string `json:"preferIP"`
	AutoUpdate                  bool   `json:"autoUpdate"`
	DomainFrontingPort          uint32 `json:"domainFrontingPort"`
	TolerateTimeSkewnessSeconds uint32 `json:"tolerateTimeSkewnessSeconds"`
	AntiReplay                  *bool  `json:"antiReplay"`
}

func (c *MTProtoConfig) Build() (proto.Message, error) {
	config := &mtproto.Config{
		Secret:                      c.Secret,
		Concurrency:                 c.Concurrency,
		AllowFallbackOnUnknownDc:    c.AllowFallbackOnUnknownDC,
		PreferIp:                    c.PreferIP,
		AutoUpdate:                  c.AutoUpdate,
		DomainFrontingPort:          c.DomainFrontingPort,
		TolerateTimeSkewnessSeconds: c.TolerateTimeSkewnessSeconds,
	}

	// Default anti-replay to true
	if c.AntiReplay == nil || *c.AntiReplay {
		config.AntiReplay = true
	}

	return config, nil
}
