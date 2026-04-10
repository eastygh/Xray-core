package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/selector"
	"google.golang.org/protobuf/proto"
)

type SelectorRule struct {
	Match         string `json:"match"`   // exact SNI or empty for catch-all
	Pattern       string `json:"pattern"` // regex SNI (takes priority over match)
	HandlerTag    string `json:"handlerTag"`
	LoopbackAddr  string `json:"loopbackAddr"`
	ProxyProtocol uint32 `json:"proxyProtocol"`
}

type SelectorConfig struct {
	Rules             []*SelectorRule `json:"rules"`
	DefaultHandlerTag string          `json:"defaultHandlerTag"`
	ReadSize          int32           `json:"readSize"`
	PeekTimeoutMs     int32           `json:"peekTimeoutMs"`
	MinPeekSize       int32           `json:"minPeekSize"`
}

func (c *SelectorConfig) Build() (proto.Message, error) {
	config := &selector.Config{
		DefaultHandlerTag: c.DefaultHandlerTag,
		ReadSize:          c.ReadSize,
		PeekTimeoutMs:     c.PeekTimeoutMs,
		MinPeekSize:       c.MinPeekSize,
	}

	config.Rules = make([]*selector.Rule, len(c.Rules))
	for i, r := range c.Rules {
		if r.ProxyProtocol > 2 {
			return nil, errors.New("selector rule: invalid proxyProtocol, only 0, 1, 2 are accepted")
		}
		config.Rules[i] = &selector.Rule{
			Match:         r.Match,
			Pattern:       r.Pattern,
			HandlerTag:    r.HandlerTag,
			LoopbackAddr:  r.LoopbackAddr,
			ProxyProtocol: r.ProxyProtocol,
		}
	}

	return config, nil
}
