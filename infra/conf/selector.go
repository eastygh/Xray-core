package conf

import (
	"github.com/xtls/xray-core/proxy/selector"
	"google.golang.org/protobuf/proto"
)

type SelectorRule struct {
	Match      string `json:"match"`
	Pattern    string `json:"pattern"`
	HandlerTag string `json:"handlerTag"`
}

type SelectorConfig struct {
	Rules             []*SelectorRule `json:"rules"`
	DefaultHandlerTag string          `json:"defaultHandlerTag"`
	ReadSize          int32           `json:"readSize"`
}

func (c *SelectorConfig) Build() (proto.Message, error) {
	config := &selector.Config{
		DefaultHandlerTag: c.DefaultHandlerTag,
		ReadSize:          c.ReadSize,
	}

	config.Rules = make([]*selector.Rule, len(c.Rules))
	for i, r := range c.Rules {
		config.Rules[i] = &selector.Rule{
			Match:      r.Match,
			Pattern:    r.Pattern,
			HandlerTag: r.HandlerTag,
		}
	}

	return config, nil
}
