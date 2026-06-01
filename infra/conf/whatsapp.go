package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/whatsapp"
	"google.golang.org/protobuf/proto"
)

type WhatsAppConfig struct {
	ChatHost      string   `json:"chatHost"`
	ChatPort      uint32   `json:"chatPort"`
	MediaHost     string   `json:"mediaHost"`
	MediaPort     uint32   `json:"mediaPort"`
	ChatPorts     []uint32 `json:"chatPorts"`
	MediaPorts    []uint32 `json:"mediaPorts"`
	SniffSNI      *bool    `json:"sniffSNI"`
	DefaultTarget string   `json:"defaultTarget"`
}

func (c *WhatsAppConfig) Build() (proto.Message, error) {
	cfg := &whatsapp.Config{
		ChatHost:   c.ChatHost,
		ChatPort:   c.ChatPort,
		MediaHost:  c.MediaHost,
		MediaPort:  c.MediaPort,
		ChatPorts:  c.ChatPorts,
		MediaPorts: c.MediaPorts,
	}

	// Default sniffSNI to true: this is the entire reason a single inbound can
	// transparently split chat and media on port 443.
	if c.SniffSNI == nil || *c.SniffSNI {
		cfg.SniffSni = true
	}

	switch strings.ToLower(c.DefaultTarget) {
	case "", "chat":
		cfg.DefaultTarget = whatsapp.Target_TARGET_CHAT
	case "media":
		cfg.DefaultTarget = whatsapp.Target_TARGET_MEDIA
	default:
		return nil, errors.New("whatsapp: unknown defaultTarget ", c.DefaultTarget)
	}

	return cfg, nil
}
