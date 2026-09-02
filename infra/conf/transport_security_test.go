package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
)

func TestVLessOutboundXorenTransportWithoutTLS(t *testing.T) {
	config := new(OutboundDetourConfig)
	input := `{
		"protocol": "vless",
		"settings": {
			"vnext": [{
				"address": "example.com",
				"port": 443,
				"users": [{
					"id": "27848739-7e62-4138-9fd3-098a63964b6b",
					"encryption": "none"
				}]
			}]
		},
		"streamSettings": {
			"network": "xoren",
			"xorenSettings": {
				"key": [1, 2, 3]
			}
		}
	}`
	if err := json.Unmarshal([]byte(input), config); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Build(); err != nil {
		t.Fatal("vless over xoren transport without TLS should build: ", err)
	}
}

func TestVLessOutboundPlainTCPWithoutTLSProhibited(t *testing.T) {
	config := new(OutboundDetourConfig)
	input := `{
		"protocol": "vless",
		"settings": {
			"vnext": [{
				"address": "example.com",
				"port": 443,
				"users": [{
					"id": "27848739-7e62-4138-9fd3-098a63964b6b",
					"encryption": "none"
				}]
			}]
		}
	}`
	if err := json.Unmarshal([]byte(input), config); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Build(); err == nil {
		t.Fatal("vless over plain TCP without TLS should be rejected")
	}
}
