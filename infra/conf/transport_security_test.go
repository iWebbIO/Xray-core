package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestTLSConfigAllowInsecure(t *testing.T) {
	config := new(TLSConfig)
	if err := json.Unmarshal([]byte(`{"allowInsecure": true}`), config); err != nil {
		t.Fatal(err)
	}
	message, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, ok := message.(*xraytls.Config)
	if !ok {
		t.Fatalf("unexpected message type %T", message)
	}
	if !tlsConfig.AllowInsecure {
		t.Fatal("allowInsecure was not applied to the core TLS config")
	}
}
