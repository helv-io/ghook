package config

import "testing"

func TestAuthModeDefault(t *testing.T) {
	if got := normalizeMode("", true); got != AuthOIDC {
		t.Fatal(got)
	}
	if got := normalizeMode("", false); got != AuthNone {
		t.Fatal(got)
	}
	if got := normalizeMode("PROXY", false); got != AuthProxy {
		t.Fatal(got)
	}
	if got := normalizeMode("none", true); got != AuthNone {
		t.Fatal(got)
	}
}

func TestTrustedProxyDefaults(t *testing.T) {
	c := &Config{Trust: parseTrust("")}
	if !c.TrustedProxy("10.1.2.3:443") || !c.TrustedProxy("172.18.0.2:80") || !c.TrustedProxy("127.0.0.1:9") || !c.TrustedProxy("[::1]:80") {
		t.Fatal("private peers must be trusted")
	}
	if c.TrustedProxy("8.8.8.8:443") || c.TrustedProxy("") || c.TrustedProxy("not-an-ip") {
		t.Fatal("public or empty peers must not be trusted")
	}
	narrow := &Config{Trust: parseTrust("192.168.1.1")}
	if !narrow.TrustedProxy("192.168.1.1:1") || narrow.TrustedProxy("192.168.1.2:1") || narrow.TrustedProxy("10.0.0.1:1") {
		t.Fatal("an explicit list replaces the defaults")
	}
}
