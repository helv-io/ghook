package config

import (
	"net"
	"os"
	"strings"
)

// Auth modes. AUTH_MODE picks one. When it is unset, OIDC is used if the
// OIDC variables are set, and otherwise nobody has to sign in.
const (
	AuthOIDC  = "oidc"
	AuthProxy = "proxy"
	AuthNone  = "none"
)

// Proxy header defaults match Authelia's forward-auth headers.
const (
	DefaultProxyUser   = "Remote-User"
	DefaultProxyEmail  = "Remote-Email"
	DefaultProxyName   = "Remote-Name"
	DefaultProxyGroups = "Remote-Groups"
)

// Config gains the auth fields in Load. They live here so the mode rules are
// next to the tests.
func (c *Config) applyAuth() {
	c.AuthMode = normalizeMode(strings.TrimSpace(os.Getenv("AUTH_MODE")), c.OIDCEnabled())
	c.ProxyUser = env("AUTH_PROXY_HEADER", DefaultProxyUser)
	c.ProxyEmail = env("AUTH_PROXY_EMAIL_HEADER", DefaultProxyEmail)
	c.ProxyName = env("AUTH_PROXY_NAME_HEADER", DefaultProxyName)
	c.ProxyGroups = env("AUTH_PROXY_GROUPS_HEADER", DefaultProxyGroups)
	c.ProxyFallback = strings.TrimSpace(os.Getenv("PROXY_FALLBACK_USER"))
	c.Trust = parseTrust(os.Getenv("AUTH_TRUSTED_PROXIES"))
}

// Mode is the auth mode actually in effect.
func (c *Config) Mode() string {
	if c == nil {
		return AuthNone
	}
	if c.AuthMode != "" {
		return c.AuthMode
	}
	if c.OIDCEnabled() {
		return AuthOIDC
	}
	return AuthNone
}

func normalizeMode(raw string, oidc bool) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case AuthOIDC:
		return AuthOIDC
	case AuthProxy:
		return AuthProxy
	case AuthNone:
		return AuthNone
	}
	if oidc {
		return AuthOIDC
	}
	return AuthNone
}

func parseTrust(raw string) []*net.IPNet {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7"
	}
	var out []*net.IPNet
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			if _, n, err := net.ParseCIDR(p); err == nil {
				out = append(out, n)
			}
			continue
		}
		if ip := net.ParseIP(p); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return out
}

// TrustedProxy reports whether the TCP peer (host or host:port) may set the
// proxy identity headers. An empty address is not trusted.
func (c *Config) TrustedProxy(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	for _, n := range c.Trust {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
