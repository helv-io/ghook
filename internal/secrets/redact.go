package secrets

import "strings"

// RedactEmail hides a local-part so logs and metrics can name an address
// without repeating it. "ada@example.com" becomes "a***@example.com".
// The empty string stays empty. Values without "@" are replaced with "***".
func RedactEmail(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 {
		return "***"
	}
	local, host := s[:at], s[at+1:]
	if local == "" {
		return "***@" + host
	}
	return string(local[0]) + "***@" + host
}

// LooksLikeSecret is a conservative test used when scrubbing log lines.
func LooksLikeSecret(s string) bool {
	if IsSealed(s) || strings.HasPrefix(s, wrapPrefix) {
		return true
	}
	if strings.HasPrefix(s, "ya29.") || strings.HasPrefix(s, "1//") {
		return true
	}
	return false
}
