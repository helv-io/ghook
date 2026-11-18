// Package secrets encrypts small values before they are written to SQLite.
// AES-256-GCM, a random nonce per value, stored as "enc:v1:" plus base64url.
//
// The key comes from SECRETS_KEY (base64 of 32 bytes, or a passphrase stretched
// with scrypt) or, when that is unset, from a random key file created next to
// the database on first run.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const prefix = "enc:v1:"

// Box seals and opens values with one key.
type Box struct {
	aead cipher.AEAD
	key  []byte
}

// New builds a Box from a 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("secrets: key must be 32 bytes")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	k := make([]byte, 32)
	copy(k, key)
	return &Box{aead: a, key: k}, nil
}

// Derive returns a box whose key is bound to one workspace. A secret sealed
// for workspace A does not open in workspace B. The instance key stays in /data.
func (b *Box) Derive(workspaceID int64) *Box {
	if b == nil || workspaceID == 0 {
		return b
	}
	m := hmac.New(sha256.New, b.key)
	_, _ = fmt.Fprintf(m, "ghook/workspace/%d", workspaceID)
	out, err := New(m.Sum(nil))
	if err != nil {
		panic(err)
	}
	return out
}

// FromString builds the Box for a SECRETS_KEY value.
func FromString(s string) (*Box, error) {
	key := KeyFromString(s)
	return New(key)
}

// Ephemeral returns a Box with a random key that is lost on exit.
func Ephemeral() *Box {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	b, err := New(k)
	if err != nil {
		panic(err)
	}
	return b
}

// KeyFromString turns SECRETS_KEY into a key. Base64 of exactly 32 bytes is used
// as is. Anything else is a passphrase stretched with scrypt.
func KeyFromString(s string) []byte {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b
		}
	}
	k, err := scrypt.Key([]byte(s), []byte("ghook/secrets/v1"), 1<<15, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// LoadOrCreate returns the Box for envKey when set, else for the key file, which
// is created with mode 0600 when missing. The second result names the source.
func LoadOrCreate(envKey, keyFile string) (*Box, string, error) {
	if strings.TrimSpace(envKey) != "" {
		b, err := FromString(envKey)
		return b, "SECRETS_KEY", err
	}
	if keyFile == "" {
		return Ephemeral(), "ephemeral", nil
	}
	raw, err := os.ReadFile(keyFile)
	if err == nil {
		k, derr := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if derr != nil || len(k) != 32 {
			return nil, "", fmt.Errorf("secrets: %s is not a valid key file", keyFile)
		}
		b, nerr := New(k)
		return b, keyFile, nerr
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, "", err
	}
	f, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadOrCreate("", keyFile)
		}
		return nil, "", err
	}
	_, werr := f.WriteString(base64.RawStdEncoding.EncodeToString(k) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return nil, "", werr
	}
	b, err := New(k)
	return b, keyFile + " (created)", err
}

// IsSealed reports whether s is in the sealed form.
func IsSealed(s string) bool { return strings.HasPrefix(s, prefix) }

// Seal encrypts plain. The empty string stays empty.
func (b *Box) Seal(plain string) string {
	if plain == "" || b == nil {
		return ""
	}
	nonce := make([]byte, b.aead.NonceSize())
	_, _ = rand.Read(nonce)
	ct := b.aead.Seal(nonce, nonce, []byte(plain), nil)
	return prefix + base64.RawURLEncoding.EncodeToString(ct)
}

// Open decrypts a sealed value. A value without the prefix is returned unchanged
// so a row written before sealing still opens. A sealed value that fails
// authentication is an error.
func (b *Box) Open(s string) (string, error) {
	if !strings.HasPrefix(s, prefix) {
		return s, nil
	}
	if b == nil {
		return "", errors.New("secrets: no key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	ns := b.aead.NonceSize()
	if err != nil || len(raw) < ns+b.aead.Overhead() {
		return "", errors.New("secrets: malformed value")
	}
	pt, err := b.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", errors.New("secrets: cannot decrypt (wrong SECRETS_KEY or key file?)")
	}
	return string(pt), nil
}
