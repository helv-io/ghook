package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// wrapPrefix is a DEK wrapped by a KEK. Not a user-data ciphertext.
const wrapPrefix = "wrap:v1:"

// KEK wraps and unwraps per-user data-encryption keys. LocalKEK uses the
// instance secrets.key / SECRETS_KEY. A GCP KMS (or other) implementation
// can be swapped in later without changing callers.
type KEK interface {
	ID() string
	Wrap(dek []byte) (string, error)
	Unwrap(blob string) ([]byte, error)
}

// LocalKEK is AES-256-GCM over a 32-byte instance key.
type LocalKEK struct {
	id  string
	key []byte
}

// NewLocalKEK builds a KEK from a 32-byte key. id names the source
// (for example "secrets.key") without including key material.
func NewLocalKEK(key []byte, id string) (*LocalKEK, error) {
	if len(key) != 32 {
		return nil, errors.New("secrets: KEK must be 32 bytes")
	}
	if id == "" {
		id = "local"
	}
	k := make([]byte, 32)
	copy(k, key)
	return &LocalKEK{id: id, key: k}, nil
}

// ID is a non-secret name for this KEK.
func (k *LocalKEK) ID() string { return k.id }

// Wrap encrypts a 32-byte DEK.
func (k *LocalKEK) Wrap(dek []byte) (string, error) {
	if k == nil {
		return "", errors.New("secrets: no KEK")
	}
	if len(dek) != 32 {
		return "", errors.New("secrets: DEK must be 32 bytes")
	}
	blk, err := aes.NewCipher(k.key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nonce, nonce, dek, []byte("ghook/dek/v1"))
	return wrapPrefix + base64.RawURLEncoding.EncodeToString(ct), nil
}

// Unwrap decrypts a blob from Wrap.
func (k *LocalKEK) Unwrap(blob string) ([]byte, error) {
	if k == nil {
		return nil, errors.New("secrets: no KEK")
	}
	if !strings.HasPrefix(blob, wrapPrefix) {
		return nil, errors.New("secrets: malformed wrapped DEK")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(blob, wrapPrefix))
	if err != nil {
		return nil, errors.New("secrets: malformed wrapped DEK")
	}
	blk, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(raw) < ns+aead.Overhead() {
		return nil, errors.New("secrets: malformed wrapped DEK")
	}
	pt, err := aead.Open(nil, raw[:ns], raw[ns:], []byte("ghook/dek/v1"))
	if err != nil {
		return nil, errors.New("secrets: cannot unwrap DEK (wrong KEK?)")
	}
	if len(pt) != 32 {
		return nil, errors.New("secrets: unwrapped DEK is the wrong size")
	}
	return pt, nil
}

// NewDEK returns a Box that seals as enc:v2: with a fresh random key.
func NewDEK() (*Box, []byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, nil, err
	}
	b, err := newWithPrefix(k, prefixV2)
	return b, k, err
}

// BoxFromDEK builds a v2 box from an existing 32-byte DEK.
func BoxFromDEK(dek []byte) (*Box, error) {
	return newWithPrefix(dek, prefixV2)
}

// RotateLocalKEKFile writes a new key to keyFile+".new", leaving the previous
// file in place until the caller re-wraps DEKs and replaces it. The new key
// bytes are returned so the caller can re-wrap; they must not be logged.
func RotateLocalKEKFile(keyFile string) (newKEK *LocalKEK, dek []byte, err error) {
	if keyFile == "" {
		return nil, nil, errors.New("secrets: no key file to rotate")
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, nil, err
	}
	tmp := keyFile + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, err
	}
	_, werr := f.WriteString(base64.RawStdEncoding.EncodeToString(k) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return nil, nil, werr
	}
	kek, err := NewLocalKEK(k, keyFile)
	if err != nil {
		return nil, nil, err
	}
	return kek, k, nil
}

// InstallRotatedKEKFile moves keyFile to keyFile+".bak" and the .new file into place.
func InstallRotatedKEKFile(keyFile string) error {
	bak := keyFile + ".bak"
	_ = os.Remove(bak)
	if err := os.Rename(keyFile, bak); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("secrets: could not keep previous KEK as .bak: %w", err)
	}
	if err := os.Rename(keyFile+".new", keyFile); err != nil {
		return err
	}
	return nil
}
