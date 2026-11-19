// Package payloadenc encrypts outbound webhook bodies so only the receiver
// who holds the matching private key can read them.
package payloadenc

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
)

// Validate checks an age X25519 recipient (age1...).
func Validate(pub string) error {
	_, err := parse(pub)
	return err
}

func parse(pub string) (age.Recipient, error) {
	pub = strings.TrimSpace(pub)
	if pub == "" {
		return nil, fmt.Errorf("payload public key is empty")
	}
	rec, err := age.ParseX25519Recipient(pub)
	if err != nil {
		return nil, fmt.Errorf("payload public key must be an age X25519 recipient (age1...)")
	}
	return rec, nil
}

// Encrypt seals plain for the given age recipient.
func Encrypt(pub string, plain []byte) ([]byte, error) {
	rec, err := parse(pub)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rec)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decrypt is used by tests. Receivers decrypt with age on their side.
func Decrypt(ident age.Identity, ct []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ct), ident)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
