package store

import "github.com/helv-io/ghook/internal/payloadenc"

// ValidatePayloadPubKey checks an optional age recipient used to encrypt
// outbound webhook bodies.
func ValidatePayloadPubKey(pub string) error {
	return payloadenc.Validate(pub)
}
