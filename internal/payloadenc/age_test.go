package payloadenc

import (
	"bytes"
	"testing"

	"filippo.io/age"
)

func TestEncryptRoundTrip(t *testing.T) {
	ident, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pub := ident.Recipient().String()
	if err := Validate(pub); err != nil {
		t.Fatal(err)
	}
	if err := Validate("not-a-key"); err == nil {
		t.Fatal("accepted junk")
	}
	ct, err := Encrypt(pub, []byte(`{"source":"ghook"}`))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("ghook")) {
		t.Fatal("plaintext leaked into the ciphertext")
	}
	pt, err := Decrypt(ident, ct)
	if err != nil || string(pt) != `{"source":"ghook"}` {
		t.Fatalf("decrypt %q %v", pt, err)
	}
}
