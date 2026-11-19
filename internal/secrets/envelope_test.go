package secrets

import (
	"strings"
	"testing"
)

func TestDEKRoundTripAndVersions(t *testing.T) {
	box, dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	if len(dek) != 32 {
		t.Fatalf("dek len %d", len(dek))
	}
	got := box.Seal("refresh-token-value")
	if !IsV2(got) || IsV1(got) {
		t.Fatalf("want v2 got %q", got[:min(20, len(got))])
	}
	plain, err := box.Open(got)
	if err != nil || plain != "refresh-token-value" {
		t.Fatalf("open %q %v", plain, err)
	}
	other, err := BoxFromDEK(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(got); err == nil {
		t.Fatal("opened with a different DEK")
	}
}

func TestKEKWrapUnwrap(t *testing.T) {
	kek, err := NewLocalKEK(bytes32('k'), "test")
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes32('d')
	blob, err := kek.Wrap(dek)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(blob, wrapPrefix) {
		t.Fatalf("blob %q", blob)
	}
	out, err := kek.Unwrap(blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(dek) {
		t.Fatal("dek mismatch")
	}
	other, _ := NewLocalKEK(bytes32('x'), "other")
	if _, err := other.Unwrap(blob); err == nil {
		t.Fatal("unwrapped with the wrong KEK")
	}
}

func TestRedactEmail(t *testing.T) {
	if got := RedactEmail("ada@example.com"); got != "a***@example.com" {
		t.Fatalf("got %q", got)
	}
	if RedactEmail("") != "" {
		t.Fatal("empty")
	}
}

func bytes32(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
