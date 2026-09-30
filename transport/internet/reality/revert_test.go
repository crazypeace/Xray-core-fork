package reality_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xreality "github.com/xtls/xray-core/transport/internet/reality"
)

// TestForkServerConfigHasNoMinClientVer guards the minClientVer revert: the
// server must not silently carry a default minimum client version.
//
// Reverts Xray-core #6508-era behavior (REALITY server: Set default
// "minClientVer": "26.3.27").
func TestForkServerConfigHasNoMinClientVer(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &xreality.Config{
		PrivateKey:  serverPriv.Bytes(),
		ServerNames: []string{"example.com"},
		ShortIds:    [][]byte{make([]byte, 8)},
	}
	if got := cfg.GetREALITYConfig(); len(got.MinClientVer) != 0 {
		t.Fatalf("expected no default MinClientVer, got %v", got.MinClientVer)
	}
}

// TestVendoredRealityHasNoMLKEMKeyShareRequirement guards the reversion of
// upstream xtls/reality@8cdf7bf ("REALITY protocol: Reject outdated/strange
// Client Hello that doesn't have X25519MLKEM768 before optional X25519").
//
// That commit made the server drop the ClientHello unless an X25519MLKEM768
// key_share preceded X25519. This fork vendors the pre-restriction tls.go, so
// the rejection branch (the peerPub2 sentinel) must be absent while the
// original key_share selection must remain.
func TestVendoredRealityHasNoMLKEMKeyShareRequirement(t *testing.T) {
	path := filepath.Join("..", "..", "..", "third_party", "reality", "tls.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("vendored reality source not available: %v", err)
	}
	code := string(src)

	if strings.Contains(code, "peerPub2") {
		t.Error("vendored reality/tls.go still contains the X25519MLKEM768 key_share rejection logic")
	}
	if strings.Contains(code, "reject outdated/strange Client Hello") {
		t.Error("vendored reality/tls.go still rejects Client Hello without X25519MLKEM768")
	}

	// The pre-restriction logic must still be present: prefer a standalone
	// X25519 key_share, and fall back to the X25519 half of the hybrid share.
	for _, want := range []string{
		"keyShare.group == X25519 && len(keyShare.data) == 32",
		"keyShare.group == X25519MLKEM768 && len(keyShare.data) == mlkem.EncapsulationKeySize768+32",
		"peerPub = keyShare.data[mlkem.EncapsulationKeySize768:]",
	} {
		if !strings.Contains(code, want) {
			t.Errorf("vendored reality/tls.go is missing expected key_share handling: %q", want)
		}
	}
}
