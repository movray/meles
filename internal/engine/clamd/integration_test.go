//go:build integration

package clamd

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestRealClamd needs a running clamd, e.g.
// MELES_TEST_CLAMD=unix:///run/clamav/clamd.ctl go test -tags integration ./...
// For meles clamd-proxy (tls://) set MELES_CLAMD_TOKEN and MELES_CLAMD_CA.
func TestRealClamd(t *testing.T) {
	addr := os.Getenv("MELES_TEST_CLAMD")
	if addr == "" {
		t.Skip("MELES_TEST_CLAMD not set")
	}
	c, err := New(addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Token = os.Getenv("MELES_CLAMD_TOKEN")
	if ca := os.Getenv("MELES_CLAMD_CA"); ca != "" {
		if c.TLSConfig, err = LoadCA(ca); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	v, err := c.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("clamd: %s", v.Raw)

	s, err := c.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Built at runtime so this file does not trigger virus scanners.
	eicar := strings.Join([]string{`X5O!P%@AP[4\PZX54(P^)7CC)7}$`, "EICAR-STANDARD-ANTIVIRUS-", "TEST-FILE!$H+H*"}, "")
	sig, err := s.Scan(ctx, strings.NewReader(eicar))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sig, "Eicar") {
		t.Errorf("signature = %q, want an EICAR signature", sig)
	}
	sig, err = s.Scan(ctx, strings.NewReader("hello"))
	if err != nil || sig != "" {
		t.Errorf("clean stream: signature %q, err %v", sig, err)
	}
}
