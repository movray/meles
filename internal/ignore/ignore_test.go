package ignore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

const (
	php    = "/usr/src/php.tar.xz"
	hashA  = "84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882"
	digest = "sha256:fe5166b04f217c9e3a263bfe76eef5e13de0dd3919966827de1b47bae2308b01"
)

func TestFind(t *testing.T) {
	rules, errs := New([]Rule{
		{Name: "php-quine", Path: php, Signature: "Heuristics.Limits.Exceeded.MaxRecursion", Reason: "PHP test file", Expires: "2027-06-30"},
		{Name: "xmrig-in-monitoring", Signature: "*.Coinminer.*", Image: "ghcr.io/acme/*", Reason: "miner detector test data", Expires: "2027-01-31"},
		{Name: "exact-file", SHA256: "sha256:" + strings.ToUpper(hashA), Reason: "reviewed", Expires: "2027-01-31"},
		{Name: "tools-dir", Path: "/opt/tools/**", Image: "nextcloud", Reason: "vendored tools", Expires: "2027-01-31"},
		{Name: "pinned-image", Path: "/x", Image: digest, Reason: "one release", Expires: "2027-01-31"},
		{Name: "old", Path: "/old", Reason: "was fine", Expires: "2026-10-01"},
	}, "test", now)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	nextcloud := Image{Repository: "docker.io/library/nextcloud", Digests: []string{digest}}
	acme := Image{Repository: "ghcr.io/acme/monitor"}
	tests := []struct {
		name string
		img  Image
		e    Entry
		want string // rule name, "" for none
		exp  bool
	}{
		{"php quine in any image", acme, Entry{Path: php, Signature: "Heuristics.Limits.Exceeded.MaxRecursion"}, "php-quine", false},
		{"php other limit", nextcloud, Entry{Path: php, Signature: "Heuristics.Limits.Exceeded.MaxScanTime"}, "", false},
		{"signature glob, right image", acme, Entry{Path: "/bin/xmrig", Signature: "Unix.Coinminer.Xmrig"}, "xmrig-in-monitoring", false},
		{"signature glob, other image", nextcloud, Entry{Path: "/bin/xmrig", Signature: "Unix.Coinminer.Xmrig"}, "", false},
		{"hash, any case", acme, Entry{Path: "/anything", Signature: "Eicar", SHA256: hashA}, "exact-file", false},
		{"** across segments, short Hub name", Image{Repository: "index.docker.io/library/nextcloud"}, Entry{Path: "/opt/tools/a/b/c"}, "tools-dir", false},
		{"* stays in its segment", nextcloud, Entry{Path: "/opt/toolsX/a"}, "", false},
		{"digest matches", nextcloud, Entry{Path: "/x"}, "pinned-image", false},
		{"digest does not match", acme, Entry{Path: "/x"}, "", false},
		{"expired rule counts again", acme, Entry{Path: "/old"}, "old", true},
	}
	for _, tt := range tests {
		m := rules.Find(tt.img, tt.e, now)
		got := ""
		if m != nil {
			got = m.Rule
		}
		if got != tt.want || (m != nil && m.Expired != tt.exp) {
			t.Errorf("%s: match %+v, want %q (expired %v)", tt.name, m, tt.want, tt.exp)
		}
	}
	if next := rules.NextExpiry(now); !next.Equal(time.Date(2027, 1, 31, 23, 59, 59, 999999999, time.UTC)) {
		t.Errorf("NextExpiry = %v", next)
	}
}

func TestInvalidRules(t *testing.T) {
	tests := map[string]Rule{
		"reason":     {Path: "/a", Expires: "2027-01-01"},
		"at least":   {Image: "nextcloud", Reason: "r", Expires: "2027-01-01"},
		"use a date": {Path: "/a", Reason: "r", Expires: "next year"},
		"year ahead": {Path: "/a", Reason: "r", Expires: "2028-01-01"},
		"64 hex":     {SHA256: "abc", Reason: "r", Expires: "2027-01-01"},
		"absolute":   {Path: "usr/bin/x", Reason: "r", Expires: "2027-01-01"},
	}
	for want, r := range tests {
		_, errs := New([]Rule{r}, "test", now)
		if len(errs) != 1 || !strings.Contains(errs[0].Error(), want) {
			t.Errorf("rule %+v: errors %v, want one with %q", r, errs, want)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	os.WriteFile(good, []byte(`rules:
  - name: php-quine
    path: /usr/src/php.tar.xz
    signature: Heuristics.Limits.Exceeded.MaxRecursion
    reason: ext/phar/tests/bug81726.gz unpacks to itself
    expires: "2027-06-30"
`), 0o600)
	rules, err := Load(good, now)
	if err != nil || rules.Len() != 1 {
		t.Fatalf("Load = %v, %v", rules, err)
	}
	// A typo must fail loudly, not silently match nothing.
	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte("rules:\n  - pth: /a\n    reason: r\n    expires: \"2027-01-01\"\n"), 0o600)
	if _, err := Load(bad, now); err == nil {
		t.Error("unknown field accepted")
	}
}
