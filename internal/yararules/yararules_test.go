package yararules

import (
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	tests := []struct {
		sig    string
		ok     bool
		author string
	}{
		{"YARA.SIGNATURE_BASE_XMRIG_Monero_Miner.UNOFFICIAL", true, "Florian Roth (Nextron Systems)"},
		{"YARA.SIGNATURE_BASE_XMRIG_Monero_Miner", true, "Florian Roth (Nextron Systems)"},
		{"YARA.Own_Team_Rule.UNOFFICIAL", false, ""},
		{"Eicar-Signature", false, ""},
		{"SIGNATURE_BASE_XMRIG_Monero_Miner", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.sig, func(t *testing.T) {
			info, ok := Lookup(tt.sig)
			if ok != tt.ok || info.Author != tt.author {
				t.Fatalf("Lookup = %+v, %v; want author %q, %v", info, ok, tt.author, tt.ok)
			}
			if ok && (info.Name != "SIGNATURE_BASE_XMRIG_Monero_Miner" || info.License != "DRL-1.1" || !strings.HasPrefix(info.URL, "https://")) {
				t.Fatalf("Lookup = %+v", info)
			}
		})
	}
}

func TestIndexComplete(t *testing.T) {
	if Len() < 100 {
		t.Fatalf("index has %d rules", Len())
	}
	for name, info := range index {
		if info.Author == "" || info.License == "" || info.URL == "" {
			t.Errorf("%s: incomplete %+v", name, info)
		}
	}
}
