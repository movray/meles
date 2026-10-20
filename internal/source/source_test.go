package source

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestParsePlatforms(t *testing.T) {
	amd := v1.Platform{OS: "linux", Architecture: "amd64"}
	arm := v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	tests := []struct {
		in       string
		wantErr  bool
		matchAmd bool
		matchArm bool
	}{
		{"all", false, true, true},
		{"", false, true, true},
		{"linux/amd64", false, true, false},
		{"linux/arm64", false, false, true},
		{"linux/arm64/v8", false, false, true},
		{"linux/amd64, linux/arm64", false, true, true},
		{"linux", true, false, false},
	}
	for _, tt := range tests {
		f, err := ParsePlatforms(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParsePlatforms(%q) err = %v", tt.in, err)
			continue
		}
		if err != nil {
			continue
		}
		if f.Match(amd) != tt.matchAmd || f.Match(arm) != tt.matchArm {
			t.Errorf("%q: Match(amd64) = %v, Match(arm64) = %v", tt.in, f.Match(amd), f.Match(arm))
		}
	}
}
