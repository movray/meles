// Package source resolves image references to the platform images to scan,
// pulling directly from the registry without a Docker daemon.
package source

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// PlatformFilter selects the platforms of a multi-arch image. The zero
// value selects all platforms.
type PlatformFilter struct {
	specs []v1.Platform
}

// ParsePlatforms parses "all", "host" or a comma-separated list such as
// "linux/amd64,linux/arm64".
func ParsePlatforms(s string) (PlatformFilter, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "", "all":
		return PlatformFilter{}, nil
	case "host":
		return PlatformFilter{specs: []v1.Platform{{OS: "linux", Architecture: runtime.GOARCH}}}, nil
	}
	var f PlatformFilter
	for _, part := range strings.Split(s, ",") {
		p, err := v1.ParsePlatform(strings.TrimSpace(part))
		if err != nil {
			return PlatformFilter{}, fmt.Errorf("parse platform %q: %w", part, err)
		}
		if p.OS == "" || p.Architecture == "" {
			return PlatformFilter{}, fmt.Errorf("platform %q: want os/arch[/variant]", part)
		}
		f.specs = append(f.specs, *p)
	}
	return f, nil
}

// Match reports whether p is selected.
func (f PlatformFilter) Match(p v1.Platform) bool {
	if len(f.specs) == 0 {
		return true
	}
	for _, spec := range f.specs {
		if p.Satisfies(spec) {
			return true
		}
	}
	return false
}

func (f PlatformFilter) String() string {
	if len(f.specs) == 0 {
		return "all"
	}
	parts := make([]string, len(f.specs))
	for i, s := range f.specs {
		parts[i] = s.String()
	}
	return strings.Join(parts, ",")
}

// Image is a resolved image reference.
type Image struct {
	Ref string
	// Digest of the manifest or index the reference points to.
	Digest    string
	Platforms []PlatformImage
}

// PlatformImage is the image of one platform.
type PlatformImage struct {
	Platform string
	Digest   string
	Image    v1.Image
}

// ErrNoPlatform is returned when the filter matches no platform of an image.
var ErrNoPlatform = errors.New("no matching platform")

// Options configure Fetch.
type Options struct {
	Platforms PlatformFilter
	Keychain  authn.Keychain
	// Insecure allows plain HTTP registries (for tests and local registries).
	Insecure bool
}

// Fetch resolves ref and returns the selected platform images. Layers are
// fetched lazily when they are read.
func Fetch(ctx context.Context, ref string, opts Options) (*Image, error) {
	var nopts []name.Option
	if opts.Insecure {
		nopts = append(nopts, name.Insecure)
	}
	r, err := name.ParseReference(ref, nopts...)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	kc := opts.Keychain
	if kc == nil {
		kc = authn.DefaultKeychain
	}
	desc, err := remote.Get(r, remote.WithContext(ctx), remote.WithAuthFromKeychain(kc))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", ref, err)
	}

	img := &Image{Ref: ref, Digest: desc.Digest.String()}
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return nil, fmt.Errorf("read index %s: %w", ref, err)
		}
		im, err := idx.IndexManifest()
		if err != nil {
			return nil, fmt.Errorf("read index manifest %s: %w", ref, err)
		}
		for _, m := range im.Manifests {
			if m.MediaType.IsIndex() {
				return nil, fmt.Errorf("%s: nested image index %s is not supported", ref, m.Digest)
			}
			// BuildKit attestation manifests use the platform unknown/unknown.
			if m.Platform == nil || m.Platform.OS == "unknown" || !opts.Platforms.Match(*m.Platform) {
				continue
			}
			pi, err := idx.Image(m.Digest)
			if err != nil {
				return nil, fmt.Errorf("read image %s (%s): %w", ref, m.Platform, err)
			}
			img.Platforms = append(img.Platforms, PlatformImage{Platform: m.Platform.String(), Digest: m.Digest.String(), Image: pi})
		}
	} else {
		pi, err := desc.Image()
		if err != nil {
			return nil, fmt.Errorf("read image %s: %w", ref, err)
		}
		cf, err := pi.ConfigFile()
		if err != nil {
			return nil, fmt.Errorf("read config %s: %w", ref, err)
		}
		p := cf.Platform()
		if p == nil {
			p = &v1.Platform{OS: cf.OS, Architecture: cf.Architecture, Variant: cf.Variant}
		}
		if opts.Platforms.Match(*p) {
			img.Platforms = append(img.Platforms, PlatformImage{Platform: p.String(), Digest: desc.Digest.String(), Image: pi})
		}
	}
	if len(img.Platforms) == 0 {
		return nil, fmt.Errorf("%s: platforms %s: %w", ref, opts.Platforms, ErrNoPlatform)
	}
	return img, nil
}
