// Package source resolves image references to the platform images to scan,
// pulling directly from the registry without a Docker daemon.
package source

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	// Mirrors are tried in order before the registry itself, which is the
	// fallback if all fail (as containerd does).
	Mirrors []Mirror
	// Logger notes failed mirrors; nil for none.
	Logger *slog.Logger
}

// Mirror serves the images of Registry under Prefix, e.g. a Harbor proxy
// cache project for Docker Hub: docker.io=harbor.example.com/dockerhub
// pulls docker.io/library/nginx from harbor.example.com/dockerhub/library/nginx.
// A mirror is trusted for tags; digests are verified.
type Mirror struct {
	Registry string
	Prefix   string
}

// ParseMirror parses "registry=host[/path]".
func ParseMirror(s string) (Mirror, error) {
	reg, prefix, ok := strings.Cut(strings.TrimSpace(s), "=")
	reg, prefix = strings.TrimSpace(reg), strings.Trim(strings.TrimSpace(prefix), "/")
	if !ok || reg == "" || prefix == "" || strings.Contains(reg, "/") || strings.Contains(prefix, "://") {
		return Mirror{}, fmt.Errorf("registry mirror %q: want registry=host[/path], e.g. docker.io=harbor.example.com/dockerhub", s)
	}
	return Mirror{Registry: reg, Prefix: prefix}, nil
}

func (m Mirror) String() string { return m.Registry + "=" + m.Prefix }

// mirrored returns r with its registry replaced by the mirror's prefix, or
// false if the mirror is not for r's registry.
func (m Mirror) mirrored(r name.Reference, nopts []name.Option) (name.Reference, bool, error) {
	reg := m.Registry
	if reg == "docker.io" {
		reg = name.DefaultRegistry
	}
	if r.Context().RegistryStr() != reg {
		return nil, false, nil
	}
	ref := m.Prefix + "/" + r.Context().RepositoryStr()
	switch v := r.(type) {
	case name.Digest:
		ref += "@" + v.DigestStr()
	case name.Tag:
		ref += ":" + v.TagStr()
	}
	mr, err := name.ParseReference(ref, nopts...)
	if err != nil {
		return nil, false, fmt.Errorf("mirror %s: %w", m, err)
	}
	return mr, true, nil
}

// get fetches the descriptor of r, from its mirrors first.
func get(ctx context.Context, r name.Reference, nopts []name.Option, opts Options, ropts ...remote.Option) (*remote.Descriptor, error) {
	var mirrorErrs []string
	for _, m := range opts.Mirrors {
		mr, ok, err := m.mirrored(r, nopts)
		if !ok {
			if err != nil {
				mirrorErrs = append(mirrorErrs, err.Error())
			}
			continue
		}
		desc, err := remote.Get(mr, ropts...)
		if err == nil {
			if d, isDigest := r.(name.Digest); isDigest && desc.Digest.String() != d.DigestStr() {
				err = fmt.Errorf("served %s instead of %s", desc.Digest, d.DigestStr())
			} else {
				return desc, nil
			}
		}
		mirrorErrs = append(mirrorErrs, fmt.Sprintf("mirror %s: %v", mr, err))
		if opts.Logger != nil {
			opts.Logger.Warn("registry mirror failed, pulling from the registry", "ref", r.String(), "mirror", mr.String(), "err", err)
		}
	}
	desc, err := remote.Get(r, ropts...)
	if err != nil && len(mirrorErrs) > 0 {
		return nil, fmt.Errorf("%w (%s)", err, strings.Join(mirrorErrs, "; "))
	}
	return desc, err
}

// Resolve returns the repository and the digest a reference points to now,
// without fetching the image: for a tag, the digest of the manifest or index
// the registry serves, as the kubelet would pull it. If only the lookup
// fails, the repository is returned with the error.
func Resolve(ctx context.Context, ref string, opts Options) (repository, digest string, err error) {
	var nopts []name.Option
	if opts.Insecure {
		nopts = append(nopts, name.Insecure)
	}
	r, err := name.ParseReference(ref, nopts...)
	if err != nil {
		return "", "", fmt.Errorf("parse reference %q: %w", ref, err)
	}
	repository = r.Context().Name()
	if reg := r.Context().RegistryStr(); reg == name.DefaultRegistry {
		// As the kubelet reports it.
		repository = "docker.io/" + r.Context().RepositoryStr()
	}
	if d, ok := r.(name.Digest); ok {
		return repository, d.DigestStr(), nil
	}
	kc := opts.Keychain
	if kc == nil {
		kc = authn.DefaultKeychain
	}
	if len(opts.Mirrors) > 0 {
		d, err := get(ctx, r, nopts, opts, remote.WithContext(ctx), remote.WithAuthFromKeychain(kc))
		if err != nil {
			return repository, "", fmt.Errorf("resolve %s: %w", ref, err)
		}
		return repository, d.Digest.String(), nil
	}
	desc, err := remote.Head(r, remote.WithContext(ctx), remote.WithAuthFromKeychain(kc))
	if err != nil {
		// Some registries answer HEAD poorly.
		d, gerr := remote.Get(r, remote.WithContext(ctx), remote.WithAuthFromKeychain(kc))
		if gerr != nil {
			return repository, "", fmt.Errorf("resolve %s: %w", ref, gerr)
		}
		return repository, d.Digest.String(), nil
	}
	return repository, desc.Digest.String(), nil
}

// Fetch resolves ref and returns the selected platform images. Layers are
// fetched lazily when they are read; a layer download that breaks off is
// resumed with an HTTP Range request.
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
	// Layers are read through this transport too: it resumes downloads that
	// break off while meles waits for clamd.
	rt := newResumingTransport(remote.DefaultTransport, opts.Logger)
	desc, err := get(ctx, r, nopts, opts, remote.WithContext(ctx), remote.WithAuthFromKeychain(kc), remote.WithTransport(rt))
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
			if m.Platform != nil && (m.Platform.OS == "unknown" || !opts.Platforms.Match(*m.Platform)) {
				continue
			}
			pi, err := idx.Image(m.Digest)
			if err != nil {
				return nil, fmt.Errorf("read image %s (%s): %w", ref, m.Digest, err)
			}
			p := m.Platform
			if p == nil {
				// Like containerd, take the platform from the config
				// instead of skipping the entry.
				if p, err = configPlatform(pi); err != nil {
					return nil, fmt.Errorf("%s: index entry %s without platform: %w", ref, m.Digest, err)
				}
				// Without an OS (e.g. OCI artifacts) no runtime runs it.
				if p.OS == "" || p.OS == "unknown" || !opts.Platforms.Match(*p) {
					continue
				}
			}
			img.Platforms = append(img.Platforms, PlatformImage{Platform: p.String(), Digest: m.Digest.String(), Image: pi})
		}
	} else {
		pi, err := desc.Image()
		if err != nil {
			return nil, fmt.Errorf("read image %s: %w", ref, err)
		}
		p, err := configPlatform(pi)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ref, err)
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

// configPlatform reads the platform of an image from its config.
func configPlatform(img v1.Image) (*v1.Platform, error) {
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	p := cf.Platform()
	if p == nil {
		p = &v1.Platform{OS: cf.OS, Architecture: cf.Architecture, Variant: cf.Variant}
	}
	return p, nil
}
