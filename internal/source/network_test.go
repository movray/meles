package source

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestPolicyCheck(t *testing.T) {
	opts := Options{
		Network: Network{Restrict: true, AllowPrivate: []string{"harbor.example.com", "reg.example.com:5000", "*.ecr.example.com", "10.20.0.0/16"}},
		Mirrors: []Mirror{{Registry: "docker.io", Prefix: "mirror.example.com:8443/dockerhub"}},
	}
	p := policyFrom(withPolicy(context.Background(), opts))
	for _, c := range []struct {
		host, port, addr string
		ok               bool
	}{
		{"ghcr.io", "443", "140.82.121.34", true},
		{"evil.example.com", "443", "10.43.0.10", false},
		{"evil.example.com", "443", "192.168.1.1", false},
		{"evil.example.com", "443", "100.100.100.200", false}, // CGNAT, Alibaba metadata
		{"evil.example.com", "443", "fd00:ec2::254", false},   // ULA, AWS metadata (IPv6)
		{"harbor.example.com", "443", "192.168.5.31", true},
		{"HARBOR.example.com.", "443", "192.168.5.31", true},
		{"reg.example.com", "5000", "10.1.1.1", true},
		{"reg.example.com", "443", "10.1.1.1", false},
		{"x.ecr.example.com", "443", "10.1.1.1", true},
		{"ecr.example.com", "443", "10.1.1.1", false},
		{"mirror.example.com", "8443", "10.1.1.1", true},
		{"other.example.com", "443", "10.20.3.4", true},
		{"other.example.com", "443", "10.21.3.4", false},
		// Never, not even for allowed hosts.
		{"harbor.example.com", "443", "127.0.0.1", false},
		{"harbor.example.com", "443", "169.254.169.254", false},
		{"harbor.example.com", "443", "::1", false},
		{"harbor.example.com", "443", "::ffff:127.0.0.1", false},
		{"harbor.example.com", "443", "fe80::1", false},
		{"harbor.example.com", "443", "0.0.0.0", false},
		{"harbor.example.com", "443", "0.1.2.3", false},
	} {
		err := p.check(c.host, c.port, netip.MustParseAddr(c.addr))
		if (err == nil) != c.ok {
			t.Errorf("%s:%s -> %s: err = %v, want allowed %v", c.host, c.port, c.addr, err, c.ok)
		}
		if err != nil && !errors.Is(err, errBlocked) {
			t.Errorf("%s: error %v does not wrap errBlocked", c.addr, err)
		}
	}
}

func TestParseAllowPrivate(t *testing.T) {
	got, err := ParseAllowPrivate([]string{" Harbor.example.com ", "", "10.0.0.0/8", "*.example.com", "reg:5000"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "harbor.example.com,10.0.0.0/8,*.example.com,reg:5000"; strings.Join(got, ",") != want {
		t.Errorf("got %v, want %s", got, want)
	}
	for _, bad := range []string{"https://harbor.example.com", "169.254.0.0/16", "127.0.0.0/8", "a.*.example.com", "10.0.0.0/33"} {
		if _, err := ParseAllowPrivate([]string{bad}); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

// A restricted pull refuses a registry on loopback, the way an image
// reference to an internal service would be refused; unrestricted (the
// CLI), the same registry works.
func TestRestrictedResolveRefusesLoopback(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "INTERNAL-SECRET-BODY", http.StatusNotFound)
	}))
	defer srv.Close()
	ref := strings.TrimPrefix(srv.URL, "http://") + "/x:latest"

	_, _, err := Resolve(context.Background(), ref, Options{Insecure: true, Network: Network{Restrict: true, AllowPrivate: []string{"127.0.0.1"}}})
	if !errors.Is(err, errBlocked) {
		t.Fatalf("restricted: err = %v, want errBlocked", err)
	}
	if hits != 0 {
		t.Errorf("restricted: server got %d requests", hits)
	}
	_, _, err = Resolve(context.Background(), ref, Options{Insecure: true})
	if err == nil || errors.Is(err, errBlocked) || hits == 0 {
		t.Fatalf("unrestricted: err = %v, hits = %d; want a 404 from the server", err, hits)
	}
}

type fakeRT struct {
	status int
	body   string
	calls  int
}

func (f *fakeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	f.calls++
	return &http.Response{StatusCode: f.status, Body: io.NopCloser(strings.NewReader(f.body)), Request: req}, nil
}

func TestPolicyTransport(t *testing.T) {
	restricted := withPolicy(context.Background(), Options{Network: Network{Restrict: true}})
	get := func(ctx context.Context, url string, inner *fakeRT) (*http.Response, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		return (&policyTransport{inner: inner}).RoundTrip(req)
	}

	inner := &fakeRT{status: 200}
	if _, err := get(restricted, "http://registry.example.com/v2/", inner); !errors.Is(err, errBlocked) || inner.calls != 0 {
		t.Errorf("plain HTTP restricted: err = %v, calls = %d", err, inner.calls)
	}
	insecure := withPolicy(context.Background(), Options{Insecure: true, Network: Network{Restrict: true}})
	if _, err := get(insecure, "http://registry.example.com/v2/", inner); err != nil {
		t.Errorf("plain HTTP with Insecure: %v", err)
	}

	secret := "<html>" + strings.Repeat("SECRET\x1b[31m ", 100) + "</html>"
	resp, err := get(restricted, "https://registry.example.com/v2/", &fakeRT{status: 404, body: secret})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if len(b) > maxTextError+len("…") || strings.ContainsRune(string(b), 0x1b) {
		t.Errorf("error body not shortened: %d bytes %q", len(b), b)
	}

	regErr := `{"errors":[{"code":"TOOMANYREQUESTS","message":"rate limit"}]}`
	resp, _ = get(restricted, "https://registry.example.com/v2/", &fakeRT{status: 429, body: regErr})
	if b, _ := io.ReadAll(resp.Body); string(b) != regErr {
		t.Errorf("registry JSON error changed: %q", b)
	}

	resp, _ = get(context.Background(), "https://registry.example.com/v2/", &fakeRT{status: 404, body: secret})
	if b, _ := io.ReadAll(resp.Body); string(b) != secret {
		t.Error("unrestricted error body changed")
	}
}
