package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Network limits where meles connects to when it pulls images. In a cluster
// the references come from anyone who may create a pod (operator) or a run
// (server); without limits they would let meles send requests to internal
// services and the cloud metadata endpoint, and show the answers in reports
// and events (SSRF).
//
// With Restrict, meles
//   - never connects to loopback, link-local (169.254.0.0/16 with the cloud
//     metadata endpoint, fe80::/10), unspecified or multicast addresses,
//   - connects to private addresses (10/8, 172.16/12, 192.168/16,
//     100.64/10, fc00::/7) only for hosts and networks in AllowPrivate,
//   - speaks plain HTTP only with Options.Insecure,
//   - keeps at most a short, printable excerpt of the body of an error
//     response.
//
// The check applies to the resolved address of every connection, so it
// holds for redirects, token realms and DNS names alike. Hosts of mirrors
// and of the HTTP(S)_PROXY are allowed. Through a proxy, meles connects only
// to the proxy; the proxy has to enforce its own rules for the targets.
type Network struct {
	Restrict bool
	// AllowPrivate lists registries that may use private addresses: a host
	// ("harbor.example.com"), a host with port, a wildcard for subdomains
	// ("*.dkr.ecr.eu-central-1.amazonaws.com", e.g. for VPC endpoints) or a
	// network ("10.0.0.0/8").
	AllowPrivate []string
}

// ParseAllowPrivate checks entries of Network.AllowPrivate.
func ParseAllowPrivate(entries []string) ([]string, error) {
	var out []string
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, fmt.Errorf("allowed private registry %q: want a host, host:port, *.domain or a network such as 10.0.0.0/8", e)
			}
			if blockedAlways(p.Addr()) {
				return nil, fmt.Errorf("allowed private registry %q: loopback, link-local and multicast addresses are never allowed", e)
			}
			out = append(out, e)
			continue
		}
		if strings.Contains(e, "://") || strings.ContainsAny(e, " @?#") || strings.Count(strings.TrimPrefix(e, "*."), "*") > 0 {
			return nil, fmt.Errorf("allowed private registry %q: want a host, host:port, *.domain or a network such as 10.0.0.0/8", e)
		}
		out = append(out, e)
	}
	return out, nil
}

// policy is the Network of one Fetch or Resolve, carried in the context to
// the shared transport.
type policy struct {
	insecure bool
	hosts    []string // host, host:port or *.suffix
	nets     []netip.Prefix
}

type policyKey struct{}

// withPolicy attaches the restrictions of opts to ctx; unrestricted options
// leave ctx unchanged.
func withPolicy(ctx context.Context, opts Options) context.Context {
	if !opts.Network.Restrict {
		return ctx
	}
	p := &policy{insecure: opts.Insecure}
	for _, e := range opts.Network.AllowPrivate {
		e = strings.ToLower(strings.TrimSpace(e))
		if pr, err := netip.ParsePrefix(e); err == nil {
			p.nets = append(p.nets, pr.Masked())
		} else if e != "" {
			p.hosts = append(p.hosts, e)
		}
	}
	for _, m := range opts.Mirrors {
		host, _, _ := strings.Cut(m.Prefix, "/")
		p.hosts = append(p.hosts, strings.ToLower(host))
	}
	p.hosts = append(p.hosts, proxyHosts()...)
	return context.WithValue(ctx, policyKey{}, p)
}

func policyFrom(ctx context.Context) *policy {
	p, _ := ctx.Value(policyKey{}).(*policy)
	return p
}

// proxyHosts returns the hosts of the proxies in the environment, which
// meles connects to instead of the registries.
func proxyHosts() []string {
	var hosts []string
	for _, v := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		s := os.Getenv(v)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "://") {
			s = "http://" + s
		}
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			hosts = append(hosts, strings.ToLower(u.Hostname()))
		}
	}
	return hosts
}

// hostAllowed reports whether host (with port) is listed for private
// addresses.
func (p *policy) hostAllowed(host, port string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	hp := net.JoinHostPort(host, port)
	for _, e := range p.hosts {
		switch {
		case strings.HasPrefix(e, "*."):
			if strings.HasSuffix(host, e[1:]) {
				return true
			}
		case e == host, e == hp, strings.Trim(e, "[]") == host:
			return true
		}
	}
	return false
}

func (p *policy) netAllowed(a netip.Addr) bool {
	for _, n := range p.nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

var (
	cgnat       = netip.MustParsePrefix("100.64.0.0/10")
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
)

// blockedAlways reports addresses meles never connects to with Restrict.
func blockedAlways(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() ||
		(a.Is4() && thisNetwork.Contains(a))
}

func private(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || (a.Is4() && cgnat.Contains(a))
}

// errBlocked is wrapped by refused connections.
var errBlocked = errors.New("address not allowed")

// check returns an error if the policy forbids connecting to a for host.
func (p *policy) check(host, port string, a netip.Addr) error {
	what := host + " resolves to " + a.String()
	if strings.Trim(host, "[]") == a.String() {
		what = host + " is"
	}
	switch {
	case blockedAlways(a):
		return fmt.Errorf("%w: %s, a loopback, link-local or similar address, which meles never connects to", errBlocked, what)
	case private(a) && !p.hostAllowed(host, port) && !p.netAllowed(a.Unmap()):
		return fmt.Errorf("%w: %s, a private address; if it is a registry, allow it with --allow-private-registry (Helm: scan.allowPrivateRegistries)", errBlocked, what)
	}
	return nil
}

var dialer = &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

// dial resolves addr itself and connects only to permitted addresses, so
// that a DNS answer cannot change between the check and the connection.
func dial(ctx context.Context, network, addr string) (net.Conn, error) {
	p := policyFrom(ctx)
	if p == nil {
		return dialer.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		addrs = []netip.Addr{a}
	} else if addrs, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, err
	}
	var errs []error
	for _, a := range addrs {
		if err := p.check(host, port, a); err != nil {
			errs = append(errs, err)
			continue
		}
		c, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("%s: no addresses", host)
	}
	return nil, errors.Join(errs...)
}

// sharedTransport is used for every registry request, so that connections
// are reused across scans as with remote.DefaultTransport.
var sharedTransport http.RoundTripper = newTransport()

func newTransport() http.RoundTripper {
	t := remote.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = dial
	return &policyTransport{inner: t}
}

// policyTransport refuses plain HTTP without Insecure and shortens the
// bodies of error responses under a policy.
type policyTransport struct {
	inner http.RoundTripper
}

func (t *policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	p := policyFrom(req.Context())
	if p == nil {
		return t.inner.RoundTrip(req)
	}
	if req.URL.Scheme == "http" && !p.insecure {
		return nil, fmt.Errorf("%w: plain HTTP to %s; allow it with --insecure-registry", errBlocked, req.URL.Host)
	}
	resp, err := t.inner.RoundTrip(req)
	if err != nil || resp.StatusCode < 400 {
		return resp, err
	}
	resp.Body = limitErrorBody(resp.Body)
	resp.ContentLength = -1
	return resp, nil
}

const (
	maxJSONError = 4 << 10
	maxTextError = 200
)

// limitErrorBody keeps a registry's JSON error (the codes and messages the
// error shows) and otherwise at most maxTextError printable characters: the
// body ends up in reports and events that others can read.
func limitErrorBody(rc io.ReadCloser) io.ReadCloser {
	defer rc.Close()
	b, _ := io.ReadAll(io.LimitReader(rc, maxJSONError+1))
	if len(b) <= maxJSONError {
		var v struct {
			Errors []json.RawMessage `json:"errors"`
		}
		if json.Unmarshal(b, &v) == nil && len(v.Errors) > 0 {
			return io.NopCloser(bytes.NewReader(b))
		}
	}
	var sb strings.Builder
	for _, r := range string(b) {
		if sb.Len() >= maxTextError {
			sb.WriteString("…")
			break
		}
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			sb.WriteByte(' ')
		case r >= 0x20 && r < 0x7f:
			sb.WriteRune(r)
		}
	}
	return io.NopCloser(strings.NewReader(sb.String()))
}
