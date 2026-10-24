// Package ignore matches findings and skipped files against ignore rules:
// known false positives, or files the engine cannot scan completely for a
// known harmless reason. Every rule needs a reason and an expiry date at
// most MaxValidity ahead; an ignored entry stays in the report, marked with
// the rule, it only no longer counts for the verdict. Scan errors cannot be
// ignored.
package ignore

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// MaxValidity is how far ahead a rule may expire, so that exceptions are
// reviewed at least once a year.
const MaxValidity = 366 * 24 * time.Hour

// dateLayout is the format of Rule.Expires.
const dateLayout = "2006-01-02"

// Rule ignores the findings and skipped files that match all of its set
// matchers. At least one of Path, Signature and SHA256 must be set.
type Rule struct {
	// Name identifies the rule in reports; empty: its source and position.
	Name string `json:"name,omitempty"`
	// Path of the file in the image, a glob: * and ? within a path segment,
	// ** across segments, e.g. "/usr/src/php.tar.xz" or "/opt/tools/**".
	Path string `json:"path,omitempty"`
	// Signature of the finding, or of the skipped file (e.g.
	// "Heuristics.Limits.Exceeded.MaxRecursion"), a glob.
	Signature string `json:"signature,omitempty"`
	// Image restricts the rule: a repository glob such as
	// "docker.io/library/nextcloud" or "ghcr.io/acme/*", or an image digest
	// "sha256:…". Empty: every image.
	Image string `json:"image,omitempty"`
	// SHA256 of the file content (hex): the rule names exactly this file.
	SHA256 string `json:"sha256,omitempty"`
	// Reason why the entry is harmless (required).
	Reason string `json:"reason"`
	// Expires is the last day the rule applies, YYYY-MM-DD (required).
	Expires string `json:"expires"`
}

// File is the format of an ignore file (YAML or JSON).
type File struct {
	Rules []Rule `json:"rules"`
}

// Match tells which rule ignores an entry.
type Match struct {
	Rule    string `json:"rule"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
	// Expired is set if the rule matched but its date has passed: the entry
	// counts again.
	Expired bool `json:"expired,omitempty"`
}

// Image is the image an entry belongs to.
type Image struct {
	// Repository, e.g. "docker.io/library/nextcloud".
	Repository string
	// Digest, e.g. "sha256:…" (the index or the manifest).
	Digests []string
}

// Entry is a finding or a skipped file.
type Entry struct {
	Path      string
	Signature string
	SHA256    string
}

// Rules is a validated set of rules.
type Rules struct {
	rules []compiled
}

type compiled struct {
	Rule
	path, sig, image *regexp.Regexp
	expires          time.Time // end of the last day, UTC
}

// Load reads and validates an ignore file. Any invalid rule fails the load:
// a typo must not silently turn into "not ignored" or "ignored".
func Load(path string, now time.Time) (*Rules, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ignore file: %w", err)
	}
	var f File
	if err := yaml.UnmarshalStrict(b, &f); err != nil {
		return nil, fmt.Errorf("parse ignore file %s: %w", path, err)
	}
	rules, errs := New(f.Rules, path, now)
	if len(errs) > 0 {
		return nil, fmt.Errorf("ignore file %s: %w", path, errors.Join(errs...))
	}
	return rules, nil
}

// New validates rules; source names them in errors and default names. It
// returns the valid rules and an error for every invalid one.
func New(rules []Rule, source string, now time.Time) (*Rules, []error) {
	out := &Rules{}
	var errs []error
	for i, r := range rules {
		if r.Name == "" {
			r.Name = fmt.Sprintf("%s#%d", source, i+1)
		}
		c, err := compile(r, now)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %s: %w", r.Name, err))
			continue
		}
		out.rules = append(out.rules, c)
	}
	return out, errs
}

// Merge returns the rules of all sets.
func Merge(sets ...*Rules) *Rules {
	out := &Rules{}
	for _, s := range sets {
		if s != nil {
			out.rules = append(out.rules, s.rules...)
		}
	}
	return out
}

// Len returns the number of rules.
func (rs *Rules) Len() int {
	if rs == nil {
		return 0
	}
	return len(rs.rules)
}

func compile(r Rule, now time.Time) (compiled, error) {
	c := compiled{Rule: r}
	if strings.TrimSpace(r.Reason) == "" {
		return c, errors.New("reason is required: say why the entry is harmless")
	}
	if r.Path == "" && r.Signature == "" && r.SHA256 == "" {
		return c, errors.New("set at least one of path, signature and sha256; a rule must not ignore everything in an image")
	}
	day, err := time.Parse(dateLayout, r.Expires)
	if err != nil {
		return c, fmt.Errorf("expires %q: use a date like 2027-06-30", r.Expires)
	}
	c.expires = day.Add(24*time.Hour - time.Nanosecond)
	if c.expires.Sub(now) > MaxValidity {
		return c, fmt.Errorf("expires %s is more than a year ahead; exceptions must be reviewed at least once a year", r.Expires)
	}
	if r.SHA256 != "" {
		c.SHA256 = strings.ToLower(strings.TrimPrefix(r.SHA256, "sha256:"))
		if len(c.SHA256) != 64 || strings.Trim(c.SHA256, "0123456789abcdef") != "" {
			return c, fmt.Errorf("sha256 %q: want 64 hex characters", r.SHA256)
		}
	}
	if r.Path != "" {
		if !strings.HasPrefix(r.Path, "/") && !strings.HasPrefix(r.Path, "*") {
			return c, fmt.Errorf("path %q: use an absolute path in the image, e.g. /usr/src/php.tar.xz", r.Path)
		}
		c.path = glob(r.Path, true)
	}
	if r.Signature != "" {
		c.sig = glob(r.Signature, false)
	}
	if r.Image != "" && r.Image != "*" && r.Image != "**" && !strings.HasPrefix(r.Image, "sha256:") {
		c.image = glob(normalizeRepo(r.Image), true)
	}
	return c, nil
}

// glob compiles a pattern: ** matches anything, * and ? do not cross "/"
// if segments is set.
func glob(pattern string, segments bool) *regexp.Regexp {
	many, one := ".*", "."
	if segments {
		many, one = "[^/]*", "[^/]"
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; {
		case c == '*' && i+1 < len(pattern) && pattern[i+1] == '*':
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString(many)
		case c == '?':
			b.WriteString(one)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// normalizeRepo makes Docker Hub names comparable: go-containerregistry
// says index.docker.io, the kubelet docker.io, and users often write just
// "nextcloud".
func normalizeRepo(repo string) string {
	repo = strings.TrimPrefix(repo, "index.docker.io/")
	if !strings.Contains(repo, "/") {
		return "docker.io/library/" + repo
	}
	first, _, _ := strings.Cut(repo, "/")
	if !strings.ContainsAny(first, ".:") && first != "localhost" && !strings.HasPrefix(repo, "docker.io/") {
		return "docker.io/" + repo
	}
	return repo
}

func (c *compiled) matches(img Image, e Entry) bool {
	switch {
	case c.path != nil && !c.path.MatchString(e.Path):
		return false
	case c.sig != nil && !c.sig.MatchString(e.Signature):
		return false
	case c.SHA256 != "" && !strings.EqualFold(c.SHA256, e.SHA256):
		return false
	case c.image != nil && !c.image.MatchString(normalizeRepo(img.Repository)):
		return false
	case strings.HasPrefix(c.Image, "sha256:"):
		for _, d := range img.Digests {
			if d == c.Image {
				return true
			}
		}
		return false
	}
	return true
}

// Find returns the rule that ignores e at now, or nil. If only expired rules
// match, it returns the first of them with Expired set: the entry counts,
// but the report says why it is no longer ignored.
func (rs *Rules) Find(img Image, e Entry, now time.Time) *Match {
	if rs == nil {
		return nil
	}
	var expired *Match
	for i := range rs.rules {
		c := &rs.rules[i]
		if !c.matches(img, e) {
			continue
		}
		m := &Match{Rule: c.Name, Reason: c.Reason, Expires: c.Expires}
		if now.After(c.expires) {
			if expired == nil {
				m.Expired = true
				expired = m
			}
			continue
		}
		return m
	}
	return expired
}

// NextExpiry returns when the next rule expires after now, or the zero time:
// a result has to be evaluated again then.
func (rs *Rules) NextExpiry(now time.Time) time.Time {
	var next time.Time
	if rs == nil {
		return next
	}
	for _, c := range rs.rules {
		if c.expires.After(now) && (next.IsZero() || c.expires.Before(next)) {
			next = c.expires
		}
	}
	return next
}
