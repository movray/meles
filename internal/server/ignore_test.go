package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/movray/meles/api/v1alpha1"
	"github.com/movray/meles/internal/ignore"
	"github.com/movray/meles/internal/store"
)

type fakeIgnores struct {
	mu   sync.Mutex
	objs []IgnoreObject
	n    int
}

func (f *fakeIgnores) List(context.Context) ([]IgnoreObject, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]IgnoreObject(nil), f.objs...), nil
}

func (f *fakeIgnores) Create(_ context.Context, ns string, rule v1alpha1.IgnoreRule, by string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	name := fmt.Sprintf("%s%d", uiPrefix, f.n)
	f.objs = append(f.objs, IgnoreObject{Namespace: ns, Name: name, Created: time.Now(),
		Labels:      map[string]string{v1alpha1.LabelManagedBy: v1alpha1.ManagedByServer},
		Annotations: map[string]string{v1alpha1.AnnotationCreatedBy: by},
		Spec:        v1alpha1.IgnoreSpec{Rules: []v1alpha1.IgnoreRule{rule}}})
	return name, nil
}

func (f *fakeIgnores) Delete(_ context.Context, ns, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, o := range f.objs {
		if o.Namespace == ns && o.Name == name {
			if !o.Managed() {
				return errNotManaged
			}
			f.objs = append(f.objs[:i], f.objs[i+1:]...)
			return nil
		}
	}
	return store.ErrNotFound
}

func (f *fakeIgnores) get(ns, name string) *IgnoreObject {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, o := range f.objs {
		if o.Namespace == ns && o.Name == name {
			return &o
		}
	}
	return nil
}

func TestIgnoreRules(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	reports := &fakeReports{reports: []v1alpha1.MalwareReport{
		malwareReport("shop", "miner", v1alpha1.StatusInfected, v1alpha1.Finding{Platform: "linux/amd64", Layer: 2, Path: "/usr/bin/xmrig", Signature: "Unix.Coinminer.Xmrig", Status: "present", SHA256: sha}),
	}}
	ignores := &fakeIgnores{objs: []IgnoreObject{{
		Name: "known-harmless", Labels: map[string]string{"kustomize.toolkit.fluxcd.io/name": "meles"},
		Spec: v1alpha1.IgnoreSpec{Rules: []v1alpha1.IgnoreRule{{Path: "/usr/src/php.tar.xz", Reason: "PHP test quine", Expires: "2027-06-30"}}},
	}}}
	e := newEnv(t, func(c *Config) { c.Cluster, c.Ignores = reports, ignores })

	_, out := e.do("GET", "/ignores", "", "")
	if !strings.Contains(out, "known-harmless") || !strings.Contains(out, "Flux") || strings.Contains(out, "/ignores/delete") {
		t.Errorf("list: external rule missing, or deletable:\n%s", out)
	}

	// The button at the finding opens the form prefilled.
	_, out = e.do("GET", "/cluster/shop/replicaset-miner-app", "", "")
	if !strings.Contains(out, "Ignore…") || !strings.Contains(out, "namespace=shop") || !strings.Contains(out, "sha256="+sha) {
		t.Fatal("report page without the Ignore button")
	}
	q := url.Values{"path": {"/usr/bin/xmrig"}, "signature": {"Unix.Coinminer.Xmrig"}, "image": {"docker.io/acme/miner"}, "sha256": {sha},
		"namespace": {"shop"}, "back": {"/cluster/shop/replicaset-miner-app"}}
	_, out = e.do("GET", "/ignores/new?"+q.Encode(), "", "")
	for _, want := range []string{`value="/usr/bin/xmrig"`, `id="scope-ns" name="scope" value="namespace" checked`, `name="exact" value="1" checked`,
		`value="` + time.Now().AddDate(0, 0, defaultIgnoreDays).Format("2006-01-02") + `"`} {
		if !strings.Contains(out, want) {
			t.Errorf("form without %s", want)
		}
	}

	post := func(form url.Values, header ...string) (*http.Response, string) {
		return e.do("POST", "/ignores", "application/x-www-form-urlencoded", form.Encode(), header...)
	}
	form := url.Values{"path": {"/usr/bin/xmrig"}, "signature": {"Unix.Coinminer.Xmrig"}, "image": {"docker.io/acme/miner"}, "sha256": {sha}, "exact": {"1"},
		"namespace": {"shop"}, "scope": {"namespace"}, "back": {"/cluster/shop/replicaset-miner-app"},
		"expires": {time.Now().AddDate(0, 1, 0).Format("2006-01-02")}}
	if resp, out := post(form); resp.StatusCode != http.StatusBadRequest || !strings.Contains(out, "reason is required") {
		t.Errorf("without reason: %d", resp.StatusCode)
	}
	tooLate := cloneValues(form)
	tooLate.Set("reason", "miner detector test data")
	tooLate.Set("expires", time.Now().AddDate(2, 0, 0).Format("2006-01-02"))
	if resp, out := post(tooLate); resp.StatusCode != http.StatusBadRequest || !strings.Contains(out, "more than a year ahead") {
		t.Errorf("two years: %d", resp.StatusCode)
	}
	everything := url.Values{"reason": {"x"}, "expires": form["expires"], "scope": {"cluster"}}
	if resp, out := post(everything); resp.StatusCode != http.StatusBadRequest || !strings.Contains(out, "set at least one of path") {
		t.Errorf("rule without matchers: %d", resp.StatusCode)
	}

	form.Set("reason", "miner detector test data")
	resp, _ := post(form, "X-Forwarded-Email", "ops@example.com")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/cluster/shop/replicaset-miner-app" {
		t.Fatalf("create: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	o := ignores.get("shop", uiPrefix+"1")
	if o == nil || o.CreatedBy() != "ops@example.com" || o.Spec.Rules[0].SHA256 != sha || o.Spec.Rules[0].Path != "/usr/bin/xmrig" {
		t.Fatalf("created %+v", o)
	}

	// Cluster-wide, without the exact file; a foreign back link is dropped.
	form.Set("scope", "cluster")
	form.Del("exact")
	form.Set("back", "//evil.example.com/")
	if resp, _ := post(form); resp.Header.Get("Location") != "/ignores" {
		t.Errorf("redirect to %s", resp.Header.Get("Location"))
	}
	if o := ignores.get("", uiPrefix+"2"); o == nil || o.Spec.Rules[0].SHA256 != "" || o.CreatedBy() != "unknown (no login proxy)" {
		t.Errorf("cluster rule %+v", o)
	}

	_, out = e.do("GET", "/ignores", "", "")
	if !strings.Contains(out, "ops@example.com") || strings.Count(out, `action="/ignores/delete"`) != 2 {
		t.Error("list without the UI rules or their delete buttons")
	}
	del := func(ns, name string) *http.Response {
		resp, _ := e.do("POST", "/ignores/delete", "application/x-www-form-urlencoded", url.Values{"namespace": {ns}, "name": {name}}.Encode())
		return resp
	}
	if resp := del("", "known-harmless"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("delete external rule: %d", resp.StatusCode)
	}
	if resp := del("shop", uiPrefix+"1"); resp.StatusCode != http.StatusSeeOther || ignores.get("shop", uiPrefix+"1") != nil {
		t.Errorf("delete UI rule: %d", resp.StatusCode)
	}
	if resp, _ := e.do("POST", "/ignores", "application/x-www-form-urlencoded", form.Encode(), "Sec-Fetch-Site", "cross-site"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site create: %d, want 403", resp.StatusCode)
	}
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// The server's own runs apply the rules in effect when they finish.
func TestRunIgnore(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Cluster, c.Ignores = &fakeReports{}, &fakeIgnores{} })
	var mu sync.Mutex
	var rules *ignore.Rules
	e.s.runner.SetIgnore(func(context.Context) (*ignore.Rules, error) {
		mu.Lock()
		defer mu.Unlock()
		return rules, nil
	})
	run := func() (*store.Run, string) {
		t.Helper()
		resp, _ := e.do("POST", "/runs", "application/x-www-form-urlencoded", url.Values{"image_ref": {e.reg.Ref("eicar-whiteout")}, "platforms": {"linux/amd64"}}.Encode())
		var id int64
		fmt.Sscanf(resp.Header.Get("Location"), "/runs/%d", &id)
		r := e.waitDone(id)
		_, out := e.do("GET", fmt.Sprintf("/runs/%d", id), "", "")
		return r, out
	}

	r, out := run()
	if r.Status != store.StatusInfected || r.Findings != 1 || !strings.Contains(out, "Ignore…") || !strings.Contains(out, "path=%2Ftmp%2Fpayload%2Feicar.com") {
		t.Errorf("run without rules: %s, %d findings, Ignore button %v", r.Status, r.Findings, strings.Contains(out, "Ignore…"))
	}

	mu.Lock()
	rules, _ = ignore.New([]ignore.Rule{{Path: "/tmp/payload/**", Reason: "test payload", Expires: time.Now().AddDate(0, 1, 0).Format("2006-01-02")}}, "test", time.Now())
	mu.Unlock()
	r, out = run()
	if r.Status != store.StatusClean || r.Findings != 0 {
		t.Errorf("run with rule: %s, %d findings", r.Status, r.Findings)
	}
	if !strings.Contains(out, "1 entry ignored by rules") || !strings.Contains(out, "row-ignored") || !strings.Contains(out, "test payload") || strings.Contains(out, "Ignore…") {
		t.Error("run page without the ignored finding, or with an Ignore button for it")
	}
}

func TestIgnoresDisabled(t *testing.T) {
	reports := &fakeReports{reports: []v1alpha1.MalwareReport{
		malwareReport("shop", "miner", v1alpha1.StatusInfected, v1alpha1.Finding{Path: "/usr/bin/xmrig", Signature: "Unix.Coinminer.Xmrig", Status: "present"}),
	}}
	e := newEnv(t, func(c *Config) { c.Cluster = reports })
	for _, path := range []string{"/ignores", "/ignores/new"} {
		if resp, _ := e.do("GET", path, "", ""); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %d", path, resp.StatusCode)
		}
	}
	if resp, _ := e.do("POST", "/ignores", "application/x-www-form-urlencoded", "path=/x&reason=x&expires=2027-01-01"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /ignores: %d", resp.StatusCode)
	}
	if _, out := e.do("GET", "/cluster/shop/replicaset-miner-app", "", ""); strings.Contains(out, "Ignore…") || strings.Contains(out, `href="/ignores"`) {
		t.Error("Ignore button or navigation although disabled")
	}
}

func TestIgnoreOrigin(t *testing.T) {
	tests := []struct {
		labels, annotations map[string]string
		want                string
	}{
		{map[string]string{v1alpha1.LabelManagedBy: v1alpha1.ManagedByServer}, nil, "UI"},
		{nil, map[string]string{"argocd.argoproj.io/tracking-id": "meles:meles.io/ClusterMalwareIgnore:/x"}, "Argo CD"},
		{map[string]string{"helm.toolkit.fluxcd.io/name": "meles"}, nil, "Flux"},
		{map[string]string{v1alpha1.LabelManagedBy: "Helm"}, nil, "Helm"},
		{nil, nil, "kubectl or Git"},
	}
	for _, tt := range tests {
		if got := (IgnoreObject{Labels: tt.labels, Annotations: tt.annotations}).Origin(); got != tt.want {
			t.Errorf("Origin(%v, %v) = %q, want %q", tt.labels, tt.annotations, got, tt.want)
		}
	}
}
