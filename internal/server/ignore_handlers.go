package server

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/movray/meles/api/v1alpha1"
	"github.com/movray/meles/internal/ignore"
	"github.com/movray/meles/internal/store"
)

var errNoIgnores = fmt.Errorf("ignore rules from the UI are not enabled (meles server --cluster-ignore): %w", store.ErrNotFound)

// defaultIgnoreDays is the validity the form suggests.
const defaultIgnoreDays = 90

// ignoreInput is the ignore rule form.
type ignoreInput struct {
	Path      string
	Signature string
	Image     string
	// SHA256 of the file the form was opened for; Exact restricts the rule
	// to it.
	SHA256 string
	Exact  bool
	// Namespace of the report the form was opened for: the rule can apply
	// there only (a MalwareIgnore) instead of cluster-wide.
	Namespace string
	Scope     string
	Reason    string
	Expires   string
	// Back is the page the form was opened from.
	Back string
}

func ignoreInputFrom(get func(string) string) ignoreInput {
	in := ignoreInput{
		Path:      strings.TrimSpace(get("path")),
		Signature: strings.TrimSpace(get("signature")),
		Image:     strings.TrimSpace(get("image")),
		SHA256:    strings.TrimSpace(get("sha256")),
		Exact:     get("exact") != "",
		Namespace: strings.TrimSpace(get("namespace")),
		Scope:     get("scope"),
		Reason:    strings.TrimSpace(get("reason")),
		Expires:   strings.TrimSpace(get("expires")),
		Back:      localPath(get("back")),
	}
	if in.Scope != "cluster" {
		// A namespace is the narrower choice, so it is the default.
		in.Scope = "namespace"
	}
	if in.Namespace == "" {
		in.Scope = "cluster"
	}
	return in
}

// localPath returns p if it is a path on this server, else "": the form
// must not redirect elsewhere.
func localPath(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") {
		return ""
	}
	return p
}

// rule returns the rule and the namespace of the object to create, or the
// errors per field.
func (in ignoreInput) rule(now time.Time) (v1alpha1.IgnoreRule, string, map[string]string) {
	errs := map[string]string{}
	r := v1alpha1.IgnoreRule{Path: in.Path, Signature: in.Signature, Image: in.Image, Reason: in.Reason, Expires: in.Expires}
	if in.Exact {
		r.SHA256 = in.SHA256
	}
	ns := ""
	if in.Scope == "namespace" {
		ns = in.Namespace
		if msgs := validation.IsDNS1123Label(ns); len(msgs) > 0 {
			errs["Scope"] = "namespace " + ns + ": " + strings.Join(msgs, "; ")
		}
	}
	// The checks of the operator and the CLI, so that the rule takes effect.
	_, ruleErrs := ignore.New(ignore.FromSpec(v1alpha1.IgnoreSpec{Rules: []v1alpha1.IgnoreRule{r}}, "new"), "new", now)
	for _, err := range ruleErrs {
		msg := strings.TrimPrefix(err.Error(), "rule new#1: ")
		switch {
		case strings.HasPrefix(msg, "reason"):
			errs["Reason"] = msg
		case strings.HasPrefix(msg, "expires"):
			errs["Expires"] = msg
		case strings.HasPrefix(msg, "path"):
			errs["Path"] = msg
		case strings.HasPrefix(msg, "sha256"):
			errs["Exact"] = msg
		default:
			errs["Rule"] = msg
		}
	}
	return r, ns, errs
}

// createdBy names the user for the object's annotation: the headers
// oauth2-proxy sets. Without a proxy in front they are whatever the client
// sends; the UI then has no login anyway.
func createdBy(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-Email", "X-Forwarded-Preferred-Username", "X-Forwarded-User"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return v
		}
	}
	return "unknown (no login proxy)"
}

func (s *Server) handleIgnores(w http.ResponseWriter, r *http.Request) {
	if s.ignores == nil {
		s.renderError(w, http.StatusNotFound, errNoIgnores)
		return
	}
	objs, err := s.ignores.List(r.Context())
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	s.render(w, http.StatusOK, "ignores", page{Title: "Ignore rules", Nav: "ignores", Data: map[string]any{
		"Objects": objs,
	}})
}

func (s *Server) handleIgnoreNew(w http.ResponseWriter, r *http.Request) {
	if s.ignores == nil {
		s.renderError(w, http.StatusNotFound, errNoIgnores)
		return
	}
	in := ignoreInputFrom(r.URL.Query().Get)
	in.Exact = in.SHA256 != ""
	in.Expires = time.Now().In(s.loc).AddDate(0, 0, defaultIgnoreDays).Format("2006-01-02")
	s.renderIgnoreForm(w, http.StatusOK, in, nil)
}

func (s *Server) renderIgnoreForm(w http.ResponseWriter, status int, in ignoreInput, errs map[string]string) {
	now := time.Now()
	s.render(w, status, "ignore_form", page{Title: "New ignore rule", Nav: "ignores", Data: map[string]any{
		"Input":  in,
		"Errors": errs,
		"Min":    now.In(s.loc).Format("2006-01-02"),
		// Expiry dates are UTC days; the last one ignore.New accepts.
		"Max": now.UTC().Add(ignore.MaxValidity - 24*time.Hour).Format("2006-01-02"),
	}})
}

func (s *Server) handleIgnoreCreate(w http.ResponseWriter, r *http.Request) {
	if s.ignores == nil {
		s.renderError(w, http.StatusNotFound, errNoIgnores)
		return
	}
	in := ignoreInputFrom(r.PostFormValue)
	rule, ns, errs := in.rule(time.Now())
	if len(errs) > 0 {
		s.renderIgnoreForm(w, http.StatusBadRequest, in, errs)
		return
	}
	user := createdBy(r)
	name, err := s.ignores.Create(r.Context(), ns, rule, user)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	s.log.Info("ignore rule created", "namespace", ns, "name", name, "by", user,
		"path", rule.Path, "signature", rule.Signature, "image", rule.Image, "sha256", rule.SHA256, "expires", rule.Expires)
	http.Redirect(w, r, cmp.Or(in.Back, "/ignores"), http.StatusSeeOther)
}

func (s *Server) handleIgnoreDelete(w http.ResponseWriter, r *http.Request) {
	if s.ignores == nil {
		s.renderError(w, http.StatusNotFound, errNoIgnores)
		return
	}
	ns, name := r.PostFormValue("namespace"), r.PostFormValue("name")
	if err := s.ignores.Delete(r.Context(), ns, name); err != nil {
		status := errStatus(err)
		if errors.Is(err, errNotManaged) {
			status = http.StatusForbidden
		}
		s.renderError(w, status, err)
		return
	}
	s.log.Info("ignore rule deleted", "namespace", ns, "name", name, "by", createdBy(r))
	http.Redirect(w, r, "/ignores", http.StatusSeeOther)
}
