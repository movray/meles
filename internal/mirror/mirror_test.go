package mirror

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHandler(t *testing.T) {
	base := t.TempDir()
	db := filepath.Join(base, "db")
	rules := filepath.Join(base, "rules")
	outside := filepath.Join(base, "secret")
	for _, d := range []string{db, rules, filepath.Join(rules, "..data"), filepath.Join(db, "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(db, "daily.cvd"), "0123456789")
	write(filepath.Join(db, ".state.json"), "state")
	write(filepath.Join(db, "sub", "x.cvd"), "nested")
	write(outside, "secret")
	// Like a Kubernetes ConfigMap volume: the file is a link into ..data.
	write(filepath.Join(rules, "..data", "a.yar"), "rule a {}")
	symlink := func(target, link string) {
		t.Helper()
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	symlink(filepath.Join("..data", "a.yar"), filepath.Join(rules, "a.yar"))
	symlink(outside, filepath.Join(db, "abs.cvd"))
	symlink(filepath.Join("..", "secret"), filepath.Join(db, "rel.cvd"))

	modTime := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(db, "daily.cvd"), modTime, modTime); err != nil {
		t.Fatal(err)
	}

	h := Handler(db, rules, nil)
	tests := []struct {
		name     string
		method   string
		path     string
		header   map[string]string
		wantCode int
		wantBody string
	}{
		{name: "health", path: "/healthz", wantCode: 200, wantBody: "ok\n"},
		{name: "database", path: "/daily.cvd", wantCode: 200, wantBody: "0123456789"},
		{name: "head", method: http.MethodHead, path: "/daily.cvd", wantCode: 200},
		{name: "range", path: "/daily.cvd", header: map[string]string{"Range": "bytes=2-4"}, wantCode: 206, wantBody: "234"},
		{name: "not modified", path: "/daily.cvd", header: map[string]string{"If-Modified-Since": modTime.Add(time.Hour).Format(http.TimeFormat)}, wantCode: 304},
		{name: "modified", path: "/daily.cvd", header: map[string]string{"If-Modified-Since": modTime.Add(-time.Hour).Format(http.TimeFormat)}, wantCode: 200, wantBody: "0123456789"},
		{name: "rule via ..data link", path: "/rules/a.yar", wantCode: 200, wantBody: "rule a {}"},
		{name: "missing", path: "/main.cvd", wantCode: 404},
		{name: "dot file", path: "/.state.json", wantCode: 404},
		{name: "rules ..data", path: "/rules/..data/a.yar", wantCode: 404},
		{name: "subdirectory", path: "/sub/x.cvd", wantCode: 404},
		{name: "directory", path: "/sub", wantCode: 404},
		{name: "root", path: "/", wantCode: 404},
		{name: "rules root", path: "/rules/", wantCode: 404},
		{name: "absolute link out", path: "/abs.cvd", wantCode: 404},
		{name: "relative link out", path: "/rel.cvd", wantCode: 404},
		{name: "rules in db dir", path: "/a.yar", wantCode: 404},
		{name: "post", method: http.MethodPost, path: "/daily.cvd", wantCode: 405},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := tt.method
			if method == "" {
				method = http.MethodGet
			}
			req := httptest.NewRequest(method, "http://mirror"+tt.path, nil)
			for k, v := range tt.header {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.wantCode {
				t.Fatalf("code = %d, want %d (body %q)", rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.wantBody != "" {
				body, _ := io.ReadAll(rec.Body)
				if string(body) != tt.wantBody {
					t.Errorf("body = %q, want %q", body, tt.wantBody)
				}
			}
			if rec.Code == 200 && tt.path != "/healthz" {
				if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
					t.Errorf("Content-Type = %q", got)
				}
			}
		})
	}
}

func TestHandlerMissingDirs(t *testing.T) {
	base := t.TempDir()
	// cvdupdate has not created the database directory yet; no rules.
	h := Handler(filepath.Join(base, "db"), "", nil)
	tests := []struct {
		path     string
		wantCode int
	}{
		{"/healthz", 200},
		{"/daily.cvd", 404},
		{"/rules/a.yar", 404},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://mirror"+tt.path, nil))
			if rec.Code != tt.wantCode {
				t.Errorf("code = %d, want %d", rec.Code, tt.wantCode)
			}
		})
	}
}
