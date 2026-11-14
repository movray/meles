// Package mirror serves the ClamAV database mirror to freshclam: the
// database files that cvdupdate keeps in one directory, the YARA rules from
// another, and a health check. It replaces a general web server with the
// little that freshclam needs: GET and HEAD on single files, with
// If-Modified-Since and Range requests.
package mirror

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

// Handler returns the mirror's HTTP handler:
//
//	/healthz        200 "ok"
//	/rules/<name>   a file in rulesDir (empty: no rules)
//	/<name>         a file in dbDir
//
// Only regular files directly in a directory are served, no listings, no
// subdirectories and no names starting with a dot (cvdupdate's state, the
// "..data" link of a Kubernetes volume). Symbolic links are followed only as
// long as they stay inside their directory. The directories may appear
// after the start: until cvdupdate has created dbDir, every file is 404.
func Handler(dbDir, rulesDir string, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	if rulesDir != "" {
		mux.Handle("/rules/", http.StripPrefix("/rules/", files(rulesDir, log)))
	}
	mux.Handle("/", http.StripPrefix("/", files(dbDir, log)))
	return mux
}

// files serves the regular files directly in dir; the request path, with
// its prefix stripped, is the file name.
func files(dir string, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Path
		if !validName(name) {
			http.NotFound(w, r)
			return
		}
		// OpenInRoot refuses "..", absolute paths and symbolic links that
		// leave dir.
		f, err := os.OpenInRoot(dir, name)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				log.Warn("mirror: open", "dir", dir, "name", name, "err", err)
			}
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		// No content sniffing: freshclam does not care, and a rule file
		// must not be served as HTML.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.ServeContent(w, r, name, fi.ModTime(), f)
	})
}

// validName accepts one path segment that does not start with a dot.
func validName(name string) bool {
	return name != "" && !strings.HasPrefix(name, ".") && !strings.ContainsAny(name, "/\\\x00")
}
