// Command spike is a throwaway proof of concept for meles: pull an image
// without a Docker daemon, scan every layer separately with clamd and show
// that files deleted by a whiteout in a later layer are still found.
//
// Without arguments it builds test images at runtime, pushes them to an
// in-process registry and scans them from there. With arguments it scans the
// given image references, e.g. `go run . alpine:3.20`.
//
// Not production code: no tests, minimal error handling, nothing is written
// to disk (so no path traversal handling is needed yet).
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func main() {
	clamdAddr := flag.String("clamd", "unix:///run/clamav/clamd.ctl", "clamd address (unix:///path or tcp://host:port)")
	maxFileSize := flag.Int64("max-file-size", 25<<20, "skip files larger than this (must not exceed clamd StreamMaxLength)")
	flag.Parse()

	refs := flag.Args()
	var opts []name.Option
	if len(refs) == 0 {
		srv, testRefs, err := startSelftestRegistry()
		if err != nil {
			fmt.Fprintln(os.Stderr, "selftest registry:", err)
			os.Exit(2)
		}
		defer srv.Close()
		refs = testRefs
		opts = append(opts, name.Insecure)
	}

	c, err := dialClamd(*clamdAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer c.Close()

	s := &scanner{clamd: c, maxFileSize: *maxFileSize, cache: map[v1.Hash]*layerScan{}}
	found, failed := false, false
	for _, r := range refs {
		f, err := s.scanRef(r, opts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan %s: %v\n", r, err)
			failed = true
			continue
		}
		found = found || f
	}

	// Errors win over findings: an error must never look like "clean".
	switch {
	case failed:
		os.Exit(2)
	case found:
		os.Exit(1)
	}
}

// layerScan is the result of scanning one layer on its own. It does not
// depend on the image the layer belongs to, so it can be cached per diffID.
type layerScan struct {
	files     map[string]bool // non-directory entries
	whiteouts map[string]bool // paths deleted by .wh.<name>
	opaques   map[string]bool // directories hidden by .wh..wh..opq
	hits      []hit
	skipped   []string
	scanned   int
}

type hit struct {
	path, signature string
}

type scanner struct {
	clamd       *clamd
	maxFileSize int64
	cache       map[v1.Hash]*layerScan
}

type platformImage struct {
	platform string
	img      v1.Image
}

// scanRef scans all platforms of ref and prints the findings. It reports
// whether anything was found.
func (s *scanner) scanRef(ref string, opts ...name.Option) (bool, error) {
	r, err := name.ParseReference(ref, opts...)
	if err != nil {
		return false, fmt.Errorf("parse reference: %w", err)
	}
	desc, err := remote.Get(r, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return false, fmt.Errorf("pull: %w", err)
	}

	var imgs []platformImage
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return false, fmt.Errorf("read index: %w", err)
		}
		im, err := idx.IndexManifest()
		if err != nil {
			return false, fmt.Errorf("read index manifest: %w", err)
		}
		for _, m := range im.Manifests {
			// Attestation manifests (BuildKit) use platform unknown/unknown.
			if m.Platform == nil || m.Platform.OS == "unknown" {
				continue
			}
			img, err := idx.Image(m.Digest)
			if err != nil {
				return false, fmt.Errorf("image %s: %w", m.Platform, err)
			}
			imgs = append(imgs, platformImage{m.Platform.String(), img})
		}
	} else {
		img, err := desc.Image()
		if err != nil {
			return false, fmt.Errorf("read image: %w", err)
		}
		cf, err := img.ConfigFile()
		if err != nil {
			return false, fmt.Errorf("read config: %w", err)
		}
		imgs = append(imgs, platformImage{cf.OS + "/" + cf.Architecture, img})
	}

	found := false
	for _, pi := range imgs {
		f, err := s.scanImage(ref, pi)
		if err != nil {
			return found, fmt.Errorf("%s: %w", pi.platform, err)
		}
		found = found || f
	}
	return found, nil
}

func (s *scanner) scanImage(ref string, pi platformImage) (bool, error) {
	layers, err := pi.img.Layers()
	if err != nil {
		return false, fmt.Errorf("list layers: %w", err)
	}
	cf, err := pi.img.ConfigFile()
	if err != nil {
		return false, fmt.Errorf("read config: %w", err)
	}
	var createdBy []string
	for _, h := range cf.History {
		if !h.EmptyLayer {
			createdBy = append(createdBy, h.CreatedBy)
		}
	}

	start := time.Now()
	scans := make([]*layerScan, len(layers))
	diffIDs := make([]v1.Hash, len(layers))
	cached := 0
	for i, l := range layers {
		d, err := l.DiffID()
		if err != nil {
			return false, fmt.Errorf("layer %d diffID: %w", i+1, err)
		}
		diffIDs[i] = d
		if ls, ok := s.cache[d]; ok {
			scans[i] = ls
			cached++
			continue
		}
		ls, err := s.scanLayer(l)
		if err != nil {
			return false, fmt.Errorf("layer %d (%s): %w", i+1, short(d), err)
		}
		s.cache[d] = ls
		scans[i] = ls
	}

	files, skipped := 0, 0
	for _, ls := range scans {
		files += ls.scanned
		skipped += len(ls.skipped)
	}
	fmt.Printf("\n== %s (%s): %d layers (%d from cache), %d files scanned, %d skipped, %s\n",
		ref, pi.platform, len(layers), cached, files, skipped, time.Since(start).Round(time.Millisecond))

	found := false
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for i, ls := range scans {
		for _, h := range ls.hits {
			if !found {
				fmt.Fprintln(tw, "LAYER\tDIFFID\tPATH\tSIGNATURE\tSTATUS\tCREATED BY")
				found = true
			}
			status := "present"
			if j, how := hiddenBy(h.path, i, scans); j >= 0 {
				status = fmt.Sprintf("%s in layer %d", how, j+1)
			}
			cb := ""
			if i < len(createdBy) {
				cb = truncate(createdBy[i], 50)
			}
			fmt.Fprintf(tw, "%d/%d\t%s\t%s\t%s\t%s\t%s\n", i+1, len(scans), short(diffIDs[i]), h.path, h.signature, status, cb)
		}
	}
	tw.Flush()
	if !found {
		fmt.Println("clean")
	}
	for i, ls := range scans {
		for _, p := range ls.skipped {
			fmt.Printf("skipped (larger than %d bytes): layer %d %s\n", s.maxFileSize, i+1, p)
		}
	}
	return found, nil
}

func (s *scanner) scanLayer(l v1.Layer) (*layerScan, error) {
	rc, err := l.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer rc.Close()

	ls := &layerScan{files: map[string]bool{}, whiteouts: map[string]bool{}, opaques: map[string]bool{}}
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return ls, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		p := path.Clean("/" + h.Name)
		dir, base := path.Dir(p), path.Base(p)
		switch {
		case base == ".wh..wh..opq":
			ls.opaques[dir] = true
			continue
		case strings.HasPrefix(base, ".wh."):
			ls.whiteouts[path.Join(dir, strings.TrimPrefix(base, ".wh."))] = true
			continue
		case h.Typeflag == tar.TypeDir:
			continue
		}
		ls.files[p] = true
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if h.Size > s.maxFileSize {
			ls.skipped = append(ls.skipped, p)
			continue
		}
		sig, err := s.clamd.scan(tr)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", p, err)
		}
		ls.scanned++
		if sig != "" {
			ls.hits = append(ls.hits, hit{p, sig})
		}
	}
}

// hiddenBy reports the first later layer that hides path p of layer i in the
// final filesystem, and how. It returns -1 if p is still visible.
func hiddenBy(p string, i int, layers []*layerScan) (int, string) {
	for j := i + 1; j < len(layers); j++ {
		l := layers[j]
		if l.files[p] {
			return j, "overwritten"
		}
		for d := p; d != "/"; d = path.Dir(d) {
			if l.whiteouts[d] {
				return j, "deleted (whiteout)"
			}
			if d != p && l.opaques[d] {
				return j, "deleted (opaque " + d + ")"
			}
		}
	}
	return -1, ""
}

// clamd is a client for one clamd session (IDSESSION). Commands are sent one
// at a time, so replies arrive in order.
type clamd struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialClamd(addr string) (*clamd, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("parse clamd address %q: %w", addr, err)
	}
	var network, address string
	switch u.Scheme {
	case "unix":
		network, address = "unix", u.Path
	case "tcp":
		network, address = "tcp", u.Host
	default:
		return nil, fmt.Errorf("clamd address %q: scheme must be unix or tcp", addr)
	}
	conn, err := net.DialTimeout(network, address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect clamd %s: %w", addr, err)
	}
	if _, err := conn.Write([]byte("zIDSESSION\x00")); err != nil {
		conn.Close()
		return nil, fmt.Errorf("start clamd session: %w", err)
	}
	return &clamd{conn: conn, r: bufio.NewReader(conn)}, nil
}

// scan streams r to clamd with INSTREAM and returns the signature name, or ""
// if clamd reports the stream as clean.
func (c *clamd) scan(r io.Reader) (string, error) {
	if _, err := c.conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", fmt.Errorf("send INSTREAM: %w", err)
	}
	buf := make([]byte, 4+64<<10)
	for {
		n, err := r.Read(buf[4:])
		if n > 0 {
			binary.BigEndian.PutUint32(buf, uint32(n))
			if _, werr := c.conn.Write(buf[:4+n]); werr != nil {
				return "", fmt.Errorf("send chunk: %w", werr)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read file: %w", err)
		}
	}
	if _, err := c.conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", fmt.Errorf("send end of stream: %w", err)
	}

	resp, err := c.r.ReadString(0)
	if err != nil {
		return "", fmt.Errorf("read reply: %w", err)
	}
	// Replies look like "<id>: stream: OK", "<id>: stream: <sig> FOUND"
	// or "<id>: <message> ERROR".
	_, msg, _ := strings.Cut(strings.TrimSuffix(resp, "\x00"), ": ")
	switch {
	case msg == "stream: OK":
		return "", nil
	case strings.HasPrefix(msg, "stream: ") && strings.HasSuffix(msg, " FOUND"):
		return strings.TrimSuffix(strings.TrimPrefix(msg, "stream: "), " FOUND"), nil
	default:
		return "", fmt.Errorf("clamd: %s", msg)
	}
}

func (c *clamd) Close() error {
	c.conn.Write([]byte("zEND\x00"))
	return c.conn.Close()
}

type testLayer struct {
	createdBy string
	files     map[string]string
}

// startSelftestRegistry serves an in-memory registry with test images and
// returns their references.
func startSelftestRegistry() (*httptest.Server, []string, error) {
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	host := strings.TrimPrefix(srv.URL, "http://")

	base := testLayer{"COPY hello.txt /etc/", map[string]string{"/etc/hello.txt": "hello\n"}}
	images := []struct {
		name   string
		layers []testLayer
	}{
		{"clean", []testLayer{base}},
		{"eicar-present", []testLayer{base,
			{"COPY eicar.com /opt/", map[string]string{"/opt/eicar.com": eicar()}},
		}},
		{"eicar-whiteout", []testLayer{base,
			{"COPY eicar.com /tmp/payload/", map[string]string{"/tmp/payload/eicar.com": eicar()}},
			{"RUN rm /tmp/payload/eicar.com", map[string]string{"/tmp/payload/.wh.eicar.com": ""}},
		}},
		{"eicar-opaque", []testLayer{base,
			{"COPY eicar.com /data/", map[string]string{"/data/eicar.com": eicar()}},
			{"RUN rm -rf /data && mkdir /data && echo replaced > /data/readme.txt",
				map[string]string{"/data/.wh..wh..opq": "", "/data/readme.txt": "replaced\n"}},
		}},
	}

	var refs []string
	for _, ti := range images {
		img, err := buildImage(ti.layers)
		if err != nil {
			srv.Close()
			return nil, nil, fmt.Errorf("build %s: %w", ti.name, err)
		}
		ref := host + "/selftest/" + ti.name + ":latest"
		r, err := name.ParseReference(ref, name.Insecure)
		if err != nil {
			srv.Close()
			return nil, nil, fmt.Errorf("parse %s: %w", ref, err)
		}
		if err := remote.Write(r, img); err != nil {
			srv.Close()
			return nil, nil, fmt.Errorf("push %s: %w", ref, err)
		}
		refs = append(refs, ref)
	}
	return srv, refs, nil
}

func buildImage(layers []testLayer) (v1.Image, error) {
	img := empty.Image
	for _, tl := range layers {
		b, err := tarBytes(tl.files)
		if err != nil {
			return nil, err
		}
		l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(b)), nil
		})
		if err != nil {
			return nil, fmt.Errorf("layer: %w", err)
		}
		img, err = mutate.Append(img, mutate.Addendum{Layer: l, History: v1.History{CreatedBy: tl.createdBy}})
		if err != nil {
			return nil, fmt.Errorf("append layer: %w", err)
		}
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", "amd64"
	return mutate.ConfigFile(img, cf)
}

func tarBytes(files map[string]string) ([]byte, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		content := files[n]
		h := &tar.Header{Name: strings.TrimPrefix(n, "/"), Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(h); err != nil {
			return nil, fmt.Errorf("tar header %s: %w", n, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			return nil, fmt.Errorf("tar write %s: %w", n, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("tar close: %w", err)
	}
	return buf.Bytes(), nil
}

// eicar builds the EICAR test string at runtime so that this source file does
// not trigger virus scanners itself.
func eicar() string {
	return strings.Join([]string{`X5O!P%@AP[4\PZX54(P^)7CC)7}$`, "EICAR-STANDARD-ANTIVIRUS-", "TEST-FILE!$H+H*"}, "")
}

func short(h v1.Hash) string {
	return h.Hex[:12]
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
