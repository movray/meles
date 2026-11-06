// Package extract walks the files of a single image layer without writing
// them to disk. It records whiteouts so that callers can tell which files are
// still visible in the final image filesystem and which were deleted by a
// later layer but are still shipped with the image.
package extract

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"strings"
)

// ErrLimitExceeded is returned (wrapped) when a layer exceeds a hard limit.
// A layer that exceeds a hard limit is never reported as clean.
var ErrLimitExceeded = errors.New("limit exceeded")

const (
	whiteoutPrefix = ".wh."
	opaqueMarker   = ".wh..wh..opq"
)

// Limits protect against tar bombs and oversized files.
type Limits struct {
	// MaxFileSize skips (and reports) regular files larger than this.
	// 0 means no limit.
	MaxFileSize int64
	// MaxLayerSize is a hard limit on the uncompressed size of a layer.
	// 0 means no limit.
	MaxLayerSize int64
	// MaxFiles is a hard limit on the number of entries in a layer.
	// 0 means no limit.
	MaxFiles int
}

// File is a regular file of a layer. Content is only valid during the
// callback passed to Walk.
type File struct {
	Path    string
	Size    int64
	Content io.Reader
}

// Signatures of skipped files, in the style of the engine's
// Heuristics.Limits.Exceeded.* results, so that ignore rules can name them.
const (
	SigMaxFileSize  = "meles.Limits.MaxFileSize"
	SigUnsupported  = "meles.Unsupported.TarEntry"
	SigEngineTooBig = "meles.Limits.StreamMaxLength"
	SigTrailingData = "meles.Unsupported.TrailingData"
)

// TrailingDataPath stands for the data after the end of a tar archive, which
// is no file and has no path of its own.
const TrailingDataPath = "/(data after the end of the archive)"

// Skipped is a file that was not scanned.
type Skipped struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Reason string `json:"reason"`
	// Signature names the reason: SigMaxFileSize, SigUnsupported,
	// SigEngineTooBig, SigTrailingData or the engine's
	// Heuristics.Limits.Exceeded.*.
	Signature string `json:"signature"`
	// SHA256 of the file content, hex.
	SHA256 string `json:"sha256,omitempty"`
}

// hashRest reads the rest of r and returns its sha256, hex.
func hashRest(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Layer is everything Walk learned about a layer apart from file contents.
type Layer struct {
	// Entries holds all non-directory entries by absolute path.
	Entries map[string]bool
	// Whiteouts holds paths deleted by a .wh.<name> entry.
	Whiteouts map[string]bool
	// Opaques holds directories whose lower-layer content is hidden by a
	// .wh..wh..opq entry.
	Opaques map[string]bool
	// Hidden holds whiteout entries that carry content. A container runtime
	// never unpacks them, but the content is shipped in the layer.
	Hidden  map[string]bool
	Skipped []Skipped
	// Files is the number of regular files passed to the callback.
	Files int
	// Bytes is the number of uncompressed bytes read.
	Bytes int64
}

// Walk reads the uncompressed layer tarball r and calls fn for every regular
// file within the limits. Whiteout entries are recorded; those with content
// are passed to fn as well, because the name of an entry must not decide
// whether its content is scanned. Walk reads r to the end: content after the
// end of the archive cannot be attributed to a file and is reported as
// skipped.
func Walk(r io.Reader, lim Limits, fn func(File) error) (*Layer, error) {
	cr := &countingReader{r: r}
	tr := tar.NewReader(cr)
	l := &Layer{Entries: map[string]bool{}, Whiteouts: map[string]bool{}, Opaques: map[string]bool{}, Hidden: map[string]bool{}}
	// expanded counts the declared size of all files. It can exceed the bytes
	// read: sparse files expand to far more than the layer holds.
	var expanded int64

	for entries := 0; ; entries++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			if err := trailingData(cr, lim, l); err != nil {
				return nil, err
			}
			l.Bytes = cr.n
			return l, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if lim.MaxFiles > 0 && entries >= lim.MaxFiles {
			return nil, fmt.Errorf("more than %d entries: %w", lim.MaxFiles, ErrLimitExceeded)
		}
		if h.Size < 0 {
			return nil, fmt.Errorf("read tar: negative size of %q", h.Name)
		}
		if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeGNUSparse {
			if h.Size > math.MaxInt64-expanded {
				return nil, fmt.Errorf("size overflow at %q: %w", h.Name, ErrLimitExceeded)
			}
			expanded += h.Size
		}
		if lim.MaxLayerSize > 0 && (expanded > lim.MaxLayerSize || cr.n > lim.MaxLayerSize-h.Size) {
			return nil, fmt.Errorf("larger than %d bytes: %w", lim.MaxLayerSize, ErrLimitExceeded)
		}

		p := CleanPath(h.Name)
		dir, base := path.Dir(p), path.Base(p)
		whiteout := true
		switch {
		case base == opaqueMarker:
			l.Opaques[dir] = true
		case strings.HasPrefix(base, whiteoutPrefix):
			l.Whiteouts[path.Join(dir, strings.TrimPrefix(base, whiteoutPrefix))] = true
		case h.Typeflag == tar.TypeDir:
			continue
		default:
			whiteout = false
		}
		switch {
		case !whiteout:
			l.Entries[p] = true
		case h.Size == 0:
			continue
		default:
			l.Hidden[p] = true
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeGNUSparse:
			// archive/tar expands sparse files when they are read.
		case tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			// No content of their own.
			continue
		default:
			sum, err := hashRest(tr)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", p, err)
			}
			l.Skipped = append(l.Skipped, Skipped{Path: p, Size: h.Size, Reason: fmt.Sprintf("unsupported tar entry type %q", h.Typeflag), Signature: SigUnsupported, SHA256: sum})
			continue
		}
		if lim.MaxFileSize > 0 && h.Size > lim.MaxFileSize {
			// The content is read anyway to get to the next entry; its hash
			// lets an ignore rule name exactly this file.
			sum, err := hashRest(tr)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", p, err)
			}
			l.Skipped = append(l.Skipped, Skipped{Path: p, Size: h.Size, Reason: fmt.Sprintf("larger than max file size (%d bytes)", lim.MaxFileSize), Signature: SigMaxFileSize, SHA256: sum})
			continue
		}
		if err := fn(File{Path: p, Size: h.Size, Content: tr}); err != nil {
			return nil, err
		}
		l.Files++
	}
}

// trailingData reads what follows the end of the archive. Zero padding is
// normal; anything else is shipped with the layer, but no file of it, and is
// reported as skipped.
func trailingData(r *countingReader, lim Limits, l *Layer) error {
	h := sha256.New()
	var size, last int64
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		h.Write(buf[:n])
		for i := n - 1; i >= 0; i-- {
			if buf[i] != 0 {
				last = size + int64(i) + 1
				break
			}
		}
		size += int64(n)
		if lim.MaxLayerSize > 0 && r.n > lim.MaxLayerSize {
			return fmt.Errorf("larger than %d bytes: %w", lim.MaxLayerSize, ErrLimitExceeded)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read after the end of the archive: %w", err)
		}
	}
	if last > 0 {
		l.Skipped = append(l.Skipped, Skipped{Path: TrailingDataPath, Size: size, Reason: "data after the end of the tar archive", Signature: SigTrailingData, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	return nil
}

// CleanPath turns a tar entry name into a clean absolute path. Traversal
// such as "../../etc/passwd" stays inside the layer root.
func CleanPath(name string) string {
	return path.Clean("/" + name)
}

// HiddenBy returns the index of the first layer after layer i that hides
// path p in the final filesystem, and how it does so ("overwritten",
// "whiteout" or "opaque"). It returns -1 if p is still visible. A whiteout
// entry with content is hidden by its own layer.
func HiddenBy(p string, i int, layers []*Layer) (int, string) {
	if layers[i].Hidden[p] {
		return i, "whiteout"
	}
	for j := i + 1; j < len(layers); j++ {
		l := layers[j]
		for d := p; d != "/"; d = path.Dir(d) {
			if l.Whiteouts[d] {
				return j, "whiteout"
			}
			if d != p && l.Opaques[d] {
				return j, "opaque"
			}
			// A later file at p, or at a parent directory of p, replaces it.
			if l.Entries[d] {
				return j, "overwritten"
			}
		}
	}
	return -1, ""
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
