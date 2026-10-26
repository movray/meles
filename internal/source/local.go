package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/klauspost/compress/zstd"
)

// Local image inputs: an OCI image layout (a directory, or a tar of one as
// written by docker save since Docker 25, buildx --output type=oci, podman
// save --format oci-archive or skopeo), or a docker save archive in the
// older format with only manifest.json. Tars may be compressed with gzip or
// zstd. The images are read in place: nothing is extracted, except that a
// compressed tar is unpacked into one temporary file.

// maxJSON bounds index, manifest and config blobs read into memory.
const maxJSON = 16 << 20

// maxTarEntries bounds the entries of an input tar.
const maxTarEntries = 1 << 20

// Annotations that name an image in an OCI layout: containerd and Docker
// write the full reference, skopeo and buildx often only the tag.
const (
	annotationImageName = "io.containerd.image.name"
	annotationRefName   = "org.opencontainers.image.ref.name"
)

// fetchLocal reads the image named name (empty: the only one) from the
// layout or archive at input.
func fetchLocal(input, name string, opts Options) (_ *Image, err error) {
	in, err := openInput(input)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			in.close()
		}
	}()
	var img *Image
	switch {
	case exists(in.fsys, "index.json"):
		img, err = in.oci(name, opts.Platforms)
	case exists(in.fsys, "manifest.json") && in.tar != "":
		img, err = in.dockerArchive(name, opts.Platforms)
	case exists(in.fsys, "manifest.json"):
		return nil, fmt.Errorf("%s: a directory with manifest.json (an unpacked docker save of Docker before 25) is not supported; pass the tar file", input)
	default:
		return nil, fmt.Errorf("%s: neither an OCI image layout (index.json) nor a docker save archive (manifest.json)", input)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", input, err)
	}
	img.Input = input
	img.close = in.close
	if img.Ref == "" {
		img.Ref = input
	}
	return img, nil
}

func exists(fsys fs.FS, name string) bool {
	_, err := fs.Stat(fsys, name)
	return err == nil
}

// input is an opened layout or archive.
type input struct {
	fsys fs.FS
	// tar is the (uncompressed) tar file, empty for a directory.
	tar   string
	close func() error
}

func openInput(p string) (*input, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("input: %w", err)
	}
	if st.IsDir() {
		// The root keeps symlinks from leading out of the directory.
		root, err := os.OpenRoot(p)
		if err != nil {
			return nil, fmt.Errorf("input: %w", err)
		}
		return &input{fsys: root.FS(), close: root.Close}, nil
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("input: %w", err)
	}
	tarPath, cleanup, err := uncompressed(f, p)
	if err != nil {
		f.Close()
		return nil, err
	}
	if tarPath != p {
		f.Close()
		if f, err = os.Open(tarPath); err != nil {
			cleanup()
			return nil, fmt.Errorf("input: %w", err)
		}
	}
	tfs, err := indexTar(f)
	if err != nil {
		f.Close()
		cleanup()
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &input{fsys: tfs, tar: tarPath, close: func() error {
		err := f.Close()
		cleanup()
		return err
	}}, nil
}

// uncompressed returns the path of the uncompressed tar: p itself, or a
// temporary file that cleanup removes.
func uncompressed(f *os.File, p string) (string, func(), error) {
	magic := make([]byte, 4)
	n, _ := io.ReadFull(f, magic)
	magic = magic[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", nil, fmt.Errorf("input: %w", err)
	}
	var r io.Reader
	switch {
	case bytes.HasPrefix(magic, []byte{0x1f, 0x8b}):
		zr, err := gzip.NewReader(f)
		if err != nil {
			return "", nil, fmt.Errorf("%s: gzip: %w", p, err)
		}
		r = zr
	case bytes.HasPrefix(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		zr, err := zstd.NewReader(f)
		if err != nil {
			return "", nil, fmt.Errorf("%s: zstd: %w", p, err)
		}
		defer zr.Close()
		r = zr
	default:
		return p, func() {}, nil
	}
	tmp, err := os.CreateTemp("", "meles-input-*.tar")
	if err != nil {
		return "", nil, fmt.Errorf("unpack %s: %w", p, err)
	}
	cleanup := func() { os.Remove(tmp.Name()) }
	_, err = io.Copy(tmp, r)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("unpack %s: %w", p, err)
	}
	return tmp.Name(), cleanup, nil
}

// tarFS serves the regular files of a tar from their offsets.
type tarFS struct {
	f       *os.File
	entries map[string]tarEntry
}

type tarEntry struct {
	off, size int64
	mod       time.Time
}

// offsetReader tracks the position in the tar, so that tar.Reader's
// headers tell where each file's data starts. It seeks, so that tar.Reader
// skips file data instead of reading it.
type offsetReader struct {
	f   *os.File
	pos int64
}

func (r *offsetReader) Read(p []byte) (int, error) {
	n, err := r.f.Read(p)
	r.pos += int64(n)
	return n, err
}

func (r *offsetReader) Seek(off int64, whence int) (int64, error) {
	pos, err := r.f.Seek(off, whence)
	if err == nil {
		r.pos = pos
	}
	return pos, err
}

func indexTar(f *os.File) (*tarFS, error) {
	or := &offsetReader{f: f}
	tr := tar.NewReader(or)
	t := &tarFS{f: f, entries: map[string]tarEntry{}}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if len(t.entries) >= maxTarEntries {
			return nil, fmt.Errorf("more than %d files in the tar", maxTarEntries)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		// fs.ValidPath rejects "..", absolute and unclean names; such
		// entries cannot be asked for, so they are left out.
		n := strings.TrimPrefix(path.Clean(strings.TrimPrefix(h.Name, "./")), "/")
		if !fs.ValidPath(n) {
			continue
		}
		t.entries[n] = tarEntry{off: or.pos, size: h.Size, mod: h.ModTime}
	}
	return t, nil
}

func (t *tarFS) Open(n string) (fs.File, error) {
	if !fs.ValidPath(n) {
		return nil, &fs.PathError{Op: "open", Path: n, Err: fs.ErrInvalid}
	}
	e, ok := t.entries[n]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: n, Err: fs.ErrNotExist}
	}
	return &tarFile{SectionReader: io.NewSectionReader(t.f, e.off, e.size), name: path.Base(n), e: e}, nil
}

type tarFile struct {
	*io.SectionReader
	name string
	e    tarEntry
}

func (f *tarFile) Stat() (fs.FileInfo, error) { return tarInfo{f.name, f.e}, nil }
func (f *tarFile) Close() error               { return nil }

type tarInfo struct {
	name string
	e    tarEntry
}

func (i tarInfo) Name() string       { return i.name }
func (i tarInfo) Size() int64        { return i.e.size }
func (i tarInfo) Mode() fs.FileMode  { return 0o444 }
func (i tarInfo) ModTime() time.Time { return i.e.mod }
func (i tarInfo) IsDir() bool        { return false }
func (i tarInfo) Sys() any           { return nil }

// oci reads an OCI image layout.
func (in *input) oci(want string, pf PlatformFilter) (*Image, error) {
	o := &ociLayout{fsys: in.fsys}
	raw, err := readLimited(in.fsys, "index.json")
	if err != nil {
		return nil, err
	}
	top, err := v1.ParseIndexManifest(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse index.json: %w", err)
	}
	var cands []v1.Descriptor
	for _, d := range top.Manifests {
		if isIndex(d.MediaType) || isImage(d.MediaType) {
			cands = append(cands, d)
		}
	}
	var desc *v1.Descriptor
	switch {
	case want != "":
		for i, d := range cands {
			if nameMatches(want, d.Annotations) {
				desc = &cands[i]
				break
			}
		}
		if desc == nil && len(cands) == 1 && unnamed(cands[0].Annotations) {
			// One image without a name (e.g. crane pull --format=oci): the
			// name the user gives is its name in the report.
			desc = &cands[0]
		}
		if desc == nil {
			return nil, fmt.Errorf("no image named %s; the layout holds %s", want, describe(cands))
		}
	case len(cands) == 1:
		desc = &cands[0]
	case len(cands) > 1 && allPlatformImages(cands):
		// The platform images are listed in index.json itself.
		idx := &ociIndex{o: o, raw: raw, im: top, mediaType: types.OCIImageIndex}
		img := &Image{}
		if img.Platforms, err = collectIndex("index.json", idx, pf); err != nil {
			return nil, err
		}
		img.Digest = digestOf(raw).String()
		return img, nil
	case len(cands) == 0:
		return nil, errors.New("index.json lists no image")
	default:
		return nil, fmt.Errorf("the layout holds several images (%s); name the one to scan", describe(cands))
	}

	img := &Image{Ref: imageName(desc.Annotations, want), Digest: desc.Digest.String()}
	if isIndex(desc.MediaType) {
		idx, err := o.index(*desc)
		if err != nil {
			return nil, err
		}
		img.Platforms, err = collectIndex(desc.Digest.String(), idx, pf)
		return img, err
	}
	pi, err := o.image(*desc)
	if err != nil {
		return nil, err
	}
	img.Platforms, err = collectImage(desc.Digest.String(), pi, desc.Digest.String(), pf)
	return img, err
}

func unnamed(ann map[string]string) bool {
	return ann[annotationImageName] == "" && ann[annotationRefName] == ""
}

func isIndex(mt types.MediaType) bool {
	return mt == types.OCIImageIndex || mt == types.DockerManifestList
}

func isImage(mt types.MediaType) bool {
	return mt == types.OCIManifestSchema1 || mt == types.DockerManifestSchema2
}

func allPlatformImages(ds []v1.Descriptor) bool {
	for _, d := range ds {
		if !isImage(d.MediaType) || d.Platform == nil {
			return false
		}
	}
	return true
}

// nameMatches compares a name given by the user with the names of an
// entry: a full reference such as alpine:3.20 or docker.io/library/alpine:3.20,
// or a bare ref.name such as 3.20.
func nameMatches(want string, ann map[string]string) bool {
	for _, have := range []string{ann[annotationImageName], ann[annotationRefName]} {
		if have == "" {
			continue
		}
		if have == want {
			return true
		}
		w, err1 := name.ParseReference(want)
		h, err2 := name.ParseReference(have)
		if err1 == nil && err2 == nil && w.Name() == h.Name() {
			return true
		}
	}
	return false
}

// imageName returns the name of an entry for the report: the full
// reference if the layout has one, else what the user asked for.
func imageName(ann map[string]string, want string) string {
	if n := ann[annotationImageName]; n != "" {
		return n
	}
	if n := ann[annotationRefName]; n != "" && strings.ContainsAny(n, "/:") {
		return n
	}
	return want
}

func describe(ds []v1.Descriptor) string {
	var names []string
	for _, d := range ds {
		n := cmpOr(d.Annotations[annotationImageName], d.Annotations[annotationRefName], d.Digest.String())
		names = append(names, n)
	}
	return strings.Join(names, ", ")
}

func cmpOr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func readLimited(fsys fs.FS, n string) ([]byte, error) {
	f, err := fsys.Open(n)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxJSON+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", n, err)
	}
	if len(b) > maxJSON {
		return nil, fmt.Errorf("%s is larger than %d bytes", n, maxJSON)
	}
	return b, nil
}

func digestOf(b []byte) v1.Hash {
	s := sha256.Sum256(b)
	return v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(s[:])}
}

// ociLayout reads blobs by digest.
type ociLayout struct {
	fsys fs.FS
}

func blobPath(h v1.Hash) (string, error) {
	if h.Algorithm != "sha256" || len(h.Hex) != 64 || strings.Trim(h.Hex, "0123456789abcdef") != "" {
		return "", fmt.Errorf("unsupported digest %s", h)
	}
	return "blobs/sha256/" + h.Hex, nil
}

// bytes reads a small blob and checks its digest.
func (o *ociLayout) bytes(d v1.Descriptor) ([]byte, error) {
	p, err := blobPath(d.Digest)
	if err != nil {
		return nil, err
	}
	b, err := readLimited(o.fsys, p)
	if err != nil {
		return nil, fmt.Errorf("blob %s: %w", d.Digest, err)
	}
	if got := digestOf(b); got != d.Digest {
		return nil, fmt.Errorf("blob %s has digest %s", d.Digest, got)
	}
	return b, nil
}

func (o *ociLayout) index(d v1.Descriptor) (*ociIndex, error) {
	raw, err := o.bytes(d)
	if err != nil {
		return nil, err
	}
	im, err := v1.ParseIndexManifest(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse index %s: %w", d.Digest, err)
	}
	return &ociIndex{o: o, raw: raw, im: im, mediaType: d.MediaType}, nil
}

func (o *ociLayout) image(d v1.Descriptor) (v1.Image, error) {
	raw, err := o.bytes(d)
	if err != nil {
		return nil, err
	}
	m, err := v1.ParseManifest(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", d.Digest, err)
	}
	img, err := partial.CompressedToImage(&ociImage{o: o, raw: raw, m: m, mediaType: d.MediaType})
	if err != nil {
		return nil, fmt.Errorf("image %s: %w", d.Digest, err)
	}
	return img, nil
}

// ociIndex is an image index in a layout.
type ociIndex struct {
	o         *ociLayout
	raw       []byte
	im        *v1.IndexManifest
	mediaType types.MediaType
}

func (i *ociIndex) MediaType() (types.MediaType, error)       { return i.mediaType, nil }
func (i *ociIndex) Digest() (v1.Hash, error)                  { return digestOf(i.raw), nil }
func (i *ociIndex) Size() (int64, error)                      { return int64(len(i.raw)), nil }
func (i *ociIndex) IndexManifest() (*v1.IndexManifest, error) { return i.im, nil }
func (i *ociIndex) RawManifest() ([]byte, error)              { return i.raw, nil }

func (i *ociIndex) descriptor(h v1.Hash) (v1.Descriptor, error) {
	for _, d := range i.im.Manifests {
		if d.Digest == h {
			return d, nil
		}
	}
	return v1.Descriptor{}, fmt.Errorf("index has no entry %s", h)
}

func (i *ociIndex) Image(h v1.Hash) (v1.Image, error) {
	d, err := i.descriptor(h)
	if err != nil {
		return nil, err
	}
	return i.o.image(d)
}

func (i *ociIndex) ImageIndex(h v1.Hash) (v1.ImageIndex, error) {
	d, err := i.descriptor(h)
	if err != nil {
		return nil, err
	}
	return i.o.index(d)
}

// ociImage is the core of an image in a layout for partial.CompressedToImage.
type ociImage struct {
	o         *ociLayout
	raw       []byte
	m         *v1.Manifest
	mediaType types.MediaType
}

func (i *ociImage) MediaType() (types.MediaType, error) { return i.mediaType, nil }
func (i *ociImage) RawManifest() ([]byte, error)        { return i.raw, nil }
func (i *ociImage) RawConfigFile() ([]byte, error)      { return i.o.bytes(i.m.Config) }

func (i *ociImage) LayerByDigest(h v1.Hash) (partial.CompressedLayer, error) {
	for _, d := range i.m.Layers {
		if d.Digest == h {
			return &ociLayer{o: i.o, d: d}, nil
		}
	}
	return nil, fmt.Errorf("manifest has no layer %s", h)
}

// ociLayer is a layer blob; its digest is checked while it is read.
type ociLayer struct {
	o *ociLayout
	d v1.Descriptor
}

func (l *ociLayer) Digest() (v1.Hash, error)            { return l.d.Digest, nil }
func (l *ociLayer) Size() (int64, error)                { return l.d.Size, nil }
func (l *ociLayer) MediaType() (types.MediaType, error) { return l.d.MediaType, nil }

func (l *ociLayer) Compressed() (io.ReadCloser, error) {
	p, err := blobPath(l.d.Digest)
	if err != nil {
		return nil, err
	}
	f, err := l.o.fsys.Open(p)
	if err != nil {
		return nil, fmt.Errorf("layer %s: %w", l.d.Digest, err)
	}
	return &verifyReader{rc: f, h: sha256.New(), want: l.d.Digest, size: l.d.Size}, nil
}

// verifyReader fails at EOF if the content does not match the digest and
// size, as go-containerregistry does for registry blobs: the scanner
// trusts a layer's identity only once it was read to the end.
type verifyReader struct {
	rc   io.ReadCloser
	h    hash.Hash
	want v1.Hash
	size int64
	n    int64
}

func (r *verifyReader) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	r.h.Write(p[:n])
	r.n += int64(n)
	if errors.Is(err, io.EOF) {
		if r.n != r.size {
			return n, fmt.Errorf("layer %s: read %d bytes, want %d", r.want, r.n, r.size)
		}
		if got := hex.EncodeToString(r.h.Sum(nil)); got != r.want.Hex {
			return n, fmt.Errorf("layer %s: content has digest sha256:%s", r.want, got)
		}
	}
	return n, err
}

func (r *verifyReader) Close() error { return r.rc.Close() }

// dockerArchive reads a docker save archive in the format before Docker 25
// (podman's docker-archive too), with go-containerregistry's tarball.
func (in *input) dockerArchive(want string, pf PlatformFilter) (*Image, error) {
	opener := func() (io.ReadCloser, error) { return os.Open(in.tar) }
	m, err := tarball.LoadManifest(opener)
	if err != nil {
		return nil, fmt.Errorf("read manifest.json: %w", err)
	}
	var tag *name.Tag
	ref := ""
	switch {
	case want != "":
		for _, e := range m {
			for _, t := range e.RepoTags {
				if t == want || sameName(t, want) {
					if parsed, err := name.NewTag(t); err == nil {
						tag, ref = &parsed, t
					}
				}
			}
		}
		if tag == nil && len(m) == 1 && len(m[0].RepoTags) == 0 {
			ref = want // one untagged image: it gets the name the user gives
		} else if tag == nil {
			return nil, fmt.Errorf("no image tagged %s; the archive holds %s", want, repoTags(m))
		}
	case len(m) == 1:
		if len(m[0].RepoTags) > 0 {
			ref = m[0].RepoTags[0]
		}
	default:
		return nil, fmt.Errorf("the archive holds several images (%s); name the one to scan", repoTags(m))
	}
	img, err := tarball.Image(opener, tag)
	if err != nil {
		return nil, fmt.Errorf("read image: %w", err)
	}
	d, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("image digest: %w", err)
	}
	out := &Image{Ref: ref, Digest: d.String()}
	out.Platforms, err = collectImage(ref, img, d.String(), pf)
	return out, err
}

func sameName(a, b string) bool {
	ra, err1 := name.ParseReference(a)
	rb, err2 := name.ParseReference(b)
	return err1 == nil && err2 == nil && ra.Name() == rb.Name()
}

func repoTags(m tarball.Manifest) string {
	var tags []string
	for _, e := range m {
		if len(e.RepoTags) == 0 {
			tags = append(tags, "an untagged image ("+e.Config+")")
		}
		tags = append(tags, e.RepoTags...)
	}
	return strings.Join(slices.Compact(tags), ", ")
}
