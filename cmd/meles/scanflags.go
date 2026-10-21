package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	"git.itknecht.de/sugras/meles/internal/engine/clamd"
	"git.itknecht.de/sugras/meles/internal/extract"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/source"
)

// scanFlags are shared by all commands that scan.
type scanFlags struct {
	clamd        string
	clamdToken   string
	clamdCA      string
	concurrency  int
	maxFileSize  sizeValue
	maxLayerSize sizeValue
	maxFiles     int
	insecure     bool
}

func (f *scanFlags) register(fs *pflag.FlagSet) {
	f.maxFileSize = 25 << 20
	f.maxLayerSize = 4 << 30
	fs.StringVar(&f.clamd, "clamd", "unix:///run/clamav/clamd.ctl", "clamd address: unix:///path, tcp://host:3310 or tls://host:3310 (meles clamd-proxy)")
	fs.StringVar(&f.clamdToken, "clamd-token", "", "token for meles clamd-proxy; prefer MELES_CLAMD_TOKEN, a flag is visible in the process list")
	fs.StringVar(&f.clamdCA, "clamd-ca", "", "CA certificate (PEM) of meles clamd-proxy; default: system roots")
	fs.IntVar(&f.concurrency, "concurrency", 4, "parallel clamd sessions per scan")
	fs.Var(&f.maxFileSize, "max-file-size", "skip and report files larger than this; keep it at or below clamd's StreamMaxLength")
	fs.Var(&f.maxLayerSize, "max-layer-size", "fail on layers larger than this (uncompressed)")
	fs.IntVar(&f.maxFiles, "max-files", 500000, "fail on layers with more entries than this")
	fs.BoolVar(&f.insecure, "insecure-registry", false, "allow plain HTTP registries")
}

func (f *scanFlags) scanner(cache *scan.Cache) (*scan.Scanner, error) {
	c, err := clamd.New(f.clamd)
	if err != nil {
		return nil, err
	}
	c.Token = f.clamdToken
	if f.clamdCA != "" {
		pem, err := os.ReadFile(f.clamdCA)
		if err != nil {
			return nil, fmt.Errorf("--clamd-ca: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--clamd-ca %s: no PEM certificate", f.clamdCA)
		}
		c.TLSConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	if f.concurrency < 1 {
		return nil, fmt.Errorf("--concurrency must be at least 1")
	}
	// Files are held in memory while they are scanned.
	if f.maxFileSize <= 0 {
		return nil, fmt.Errorf("--max-file-size must be greater than 0")
	}
	return &scan.Scanner{
		Engine:      c,
		Limits:      extract.Limits{MaxFileSize: int64(f.maxFileSize), MaxLayerSize: int64(f.maxLayerSize), MaxFiles: f.maxFiles},
		Concurrency: f.concurrency,
		Cache:       cache,
		Source:      source.Options{Insecure: f.insecure},
		Logger:      slog.Default(),
	}, nil
}

// sizeValue is a byte size flag that accepts suffixes: 512K, 25M, 4G.
type sizeValue int64

func (s *sizeValue) String() string { return formatSize(int64(*s)) }
func (s *sizeValue) Type() string   { return "size" }

func (s *sizeValue) Set(v string) error {
	n, err := parseSize(v)
	if err != nil {
		return err
	}
	*s = sizeValue(n)
	return nil
}

func parseSize(v string) (int64, error) {
	v = strings.TrimSpace(strings.ToUpper(v))
	v = strings.TrimSuffix(strings.TrimSuffix(v, "B"), "I")
	mult := int64(1)
	if v != "" {
		switch v[len(v)-1] {
		case 'K':
			mult = 1 << 10
		case 'M':
			mult = 1 << 20
		case 'G':
			mult = 1 << 30
		}
		if mult > 1 {
			v = v[:len(v)-1]
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q (examples: 512K, 25M, 4G)", v)
	}
	return n * mult, nil
}

func formatSize(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%dG", n>>30)
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%dM", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%dK", n>>10)
	}
	return strconv.FormatInt(n, 10)
}
