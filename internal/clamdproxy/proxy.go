// Package clamdproxy puts TLS, token authentication and a command filter in
// front of clamd, which has none of these. Clients first send
// "zAUTH <token>\0"; afterwards only the commands meles needs are forwarded
// (PING, VERSION, IDSESSION, INSTREAM, END). Everything else, in particular
// SHUTDOWN and SCAN <path>, closes the connection.
//
// With RulesDir set, the proxy appends a hash of the YARA rules in clamd's
// database directory to the VERSION reply ("ClamAV 1.4.6/28164+rules.<hash>/
// <date>"). Clients use the signature version as cache and rescan key, so
// changed rules count like a signature update.
package clamdproxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"git.itknecht.de/sugras/meles/internal/engine/clamd"
)

const (
	// maxAuthLen bounds the authentication command.
	maxAuthLen = 4096
	// maxCommandLen bounds all other commands; the longest allowed one is
	// "zIDSESSION".
	maxCommandLen = 64
)

// allowed lists the forwarded clamd commands.
var allowed = map[string]bool{
	"PING":      true,
	"VERSION":   true,
	"IDSESSION": true,
	"INSTREAM":  true,
	"END":       true,
}

// Proxy forwards authenticated connections to clamd.
type Proxy struct {
	// Upstream is the clamd address, e.g. tcp://127.0.0.1:3310 or
	// unix:///tmp/clamd.sock.
	Upstream string
	// CertFile and KeyFile are reloaded when they change, e.g. after a
	// renewal by cert-manager.
	CertFile, KeyFile string
	// TokenFile holds the accepted tokens, one per line, so that a token can
	// be rotated without downtime. It is reloaded when it changes.
	TokenFile string
	// AuthTimeout bounds the TLS handshake and the authentication.
	AuthTimeout time.Duration
	// MaxConns limits concurrent client connections. 0 means no limit.
	MaxConns int
	// RulesDir is clamd's DatabaseDirectory; empty: VERSION is forwarded
	// unchanged.
	RulesDir string
	Logger   *slog.Logger

	cert   reloader[tls.Certificate]
	tokens reloader[[][32]byte]
}

// Serve accepts connections on ln until ctx is done.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	if p.Logger == nil {
		p.Logger = slog.New(slog.DiscardHandler)
	}
	if p.AuthTimeout <= 0 {
		p.AuthTimeout = 10 * time.Second
	}
	if _, _, err := p.upstream(); err != nil {
		return err
	}
	// Fail at startup, not on the first connection.
	if _, err := p.certificate(nil); err != nil {
		return err
	}
	if _, err := p.tokens.get(p.TokenFile, loadTokens); err != nil {
		return err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: p.certificate}
	tln := tls.NewListener(ln, cfg)

	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	var sem chan struct{}
	if p.MaxConns > 0 {
		sem = make(chan struct{}, p.MaxConns)
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := tln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("accept: %w", err)
		}
		if sem != nil {
			select {
			case sem <- struct{}{}:
			default:
				p.Logger.Warn("too many connections, rejecting", "remote", conn.RemoteAddr())
				conn.Close()
				continue
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sem != nil {
				defer func() { <-sem }()
			}
			p.handle(ctx, conn.(*tls.Conn))
		}()
	}
}

func (p *Proxy) handle(ctx context.Context, conn *tls.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	log := p.Logger.With("remote", conn.RemoteAddr().String())

	conn.SetDeadline(time.Now().Add(p.AuthTimeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		// Also TCP probes, so only at debug level.
		log.Debug("TLS handshake failed", "err", err)
		return
	}
	r := bufio.NewReader(conn)
	if err := p.authenticate(r, conn); err != nil {
		log.Warn("authentication failed", "err", err)
		return
	}
	conn.SetDeadline(time.Time{})

	first, err := readCommand(r, maxCommandLen)
	if err != nil {
		return
	}
	if !allowed[first.text] {
		log.Warn("connection closed", "err", fmt.Errorf("command %q not allowed", first.text))
		return
	}
	network, address, _ := p.upstream()
	up, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		log.Error("connect clamd", "err", err)
		return
	}
	defer up.Close()

	// VERSION outside a session is a connection of its own: clamd answers
	// and closes it.
	if first.text == "VERSION" && p.RulesDir != "" {
		if err := p.version(first, up, conn); err != nil {
			log.Error("VERSION", "err", err)
		}
		return
	}
	if _, err := up.Write(first.raw); err != nil {
		return
	}

	// clamd's replies go back unchanged. When clamd closes the connection,
	// e.g. after its IdleTimeout, the client connection is closed as well.
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(conn, up)
		conn.Close()
	}()
	err = nil
	if first.text == "INSTREAM" {
		err = forwardChunks(r, up)
	}
	if err == nil {
		err = forward(r, up)
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		log.Warn("connection closed", "err", err)
	}
	up.Close()
	<-done
}

// version forwards VERSION and appends the rules hash to the signature
// version in clamd's reply. Without readable rules the client gets no
// reply, rather than a version that hides the rules.
func (p *Proxy) version(cmd command, up net.Conn, client io.Writer) error {
	hash, err := rulesHash(p.RulesDir)
	if err != nil {
		return err
	}
	up.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := up.Write(cmd.raw); err != nil {
		return err
	}
	term := byte(0)
	if cmd.prefix == 'n' {
		term = '\n'
	}
	reply, err := bufio.NewReader(io.LimitReader(up, 1024)).ReadString(term)
	if err != nil {
		return fmt.Errorf("read reply: %w", err)
	}
	_, err = client.Write([]byte(withRules(reply, hash)))
	return err
}

// withRules turns "ClamAV 1.4.6/28164/<date>" into
// "ClamAV 1.4.6/28164+rules.<hash>/<date>".
func withRules(reply, hash string) string {
	parts := strings.SplitN(reply, "/", 3)
	if hash == "" || len(parts) < 2 {
		return reply
	}
	parts[1] += "+rules." + hash
	return strings.Join(parts, "/")
}

// rulesHash hashes the names and contents of the .yar and .yara files in
// dir; "" if there are none.
func rulesHash(dir string) (string, error) {
	var files []string
	for _, pat := range []string{"*.yar", "*.yara"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return "", err
		}
		files = append(files, m...)
	}
	if len(files) == 0 {
		return "", nil
	}
	slices.Sort(files)
	h := sha256.New()
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("rules hash: %w", err)
		}
		fmt.Fprintf(h, "%s\x00%d\x00", filepath.Base(f), len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12], nil
}

// authenticate reads "zAUTH <token>\0" and answers AUTH OK or AUTH FAILED.
func (p *Proxy) authenticate(r *bufio.Reader, w io.Writer) error {
	cmd, err := readCommand(r, maxAuthLen)
	if err != nil {
		return err
	}
	name, token, _ := strings.Cut(cmd.text, " ")
	if cmd.prefix != 'z' || name != clamd.AuthCommand {
		w.Write([]byte(clamd.AuthFailed + "\x00"))
		return fmt.Errorf("first command is not %s", clamd.AuthCommand)
	}
	tokens, err := p.tokens.get(p.TokenFile, loadTokens)
	if err != nil {
		w.Write([]byte(clamd.AuthFailed + "\x00"))
		return err
	}
	if !validToken(token, tokens) {
		w.Write([]byte(clamd.AuthFailed + "\x00"))
		return errors.New("wrong token")
	}
	_, err = w.Write([]byte(clamd.AuthOK + "\x00"))
	return err
}

// forward copies allowed commands from r to up until r ends or a command is
// not allowed.
func forward(r *bufio.Reader, up io.Writer) error {
	for {
		cmd, err := readCommand(r, maxCommandLen)
		if err != nil {
			return err
		}
		if !allowed[cmd.text] {
			return fmt.Errorf("command %q not allowed", cmd.text)
		}
		if _, err := up.Write(cmd.raw); err != nil {
			return err
		}
		if cmd.text == "INSTREAM" {
			if err := forwardChunks(r, up); err != nil {
				return err
			}
		}
	}
}

// forwardChunks copies INSTREAM chunks (4-byte big-endian length, data) up
// to and including the terminating zero-length chunk. clamd enforces its
// StreamMaxLength itself.
func forwardChunks(r io.Reader, up io.Writer) error {
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return fmt.Errorf("read chunk header: %w", err)
		}
		if _, err := up.Write(hdr[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 {
			return nil
		}
		if _, err := io.CopyN(up, r, int64(n)); err != nil {
			return fmt.Errorf("copy chunk: %w", err)
		}
	}
}

type command struct {
	prefix byte   // 'z' (NUL-terminated) or 'n' (newline-terminated)
	text   string // without prefix and terminator
	raw    []byte
}

// readCommand reads one z- or n-prefixed command of at most max bytes.
// Commands without prefix are rejected: they end the session in clamd and
// are not used by meles.
func readCommand(r *bufio.Reader, max int) (command, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return command{}, err
	}
	var term byte
	switch prefix {
	case 'z':
		term = 0
	case 'n':
		term = '\n'
	default:
		return command{}, fmt.Errorf("command without z or n prefix")
	}
	raw := []byte{prefix}
	for {
		b, err := r.ReadByte()
		if err != nil {
			return command{}, fmt.Errorf("read command: %w", err)
		}
		raw = append(raw, b)
		if b == term {
			return command{prefix: prefix, text: string(raw[1 : len(raw)-1]), raw: raw}, nil
		}
		if len(raw) > max {
			return command{}, fmt.Errorf("command longer than %d bytes", max)
		}
	}
}

func validToken(token string, tokens [][32]byte) bool {
	h := sha256.Sum256([]byte(token))
	ok := 0
	for _, t := range tokens {
		ok |= subtle.ConstantTimeCompare(h[:], t[:])
	}
	return token != "" && ok == 1
}

func loadTokens(path string) ([][32]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	var out [][32]byte
	for _, line := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, sha256.Sum256([]byte(t)))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("token file %s: no token", path)
	}
	return out, nil
}

func (p *Proxy) certificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c, err := p.cert.get(p.CertFile, func(string) (tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
		if err != nil {
			return c, fmt.Errorf("load TLS certificate: %w", err)
		}
		return c, nil
	})
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (p *Proxy) upstream() (network, address string, err error) {
	u, err := url.Parse(p.Upstream)
	if err != nil {
		return "", "", fmt.Errorf("parse upstream %q: %w", p.Upstream, err)
	}
	switch u.Scheme {
	case "unix":
		return "unix", u.Path, nil
	case "tcp":
		return "tcp", u.Host, nil
	}
	return "", "", fmt.Errorf("upstream %q: scheme must be unix or tcp", p.Upstream)
}

// reloader caches a value loaded from a file and loads it again when the
// file's modification time changes. Kubernetes updates mounted secrets by
// swapping a symlink, which os.Stat follows.
type reloader[T any] struct {
	mu      sync.Mutex
	val     T
	modTime time.Time
	loaded  bool
}

func (r *reloader[T]) get(path string, load func(string) (T, error)) (T, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fi, err := os.Stat(path)
	if err != nil {
		if r.loaded {
			// Keep the last good value during a secret update.
			return r.val, nil
		}
		var zero T
		return zero, fmt.Errorf("stat %s: %w", path, err)
	}
	if r.loaded && fi.ModTime().Equal(r.modTime) {
		return r.val, nil
	}
	v, err := load(path)
	if err != nil {
		if r.loaded {
			return r.val, nil
		}
		return v, err
	}
	r.val, r.modTime, r.loaded = v, fi.ModTime(), true
	return v, nil
}
