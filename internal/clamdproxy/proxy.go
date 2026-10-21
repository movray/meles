// Package clamdproxy puts TLS, token authentication and a command filter in
// front of clamd, which has none of these. Clients first send
// "zAUTH <token>\0"; afterwards only the commands meles needs are forwarded
// (PING, VERSION, IDSESSION, INSTREAM, END). Everything else, in particular
// SHUTDOWN and SCAN <path>, closes the connection.
package clamdproxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
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

	network, address, _ := p.upstream()
	up, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		log.Error("connect clamd", "err", err)
		return
	}
	defer up.Close()

	// clamd's replies go back unchanged. When clamd closes the connection,
	// e.g. after its IdleTimeout, the client connection is closed as well.
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(conn, up)
		conn.Close()
	}()
	if err := forward(r, up); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		log.Warn("connection closed", "err", err)
	}
	up.Close()
	<-done
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
