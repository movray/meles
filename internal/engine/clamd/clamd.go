// Package clamd talks to a ClamAV daemon over its socket protocol.
//
// meles never links against libclamav (GPLv2): clamd runs as a separate
// process and keeps the signature database in memory once.
//
// With a tls:// address the client talks to meles clamd-proxy instead, which
// adds TLS and token authentication in front of clamd: the first command on
// every connection is "zAUTH <token>\0", answered with "AUTH OK\0".
package clamd

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"

	"git.itknecht.de/sugras/meles/internal/engine"
)

// chunkSize is the INSTREAM chunk size. clamd accepts any size up to its
// StreamMaxLength; 64 KiB keeps memory per session small.
const chunkSize = 64 << 10

// Authentication with meles clamd-proxy.
const (
	AuthCommand = "AUTH"
	AuthOK      = "AUTH OK"
	AuthFailed  = "AUTH FAILED"
)

// Client connects to clamd. The zero value is not usable; use New.
type Client struct {
	network, address string
	tls              bool
	// Timeout bounds dialing and each single scan.
	Timeout time.Duration
	// TLSConfig is used for tls:// addresses. Nil means the system roots.
	TLSConfig *tls.Config
	// Token authenticates with meles clamd-proxy. It is only sent over TLS.
	Token string
	// ConnectRetry is how long refused or timed-out connections are retried.
	// A new pod may be rejected by network policies for a few seconds until
	// the CNI knows it (seen with k3s/kube-router), and clamd may just be
	// restarting.
	ConnectRetry time.Duration
}

var _ engine.Engine = (*Client)(nil)

// New parses addr: "unix:///run/clamav/clamd.ctl", "tcp://host:3310" or
// "tls://host:3310" (meles clamd-proxy).
func New(addr string) (*Client, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("parse clamd address %q: %w", addr, err)
	}
	c := &Client{Timeout: 5 * time.Minute, ConnectRetry: 30 * time.Second}
	switch u.Scheme {
	case "unix":
		c.network, c.address = "unix", u.Path
	case "tcp", "tls":
		if u.Port() == "" {
			return nil, fmt.Errorf("clamd address %q: missing port", addr)
		}
		c.network, c.address, c.tls = "tcp", u.Host, u.Scheme == "tls"
	default:
		return nil, fmt.Errorf("clamd address %q: scheme must be unix, tcp or tls", addr)
	}
	if c.address == "" {
		return nil, fmt.Errorf("clamd address %q: missing path or host", addr)
	}
	return c, nil
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	if c.Token != "" && !c.tls {
		return nil, errors.New("clamd token requires a tls:// address")
	}
	conn, err := c.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect clamd %s: %w", c.url(), err)
	}
	if c.tls {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if c.TLSConfig != nil {
			cfg = c.TLSConfig.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName, _, _ = net.SplitHostPort(c.address)
		}
		tc := tls.Client(conn, cfg)
		hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("connect clamd %s: %w", c.url(), err)
		}
		conn = tc
	}
	if c.Token != "" {
		if err := authenticate(conn, c.Token); err != nil {
			conn.Close()
			return nil, fmt.Errorf("clamd %s: %w", c.url(), err)
		}
	}
	return conn, nil
}

// connect opens the connection and retries refused or timed-out attempts
// for up to ConnectRetry.
func (c *Client) connect(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	deadline := time.Now().Add(c.ConnectRetry)
	wait := 500 * time.Millisecond
	for {
		conn, err := d.DialContext(ctx, c.network, c.address)
		if err == nil || !retryable(err) || time.Now().Add(wait).After(deadline) {
			return conn, err
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, err
		}
		wait = min(2*wait, 5*time.Second)
	}
}

func retryable(err error) bool {
	var ne net.Error
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) || errors.As(err, &ne) && ne.Timeout()
}

func (c *Client) url() string {
	switch {
	case c.tls:
		return "tls://" + c.address
	case c.network == "unix":
		return "unix://" + c.address
	}
	return "tcp://" + c.address
}

// authenticate sends the token to meles clamd-proxy and waits for AUTH OK.
// It reads byte by byte so that nothing after the reply is consumed.
func authenticate(conn net.Conn, token string) error {
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte("z" + AuthCommand + " " + token + "\x00")); err != nil {
		return fmt.Errorf("send token: %w", err)
	}
	var reply []byte
	b := make([]byte, 1)
	for len(reply) < 64 {
		if _, err := io.ReadFull(conn, b); err != nil {
			return fmt.Errorf("read authentication reply: %w", err)
		}
		if b[0] == 0 {
			break
		}
		reply = append(reply, b[0])
	}
	switch string(reply) {
	case AuthOK:
		return nil
	case AuthFailed:
		return errors.New("authentication failed (wrong token)")
	}
	return fmt.Errorf("unexpected authentication reply %q", reply)
}

// Version sends VERSION, e.g. "ClamAV 1.4.3/28159/Tue Oct 20 08:24:12 2026".
func (c *Client) Version(ctx context.Context) (engine.Version, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return engine.Version{}, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write([]byte("zVERSION\x00")); err != nil {
		return engine.Version{}, fmt.Errorf("send VERSION: %w", err)
	}
	resp, err := bufio.NewReader(conn).ReadString(0)
	if err != nil {
		return engine.Version{}, fmt.Errorf("read VERSION reply: %w", err)
	}
	resp = strings.TrimSuffix(resp, "\x00")
	switch {
	case resp == AuthFailed:
		return engine.Version{}, errors.New("clamd proxy requires a token (--clamd-token)")
	case !strings.HasPrefix(resp, "ClamAV "):
		return engine.Version{}, fmt.Errorf("unexpected VERSION reply %q", resp)
	}
	return ParseVersion(resp), nil
}

// ParseVersion splits a clamd VERSION reply into engine and signature
// database version.
func ParseVersion(raw string) engine.Version {
	parts := strings.SplitN(raw, "/", 3)
	v := engine.Version{Engine: parts[0], Raw: raw}
	if len(parts) > 1 {
		v.Signatures = parts[1]
	}
	return v
}

// Open starts an IDSESSION. Commands are sent one at a time, so replies
// arrive in order.
func (c *Client) Open(ctx context.Context) (engine.Session, error) {
	s := &session{client: c}
	if err := s.connect(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

type session struct {
	client *Client
	conn   net.Conn
	r      *bufio.Reader
	broken bool
}

// errBroken marks a session that must not be reused.
var errBroken = errors.New("clamd session broken")

// connError is an I/O error on the connection, as opposed to an error
// reported by clamd.
type connError struct{ err error }

func (e *connError) Error() string { return e.err.Error() }
func (e *connError) Unwrap() error { return e.err }

func (s *session) connect(ctx context.Context) error {
	conn, err := s.client.dial(ctx)
	if err != nil {
		return err
	}
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write([]byte("zIDSESSION\x00")); err != nil {
		conn.Close()
		return fmt.Errorf("start clamd session: %w", err)
	}
	s.conn, s.r = conn, bufio.NewReader(conn)
	return nil
}

// Scan scans r. clamd closes sessions that were idle for longer than its
// IdleTimeout, e.g. while meles downloads a large layer. On a connection
// error Scan therefore retries once on a new session if r is an io.Seeker.
func (s *session) Scan(ctx context.Context, r io.Reader) (string, error) {
	if s.broken {
		return "", errBroken
	}
	sig, err := s.scan(ctx, r)
	var ce *connError
	if seeker, ok := r.(io.Seeker); ok && errors.As(err, &ce) && ctx.Err() == nil {
		s.conn.Close()
		if _, serr := seeker.Seek(0, io.SeekStart); serr != nil {
			err = fmt.Errorf("rewind input: %w", serr)
		} else if cerr := s.connect(ctx); cerr != nil {
			err = fmt.Errorf("reconnect after %v: %w", err, cerr)
		} else {
			sig, err = s.scan(ctx, r)
		}
	}
	if err != nil {
		// After a protocol or I/O error the reply stream is out of sync.
		s.broken = true
	}
	return sig, err
}

func (s *session) scan(ctx context.Context, r io.Reader) (string, error) {
	if dl, ok := ctx.Deadline(); ok {
		s.conn.SetDeadline(dl)
	} else {
		s.conn.SetDeadline(time.Now().Add(s.client.Timeout))
	}
	stop := context.AfterFunc(ctx, func() { s.conn.SetDeadline(time.Now()) })
	defer stop()

	if _, err := s.conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", &connError{fmt.Errorf("send INSTREAM: %w", err)}
	}
	buf := make([]byte, 4+chunkSize)
	for {
		n, err := r.Read(buf[4:])
		if n > 0 {
			binary.BigEndian.PutUint32(buf, uint32(n))
			if _, werr := s.conn.Write(buf[:4+n]); werr != nil {
				return "", &connError{fmt.Errorf("send chunk: %w", werr)}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read input: %w", err)
		}
	}
	if _, err := s.conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", &connError{fmt.Errorf("send end of stream: %w", err)}
	}

	resp, err := s.r.ReadString(0)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", &connError{fmt.Errorf("read reply: %w", err)}
	}
	return ParseReply(strings.TrimSuffix(resp, "\x00"))
}

// ParseReply interprets a session reply: "<id>: stream: OK",
// "<id>: stream: <signature> FOUND" or "<id>: <message> ERROR".
func ParseReply(resp string) (string, error) {
	_, msg, ok := strings.Cut(resp, ": ")
	if !ok {
		return "", fmt.Errorf("clamd: unexpected reply %q", resp)
	}
	switch {
	case msg == "stream: OK":
		return "", nil
	case strings.HasPrefix(msg, "stream: ") && strings.HasSuffix(msg, " FOUND"):
		return strings.TrimSuffix(strings.TrimPrefix(msg, "stream: "), " FOUND"), nil
	default:
		return "", fmt.Errorf("clamd: %s", msg)
	}
}

func (s *session) Close() error {
	s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	s.conn.Write([]byte("zEND\x00"))
	return s.conn.Close()
}
