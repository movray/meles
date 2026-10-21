// Package clamd talks to a ClamAV daemon over its socket protocol.
//
// meles never links against libclamav (GPLv2): clamd runs as a separate
// process and keeps the signature database in memory once.
package clamd

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"git.itknecht.de/sugras/meles/internal/engine"
)

// chunkSize is the INSTREAM chunk size. clamd accepts any size up to its
// StreamMaxLength; 64 KiB keeps memory per session small.
const chunkSize = 64 << 10

// Client connects to clamd. The zero value is not usable; use New.
type Client struct {
	network, address string
	// Timeout bounds dialing and each single scan.
	Timeout time.Duration
}

var _ engine.Engine = (*Client)(nil)

// New parses addr ("unix:///run/clamav/clamd.ctl" or "tcp://host:3310").
func New(addr string) (*Client, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("parse clamd address %q: %w", addr, err)
	}
	c := &Client{Timeout: 5 * time.Minute}
	switch u.Scheme {
	case "unix":
		c.network, c.address = "unix", u.Path
	case "tcp":
		if u.Port() == "" {
			return nil, fmt.Errorf("clamd address %q: missing port", addr)
		}
		c.network, c.address = "tcp", u.Host
	default:
		return nil, fmt.Errorf("clamd address %q: scheme must be unix or tcp", addr)
	}
	if c.address == "" {
		return nil, fmt.Errorf("clamd address %q: missing path or host", addr)
	}
	return c, nil
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, c.network, c.address)
	if err != nil {
		return nil, fmt.Errorf("connect clamd %s://%s: %w", c.network, c.address, err)
	}
	return conn, nil
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
	return ParseVersion(strings.TrimSuffix(resp, "\x00")), nil
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
