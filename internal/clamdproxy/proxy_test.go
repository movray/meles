package clamdproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"git.itknecht.de/sugras/meles/internal/engine/clamd"
)

// fakeClamd records the commands it receives and answers VERSION and
// INSTREAM like clamd; streams containing "EVIL" are infected.
type fakeClamd struct {
	mu   sync.Mutex
	cmds []string
}

func (f *fakeClamd) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func (f *fakeClamd) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	id := 0
	for {
		cmd, err := r.ReadString(0)
		if err != nil {
			return
		}
		cmd = strings.TrimSuffix(cmd, "\x00")
		f.mu.Lock()
		f.cmds = append(f.cmds, cmd)
		f.mu.Unlock()
		switch cmd {
		case "zVERSION":
			fmt.Fprint(conn, "ClamAV 1.4.3/28159/Tue Oct 20 08:24:12 2026\x00")
			return
		case "zIDSESSION":
		case "zEND":
			return
		case "zINSTREAM":
			id++
			var data bytes.Buffer
			for {
				var size uint32
				if err := binary.Read(r, binary.BigEndian, &size); err != nil {
					return
				}
				if size == 0 {
					break
				}
				if _, err := io.CopyN(&data, r, int64(size)); err != nil {
					return
				}
			}
			if bytes.Contains(data.Bytes(), []byte("EVIL")) {
				fmt.Fprintf(conn, "%d: stream: Fake.Evil FOUND\x00", id)
			} else {
				fmt.Fprintf(conn, "%d: stream: OK\x00", id)
			}
		default:
			fmt.Fprint(conn, "UNKNOWN COMMAND\x00")
		}
	}
}

type env struct {
	addr      string
	roots     *x509.CertPool
	tokenFile string
	clamd     *fakeClamd
}

func setup(t *testing.T, opts ...func(*Proxy)) *env {
	t.Helper()
	dir := t.TempDir()

	upSock := filepath.Join(dir, "clamd.sock")
	upLn, err := net.Listen("unix", upSock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { upLn.Close() })
	fc := &fakeClamd{}
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go fc.serve(c)
		}
	}()

	certFile, keyFile, roots := selfSigned(t, dir)
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("secret-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{Upstream: "unix://" + upSock, CertFile: certFile, KeyFile: keyFile, TokenFile: tokenFile, AuthTimeout: 2 * time.Second}
	for _, o := range opts {
		o(p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- p.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return &env{addr: ln.Addr().String(), roots: roots, tokenFile: tokenFile, clamd: fc}
}

func (e *env) client(t *testing.T, token string) *clamd.Client {
	t.Helper()
	c, err := clamd.New("tls://" + e.addr)
	if err != nil {
		t.Fatal(err)
	}
	c.TLSConfig = &tls.Config{RootCAs: e.roots, ServerName: "localhost"}
	c.Token = token
	return c
}

func selfSigned(t *testing.T, dir string) (certFile, keyFile string, roots *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	cert, _ := x509.ParseCertificate(der)
	roots = x509.NewCertPool()
	roots.AddCert(cert)
	return certFile, keyFile, roots
}

func TestProxyScan(t *testing.T) {
	e := setup(t)
	c := e.client(t, "secret-1")
	ctx := context.Background()

	v, err := c.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Signatures != "28159" {
		t.Errorf("version = %+v", v)
	}
	sess, err := c.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	for _, tt := range []struct{ data, want string }{{"clean", ""}, {"xx EVIL xx", "Fake.Evil"}, {strings.Repeat("a", 200<<10), ""}} {
		sig, err := sess.Scan(ctx, strings.NewReader(tt.data))
		if err != nil {
			t.Fatal(err)
		}
		if sig != tt.want {
			t.Errorf("scan: signature %q, want %q", sig, tt.want)
		}
	}
}

func TestProxyRejectsWrongToken(t *testing.T) {
	e := setup(t)
	for _, token := range []string{"wrong", ""} {
		_, err := e.client(t, token).Version(context.Background())
		if err == nil {
			t.Errorf("token %q: want error", token)
		}
	}
	if cmds := e.clamd.commands(); len(cmds) > 0 {
		t.Errorf("clamd received %v from unauthenticated clients", cmds)
	}
}

// Commands other than those meles needs never reach clamd.
func TestProxyCommandFilter(t *testing.T) {
	e := setup(t)
	tests := []string{
		"zSHUTDOWN\x00",
		"nSHUTDOWN\n",
		"SHUTDOWN\n",
		"zSCAN /etc/passwd\x00",
		"zIDSESSION\x00zSHUTDOWN\x00",
		"zRELOAD\x00",
		"z" + strings.Repeat("A", 100) + "\x00",
	}
	for _, tt := range tests {
		conn, err := tls.Dial("tcp", e.addr, &tls.Config{RootCAs: e.roots, ServerName: "localhost"})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "zAUTH secret-1\x00%s", tt)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		reply, _ := io.ReadAll(conn) // the proxy closes the connection
		conn.Close()
		if string(reply) != clamd.AuthOK+"\x00" {
			t.Errorf("%q: reply %q", tt, reply)
		}
	}
	for _, c := range e.clamd.commands() {
		if c != "zIDSESSION" {
			t.Errorf("clamd received %q", c)
		}
	}
}

// writeTokens replaces the token file atomically, like the kubelet updates a
// mounted secret: os.WriteFile truncates first, and a proxy reading at that
// moment would see no token. The modification time is moved by age, so that
// the change is noticed within the same second.
func writeTokens(t *testing.T, path, content string, age time.Duration) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, time.Now(), time.Now().Add(age)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// A new token file is picked up; the old token stops working.
func TestProxyTokenRotation(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	writeTokens(t, e.tokenFile, "secret-1\nsecret-2\n", time.Second)
	for _, tok := range []string{"secret-1", "secret-2"} {
		if _, err := e.client(t, tok).Version(ctx); err != nil {
			t.Errorf("%s during rotation: %v", tok, err)
		}
	}
	writeTokens(t, e.tokenFile, "secret-2\n", 2*time.Second)
	if _, err := e.client(t, "secret-1").Version(ctx); err == nil {
		t.Error("old token still accepted")
	}
}

func TestClientRefusesTokenWithoutTLS(t *testing.T) {
	c, err := clamd.New("tcp://127.0.0.1:3310")
	if err != nil {
		t.Fatal(err)
	}
	c.Token = "secret"
	if _, err := c.Version(context.Background()); err == nil || !strings.Contains(err.Error(), "tls://") {
		t.Errorf("err = %v, want refusal to send the token without TLS", err)
	}
}

func TestProxyVersionWithRules(t *testing.T) {
	rules := t.TempDir()
	e := setup(t, func(p *Proxy) { p.RulesDir = rules })
	version := func() string {
		t.Helper()
		v, err := e.client(t, "secret-1").Version(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(v.Raw, "/Tue Oct 20 08:24:12 2026") {
			t.Errorf("raw = %q", v.Raw)
		}
		return v.Signatures
	}
	if got := version(); got != "28159" {
		t.Errorf("without rules: signatures %q", got)
	}
	os.WriteFile(filepath.Join(rules, "main.cvd"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(rules, "meles.yar"), []byte("rule a { condition: true }"), 0o644)
	first := version()
	if !strings.HasPrefix(first, "28159+rules.") || len(first) != len("28159+rules.")+12 {
		t.Fatalf("with rules: signatures %q", first)
	}
	if again := version(); again != first {
		t.Errorf("unchanged rules: %q, then %q", first, again)
	}
	os.WriteFile(filepath.Join(rules, "team.yara"), []byte("rule b { condition: true }"), 0o644)
	if changed := version(); changed == first {
		t.Errorf("added rule file: version stays %q", changed)
	}
	// Sessions still work.
	sess, err := e.client(t, "secret-1").Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if sig, err := sess.Scan(context.Background(), strings.NewReader("EVIL")); err != nil || sig != "Fake.Evil" {
		t.Errorf("scan = %q, %v", sig, err)
	}
}
