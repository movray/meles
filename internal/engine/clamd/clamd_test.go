package clamd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// fakeClamd speaks enough of the clamd protocol for the client: VERSION,
// IDSESSION, INSTREAM and END. Streams containing "EVIL" are reported as
// infected, streams containing "ERROR" get an error reply.
func fakeClamd(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "clamd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFake(conn)
		}
	}()
	return "unix://" + sock
}

func serveFake(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	id := 0
	for {
		cmd, err := r.ReadString(0)
		if err != nil {
			return
		}
		switch strings.TrimSuffix(cmd, "\x00") {
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
			switch {
			case bytes.Contains(data.Bytes(), []byte("EVIL")):
				fmt.Fprintf(conn, "%d: stream: Fake.Evil FOUND\x00", id)
			case bytes.Contains(data.Bytes(), []byte("ERROR")):
				fmt.Fprintf(conn, "%d: INSTREAM size limit exceeded. ERROR\x00", id)
			default:
				fmt.Fprintf(conn, "%d: stream: OK\x00", id)
			}
		default:
			fmt.Fprint(conn, "UNKNOWN COMMAND\x00")
			return
		}
	}
}

func TestSession(t *testing.T) {
	c, err := New(fakeClamd(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, err := c.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	big := strings.Repeat("a", 3*chunkSize) + "EVIL"
	tests := []struct {
		name, data, want string
	}{
		{"clean", "hello", ""},
		{"infected", "xxEVILxx", "Fake.Evil"},
		{"empty", "", ""},
		{"multiple chunks", big, "Fake.Evil"},
		{"clean after infected", "hello", ""},
	}
	for _, tt := range tests {
		got, err := s.Scan(ctx, strings.NewReader(tt.data))
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if got != tt.want {
			t.Errorf("%s: signature = %q, want %q", tt.name, got, tt.want)
		}
	}

	if _, err := s.Scan(ctx, strings.NewReader("ERROR")); err == nil {
		t.Fatal("error reply: want error")
	}
	if _, err := s.Scan(ctx, strings.NewReader("hello")); err == nil {
		t.Fatal("session after error: want error, session must not be reused")
	}
}

func TestVersion(t *testing.T) {
	c, err := New(fakeClamd(t))
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.Engine != "ClamAV 1.4.3" || v.Signatures != "28159" {
		t.Errorf("version = %+v", v)
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		addr    string
		wantErr bool
	}{
		{"unix:///run/clamav/clamd.ctl", false},
		{"tcp://clamd:3310", false},
		{"tcp://clamd", true},
		{"http://clamd:3310", true},
		{"unix://", true},
	}
	for _, tt := range tests {
		_, err := New(tt.addr)
		if (err != nil) != tt.wantErr {
			t.Errorf("New(%q) err = %v, wantErr %v", tt.addr, err, tt.wantErr)
		}
	}
}

func TestParseReply(t *testing.T) {
	tests := []struct {
		reply   string
		want    string
		wantErr bool
	}{
		{"1: stream: OK", "", false},
		{"2: stream: Eicar-Test-Signature FOUND", "Eicar-Test-Signature", false},
		{"3: INSTREAM size limit exceeded. ERROR", "", true},
		{"garbage", "", true},
	}
	for _, tt := range tests {
		got, err := ParseReply(tt.reply)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("ParseReply(%q) = %q, %v", tt.reply, got, err)
		}
	}
}
