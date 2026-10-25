package opstatus

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// replica serves the status of one operator replica on addr.
func replica(t *testing.T, addr string, st Status) *httptest.Server {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("listen %s: %v", addr, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(st)
	}))
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchLeader(t *testing.T) {
	standby := replica(t, "127.0.0.1:0", Status{Pod: "standby"})
	_, port, _ := net.SplitHostPort(standby.Listener.Addr().String())
	replica(t, "127.0.0.2:"+port, Status{Pod: "leader", Leader: true, Queued: map[string]int{"new": 2, "rescan": 3}})

	c := &Client{URL: "http://operator.meles:" + port, LookupHost: func(context.Context, string) ([]string, error) {
		return []string{"127.0.0.1", "127.0.0.2"}, nil
	}}
	st, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Pod != "leader" || st.QueuedTotal() != 5 {
		t.Errorf("status = %+v", st)
	}

	c.LookupHost = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	if _, err := c.Fetch(context.Background()); !errors.Is(err, ErrNoLeader) {
		t.Errorf("only a standby replica: %v", err)
	}
	c.URL = "http://operator.meles:1"
	if _, err := c.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "operator status") {
		t.Errorf("unreachable: %v", err)
	}
}
