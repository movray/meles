// Package opstatus is the status the meles operator serves at /status: its
// scan queue, running and recent scans and the pods its scan gate holds.
// The server fetches it to show what the operator is doing.
package opstatus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Status of one operator replica. Only the leader scans; the others report
// Leader false and no queue.
type Status struct {
	Pod       string    `json:"pod"`
	Version   string    `json:"version"`
	Leader    bool      `json:"leader"`
	StartedAt time.Time `json:"startedAt"`
	Workers   int       `json:"workers"`
	Engine    string    `json:"engine,omitempty"`
	// Queued scans by priority: gated, new, rescan.
	Queued       map[string]int `json:"queued"`
	OldestQueued *time.Time     `json:"oldestQueued,omitempty"`
	Running      []Scan         `json:"running"`
	// Recent finished scans, newest first.
	Recent []Scan `json:"recent"`
	// Totals of finished scans by status since the start.
	Totals map[string]int `json:"totals"`
	Gate   Gate           `json:"gate"`
}

// Scan is a queued, running or finished image scan.
type Scan struct {
	Image    string `json:"image"`
	Priority string `json:"priority,omitempty"`
	// Pods waiting for a running scan.
	Pods        int           `json:"pods,omitempty"`
	Started     time.Time     `json:"started"`
	Finished    *time.Time    `json:"finished,omitempty"`
	Duration    time.Duration `json:"duration,omitempty"`
	Status      string        `json:"status,omitempty"`
	Error       string        `json:"error,omitempty"`
	Findings    int           `json:"findings,omitempty"`
	Skipped     int           `json:"skipped,omitempty"`
	ErrorSource string        `json:"errorSource,omitempty"`
}

// Gate is the state of the scan gate.
type Gate struct {
	Enabled  bool    `json:"enabled"`
	FailOpen bool    `json:"failOpen,omitempty"`
	Held     []Held  `json:"held"`
	Released Counter `json:"released"`
}

// Counter counts released pods.
type Counter struct {
	Scanned   int `json:"scanned"`
	Unscanned int `json:"unscanned"`
}

// Held is a pod the scan gate holds.
type Held struct {
	Namespace string    `json:"namespace"`
	Pod       string    `json:"pod"`
	Mode      string    `json:"mode"`
	Since     time.Time `json:"since"`
	Reasons   []string  `json:"reasons"`
}

// QueuedTotal is the number of queued scans.
func (s *Status) QueuedTotal() int {
	n := 0
	for _, v := range s.Queued {
		n += v
	}
	return n
}

// Client fetches the status of the operator. URL names a headless service
// of the operator replicas (e.g. http://meles-operator-metrics.meles:8080):
// its name resolves to every replica, and the leader's status is returned.
type Client struct {
	URL     string
	HTTP    *http.Client
	Timeout time.Duration
	// LookupHost resolves the service name; net.DefaultResolver if nil.
	LookupHost func(ctx context.Context, host string) ([]string, error)
}

// ErrNoLeader means no replica reported to be the leader.
var ErrNoLeader = errors.New("no operator replica is the leader")

// Fetch returns the leader's status.
func (c *Client) Fetch(ctx context.Context) (*Status, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, fmt.Errorf("operator status url: %w", err)
	}
	lookup := c.LookupHost
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	addrs, err := lookup(ctx, u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", u.Hostname(), err)
	}
	type answer struct {
		st  *Status
		err error
	}
	answers := make([]answer, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Go(func() {
			r := *u
			r.Host = net.JoinHostPort(a, u.Port())
			if u.Port() == "" {
				r.Host = a
			}
			r.Path = "/status"
			st, err := c.get(ctx, r.String())
			answers[i] = answer{st, err}
		})
	}
	wg.Wait()
	var errs []error
	for _, a := range answers {
		if a.err != nil {
			errs = append(errs, a.err)
			continue
		}
		if a.st.Leader {
			return a.st, nil
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return nil, ErrNoLeader
}

func (c *Client) get(ctx context.Context, u string) (*Status, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("operator status: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("operator status %s: %s", u, resp.Status)
	}
	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, fmt.Errorf("operator status %s: %w", u, err)
	}
	return &st, nil
}
