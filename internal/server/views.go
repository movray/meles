package server

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"git.itknecht.de/sugras/meles/internal/report"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/store"
)

type pageTemplate struct {
	t *template.Template
}

// page is the data every template receives.
type page struct {
	Title   string
	Nav     string
	Engine  EngineStatus
	Version string
	Queue   int
	// Cluster shows the navigation entry for the operator's reports.
	Cluster bool
	// Refresh reloads the page after this many seconds (0 = never), used
	// while runs are active.
	Refresh int
	Data    any
}

var pageNames = []string{"dashboard", "scans", "scan_form", "scan", "runs", "run", "reports", "cluster", "cluster_report", "error"}

func (s *Server) parseTemplates() (map[string]*pageTemplate, error) {
	out := map[string]*pageTemplate{}
	for _, n := range pageNames {
		t, err := template.New("layout.html").Funcs(s.funcs()).ParseFS(webFS,
			"web/templates/layout.html", "web/templates/partials.html", "web/templates/"+n+".html")
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", n, err)
		}
		out[n] = &pageTemplate{t}
	}
	return out, nil
}

func (s *Server) render(w http.ResponseWriter, status int, name string, p page) {
	p.Engine = s.Engine()
	p.Version = s.version
	p.Queue = s.runner.QueueLen()
	p.Cluster = s.cluster != nil
	var buf bytes.Buffer
	if err := s.pages[name].t.Execute(&buf, p); err != nil {
		s.log.Error("render", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

func (s *Server) renderError(w http.ResponseWriter, status int, err error) {
	if status >= 500 {
		s.log.Error("request failed", "err", err)
	}
	s.render(w, status, "error", page{Title: http.StatusText(status), Data: map[string]any{
		"Status":  status,
		"Message": err.Error(),
	}})
}

func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"time": func(t time.Time) string {
			if t.IsZero() {
				return "–"
			}
			return t.In(s.loc).Format("2006-01-02 15:04")
		},
		"timep": func(t *time.Time) string {
			if t == nil {
				return "–"
			}
			return t.In(s.loc).Format("2006-01-02 15:04:05")
		},
		"iso":   func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
		"ago":   ago,
		"until": until,
		"dur":   formatDuration,
		"since": func(t time.Time) time.Duration { return time.Since(t) },
		"short": shortDigest,
		"findingStatus": func(f scan.Finding) string {
			return report.Status(f)
		},
		"schedule": humanSchedule,
		"next": func(id int64) time.Time {
			return s.scheduler.NextRun(id)
		},
		"bytes":       formatBytes,
		"num":         formatNumber,
		"statusLabel": statusLabel,
		"statusIcon":  statusIcon,
		"deref_time": func(t *time.Time) time.Time {
			if t == nil {
				return time.Time{}
			}
			return *t
		},
		"deref": func(p *int64) int64 {
			if p == nil {
				return 0
			}
			return *p
		},
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"query": func(base string, kv ...any) string {
			q := url.Values{}
			for i := 0; i+1 < len(kv); i += 2 {
				v := fmt.Sprint(kv[i+1])
				if v != "" && v != "0" {
					q.Set(fmt.Sprint(kv[i]), v)
				}
			}
			if len(q) == 0 {
				return base
			}
			return base + "?" + q.Encode()
		},
		"dailyChart":    func(days []store.Day) template.HTML { return dailyChart(days, s.loc) },
		"clusterChart":  func(days []store.ClusterDay) template.HTML { return clusterChart(days, s.loc) },
		"isDone":        func(r store.Run) bool { return r.Done() },
		"clusterStatus": clusterStatus,
		"rescanPending": rescanPending,
	}
}

func statusLabel(status string) string {
	switch status {
	case store.StatusClean:
		return "Clean"
	case store.StatusInfected:
		return "Infected"
	case store.StatusError:
		return "Error"
	case store.StatusRunning:
		return "Running"
	case store.StatusQueued:
		return "Queued"
	case statusIncomplete:
		return "Incomplete"
	case scan.StatusPresent:
		return "Present"
	case scan.StatusDeleted:
		return "Deleted"
	case scan.StatusOverwritten:
		return "Overwritten"
	}
	return status
}

// statusIcon pairs every status color with a glyph, so status never relies
// on color alone.
func statusIcon(status string) string {
	switch status {
	case store.StatusClean:
		return "✓"
	case store.StatusInfected, scan.StatusPresent:
		return "✕"
	case store.StatusError:
		return "!"
	case store.StatusRunning:
		return "↻"
	case store.StatusQueued:
		return "…"
	case scan.StatusDeleted, scan.StatusOverwritten:
		return "⚠"
	case statusIncomplete:
		return "?"
	}
	return "•"
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

func until(t time.Time) string {
	if t.IsZero() {
		return "–"
	}
	d := time.Until(t)
	switch {
	case d < time.Minute:
		return "in less than a minute"
	case d < time.Hour:
		return fmt.Sprintf("in %d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("in %d h", int(d.Hours()))
	default:
		return fmt.Sprintf("in %d days", int(d.Hours()/24))
	}
}

func formatDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "–"
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1f s", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%d min %d s", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
	}
}

func shortDigest(d string) string {
	_, hex, ok := strings.Cut(d, ":")
	if !ok || len(hex) < 12 {
		return d
	}
	return hex[:12]
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func formatNumber(n int) string {
	s := strconv.Itoa(n)
	if n < 0 {
		return "-" + formatNumber(-n)
	}
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// humanSchedule describes common cron expressions in words.
func humanSchedule(expr string) string {
	expr = strings.TrimSpace(expr)
	tz := ""
	if strings.HasPrefix(expr, "CRON_TZ=") || strings.HasPrefix(expr, "TZ=") {
		var rest string
		tz, rest, _ = strings.Cut(expr, " ")
		tz = " (" + strings.SplitN(tz, "=", 2)[1] + ")"
		expr = rest
	}
	switch expr {
	case "":
		return "manual only"
	case "@hourly":
		return "hourly" + tz
	case "@daily", "@midnight":
		return "daily at 00:00" + tz
	case "@weekly":
		return "weekly, Sunday 00:00" + tz
	case "@monthly":
		return "monthly, 1st at 00:00" + tz
	case "@yearly", "@annually":
		return "yearly, 1 January 00:00" + tz
	}
	if every, ok := strings.CutPrefix(expr, "@every "); ok {
		return "every " + every + tz
	}
	f := strings.Fields(expr)
	if len(f) == 5 {
		m, errM := strconv.Atoi(f[0])
		h, errH := strconv.Atoi(f[1])
		if errM == nil && errH == nil && f[2] == "*" && f[3] == "*" {
			at := fmt.Sprintf("%02d:%02d", h, m)
			if f[4] == "*" {
				return "daily at " + at + tz
			}
			if days, ok := weekdays(f[4]); ok {
				return days + " at " + at + tz
			}
		}
		if errM == nil && f[1] == "*" && f[2] == "*" && f[3] == "*" && f[4] == "*" {
			return fmt.Sprintf("hourly at minute %d", m) + tz
		}
	}
	return expr + tz
}

func weekdays(field string) (string, bool) {
	names := map[string]string{"0": "Sun", "1": "Mon", "2": "Tue", "3": "Wed", "4": "Thu", "5": "Fri", "6": "Sat", "7": "Sun"}
	switch field {
	case "1-5":
		return "Mon–Fri", true
	case "0,6", "6,0":
		return "Sat and Sun", true
	}
	var out []string
	for _, d := range strings.Split(field, ",") {
		n, ok := names[d]
		if !ok {
			return "", false
		}
		out = append(out, n)
	}
	return strings.Join(out, ", "), true
}
