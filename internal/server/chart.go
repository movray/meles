package server

import (
	"fmt"
	"html/template"
	"math"
	"strings"
	"time"

	"github.com/movray/meles/internal/store"
)

// stackSeg is one segment of a stacked column: a CSS class for its color
// and its value.
type stackSeg struct {
	cls string
	v   int
}

// stackDay is the column of one day, segments from the baseline up.
type stackDay struct {
	date time.Time
	segs []stackSeg
	tip  string
}

// dailyChart renders finished runs per day as stacked columns (infected,
// error, clean from the baseline up).
func dailyChart(days []store.Day, loc *time.Location) template.HTML {
	cols := make([]stackDay, len(days))
	for i, d := range days {
		day := d.Date.In(loc)
		cols[i] = stackDay{
			date: day,
			segs: []stackSeg{{"seg-infected", d.Infected}, {"seg-error", d.Errors}, {"seg-clean", d.Clean}},
			tip:  fmt.Sprintf("%s: %d clean · %d infected · %d errors", day.Format("Mon 02.01.2006"), d.Clean, d.Infected, d.Errors),
		}
	}
	return stackedDays("Finished runs per day by result", cols)
}

// clusterChart renders the cluster's reports by status at the end of each
// day. Error and Incomplete share one segment, "not fully scanned": the
// serious color next to warning fails the palette checks, and both mean the
// same for the chart (never shown as clean). The tooltip and the table keep
// them apart.
func clusterChart(days []store.ClusterDay, loc *time.Location) template.HTML {
	cols := make([]stackDay, len(days))
	for i, d := range days {
		day := d.Date.In(loc)
		cols[i] = stackDay{
			date: day,
			segs: []stackSeg{{"seg-infected", d.Infected}, {"seg-error", d.Errors + d.Incomplete}, {"seg-clean", d.Clean}},
			tip: fmt.Sprintf("%s: %d clean · %d infected · %d errors · %d incomplete",
				day.Format("Mon 02.01.2006"), d.Clean, d.Infected, d.Errors, d.Incomplete),
		}
	}
	return stackedDays("Workloads per day by result", cols)
}

// stackedDays renders stacked columns per day in inline SVG. Colors come
// from CSS classes so that light and dark mode each use their own tokens.
// Every column has a hover target with a tooltip; the pages also offer the
// data as a table.
func stackedDays(title string, days []stackDay) template.HTML {
	const (
		w, h                     = 760.0, 240.0
		left, right, top, bottom = 40.0, 8.0, 12.0, 28.0
		gap                      = 2.0 // surface gap between stacked segments
		radius                   = 4.0
		// A single infected workload among a hundred clean ones must stay
		// visible: segments above zero are at least this high (the tooltip
		// and the table have the exact values).
		minSeg = 4.0
	)
	plotW, plotH := w-left-right, h-top-bottom

	maxTotal := 0
	for _, d := range days {
		total := 0
		for _, sg := range d.segs {
			total += sg.v
		}
		maxTotal = max(maxTotal, total)
	}
	step, yMax := niceScale(maxTotal)

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart" viewBox="0 0 %.0f %.0f" role="img" aria-label="%s" preserveAspectRatio="xMidYMid meet">`, w, h, template.HTMLEscapeString(title))
	fmt.Fprintf(&b, `<title>%s</title>`, template.HTMLEscapeString(title))
	// Recessive grid and y-axis ticks.
	for v := 0; v <= yMax; v += step {
		y := top + plotH - float64(v)/float64(yMax)*plotH
		cls := "grid"
		if v == 0 {
			cls = "baseline"
		}
		fmt.Fprintf(&b, `<line class="%s" x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f"/>`, cls, left, w-right, y, y)
		fmt.Fprintf(&b, `<text class="tick" x="%.1f" y="%.1f" text-anchor="end" dominant-baseline="middle">%d</text>`, left-8, y, v)
	}

	n := len(days)
	if n == 0 {
		b.WriteString(`</svg>`)
		return template.HTML(b.String())
	}
	band := plotW / float64(n)
	barW := math.Min(band*0.62, 26)
	labelEvery := 1
	switch {
	case n > 45:
		labelEvery = 14
	case n > 14:
		labelEvery = 7
	}

	for i, d := range days {
		x := left + float64(i)*band + (band-barW)/2
		y := top + plotH
		segs := d.segs
		last := -1
		for j, sg := range segs {
			if sg.v > 0 {
				last = j
			}
		}
		for j, sg := range segs {
			if sg.v == 0 {
				continue
			}
			sh := math.Max(float64(sg.v)/float64(yMax)*plotH, minSeg)
			y -= sh
			drawH := sh
			if j != last {
				// Leave a gap in the surface color above inner segments.
				drawH = math.Max(sh-gap, 1)
			}
			if j == last && drawH > radius {
				// Rounded data end, square at the baseline side.
				fmt.Fprintf(&b, `<path class="%s" d="M%.1f %.1f v%.1f a%.0f %.0f 0 0 1 %.0f %.0f h%.1f a%.0f %.0f 0 0 1 %.0f %.0f v%.1f z"/>`,
					sg.cls, x, y+drawH, -(drawH - radius), radius, radius, radius, -radius, barW-2*radius, radius, radius, radius, radius, drawH-radius)
			} else {
				fmt.Fprintf(&b, `<rect class="%s" x="%.1f" y="%.1f" width="%.1f" height="%.1f"/>`, sg.cls, x, y+(sh-drawH), barW, drawH)
			}
		}

		// Count labels back from today so the newest day is always labeled
		// and labels never collide.
		if (n-1-i)%labelEvery == 0 {
			fmt.Fprintf(&b, `<text class="tick" x="%.1f" y="%.1f" text-anchor="middle">%s</text>`, x+barW/2, h-8, d.date.Format("02.01."))
		}
		tip := d.tip
		// Hover target larger than the mark: the full band and plot height.
		fmt.Fprintf(&b, `<rect class="hit" x="%.1f" y="%.1f" width="%.1f" height="%.1f" data-tip="%s"><title>%s</title></rect>`,
			left+float64(i)*band, top, band, plotH, template.HTMLEscapeString(tip), template.HTMLEscapeString(tip))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// niceScale returns a tick step and axis maximum (1, 2 or 5 times a power of
// ten) for values up to maxV.
func niceScale(maxV int) (step, top int) {
	if maxV <= 0 {
		return 1, 4
	}
	raw := float64(maxV) / 4
	mag := math.Pow(10, math.Floor(math.Log10(raw)))
	for _, m := range []float64{1, 2, 5, 10} {
		if s := m * mag; s >= raw {
			step = max(int(s), 1)
			break
		}
	}
	top = ((maxV + step - 1) / step) * step
	return step, top
}
