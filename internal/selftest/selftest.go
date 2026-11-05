// Package selftest checks the whole scan chain: it serves images with EICAR
// test files from an in-memory registry and compares what the scanner finds
// with what it must find. The CLI runs it on request, the server regularly.
package selftest

import (
	"context"
	"fmt"
	"slices"

	"github.com/movray/meles/internal/scan"
	"github.com/movray/meles/internal/source"
	"github.com/movray/meles/internal/testimage"
)

// Check is the result of one test image.
type Check struct {
	Name string
	Got  []string
	Want []string
}

// Pass reports whether the scanner found exactly what it must find.
func (c Check) Pass() bool { return slices.Equal(c.Got, c.Want) }

// String describes the check for logs and the UI.
func (c Check) String() string {
	if c.Pass() {
		return fmt.Sprintf("%s: %v", c.Name, c.Got)
	}
	return fmt.Sprintf("%s: got %v, want %v", c.Name, c.Got, c.Want)
}

// Result is the outcome of a selftest.
type Result struct {
	// Engine is the raw version of the engine.
	Engine string
	Checks []Check
}

// Failed returns the checks that did not pass.
func (r *Result) Failed() []Check {
	var out []Check
	for _, c := range r.Checks {
		if !c.Pass() {
			out = append(out, c)
		}
	}
	return out
}

// Run scans the test images with s; yara adds the images for the default
// YARA rules, which the engine must have loaded then. After an error the
// result holds the checks done so far.
//
// It works on a copy of s without the layer cache, which would answer from
// the last run without asking the engine, and without the restrictions for
// registries: the test images come from a plain HTTP registry on loopback.
func Run(ctx context.Context, s *scan.Scanner, yara bool) (*Result, error) {
	sc := *s
	sc.Cache = nil
	sc.Source.Insecure = true
	sc.Source.Mirrors = nil
	sc.Source.Network = source.Network{}

	res := &Result{}
	cases := testimage.Cases()
	if yara {
		cases = append(cases, testimage.YaraCases()...)
	}
	reg, err := testimage.Serve(cases)
	if err != nil {
		return res, err
	}
	defer reg.Close()

	v, err := sc.Engine.Version(ctx)
	if err != nil {
		return res, err
	}
	res.Engine = v.Raw
	for _, c := range cases {
		rep, err := sc.Scan(ctx, reg.Ref(c.Name), source.PlatformFilter{}, nil)
		if err != nil {
			return res, fmt.Errorf("%s: %w", c.Name, err)
		}
		res.Checks = append(res.Checks, Check{Name: c.Name, Got: findings(rep), Want: c.Want})
	}
	return res, nil
}

func findings(r *scan.Report) []string {
	var out []string
	for _, f := range r.Findings() {
		out = append(out, f.Path+" "+f.Status)
	}
	return out
}
