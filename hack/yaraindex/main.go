// Command yaraindex writes the index of the default YARA rules
// (charts/meles/rules/*.yar) that is embedded in meles: rule name → author,
// license and source. Run by go generate in internal/yararules.
//
// Every rule needs an author and a source_url, and its license_url must
// belong to a known source, so that a new rule cannot slip in without
// attribution.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// licenses maps the repository of a rule's license_url to its SPDX license.
// Keep in sync with charts/meles/rules/README.md.
var licenses = map[string]string{
	"github.com/Neo23x0/signature-base":                 "DRL-1.1",
	"github.com/SEKOIA-IO/Community":                    "DRL-1.1",
	"github.com/ditekshen/detection":                    "BSD-2-Clause",
	"github.com/volexity/threat-intel":                  "BSD-2-Clause",
	"github.com/eset/malware-ioc":                       "BSD-2-Clause",
	"github.com/mandiant/red_team_tool_countermeasures": "BSD-2-Clause",
	"github.com/WithSecureLabs/iocs":                    "BSD-2-Clause",
	"github.com/advanced-threat-research/Yara-Rules":    "Apache-2.0",
}

type entry struct {
	Author  string `json:"author"`
	License string `json:"license"`
	URL     string `json:"url"`
}

var (
	ruleRE = regexp.MustCompile(`(?m)^rule\s+(\w+)[^\n]*\n\{\s*\n\s*meta:\n((?:\s*\w+\s*=\s*(?:"(?:[^"\\]|\\.)*"|-?\d+|true|false)\s*\n)*)`)
	metaRE = regexp.MustCompile(`(?m)^\s*(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"`)
	repoRE = regexp.MustCompile(`^https://(github\.com/[^/]+/[^/]+)/`)
)

func main() {
	out := flag.String("o", "index.json", "output file")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: yaraindex [-o index.json] <rules dir>")
		os.Exit(2)
	}
	if err := run(flag.Arg(0), *out); err != nil {
		fmt.Fprintln(os.Stderr, "yaraindex:", err)
		os.Exit(1)
	}
}

func run(dir, out string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.yar"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no .yar files in %s", dir)
	}
	index := map[string]entry{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if err := parse(string(b), index); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
	}
	names := make([]string, 0, len(index))
	for n := range index {
		names = append(names, n)
	}
	sort.Strings(names)
	// One rule per line keeps diffs readable.
	var sb strings.Builder
	sb.WriteString("{\n")
	for i, n := range names {
		k, _ := json.Marshal(n)
		v, _ := json.Marshal(index[n])
		sb.WriteString("  " + string(k) + ": " + string(v))
		if i < len(names)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}
	sb.WriteString("}\n")
	return os.WriteFile(out, []byte(sb.String()), 0o644)
}

func parse(text string, index map[string]entry) error {
	total := len(regexp.MustCompile(`(?m)^rule\s+\w+`).FindAllString(text, -1))
	matches := ruleRE.FindAllStringSubmatch(text, -1)
	if len(matches) != total {
		return fmt.Errorf("found %d rules, but only %d with a meta block", total, len(matches))
	}
	for _, m := range matches {
		name := m[1]
		meta := map[string]string{}
		for _, kv := range metaRE.FindAllStringSubmatch(m[2], -1) {
			if _, ok := meta[kv[1]]; !ok {
				meta[kv[1]] = strings.ReplaceAll(kv[2], `\"`, `"`)
			}
		}
		e := entry{Author: meta["author"], URL: meta["source_url"]}
		if e.Author == "" || e.URL == "" {
			return fmt.Errorf("rule %s: author and source_url are required", name)
		}
		repo := repoRE.FindStringSubmatch(meta["license_url"])
		if repo == nil || licenses[repo[1]] == "" {
			return fmt.Errorf("rule %s: unknown license_url %q, add its source to the licenses table", name, meta["license_url"])
		}
		e.License = licenses[repo[1]]
		if _, dup := index[name]; dup {
			return fmt.Errorf("rule %s defined twice", name)
		}
		index[name] = e
	}
	return nil
}
