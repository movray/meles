// Package yararules knows the default YARA rules shipped in
// charts/meles/rules: who wrote each rule and under which license. Some
// licenses (Detection Rule License 1.1) require the rule author in every
// message about a match, so reports attach this to YARA findings.
package yararules

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:generate go run ../../hack/yaraindex -o index.json ../../charts/meles/rules

//go:embed index.json
var indexJSON []byte

// Info describes a rule.
type Info struct {
	// Name of the YARA rule.
	Name    string `json:"name"`
	Author  string `json:"author"`
	License string `json:"license"`
	// URL of the original rule.
	URL string `json:"url"`
}

var index = func() map[string]Info {
	var m map[string]Info
	if err := json.Unmarshal(indexJSON, &m); err != nil {
		panic("yararules: embedded index.json: " + err.Error())
	}
	for name, info := range m {
		info.Name = name
		m[name] = info
	}
	return m
}()

// Lookup returns the rule behind a ClamAV signature such as
// "YARA.SIGNATURE_BASE_XMRIG_Monero_Miner.UNOFFICIAL", if it is one of the
// default rules.
func Lookup(signature string) (Info, bool) {
	name, ok := strings.CutPrefix(signature, "YARA.")
	if !ok {
		return Info{}, false
	}
	name = strings.TrimSuffix(name, ".UNOFFICIAL")
	info, ok := index[name]
	return info, ok
}

// Len is the number of default rules.
func Len() int { return len(index) }
