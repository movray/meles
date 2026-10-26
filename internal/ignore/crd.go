package ignore

import (
	"fmt"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
)

// FromSpec converts the rules of a MalwareIgnore or ClusterMalwareIgnore.
// Rules are named after the object ("<source>#<n>", or "<source>/<name>"
// for named rules), so that a report tells where an exception comes from.
func FromSpec(spec v1alpha1.IgnoreSpec, source string) []Rule {
	out := make([]Rule, len(spec.Rules))
	for i, r := range spec.Rules {
		name := fmt.Sprintf("%s#%d", source, i+1)
		if r.Name != "" {
			name = source + "/" + r.Name
		}
		out[i] = Rule{Name: name, Path: r.Path, Signature: r.Signature, Image: r.Image, SHA256: r.SHA256, Reason: r.Reason, Expires: r.Expires}
	}
	return out
}
