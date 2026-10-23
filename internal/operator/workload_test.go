package operator

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestReportName(t *testing.T) {
	long := strings.Repeat("a", 250)
	tests := []struct {
		kind, workload, container, want string
	}{
		{"ReplicaSet", "web-5d8f7c", "nginx", "replicaset-web-5d8f7c-nginx"},
		{"CronJob", "Backup", "rclone", "cronjob-backup-rclone"},
	}
	for _, tt := range tests {
		if got := reportName(tt.kind, tt.workload, tt.container); got != tt.want {
			t.Errorf("reportName(%s, %s, %s) = %q, want %q", tt.kind, tt.workload, tt.container, got, tt.want)
		}
	}
	a, b := reportName("Pod", long, "a"), reportName("Pod", long, "b")
	if a == b || len(a) > validation.DNS1123SubdomainMaxLength || len(validation.IsDNS1123Subdomain(a)) > 0 {
		t.Errorf("long names: %q / %q", a, b)
	}
}

func TestParseImageID(t *testing.T) {
	const d = "sha256:3f1a6d3b84d0b5e8c0a2f0f5a1f0e0a8b9c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3"
	tests := []struct {
		imageID    string
		wantOK     bool
		wantRef    string
		wantRepo   string
		wantDigest string
	}{
		{"docker.io/library/nginx@" + d, true, "docker.io/library/nginx@" + d, "docker.io/library/nginx", d},
		{"docker-pullable://nginx@" + d, true, "nginx@" + d, "nginx", d},
		{"registry:5000/team/app@" + d, true, "registry:5000/team/app@" + d, "registry:5000/team/app", d},
		{d, false, "", "", d},
		{"", false, "", "", ""},
	}
	for _, tt := range tests {
		img, ok := parseImageID(tt.imageID, "nginx:1.29")
		if ok != tt.wantOK || img.ref != tt.wantRef || img.repository != tt.wantRepo || img.digest != tt.wantDigest {
			t.Errorf("parseImageID(%q) = %+v, %v", tt.imageID, img, ok)
		}
	}
}

func TestDigestLabel(t *testing.T) {
	got := digestLabel("sha256:" + strings.Repeat("ab", 32))
	if len(got) != 40 || len(validation.IsValidLabelValue(got)) > 0 {
		t.Errorf("digestLabel = %q", got)
	}
}
