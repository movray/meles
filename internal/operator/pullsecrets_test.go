package operator

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

func TestAuthHint(t *testing.T) {
	r := &Reconciler{PullSecretRole: "meles-pull-secret-reader", ServiceAccount: "meles:meles-operator"}
	limit := fmt.Errorf("fetch reg/web: %w", &transport.Error{StatusCode: http.StatusTooManyRequests,
		Errors: []transport.Diagnostic{{Code: transport.TooManyRequestsErrorCode, Message: "You have reached your unauthenticated pull rate limit."}}})
	unauth := errors.New("fetch reg/web: UNAUTHORIZED: authentication required")
	rolebinding := "kubectl -n shop create rolebinding meles-pull-secrets --clusterrole=meles-pull-secret-reader --serviceaccount=meles:meles-operator"
	tests := []struct {
		name    string
		err     error
		auth    pullAuth
		want    []string
		notWant []string
	}{
		{"rate limit", limit, pullAuth{},
			[]string{"TOOMANYREQUESTS", "limits pulls", "operator.registryAuthSecret"}, []string{"rolebinding", "no imagePullSecrets"}},
		{"rate limit, secrets not readable", limit, pullAuth{denied: []string{"shop"}},
			[]string{"limits pulls", "operator.registryAuthSecret", "if the pods' pull secrets authenticate", rolebinding}, nil},
		{"rate limit by status only", fmt.Errorf("fetch: %w", &transport.Error{StatusCode: http.StatusTooManyRequests}), pullAuth{},
			[]string{"limits pulls"}, nil},
		{"unauthorized, secrets not readable", unauth, pullAuth{denied: []string{"shop"}},
			[]string{"may not read the pull secrets of namespace shop", rolebinding}, []string{"limits pulls"}},
		{"unauthorized, no secrets", unauth, pullAuth{},
			[]string{"no imagePullSecrets", "operator.registryAuthSecret"}, []string{"limits pulls"}},
		{"other error", errors.New("dial tcp: connection refused"), pullAuth{denied: []string{"shop"}},
			[]string{"connection refused"}, []string{"rolebinding", "limits pulls"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.authHint(tt.err, tt.auth)
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q in %q", w, got)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(got, w) {
					t.Errorf("unexpected %q in %q", w, got)
				}
			}
		})
	}
}
