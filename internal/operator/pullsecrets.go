package operator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	k8sauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// pullAuth is what the operator could learn about the credentials of an
// image.
type pullAuth struct {
	keychain authn.Keychain
	// denied lists namespaces whose pull secrets or service accounts the
	// operator may not read.
	denied []string
	// secrets is the number of pull secrets found.
	secrets int
}

// pullKeychain returns the credentials to pull an image for pods: the
// imagePullSecrets of the pods and of their service accounts, as the
// kubelet uses them, then the operator's own Docker config (e.g.
// operator.registryAuthSecret). Secrets of several pods are combined: they
// all run the same digest.
//
// Reading them is opt-in per namespace: a team binds the
// pull-secret-reader ClusterRole to the operator in its namespace (or an
// administrator cluster-wide). Without that, the operator scans with what it
// has; only if the registry refuses, the report says which namespaces to
// grant. Missing secrets are skipped like the kubelet does.
func (r *Reconciler) pullKeychain(ctx context.Context, pods []types.NamespacedName) (pullAuth, error) {
	type ref struct{ ns, name string }
	seen := map[ref]bool{}
	var secrets []corev1.Secret
	var denied []string
	deny := func(ns string) {
		if !slices.Contains(denied, ns) {
			denied = append(denied, ns)
		}
	}
	add := func(ns, name string) error {
		if name == "" || seen[ref{ns, name}] {
			return nil
		}
		seen[ref{ns, name}] = true
		var s corev1.Secret
		err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &s)
		switch {
		case apierrors.IsNotFound(err):
		case apierrors.IsForbidden(err):
			deny(ns)
		case err != nil:
			return fmt.Errorf("read pull secret %s/%s: %w", ns, name, err)
		default:
			secrets = append(secrets, s)
		}
		return nil
	}
	for _, key := range pods {
		var pod corev1.Pod
		if err := r.Client.Get(ctx, key, &pod); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return pullAuth{}, fmt.Errorf("get pod %s: %w", key, err)
		}
		for _, s := range pod.Spec.ImagePullSecrets {
			if err := add(pod.Namespace, s.Name); err != nil {
				return pullAuth{}, err
			}
		}
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		var sa corev1.ServiceAccount
		err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: saName}, &sa)
		switch {
		case apierrors.IsNotFound(err):
			continue
		case apierrors.IsForbidden(err):
			deny(pod.Namespace)
			continue
		case err != nil:
			return pullAuth{}, fmt.Errorf("read service account %s/%s: %w", pod.Namespace, saName, err)
		}
		for _, s := range sa.ImagePullSecrets {
			if err := add(pod.Namespace, s.Name); err != nil {
				return pullAuth{}, err
			}
		}
	}
	kc, err := k8sauth.NewFromPullSecrets(ctx, secrets)
	if err != nil {
		return pullAuth{}, fmt.Errorf("pull secrets: %w", err)
	}
	slices.Sort(denied)
	return pullAuth{keychain: authn.NewMultiKeychain(kc, authn.DefaultKeychain), denied: denied, secrets: len(secrets)}, nil
}

// authHint explains a pull the registry refused: which namespaces to grant
// the operator their pull secrets, with the command, or that there were no
// pull secrets at all.
func (r *Reconciler) authHint(err error, auth pullAuth) string {
	msg := err.Error()
	limited := rateLimited(err)
	if !limited && !strings.Contains(msg, "UNAUTHORIZED") && !strings.Contains(msg, "DENIED") {
		return msg
	}
	var grant string
	if len(auth.denied) > 0 {
		role, sa := r.PullSecretRole, r.ServiceAccount
		if role == "" {
			role = "<release>-pull-secret-reader"
		}
		if sa == "" {
			sa = "<namespace>:<operator service account>"
		}
		var cmds []string
		for _, ns := range auth.denied {
			cmds = append(cmds, fmt.Sprintf("kubectl -n %s create rolebinding meles-pull-secrets --clusterrole=%s --serviceaccount=%s", ns, role, sa))
		}
		grant = fmt.Sprintf("the operator may not read the pull secrets of namespace %s; to let it use them: %s",
			strings.Join(auth.denied, ", "), strings.Join(cmds, "; "))
	}
	if limited {
		// A refused pull secret is not the cause; credentials only raise the limit.
		hint := "the registry limits pulls and the operator retries later; authenticated pulls usually get a higher limit: put an account for this registry into operator.registryAuthSecret"
		if grant != "" {
			hint += ", or if the pods' pull secrets authenticate: " + grant
		}
		return msg + " (" + hint + ")"
	}
	if grant != "" {
		return msg + " (" + grant + ")"
	}
	if auth.secrets == 0 {
		return msg + " (no imagePullSecrets on the pods or their service accounts; for a registry they do not cover, set operator.registryAuthSecret)"
	}
	return msg
}

// rateLimited reports whether a registry refused a request for too many
// pulls (HTTP 429, e.g. Docker Hub's limit for anonymous pulls).
func rateLimited(err error) bool {
	var te *transport.Error
	if errors.As(err, &te) && te.StatusCode == http.StatusTooManyRequests {
		return true
	}
	return strings.Contains(err.Error(), "TOOMANYREQUESTS")
}
