package operator

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	k8sauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// pullKeychain returns the credentials to pull an image for pods: the
// imagePullSecrets of the pods and of their service accounts, as the
// kubelet uses them, then the operator's own Docker config (e.g.
// operator.registryAuthSecret). Secrets of several pods are combined: they
// all run the same digest. Missing secrets are skipped like the kubelet
// does; any other error (e.g. no permission) fails the scan, which then
// never counts as clean.
func (r *Reconciler) pullKeychain(ctx context.Context, pods []types.NamespacedName) (authn.Keychain, error) {
	if !r.PullSecrets {
		return authn.DefaultKeychain, nil
	}
	type ref struct{ ns, name string }
	seen := map[ref]bool{}
	var secrets []corev1.Secret
	add := func(ns, name string) error {
		if name == "" || seen[ref{ns, name}] {
			return nil
		}
		seen[ref{ns, name}] = true
		var s corev1.Secret
		err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &s)
		switch {
		case apierrors.IsNotFound(err):
			return nil
		case err != nil:
			return fmt.Errorf("read pull secret %s/%s: %w", ns, name, err)
		}
		secrets = append(secrets, s)
		return nil
	}
	for _, key := range pods {
		var pod corev1.Pod
		if err := r.Client.Get(ctx, key, &pod); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("get pod %s: %w", key, err)
		}
		for _, s := range pod.Spec.ImagePullSecrets {
			if err := add(pod.Namespace, s.Name); err != nil {
				return nil, err
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
		case err != nil:
			return nil, fmt.Errorf("read service account %s/%s: %w", pod.Namespace, saName, err)
		}
		for _, s := range sa.ImagePullSecrets {
			if err := add(pod.Namespace, s.Name); err != nil {
				return nil, err
			}
		}
	}
	kc, err := k8sauth.NewFromPullSecrets(ctx, secrets)
	if err != nil {
		return nil, fmt.Errorf("pull secrets: %w", err)
	}
	return authn.NewMultiKeychain(kc, authn.DefaultKeychain), nil
}

// authHint explains a refused pull when the operator does not use the
// pods' pull secrets.
func (r *Reconciler) authHint(err error) string {
	msg := err.Error()
	if r.PullSecrets || !(strings.Contains(msg, "UNAUTHORIZED") || strings.Contains(msg, "DENIED") || strings.Contains(msg, "TOOMANYREQUESTS")) {
		return msg
	}
	return msg + " (the operator pulls without the pods' pull secrets: set operator.pullSecrets.enabled, or operator.registryAuthSecret for one account)"
}
