package server

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/movray/meles/api/v1alpha1"
	"github.com/movray/meles/internal/ignore"
	"github.com/movray/meles/internal/store"
)

// ClusterIgnores manages MalwareIgnores and ClusterMalwareIgnores from the
// UI. Every rule created there is an object of its own, labelled as the
// server's; only those can be deleted from the UI.
type ClusterIgnores interface {
	// List returns all ignore objects, ClusterMalwareIgnores first.
	List(ctx context.Context) ([]IgnoreObject, error)
	// Create creates a ClusterMalwareIgnore (empty namespace) or a
	// MalwareIgnore with one rule and returns its name.
	Create(ctx context.Context, namespace string, rule v1alpha1.IgnoreRule, createdBy string) (string, error)
	// Delete deletes an object the server created: store.ErrNotFound
	// (wrapped) for a missing one, errNotManaged for any other.
	Delete(ctx context.Context, namespace, name string) error
}

// errNotManaged refuses to delete an ignore object the UI did not create:
// whoever applied it (kubectl, Helm, a GitOps tool) would apply it again.
var errNotManaged = errors.New("this ignore object was not created in the UI; delete it where it comes from (kubectl, Helm, Git)")

// IgnoreObject is a MalwareIgnore (Namespace set) or ClusterMalwareIgnore.
type IgnoreObject struct {
	Namespace   string
	Name        string
	Labels      map[string]string
	Annotations map[string]string
	Created     time.Time
	Spec        v1alpha1.IgnoreSpec
	Status      v1alpha1.IgnoreStatus
}

// Source is the name rules of the object carry in reports.
func (o IgnoreObject) Source() string {
	if o.Namespace == "" {
		return o.Name
	}
	return o.Namespace + "/" + o.Name
}

// Managed reports whether the server created the object.
func (o IgnoreObject) Managed() bool {
	return o.Labels[v1alpha1.LabelManagedBy] == v1alpha1.ManagedByServer
}

// Origin tells where an object comes from, as far as its metadata shows:
// "UI", or the tool that applied it. Objects applied with kubectl carry no
// mark, so "kubectl or Git" is a guess.
func (o IgnoreObject) Origin() string {
	switch {
	case o.Managed():
		return "UI"
	case o.Annotations["argocd.argoproj.io/tracking-id"] != "" || o.Labels["argocd.argoproj.io/instance"] != "":
		return "Argo CD"
	case o.Labels["kustomize.toolkit.fluxcd.io/name"] != "" || o.Labels["helm.toolkit.fluxcd.io/name"] != "":
		return "Flux"
	case o.Labels[v1alpha1.LabelManagedBy] == "Helm":
		return "Helm"
	}
	return "kubectl or Git"
}

// CreatedBy is the user who created the object in the UI.
func (o IgnoreObject) CreatedBy() string { return o.Annotations[v1alpha1.AnnotationCreatedBy] }

func ignoreObject(meta metav1.ObjectMeta, spec v1alpha1.IgnoreSpec, status v1alpha1.IgnoreStatus) IgnoreObject {
	return IgnoreObject{
		Namespace: meta.Namespace, Name: meta.Name, Labels: meta.Labels, Annotations: meta.Annotations,
		Created: meta.CreationTimestamp.Time, Spec: spec, Status: status,
	}
}

// KubeIgnores implements ClusterIgnores on the cache of KubeReports.
type KubeIgnores struct {
	k *KubeReports
}

func (i *KubeIgnores) List(ctx context.Context) ([]IgnoreObject, error) {
	if !i.k.synced.Load() {
		return nil, errNotSynced
	}
	var cluster v1alpha1.ClusterMalwareIgnoreList
	if err := i.k.cache.List(ctx, &cluster); err != nil {
		return nil, fmt.Errorf("list ClusterMalwareIgnores: %w", err)
	}
	var local v1alpha1.MalwareIgnoreList
	if err := i.k.cache.List(ctx, &local); err != nil {
		return nil, fmt.Errorf("list MalwareIgnores: %w", err)
	}
	out := make([]IgnoreObject, 0, len(cluster.Items)+len(local.Items))
	for _, o := range cluster.Items {
		out = append(out, ignoreObject(o.ObjectMeta, o.Spec, o.Status))
	}
	for _, o := range local.Items {
		out = append(out, ignoreObject(o.ObjectMeta, o.Spec, o.Status))
	}
	slices.SortFunc(out, func(a, b IgnoreObject) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	return out, nil
}

// uiPrefix starts the generated names of objects the UI creates.
const uiPrefix = "meles-ui-"

func (i *KubeIgnores) Create(ctx context.Context, namespace string, rule v1alpha1.IgnoreRule, createdBy string) (string, error) {
	meta := metav1.ObjectMeta{
		GenerateName: uiPrefix,
		Namespace:    namespace,
		Labels:       map[string]string{v1alpha1.LabelManagedBy: v1alpha1.ManagedByServer},
		Annotations:  map[string]string{v1alpha1.AnnotationCreatedBy: createdBy},
	}
	spec := v1alpha1.IgnoreSpec{Rules: []v1alpha1.IgnoreRule{rule}}
	var obj client.Object = &v1alpha1.ClusterMalwareIgnore{ObjectMeta: meta, Spec: spec}
	kind := "ClusterMalwareIgnore"
	if namespace != "" {
		obj, kind = &v1alpha1.MalwareIgnore{ObjectMeta: meta, Spec: spec}, "MalwareIgnore"
	}
	if err := i.k.client.Create(ctx, obj); err != nil {
		return "", fmt.Errorf("create %s: %w", kind, err)
	}
	return obj.GetName(), nil
}

func (i *KubeIgnores) Delete(ctx context.Context, namespace, name string) error {
	// Read from the API server, not the cache: the label decides.
	var obj client.Object = &v1alpha1.ClusterMalwareIgnore{}
	kind := "ClusterMalwareIgnore " + name
	if namespace != "" {
		obj, kind = &v1alpha1.MalwareIgnore{}, "MalwareIgnore "+namespace+"/"+name
	}
	if err := i.k.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("%s: %w", kind, store.ErrNotFound)
		}
		return fmt.Errorf("get %s: %w", kind, err)
	}
	if obj.GetLabels()[v1alpha1.LabelManagedBy] != v1alpha1.ManagedByServer {
		return fmt.Errorf("%s: %w", kind, errNotManaged)
	}
	uid := obj.GetUID()
	if err := i.k.client.Delete(ctx, obj, client.Preconditions{UID: &uid}); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("%s: %w", kind, store.ErrNotFound)
		}
		return fmt.Errorf("delete %s: %w", kind, err)
	}
	return nil
}

// ClusterRules returns the valid rules of all ClusterMalwareIgnores, for
// the server's own runs: they belong to no namespace.
func (i *KubeIgnores) ClusterRules(ctx context.Context) (*ignore.Rules, error) {
	if !i.k.synced.Load() {
		return nil, errNotSynced
	}
	var list v1alpha1.ClusterMalwareIgnoreList
	if err := i.k.cache.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list ClusterMalwareIgnores: %w", err)
	}
	now := time.Now()
	sets := make([]*ignore.Rules, 0, len(list.Items))
	for _, o := range list.Items {
		// Invalid rules are left out; the operator writes why to the status.
		rs, _ := ignore.New(ignore.FromSpec(o.Spec, o.Name), o.Name, now)
		sets = append(sets, rs)
	}
	return ignore.Merge(sets...), nil
}
