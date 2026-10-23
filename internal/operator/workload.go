package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// resolveWorkload returns the workload a report of pod belongs to, as the
// owner reference of the report: its controller (ReplicaSet,
// StatefulSet, DaemonSet, Job, ...), the CronJob of a Job, or the pod itself.
// ReplicaSets are not resolved to their Deployment: a ReplicaSet belongs to
// one pod template, so its report follows exactly one image.
func resolveWorkload(ctx context.Context, c client.Reader, pod *corev1.Pod) (metav1.OwnerReference, error) {
	ctrl := metav1.GetControllerOf(pod)
	if ctrl == nil {
		return ownerRef(corev1.SchemeGroupVersion.String(), "Pod", pod.Name, pod.UID), nil
	}
	if ctrl.Kind == "Job" && ctrl.APIVersion == batchv1.SchemeGroupVersion.String() {
		var job batchv1.Job
		err := c.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: ctrl.Name}, &job)
		switch {
		case apierrors.IsNotFound(err):
			// The job is gone; the pod will follow.
		case err != nil:
			return metav1.OwnerReference{}, fmt.Errorf("get job %s: %w", ctrl.Name, err)
		default:
			if cj := metav1.GetControllerOf(&job); cj != nil && cj.Kind == "CronJob" {
				return ownerRef(cj.APIVersion, cj.Kind, cj.Name, cj.UID), nil
			}
		}
	}
	return ownerRef(ctrl.APIVersion, ctrl.Kind, ctrl.Name, ctrl.UID), nil
}

func ownerRef(apiVersion, kind, name string, uid types.UID) metav1.OwnerReference {
	return metav1.OwnerReference{APIVersion: apiVersion, Kind: kind, Name: name, UID: uid}
}

// reportName is "<kind>-<workload>-<container>", e.g.
// "replicaset-web-5d8f7c-nginx". Names that are too long are shortened and
// made unique with a hash.
func reportName(kind, workload, container string) string {
	n := strings.ToLower(kind + "-" + workload + "-" + container)
	if len(n) <= validation.DNS1123SubdomainMaxLength {
		return n
	}
	h := sha256.Sum256([]byte(n))
	return n[:validation.DNS1123SubdomainMaxLength-11] + "-" + hex.EncodeToString(h[:])[:10]
}

// labelValue returns v if it is a valid label value, otherwise "".
func labelValue(v string) string {
	if len(validation.IsValidLabelValue(v)) > 0 {
		return ""
	}
	return v
}
