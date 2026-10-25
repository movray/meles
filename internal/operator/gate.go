package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/source"
)

// resolveTimeout bounds resolving the tag of a held pod's image.
const resolveTimeout = 30 * time.Second

// gated reports whether the pod waits for the scan gate.
func gated(p *corev1.Pod) bool {
	return slices.ContainsFunc(p.Spec.SchedulingGates, func(g corev1.PodSchedulingGate) bool {
		return g.Name == v1alpha1.SchedulingGateScan
	})
}

// reconcileGated scans the images of a pod held by the scan gate and
// releases it: once every image is Clean, or in audit mode unless one is
// Infected. A held pod has not been pulled yet, so the operator resolves the
// tags itself and pins the released pod to the scanned digests: exactly
// what was scanned runs, even if a tag moved meanwhile.
func (r *Reconciler) reconcileGated(ctx context.Context, pod *corev1.Pod, owner metav1.OwnerReference) (ctrl.Result, error) {
	mode := pod.Annotations[v1alpha1.AnnotationGateMode]
	if mode != v1alpha1.GateAudit {
		mode = v1alpha1.GateEnforce
	}
	auth, err := r.pullKeychain(ctx, []client.ObjectKey{client.ObjectKeyFromObject(pod)})
	if err != nil {
		return ctrl.Result{}, err
	}

	type entry struct {
		c   container
		res result
	}
	var entries []entry
	var requeue time.Duration
	pending := false
	resolved := map[string]container{}
	groups := []struct {
		list []corev1.Container
		init bool
	}{{pod.Spec.InitContainers, true}, {pod.Spec.Containers, false}}
	for _, group := range groups {
		for _, sc := range group.list {
			c, ok := resolved[sc.Image]
			if !ok {
				c = r.resolveContainer(ctx, sc.Image, auth)
				resolved[sc.Image] = c
			}
			c.name, c.init = sc.Name, group.init
			res, wait, err := r.reconcileContainer(ctx, pod, owner, c)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("container %s: %w", sc.Name, err)
			}
			requeue = minWait(requeue, wait)
			if !c.pullable {
				// Resolving is cheap; a tag pushed later releases the pod soon.
				requeue = minWait(requeue, engineRetry)
			}
			if res == nil {
				pending = true // the finished scan reconciles the pod again
				continue
			}
			entries = append(entries, entry{c, *res})
		}
	}
	if pending {
		return ctrl.Result{RequeueAfter: requeue}, nil
	}

	var held, unscanned []string
	for _, e := range entries {
		s := e.res.summary
		switch s.Status {
		case v1alpha1.StatusInfected:
			held = append(held, fmt.Sprintf("%s: %d findings in %s", e.c.name, s.Findings, e.c.img.reference))
		case v1alpha1.StatusIncomplete:
			if mode == v1alpha1.GateEnforce {
				held = append(held, fmt.Sprintf("%s: %d files of %s not scanned", e.c.name, s.Skipped, e.c.img.reference))
			}
		case v1alpha1.StatusError:
			switch {
			case mode == v1alpha1.GateAudit, e.res.errSource == v1alpha1.ErrorSourceEngine && r.GateFailOpen:
				unscanned = append(unscanned, fmt.Sprintf("%s: %s", e.c.name, e.res.err))
			default:
				held = append(held, fmt.Sprintf("%s: %s", e.c.name, e.res.err))
			}
		}
	}
	if len(held) > 0 {
		r.event(pod, corev1.EventTypeWarning, "ScanGateHeld", "Hold", "held by the meles scan gate (%s): %s", mode, strings.Join(held, "; "))
		r.log().Info("pod held", "namespace", pod.Namespace, "pod", pod.Name, "mode", mode, "reasons", held)
		reasons := make([]string, len(held))
		for i, h := range held {
			reasons[i] = statusReason(h)
		}
		r.recordHeld(client.ObjectKeyFromObject(pod), mode, reasons)
		return ctrl.Result{RequeueAfter: requeue}, nil
	}

	if err := r.release(ctx, pod, resolved); err != nil {
		return ctrl.Result{}, err
	}
	r.recordHeld(client.ObjectKeyFromObject(pod), "", nil)
	r.recordReleased(len(unscanned) > 0)
	if len(unscanned) > 0 {
		r.event(pod, corev1.EventTypeWarning, "ScanGateReleasedUnscanned", "Release", "released by the meles scan gate without a complete scan: %s", strings.Join(unscanned, "; "))
		r.log().Warn("pod released unscanned", "namespace", pod.Namespace, "pod", pod.Name, "mode", mode, "errors", unscanned)
	} else {
		r.event(pod, corev1.EventTypeNormal, "ScanGateReleased", "Release", "images scanned, released by the meles scan gate")
		r.log().Info("pod released", "namespace", pod.Namespace, "pod", pod.Name, "mode", mode)
	}
	return ctrl.Result{}, nil
}

// resolveContainer resolves the image of a held pod's container to the
// digest its tag points to now.
func (r *Reconciler) resolveContainer(ctx context.Context, ref string, auth pullAuth) container {
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	repo, digest, err := source.Resolve(rctx, ref, source.Options{Keychain: auth.keychain, Insecure: r.Insecure, Mirrors: r.Mirrors, Logger: r.log()})
	if err != nil {
		return container{img: image{repository: repo, reference: ref}, unpullable: r.authHint(err, auth), gated: true}
	}
	return container{img: image{ref: repo + "@" + digest, repository: repo, digest: digest, reference: ref}, pullable: true, gated: true}
}

// release removes the scan gate and pins the pod's images to the scanned
// digests (image is one of the few fields of a pod that may change).
func (r *Reconciler) release(ctx context.Context, pod *corev1.Pod, resolved map[string]container) error {
	orig := pod.DeepCopy()
	pod.Spec.SchedulingGates = slices.DeleteFunc(pod.Spec.SchedulingGates, func(g corev1.PodSchedulingGate) bool {
		return g.Name == v1alpha1.SchedulingGateScan
	})
	pin := func(list []corev1.Container) {
		for i := range list {
			c := resolved[list[i].Image]
			if c.pullable && !strings.Contains(list[i].Image, "@") {
				list[i].Image += "@" + c.img.digest
			}
		}
	}
	pin(pod.Spec.InitContainers)
	pin(pod.Spec.Containers)
	if err := r.Client.Patch(ctx, pod, client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("release pod: %w", err)
	}
	return nil
}

func (r *Reconciler) event(pod *corev1.Pod, typ, reason, action, note string, args ...any) {
	if r.Recorder != nil {
		r.Recorder.Eventf(pod, nil, typ, reason, action, note, args...)
	}
}

// GateWebhook is the mutating admission webhook of the scan gate: it adds
// the scheduling gate to new pods and records the mode of the namespace.
// The webhook configuration selects the namespaces, one path per mode.
type GateWebhook struct {
	Mode    string
	Decoder admission.Decoder
}

// RegisterGateWebhooks serves the scan gate's webhooks at /gate/enforce and
// /gate/audit.
func RegisterGateWebhooks(mgr ctrl.Manager) {
	dec := admission.NewDecoder(mgr.GetScheme())
	for _, mode := range []string{v1alpha1.GateEnforce, v1alpha1.GateAudit} {
		mgr.GetWebhookServer().Register("/gate/"+mode, &webhook.Admission{Handler: &GateWebhook{Mode: mode, Decoder: dec}})
	}
}

// Handle adds the gate unless the pod opts out, is bound to a node already
// (scheduling gates are refused then, e.g. static pods) or carries it.
func (w *GateWebhook) Handle(_ context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Create {
		return admission.Allowed("")
	}
	var pod corev1.Pod
	if err := w.Decoder.Decode(req, &pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	switch {
	case pod.Annotations[v1alpha1.AnnotationGate] == v1alpha1.GateSkip:
		return admission.Allowed("opted out of the meles scan gate")
	case pod.Spec.NodeName != "", gated(&pod):
		return admission.Allowed("")
	}
	pod.Spec.SchedulingGates = append(pod.Spec.SchedulingGates, corev1.PodSchedulingGate{Name: v1alpha1.SchedulingGateScan})
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[v1alpha1.AnnotationGateMode] = w.Mode
	raw, err := json.Marshal(&pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, raw)
}
