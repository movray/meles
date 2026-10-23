// Package v1alpha1 contains the meles.io/v1alpha1 API: MalwareReport, the
// result of scanning the image of one workload container.
//
// +kubebuilder:object:generate=true
// +groupName=meles.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the API group and version of these types.
	GroupVersion = schema.GroupVersion{Group: "meles.io", Version: "v1alpha1"}

	// SchemeBuilder registers the types with a scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types of this group version to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
