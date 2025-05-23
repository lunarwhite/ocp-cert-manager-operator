// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// IstioConfigApplyConfiguration represents a declarative configuration of the IstioConfig type for use
// with apply.
type IstioConfigApplyConfiguration struct {
	Revisions []string `json:"revisions,omitempty"`
	Namespace *string  `json:"namespace,omitempty"`
}

// IstioConfigApplyConfiguration constructs a declarative configuration of the IstioConfig type for use with
// apply.
func IstioConfig() *IstioConfigApplyConfiguration {
	return &IstioConfigApplyConfiguration{}
}

// WithRevisions adds the given value to the Revisions field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Revisions field.
func (b *IstioConfigApplyConfiguration) WithRevisions(values ...string) *IstioConfigApplyConfiguration {
	for i := range values {
		b.Revisions = append(b.Revisions, values[i])
	}
	return b
}

// WithNamespace sets the Namespace field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Namespace field is set to the value of the last call.
func (b *IstioConfigApplyConfiguration) WithNamespace(value string) *IstioConfigApplyConfiguration {
	b.Namespace = &value
	return b
}
