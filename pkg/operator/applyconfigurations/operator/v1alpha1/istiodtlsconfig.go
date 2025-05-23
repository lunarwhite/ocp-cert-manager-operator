// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IstiodTLSConfigApplyConfiguration represents a declarative configuration of the IstiodTLSConfig type for use
// with apply.
type IstiodTLSConfigApplyConfiguration struct {
	CommonName             *string      `json:"commonName,omitempty"`
	TrustDomain            *string      `json:"trustDomain,omitempty"`
	CertificateDNSNames    []string     `json:"certificateDNSNames,omitempty"`
	CertificateDuration    *v1.Duration `json:"certificateDuration,omitempty"`
	CertificateRenewBefore *v1.Duration `json:"certificateRenewBefore,omitempty"`
	PrivateKeySize         *int         `json:"privateKeySize,omitempty"`
	SignatureAlgorithm     *string      `json:"signatureAlgorithm,omitempty"`
	MaxCertificateDuration *v1.Duration `json:"maxCertificateDuration,omitempty"`
}

// IstiodTLSConfigApplyConfiguration constructs a declarative configuration of the IstiodTLSConfig type for use with
// apply.
func IstiodTLSConfig() *IstiodTLSConfigApplyConfiguration {
	return &IstiodTLSConfigApplyConfiguration{}
}

// WithCommonName sets the CommonName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CommonName field is set to the value of the last call.
func (b *IstiodTLSConfigApplyConfiguration) WithCommonName(value string) *IstiodTLSConfigApplyConfiguration {
	b.CommonName = &value
	return b
}

// WithTrustDomain sets the TrustDomain field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TrustDomain field is set to the value of the last call.
func (b *IstiodTLSConfigApplyConfiguration) WithTrustDomain(value string) *IstiodTLSConfigApplyConfiguration {
	b.TrustDomain = &value
	return b
}

// WithCertificateDNSNames adds the given value to the CertificateDNSNames field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the CertificateDNSNames field.
func (b *IstiodTLSConfigApplyConfiguration) WithCertificateDNSNames(values ...string) *IstiodTLSConfigApplyConfiguration {
	for i := range values {
		b.CertificateDNSNames = append(b.CertificateDNSNames, values[i])
	}
	return b
}

// WithCertificateDuration sets the CertificateDuration field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CertificateDuration field is set to the value of the last call.
func (b *IstiodTLSConfigApplyConfiguration) WithCertificateDuration(value v1.Duration) *IstiodTLSConfigApplyConfiguration {
	b.CertificateDuration = &value
	return b
}

// WithCertificateRenewBefore sets the CertificateRenewBefore field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CertificateRenewBefore field is set to the value of the last call.
func (b *IstiodTLSConfigApplyConfiguration) WithCertificateRenewBefore(value v1.Duration) *IstiodTLSConfigApplyConfiguration {
	b.CertificateRenewBefore = &value
	return b
}

// WithPrivateKeySize sets the PrivateKeySize field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PrivateKeySize field is set to the value of the last call.
func (b *IstiodTLSConfigApplyConfiguration) WithPrivateKeySize(value int) *IstiodTLSConfigApplyConfiguration {
	b.PrivateKeySize = &value
	return b
}

// WithSignatureAlgorithm sets the SignatureAlgorithm field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SignatureAlgorithm field is set to the value of the last call.
func (b *IstiodTLSConfigApplyConfiguration) WithSignatureAlgorithm(value string) *IstiodTLSConfigApplyConfiguration {
	b.SignatureAlgorithm = &value
	return b
}

// WithMaxCertificateDuration sets the MaxCertificateDuration field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the MaxCertificateDuration field is set to the value of the last call.
func (b *IstiodTLSConfigApplyConfiguration) WithMaxCertificateDuration(value v1.Duration) *IstiodTLSConfigApplyConfiguration {
	b.MaxCertificateDuration = &value
	return b
}
