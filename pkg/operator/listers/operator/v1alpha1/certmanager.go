// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/openshift/cert-manager-operator/api/operator/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// CertManagerLister helps list CertManagers.
// All objects returned here must be treated as read-only.
type CertManagerLister interface {
	// List lists all CertManagers in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.CertManager, err error)
	// Get retrieves the CertManager from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.CertManager, error)
	CertManagerListerExpansion
}

// certManagerLister implements the CertManagerLister interface.
type certManagerLister struct {
	listers.ResourceIndexer[*v1alpha1.CertManager]
}

// NewCertManagerLister returns a new CertManagerLister.
func NewCertManagerLister(indexer cache.Indexer) CertManagerLister {
	return &certManagerLister{listers.New[*v1alpha1.CertManager](indexer, v1alpha1.Resource("certmanager"))}
}
