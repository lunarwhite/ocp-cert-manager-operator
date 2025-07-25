// Code generated for package assets by go-bindata DO NOT EDIT. (@generated)
// sources:
// bindata/cert-manager-deployment/cainjector/cert-manager-cainjector-cr.yaml
// bindata/cert-manager-deployment/cainjector/cert-manager-cainjector-crb.yaml
// bindata/cert-manager-deployment/cainjector/cert-manager-cainjector-deployment.yaml
// bindata/cert-manager-deployment/cainjector/cert-manager-cainjector-leaderelection-rb.yaml
// bindata/cert-manager-deployment/cainjector/cert-manager-cainjector-leaderelection-role.yaml
// bindata/cert-manager-deployment/cainjector/cert-manager-cainjector-sa.yaml
// bindata/cert-manager-deployment/cainjector/cert-manager-cainjector-svc.yaml
// bindata/cert-manager-deployment/cert-manager/cert-manager-controller-approve-cert-manager-io-cr.yaml
// bindata/cert-manager-deployment/cert-manager/cert-manager-controller-approve-cert-manager-io-crb.yaml
// bindata/cert-manager-deployment/cert-manager/cert-manager-controller-certificatesigningrequests-cr.yaml
// bindata/cert-manager-deployment/cert-manager/cert-manager-controller-certificatesigningrequests-crb.yaml
// bindata/cert-manager-deployment/cert-manager-namespace.yaml
// bindata/cert-manager-deployment/controller/cert-manager-cert-manager-tokenrequest-rb.yaml
// bindata/cert-manager-deployment/controller/cert-manager-cluster-view-cr.yaml
// bindata/cert-manager-deployment/controller/cert-manager-controller-certificates-cr.yaml
// bindata/cert-manager-deployment/controller/cert-manager-controller-certificates-crb.yaml
// bindata/cert-manager-deployment/controller/cert-manager-controller-challenges-cr.yaml
// bindata/cert-manager-deployment/controller/cert-manager-controller-challenges-crb.yaml
// bindata/cert-manager-deployment/controller/cert-manager-controller-clusterissuers-cr.yaml
// bindata/cert-manager-deployment/controller/cert-manager-controller-clusterissuers-crb.yaml
// bindata/cert-manager-deployment/controller/cert-manager-controller-ingress-shim-cr.yaml
// bindata/cert-manager-deployment/controller/cert-manager-controller-ingress-shim-crb.yaml
// bindata/cert-manager-deployment/controller/cert-manager-controller-issuers-cr.yaml
// bindata/cert-manager-deployment/controller/cert-manager-controller-issuers-crb.yaml
// bindata/cert-manager-deployment/controller/cert-manager-controller-orders-cr.yaml
// bindata/cert-manager-deployment/controller/cert-manager-controller-orders-crb.yaml
// bindata/cert-manager-deployment/controller/cert-manager-deployment.yaml
// bindata/cert-manager-deployment/controller/cert-manager-edit-cr.yaml
// bindata/cert-manager-deployment/controller/cert-manager-leaderelection-rb.yaml
// bindata/cert-manager-deployment/controller/cert-manager-leaderelection-role.yaml
// bindata/cert-manager-deployment/controller/cert-manager-sa.yaml
// bindata/cert-manager-deployment/controller/cert-manager-svc.yaml
// bindata/cert-manager-deployment/controller/cert-manager-tokenrequest-role.yaml
// bindata/cert-manager-deployment/controller/cert-manager-view-cr.yaml
// bindata/cert-manager-deployment/webhook/cert-manager-webhook-deployment.yaml
// bindata/cert-manager-deployment/webhook/cert-manager-webhook-dynamic-serving-rb.yaml
// bindata/cert-manager-deployment/webhook/cert-manager-webhook-dynamic-serving-role.yaml
// bindata/cert-manager-deployment/webhook/cert-manager-webhook-mutatingwebhookconfiguration.yaml
// bindata/cert-manager-deployment/webhook/cert-manager-webhook-sa.yaml
// bindata/cert-manager-deployment/webhook/cert-manager-webhook-subjectaccessreviews-cr.yaml
// bindata/cert-manager-deployment/webhook/cert-manager-webhook-subjectaccessreviews-crb.yaml
// bindata/cert-manager-deployment/webhook/cert-manager-webhook-svc.yaml
// bindata/cert-manager-deployment/webhook/cert-manager-webhook-validatingwebhookconfiguration.yaml
// bindata/istio-csr/cert-manager-istio-csr-clusterrole.yaml
// bindata/istio-csr/cert-manager-istio-csr-clusterrolebinding.yaml
// bindata/istio-csr/cert-manager-istio-csr-deployment.yaml
// bindata/istio-csr/cert-manager-istio-csr-leases-role.yaml
// bindata/istio-csr/cert-manager-istio-csr-leases-rolebinding.yaml
// bindata/istio-csr/cert-manager-istio-csr-role.yaml
// bindata/istio-csr/cert-manager-istio-csr-rolebinding.yaml
// bindata/istio-csr/cert-manager-istio-csr-service.yaml
// bindata/istio-csr/cert-manager-istio-csr-serviceaccount.yaml
// bindata/istio-csr/istiod-certificate.yaml
package assets

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// Mode return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _certManagerDeploymentCainjectorCertManagerCainjectorCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: cainjector
    app.kubernetes.io/component: cainjector
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cainjector
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-cainjector
rules:
  - apiGroups:
      - cert-manager.io
    resources:
      - certificates
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - secrets
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - events
    verbs:
      - get
      - create
      - update
      - patch
  - apiGroups:
      - admissionregistration.k8s.io
    resources:
      - validatingwebhookconfigurations
      - mutatingwebhookconfigurations
    verbs:
      - get
      - list
      - watch
      - update
      - patch
  - apiGroups:
      - apiregistration.k8s.io
    resources:
      - apiservices
    verbs:
      - get
      - list
      - watch
      - update
      - patch
  - apiGroups:
      - apiextensions.k8s.io
    resources:
      - customresourcedefinitions
    verbs:
      - get
      - list
      - watch
      - update
      - patch
`)

func certManagerDeploymentCainjectorCertManagerCainjectorCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentCainjectorCertManagerCainjectorCrYaml, nil
}

func certManagerDeploymentCainjectorCertManagerCainjectorCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentCainjectorCertManagerCainjectorCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/cainjector/cert-manager-cainjector-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentCainjectorCertManagerCainjectorCrbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    app: cainjector
    app.kubernetes.io/component: cainjector
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cainjector
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-cainjector
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-cainjector
subjects:
  - kind: ServiceAccount
    name: cert-manager-cainjector
    namespace: cert-manager
`)

func certManagerDeploymentCainjectorCertManagerCainjectorCrbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentCainjectorCertManagerCainjectorCrbYaml, nil
}

func certManagerDeploymentCainjectorCertManagerCainjectorCrbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentCainjectorCertManagerCainjectorCrbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/cainjector/cert-manager-cainjector-crb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentCainjectorCertManagerCainjectorDeploymentYaml = []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: cainjector
    app.kubernetes.io/component: cainjector
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cainjector
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-cainjector
  namespace: cert-manager
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/component: cainjector
      app.kubernetes.io/instance: cert-manager
      app.kubernetes.io/name: cainjector
  template:
    metadata:
      annotations:
        prometheus.io/path: /metrics
        prometheus.io/port: "9402"
        prometheus.io/scrape: "true"
      labels:
        app: cainjector
        app.kubernetes.io/component: cainjector
        app.kubernetes.io/instance: cert-manager
        app.kubernetes.io/name: cainjector
        app.kubernetes.io/version: v1.17.4
    spec:
      containers:
        - args:
            - --v=2
            - --leader-election-namespace=kube-system
          command:
            - /app/cmd/cainjector/cainjector
          env:
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          image: quay.io/jetstack/cert-manager-cainjector:v1.17.4
          imagePullPolicy: IfNotPresent
          name: cert-manager-cainjector
          ports:
            - containerPort: 9402
              name: http-metrics
              protocol: TCP
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            readOnlyRootFilesystem: true
      enableServiceLinks: false
      nodeSelector:
        kubernetes.io/os: linux
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      serviceAccountName: cert-manager-cainjector
`)

func certManagerDeploymentCainjectorCertManagerCainjectorDeploymentYamlBytes() ([]byte, error) {
	return _certManagerDeploymentCainjectorCertManagerCainjectorDeploymentYaml, nil
}

func certManagerDeploymentCainjectorCertManagerCainjectorDeploymentYaml() (*asset, error) {
	bytes, err := certManagerDeploymentCainjectorCertManagerCainjectorDeploymentYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/cainjector/cert-manager-cainjector-deployment.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  labels:
    app: cainjector
    app.kubernetes.io/component: cainjector
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cainjector
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-cainjector:leaderelection
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cert-manager-cainjector:leaderelection
subjects:
  - kind: ServiceAccount
    name: cert-manager-cainjector
    namespace: cert-manager
`)

func certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRbYaml, nil
}

func certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/cainjector/cert-manager-cainjector-leaderelection-rb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRoleYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  labels:
    app: cainjector
    app.kubernetes.io/component: cainjector
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cainjector
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-cainjector:leaderelection
  namespace: kube-system
rules:
  - apiGroups:
      - coordination.k8s.io
    resourceNames:
      - cert-manager-cainjector-leader-election
      - cert-manager-cainjector-leader-election-core
    resources:
      - leases
    verbs:
      - get
      - update
      - patch
  - apiGroups:
      - coordination.k8s.io
    resources:
      - leases
    verbs:
      - create
`)

func certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRoleYamlBytes() ([]byte, error) {
	return _certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRoleYaml, nil
}

func certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRoleYaml() (*asset, error) {
	bytes, err := certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/cainjector/cert-manager-cainjector-leaderelection-role.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentCainjectorCertManagerCainjectorSaYaml = []byte(`apiVersion: v1
automountServiceAccountToken: true
kind: ServiceAccount
metadata:
  labels:
    app: cainjector
    app.kubernetes.io/component: cainjector
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cainjector
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-cainjector
  namespace: cert-manager
`)

func certManagerDeploymentCainjectorCertManagerCainjectorSaYamlBytes() ([]byte, error) {
	return _certManagerDeploymentCainjectorCertManagerCainjectorSaYaml, nil
}

func certManagerDeploymentCainjectorCertManagerCainjectorSaYaml() (*asset, error) {
	bytes, err := certManagerDeploymentCainjectorCertManagerCainjectorSaYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/cainjector/cert-manager-cainjector-sa.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentCainjectorCertManagerCainjectorSvcYaml = []byte(`apiVersion: v1
kind: Service
metadata:
  labels:
    app: cainjector
    app.kubernetes.io/component: cainjector
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cainjector
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-cainjector
  namespace: cert-manager
spec:
  ports:
    - name: http-metrics
      port: 9402
      protocol: TCP
  selector:
    app.kubernetes.io/component: cainjector
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cainjector
  type: ClusterIP
`)

func certManagerDeploymentCainjectorCertManagerCainjectorSvcYamlBytes() ([]byte, error) {
	return _certManagerDeploymentCainjectorCertManagerCainjectorSvcYaml, nil
}

func certManagerDeploymentCainjectorCertManagerCainjectorSvcYaml() (*asset, error) {
	bytes, err := certManagerDeploymentCainjectorCertManagerCainjectorSvcYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/cainjector/cert-manager-cainjector-svc.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: cert-manager
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-approve:cert-manager-io
rules:
  - apiGroups:
      - cert-manager.io
    resourceNames:
      - issuers.cert-manager.io/*
      - clusterissuers.cert-manager.io/*
    resources:
      - signers
    verbs:
      - approve
`)

func certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrYaml, nil
}

func certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/cert-manager/cert-manager-controller-approve-cert-manager-io-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: cert-manager
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-approve:cert-manager-io
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-controller-approve:cert-manager-io
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
`)

func certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrbYaml, nil
}

func certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/cert-manager/cert-manager-controller-approve-cert-manager-io-crb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: cert-manager
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-certificatesigningrequests
rules:
  - apiGroups:
      - certificates.k8s.io
    resources:
      - certificatesigningrequests
    verbs:
      - get
      - list
      - watch
      - update
  - apiGroups:
      - certificates.k8s.io
    resources:
      - certificatesigningrequests/status
    verbs:
      - update
      - patch
  - apiGroups:
      - certificates.k8s.io
    resourceNames:
      - issuers.cert-manager.io/*
      - clusterissuers.cert-manager.io/*
    resources:
      - signers
    verbs:
      - sign
  - apiGroups:
      - authorization.k8s.io
    resources:
      - subjectaccessreviews
    verbs:
      - create
`)

func certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrYaml, nil
}

func certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/cert-manager/cert-manager-controller-certificatesigningrequests-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: cert-manager
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-certificatesigningrequests
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-controller-certificatesigningrequests
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
`)

func certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrbYaml, nil
}

func certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/cert-manager/cert-manager-controller-certificatesigningrequests-crb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentCertManagerNamespaceYaml = []byte(`apiVersion: v1
kind: Namespace
metadata:
  annotations:
    openshift.io/cluster-monitoring: "true"
  name: cert-manager
`)

func certManagerDeploymentCertManagerNamespaceYamlBytes() ([]byte, error) {
	return _certManagerDeploymentCertManagerNamespaceYaml, nil
}

func certManagerDeploymentCertManagerNamespaceYaml() (*asset, error) {
	bytes, err := certManagerDeploymentCertManagerNamespaceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/cert-manager-namespace.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerCertManagerTokenrequestRbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-cert-manager-tokenrequest
  namespace: cert-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cert-manager-tokenrequest
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
`)

func certManagerDeploymentControllerCertManagerCertManagerTokenrequestRbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerCertManagerTokenrequestRbYaml, nil
}

func certManagerDeploymentControllerCertManagerCertManagerTokenrequestRbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerCertManagerTokenrequestRbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-cert-manager-tokenrequest-rb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerClusterViewCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
    rbac.authorization.k8s.io/aggregate-to-cluster-reader: "true"
  name: cert-manager-cluster-view
rules:
  - apiGroups:
      - cert-manager.io
    resources:
      - clusterissuers
    verbs:
      - get
      - list
      - watch
`)

func certManagerDeploymentControllerCertManagerClusterViewCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerClusterViewCrYaml, nil
}

func certManagerDeploymentControllerCertManagerClusterViewCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerClusterViewCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-cluster-view-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerControllerCertificatesCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-certificates
rules:
  - apiGroups:
      - cert-manager.io
    resources:
      - certificates
      - certificates/status
      - certificaterequests
      - certificaterequests/status
    verbs:
      - update
      - patch
  - apiGroups:
      - cert-manager.io
    resources:
      - certificates
      - certificaterequests
      - clusterissuers
      - issuers
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - cert-manager.io
    resources:
      - certificates/finalizers
      - certificaterequests/finalizers
    verbs:
      - update
  - apiGroups:
      - acme.cert-manager.io
    resources:
      - orders
    verbs:
      - create
      - delete
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - secrets
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - delete
      - patch
  - apiGroups:
      - ""
    resources:
      - events
    verbs:
      - create
      - patch
`)

func certManagerDeploymentControllerCertManagerControllerCertificatesCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerControllerCertificatesCrYaml, nil
}

func certManagerDeploymentControllerCertManagerControllerCertificatesCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerControllerCertificatesCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-controller-certificates-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerControllerCertificatesCrbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-certificates
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-controller-certificates
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
`)

func certManagerDeploymentControllerCertManagerControllerCertificatesCrbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerControllerCertificatesCrbYaml, nil
}

func certManagerDeploymentControllerCertManagerControllerCertificatesCrbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerControllerCertificatesCrbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-controller-certificates-crb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerControllerChallengesCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-challenges
rules:
  - apiGroups:
      - acme.cert-manager.io
    resources:
      - challenges
      - challenges/status
    verbs:
      - update
      - patch
  - apiGroups:
      - acme.cert-manager.io
    resources:
      - challenges
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - cert-manager.io
    resources:
      - issuers
      - clusterissuers
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - secrets
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - events
    verbs:
      - create
      - patch
  - apiGroups:
      - ""
    resources:
      - pods
      - services
    verbs:
      - get
      - list
      - watch
      - create
      - delete
  - apiGroups:
      - networking.k8s.io
    resources:
      - ingresses
    verbs:
      - get
      - list
      - watch
      - create
      - delete
      - update
  - apiGroups:
      - gateway.networking.k8s.io
    resources:
      - httproutes
    verbs:
      - get
      - list
      - watch
      - create
      - delete
      - update
  - apiGroups:
      - route.openshift.io
    resources:
      - routes/custom-host
    verbs:
      - create
  - apiGroups:
      - acme.cert-manager.io
    resources:
      - challenges/finalizers
    verbs:
      - update
  - apiGroups:
      - ""
    resources:
      - secrets
    verbs:
      - get
      - list
      - watch
`)

func certManagerDeploymentControllerCertManagerControllerChallengesCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerControllerChallengesCrYaml, nil
}

func certManagerDeploymentControllerCertManagerControllerChallengesCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerControllerChallengesCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-controller-challenges-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerControllerChallengesCrbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-challenges
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-controller-challenges
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
`)

func certManagerDeploymentControllerCertManagerControllerChallengesCrbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerControllerChallengesCrbYaml, nil
}

func certManagerDeploymentControllerCertManagerControllerChallengesCrbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerControllerChallengesCrbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-controller-challenges-crb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerControllerClusterissuersCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-clusterissuers
rules:
  - apiGroups:
      - cert-manager.io
    resources:
      - clusterissuers
      - clusterissuers/status
    verbs:
      - update
      - patch
  - apiGroups:
      - cert-manager.io
    resources:
      - clusterissuers
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - secrets
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - delete
  - apiGroups:
      - ""
    resources:
      - events
    verbs:
      - create
      - patch
`)

func certManagerDeploymentControllerCertManagerControllerClusterissuersCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerControllerClusterissuersCrYaml, nil
}

func certManagerDeploymentControllerCertManagerControllerClusterissuersCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerControllerClusterissuersCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-controller-clusterissuers-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerControllerClusterissuersCrbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-clusterissuers
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-controller-clusterissuers
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
`)

func certManagerDeploymentControllerCertManagerControllerClusterissuersCrbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerControllerClusterissuersCrbYaml, nil
}

func certManagerDeploymentControllerCertManagerControllerClusterissuersCrbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerControllerClusterissuersCrbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-controller-clusterissuers-crb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerControllerIngressShimCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-ingress-shim
rules:
  - apiGroups:
      - cert-manager.io
    resources:
      - certificates
      - certificaterequests
    verbs:
      - create
      - update
      - delete
  - apiGroups:
      - cert-manager.io
    resources:
      - certificates
      - certificaterequests
      - issuers
      - clusterissuers
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - networking.k8s.io
    resources:
      - ingresses
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - networking.k8s.io
    resources:
      - ingresses/finalizers
    verbs:
      - update
  - apiGroups:
      - gateway.networking.k8s.io
    resources:
      - gateways
      - httproutes
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - gateway.networking.k8s.io
    resources:
      - gateways/finalizers
      - httproutes/finalizers
    verbs:
      - update
  - apiGroups:
      - ""
    resources:
      - events
    verbs:
      - create
      - patch
`)

func certManagerDeploymentControllerCertManagerControllerIngressShimCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerControllerIngressShimCrYaml, nil
}

func certManagerDeploymentControllerCertManagerControllerIngressShimCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerControllerIngressShimCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-controller-ingress-shim-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerControllerIngressShimCrbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-ingress-shim
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-controller-ingress-shim
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
`)

func certManagerDeploymentControllerCertManagerControllerIngressShimCrbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerControllerIngressShimCrbYaml, nil
}

func certManagerDeploymentControllerCertManagerControllerIngressShimCrbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerControllerIngressShimCrbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-controller-ingress-shim-crb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerControllerIssuersCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-issuers
rules:
  - apiGroups:
      - cert-manager.io
    resources:
      - issuers
      - issuers/status
    verbs:
      - update
      - patch
  - apiGroups:
      - cert-manager.io
    resources:
      - issuers
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - secrets
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - delete
  - apiGroups:
      - ""
    resources:
      - events
    verbs:
      - create
      - patch
`)

func certManagerDeploymentControllerCertManagerControllerIssuersCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerControllerIssuersCrYaml, nil
}

func certManagerDeploymentControllerCertManagerControllerIssuersCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerControllerIssuersCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-controller-issuers-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerControllerIssuersCrbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-issuers
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-controller-issuers
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
`)

func certManagerDeploymentControllerCertManagerControllerIssuersCrbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerControllerIssuersCrbYaml, nil
}

func certManagerDeploymentControllerCertManagerControllerIssuersCrbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerControllerIssuersCrbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-controller-issuers-crb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerControllerOrdersCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-orders
rules:
  - apiGroups:
      - acme.cert-manager.io
    resources:
      - orders
      - orders/status
    verbs:
      - update
      - patch
  - apiGroups:
      - acme.cert-manager.io
    resources:
      - orders
      - challenges
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - cert-manager.io
    resources:
      - clusterissuers
      - issuers
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - acme.cert-manager.io
    resources:
      - challenges
    verbs:
      - create
      - delete
  - apiGroups:
      - acme.cert-manager.io
    resources:
      - orders/finalizers
    verbs:
      - update
  - apiGroups:
      - ""
    resources:
      - secrets
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - events
    verbs:
      - create
      - patch
`)

func certManagerDeploymentControllerCertManagerControllerOrdersCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerControllerOrdersCrYaml, nil
}

func certManagerDeploymentControllerCertManagerControllerOrdersCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerControllerOrdersCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-controller-orders-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerControllerOrdersCrbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-controller-orders
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-controller-orders
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
`)

func certManagerDeploymentControllerCertManagerControllerOrdersCrbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerControllerOrdersCrbYaml, nil
}

func certManagerDeploymentControllerCertManagerControllerOrdersCrbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerControllerOrdersCrbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-controller-orders-crb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerDeploymentYaml = []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager
  namespace: cert-manager
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/component: controller
      app.kubernetes.io/instance: cert-manager
      app.kubernetes.io/name: cert-manager
  template:
    metadata:
      annotations:
        prometheus.io/path: /metrics
        prometheus.io/port: "9402"
        prometheus.io/scrape: "true"
      labels:
        app: cert-manager
        app.kubernetes.io/component: controller
        app.kubernetes.io/instance: cert-manager
        app.kubernetes.io/name: cert-manager
        app.kubernetes.io/version: v1.17.4
    spec:
      containers:
        - args:
            - --v=2
            - --cluster-resource-namespace=$(POD_NAMESPACE)
            - --leader-election-namespace=kube-system
            - --acme-http01-solver-image=quay.io/jetstack/cert-manager-acmesolver:v1.17.4
            - --max-concurrent-challenges=60
          command:
            - /app/cmd/controller/controller
          env:
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          image: quay.io/jetstack/cert-manager-controller:v1.17.4
          imagePullPolicy: IfNotPresent
          livenessProbe:
            failureThreshold: 8
            httpGet:
              path: /livez
              port: http-healthz
              scheme: HTTP
            initialDelaySeconds: 10
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 15
          name: cert-manager-controller
          ports:
            - containerPort: 9402
              name: http-metrics
              protocol: TCP
            - containerPort: 9403
              name: http-healthz
              protocol: TCP
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            readOnlyRootFilesystem: true
      enableServiceLinks: false
      nodeSelector:
        kubernetes.io/os: linux
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      serviceAccountName: cert-manager
`)

func certManagerDeploymentControllerCertManagerDeploymentYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerDeploymentYaml, nil
}

func certManagerDeploymentControllerCertManagerDeploymentYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerDeploymentYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-deployment.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerEditCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
    rbac.authorization.k8s.io/aggregate-to-admin: "true"
    rbac.authorization.k8s.io/aggregate-to-edit: "true"
  name: cert-manager-edit
rules:
  - apiGroups:
      - cert-manager.io
    resources:
      - certificates
      - certificaterequests
      - issuers
    verbs:
      - create
      - delete
      - deletecollection
      - patch
      - update
  - apiGroups:
      - cert-manager.io
    resources:
      - certificates/status
    verbs:
      - update
  - apiGroups:
      - acme.cert-manager.io
    resources:
      - challenges
      - orders
    verbs:
      - create
      - delete
      - deletecollection
      - patch
      - update
`)

func certManagerDeploymentControllerCertManagerEditCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerEditCrYaml, nil
}

func certManagerDeploymentControllerCertManagerEditCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerEditCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-edit-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerLeaderelectionRbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager:leaderelection
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cert-manager:leaderelection
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
`)

func certManagerDeploymentControllerCertManagerLeaderelectionRbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerLeaderelectionRbYaml, nil
}

func certManagerDeploymentControllerCertManagerLeaderelectionRbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerLeaderelectionRbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-leaderelection-rb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerLeaderelectionRoleYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager:leaderelection
  namespace: kube-system
rules:
  - apiGroups:
      - coordination.k8s.io
    resourceNames:
      - cert-manager-controller
    resources:
      - leases
    verbs:
      - get
      - update
      - patch
  - apiGroups:
      - coordination.k8s.io
    resources:
      - leases
    verbs:
      - create
`)

func certManagerDeploymentControllerCertManagerLeaderelectionRoleYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerLeaderelectionRoleYaml, nil
}

func certManagerDeploymentControllerCertManagerLeaderelectionRoleYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerLeaderelectionRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-leaderelection-role.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerSaYaml = []byte(`apiVersion: v1
automountServiceAccountToken: true
kind: ServiceAccount
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager
  namespace: cert-manager
`)

func certManagerDeploymentControllerCertManagerSaYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerSaYaml, nil
}

func certManagerDeploymentControllerCertManagerSaYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerSaYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-sa.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerSvcYaml = []byte(`apiVersion: v1
kind: Service
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager
  namespace: cert-manager
spec:
  ports:
    - name: tcp-prometheus-servicemonitor
      port: 9402
      protocol: TCP
      targetPort: 9402
  selector:
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
  type: ClusterIP
`)

func certManagerDeploymentControllerCertManagerSvcYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerSvcYaml, nil
}

func certManagerDeploymentControllerCertManagerSvcYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerSvcYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-svc.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerTokenrequestRoleYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-tokenrequest
  namespace: cert-manager
rules:
  - apiGroups:
      - ""
    resourceNames:
      - cert-manager
    resources:
      - serviceaccounts/token
    verbs:
      - create
`)

func certManagerDeploymentControllerCertManagerTokenrequestRoleYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerTokenrequestRoleYaml, nil
}

func certManagerDeploymentControllerCertManagerTokenrequestRoleYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerTokenrequestRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-tokenrequest-role.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentControllerCertManagerViewCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: cert-manager
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: cert-manager
    app.kubernetes.io/version: v1.17.4
    rbac.authorization.k8s.io/aggregate-to-admin: "true"
    rbac.authorization.k8s.io/aggregate-to-cluster-reader: "true"
    rbac.authorization.k8s.io/aggregate-to-edit: "true"
    rbac.authorization.k8s.io/aggregate-to-view: "true"
  name: cert-manager-view
rules:
  - apiGroups:
      - cert-manager.io
    resources:
      - certificates
      - certificaterequests
      - issuers
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - acme.cert-manager.io
    resources:
      - challenges
      - orders
    verbs:
      - get
      - list
      - watch
`)

func certManagerDeploymentControllerCertManagerViewCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentControllerCertManagerViewCrYaml, nil
}

func certManagerDeploymentControllerCertManagerViewCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentControllerCertManagerViewCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/controller/cert-manager-view-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentWebhookCertManagerWebhookDeploymentYaml = []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: webhook
    app.kubernetes.io/component: webhook
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: webhook
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-webhook
  namespace: cert-manager
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/component: webhook
      app.kubernetes.io/instance: cert-manager
      app.kubernetes.io/name: webhook
  template:
    metadata:
      annotations:
        prometheus.io/path: /metrics
        prometheus.io/port: "9402"
        prometheus.io/scrape: "true"
      labels:
        app: webhook
        app.kubernetes.io/component: webhook
        app.kubernetes.io/instance: cert-manager
        app.kubernetes.io/name: webhook
        app.kubernetes.io/version: v1.17.4
    spec:
      containers:
        - args:
            - --v=2
            - --secure-port=10250
            - --dynamic-serving-ca-secret-namespace=$(POD_NAMESPACE)
            - --dynamic-serving-ca-secret-name=cert-manager-webhook-ca
            - --dynamic-serving-dns-names=cert-manager-webhook,cert-manager-webhook.$(POD_NAMESPACE),cert-manager-webhook.$(POD_NAMESPACE).svc
          command:
            - /app/cmd/webhook/webhook
          env:
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          image: quay.io/jetstack/cert-manager-webhook:v1.17.4
          imagePullPolicy: IfNotPresent
          livenessProbe:
            failureThreshold: 3
            httpGet:
              path: /livez
              port: 6080
              scheme: HTTP
            initialDelaySeconds: 60
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 1
          name: cert-manager-webhook
          ports:
            - containerPort: 10250
              name: https
              protocol: TCP
            - containerPort: 6080
              name: healthcheck
              protocol: TCP
            - containerPort: 9402
              name: http-metrics
              protocol: TCP
          readinessProbe:
            failureThreshold: 3
            httpGet:
              path: /healthz
              port: 6080
              scheme: HTTP
            initialDelaySeconds: 5
            periodSeconds: 5
            successThreshold: 1
            timeoutSeconds: 1
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            readOnlyRootFilesystem: true
      enableServiceLinks: false
      nodeSelector:
        kubernetes.io/os: linux
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      serviceAccountName: cert-manager-webhook
`)

func certManagerDeploymentWebhookCertManagerWebhookDeploymentYamlBytes() ([]byte, error) {
	return _certManagerDeploymentWebhookCertManagerWebhookDeploymentYaml, nil
}

func certManagerDeploymentWebhookCertManagerWebhookDeploymentYaml() (*asset, error) {
	bytes, err := certManagerDeploymentWebhookCertManagerWebhookDeploymentYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/webhook/cert-manager-webhook-deployment.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentWebhookCertManagerWebhookDynamicServingRbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  labels:
    app: webhook
    app.kubernetes.io/component: webhook
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: webhook
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-webhook:dynamic-serving
  namespace: cert-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cert-manager-webhook:dynamic-serving
subjects:
  - kind: ServiceAccount
    name: cert-manager-webhook
    namespace: cert-manager
`)

func certManagerDeploymentWebhookCertManagerWebhookDynamicServingRbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentWebhookCertManagerWebhookDynamicServingRbYaml, nil
}

func certManagerDeploymentWebhookCertManagerWebhookDynamicServingRbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentWebhookCertManagerWebhookDynamicServingRbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/webhook/cert-manager-webhook-dynamic-serving-rb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentWebhookCertManagerWebhookDynamicServingRoleYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  labels:
    app: webhook
    app.kubernetes.io/component: webhook
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: webhook
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-webhook:dynamic-serving
  namespace: cert-manager
rules:
  - apiGroups:
      - ""
    resourceNames:
      - cert-manager-webhook-ca
    resources:
      - secrets
    verbs:
      - get
      - list
      - watch
      - update
  - apiGroups:
      - ""
    resources:
      - secrets
    verbs:
      - create
`)

func certManagerDeploymentWebhookCertManagerWebhookDynamicServingRoleYamlBytes() ([]byte, error) {
	return _certManagerDeploymentWebhookCertManagerWebhookDynamicServingRoleYaml, nil
}

func certManagerDeploymentWebhookCertManagerWebhookDynamicServingRoleYaml() (*asset, error) {
	bytes, err := certManagerDeploymentWebhookCertManagerWebhookDynamicServingRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/webhook/cert-manager-webhook-dynamic-serving-role.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentWebhookCertManagerWebhookMutatingwebhookconfigurationYaml = []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  annotations:
    cert-manager.io/inject-ca-from-secret: cert-manager/cert-manager-webhook-ca
  labels:
    app: webhook
    app.kubernetes.io/component: webhook
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: webhook
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-webhook
webhooks:
  - admissionReviewVersions:
      - v1
    clientConfig:
      service:
        name: cert-manager-webhook
        namespace: cert-manager
        path: /mutate
    failurePolicy: Fail
    matchPolicy: Equivalent
    name: webhook.cert-manager.io
    rules:
      - apiGroups:
          - cert-manager.io
        apiVersions:
          - v1
        operations:
          - CREATE
        resources:
          - certificaterequests
    sideEffects: None
    timeoutSeconds: 30
`)

func certManagerDeploymentWebhookCertManagerWebhookMutatingwebhookconfigurationYamlBytes() ([]byte, error) {
	return _certManagerDeploymentWebhookCertManagerWebhookMutatingwebhookconfigurationYaml, nil
}

func certManagerDeploymentWebhookCertManagerWebhookMutatingwebhookconfigurationYaml() (*asset, error) {
	bytes, err := certManagerDeploymentWebhookCertManagerWebhookMutatingwebhookconfigurationYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/webhook/cert-manager-webhook-mutatingwebhookconfiguration.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentWebhookCertManagerWebhookSaYaml = []byte(`apiVersion: v1
automountServiceAccountToken: true
kind: ServiceAccount
metadata:
  labels:
    app: webhook
    app.kubernetes.io/component: webhook
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: webhook
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-webhook
  namespace: cert-manager
`)

func certManagerDeploymentWebhookCertManagerWebhookSaYamlBytes() ([]byte, error) {
	return _certManagerDeploymentWebhookCertManagerWebhookSaYaml, nil
}

func certManagerDeploymentWebhookCertManagerWebhookSaYaml() (*asset, error) {
	bytes, err := certManagerDeploymentWebhookCertManagerWebhookSaYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/webhook/cert-manager-webhook-sa.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: webhook
    app.kubernetes.io/component: webhook
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: webhook
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-webhook:subjectaccessreviews
rules:
  - apiGroups:
      - authorization.k8s.io
    resources:
      - subjectaccessreviews
    verbs:
      - create
`)

func certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrYamlBytes() ([]byte, error) {
	return _certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrYaml, nil
}

func certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrYaml() (*asset, error) {
	bytes, err := certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/webhook/cert-manager-webhook-subjectaccessreviews-cr.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrbYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    app: webhook
    app.kubernetes.io/component: webhook
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: webhook
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-webhook:subjectaccessreviews
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-webhook:subjectaccessreviews
subjects:
  - kind: ServiceAccount
    name: cert-manager-webhook
    namespace: cert-manager
`)

func certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrbYamlBytes() ([]byte, error) {
	return _certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrbYaml, nil
}

func certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrbYaml() (*asset, error) {
	bytes, err := certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrbYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/webhook/cert-manager-webhook-subjectaccessreviews-crb.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentWebhookCertManagerWebhookSvcYaml = []byte(`apiVersion: v1
kind: Service
metadata:
  labels:
    app: webhook
    app.kubernetes.io/component: webhook
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: webhook
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-webhook
  namespace: cert-manager
spec:
  ports:
    - name: https
      port: 443
      protocol: TCP
      targetPort: https
    - name: metrics
      port: 9402
      protocol: TCP
      targetPort: http-metrics
  selector:
    app.kubernetes.io/component: webhook
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: webhook
  type: ClusterIP
`)

func certManagerDeploymentWebhookCertManagerWebhookSvcYamlBytes() ([]byte, error) {
	return _certManagerDeploymentWebhookCertManagerWebhookSvcYaml, nil
}

func certManagerDeploymentWebhookCertManagerWebhookSvcYaml() (*asset, error) {
	bytes, err := certManagerDeploymentWebhookCertManagerWebhookSvcYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/webhook/cert-manager-webhook-svc.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _certManagerDeploymentWebhookCertManagerWebhookValidatingwebhookconfigurationYaml = []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  annotations:
    cert-manager.io/inject-ca-from-secret: cert-manager/cert-manager-webhook-ca
  labels:
    app: webhook
    app.kubernetes.io/component: webhook
    app.kubernetes.io/instance: cert-manager
    app.kubernetes.io/name: webhook
    app.kubernetes.io/version: v1.17.4
  name: cert-manager-webhook
webhooks:
  - admissionReviewVersions:
      - v1
    clientConfig:
      service:
        name: cert-manager-webhook
        namespace: cert-manager
        path: /validate
    failurePolicy: Fail
    matchPolicy: Equivalent
    name: webhook.cert-manager.io
    namespaceSelector:
      matchExpressions:
        - key: cert-manager.io/disable-validation
          operator: NotIn
          values:
            - "true"
    rules:
      - apiGroups:
          - cert-manager.io
          - acme.cert-manager.io
        apiVersions:
          - v1
        operations:
          - CREATE
          - UPDATE
        resources:
          - '*/*'
    sideEffects: None
    timeoutSeconds: 30
`)

func certManagerDeploymentWebhookCertManagerWebhookValidatingwebhookconfigurationYamlBytes() ([]byte, error) {
	return _certManagerDeploymentWebhookCertManagerWebhookValidatingwebhookconfigurationYaml, nil
}

func certManagerDeploymentWebhookCertManagerWebhookValidatingwebhookconfigurationYaml() (*asset, error) {
	bytes, err := certManagerDeploymentWebhookCertManagerWebhookValidatingwebhookconfigurationYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "cert-manager-deployment/webhook/cert-manager-webhook-validatingwebhookconfiguration.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istioCsrCertManagerIstioCsrClusterroleYaml = []byte(`kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    app.kubernetes.io/name: cert-manager-istio-csr
    app.kubernetes.io/instance: cert-manager-istio-csr
    app.kubernetes.io/version: v0.14.0
    app.kubernetes.io/managed-by: cert-manager-operator
  name: cert-manager-istio-csr
rules:
  - apiGroups:
      - ""
    resources:
      - configmaps
    verbs:
      - get
      - list
      - create
      - update
      - watch
  - apiGroups:
      - ""
    resources:
      - namespaces
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - authentication.k8s.io
    resources:
      - tokenreviews
    verbs:
      - create
`)

func istioCsrCertManagerIstioCsrClusterroleYamlBytes() ([]byte, error) {
	return _istioCsrCertManagerIstioCsrClusterroleYaml, nil
}

func istioCsrCertManagerIstioCsrClusterroleYaml() (*asset, error) {
	bytes, err := istioCsrCertManagerIstioCsrClusterroleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-csr/cert-manager-istio-csr-clusterrole.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istioCsrCertManagerIstioCsrClusterrolebindingYaml = []byte(`kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    app.kubernetes.io/name: cert-manager-istio-csr
    app.kubernetes.io/instance: cert-manager-istio-csr
    app.kubernetes.io/version: v0.14.0
    app.kubernetes.io/managed-by: cert-manager-operator
  name: cert-manager-istio-csr
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-istio-csr
subjects:
  - kind: ServiceAccount
    name: cert-manager-istio-csr
    namespace: cert-manager
`)

func istioCsrCertManagerIstioCsrClusterrolebindingYamlBytes() ([]byte, error) {
	return _istioCsrCertManagerIstioCsrClusterrolebindingYaml, nil
}

func istioCsrCertManagerIstioCsrClusterrolebindingYaml() (*asset, error) {
	bytes, err := istioCsrCertManagerIstioCsrClusterrolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-csr/cert-manager-istio-csr-clusterrolebinding.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istioCsrCertManagerIstioCsrDeploymentYaml = []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-manager-istio-csr
  namespace: cert-manager
  labels:
    app.kubernetes.io/name: cert-manager-istio-csr
    app.kubernetes.io/instance: cert-manager-istio-csr
    app.kubernetes.io/version: v0.14.0
    app.kubernetes.io/managed-by: cert-manager-operator
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cert-manager-istio-csr
  template:
    metadata:
      labels:
        app: cert-manager-istio-csr
        app.kubernetes.io/name: cert-manager-istio-csr
        app.kubernetes.io/instance: cert-manager-istio-csr
        app.kubernetes.io/version: v0.14.0
    spec:
      serviceAccountName: cert-manager-istio-csr
      nodeSelector:
        kubernetes.io/os: linux
      containers:
        - name: cert-manager-istio-csr
          image: quay.io/jetstack/cert-manager-istio-csr:v0.14.0
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 6443
            - containerPort: 9402
          readinessProbe:
            httpGet:
              port: 6060
              path: /readyz
            initialDelaySeconds: 3
            periodSeconds: 7
          args:
            - --log-level=1
            - --log-format=text
            - --metrics-port=9402
            - --readiness-probe-port=6060
            - --readiness-probe-path=/readyz
            - --certificate-namespace=istio-system
            - --issuer-enabled=true
            - --issuer-name=istio-ca
            - --issuer-kind=Issuer
            - --issuer-group=cert-manager.io
            - --preserve-certificate-requests=false
            - --root-ca-file=
            - --serving-certificate-dns-names=cert-manager-istio-csr.cert-manager.svc
            - --serving-certificate-duration=1h
            - --trust-domain=cluster.local
            - --cluster-id=Kubernetes
            - --max-client-certificate-duration=1h
            - --serving-address=0.0.0.0:6443
            - --serving-certificate-key-size=2048
            - --serving-signature-algorithm=RSA
            - --enable-client-cert-authenticator=false
            - --leader-election-namespace=istio-system
            - --disable-kubernetes-client-rate-limiter=false
            - --runtime-issuance-config-map-name=
            - --runtime-issuance-config-map-namespace=cert-manager
            - --istiod-cert-enabled=false
            - --istiod-cert-name=istiod-dynamic
            - --istiod-cert-namespace=istio-system
            - --istiod-cert-duration=1h
            - --istiod-cert-renew-before=30m
            - --istiod-cert-key-algorithm=RSA
            - --istiod-cert-key-size=2048
            - --istiod-cert-additional-dns-names=
            - --istiod-cert-istio-revisions=default
          resources: {}
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            readOnlyRootFilesystem: true
            runAsNonRoot: true
`)

func istioCsrCertManagerIstioCsrDeploymentYamlBytes() ([]byte, error) {
	return _istioCsrCertManagerIstioCsrDeploymentYaml, nil
}

func istioCsrCertManagerIstioCsrDeploymentYaml() (*asset, error) {
	bytes, err := istioCsrCertManagerIstioCsrDeploymentYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-csr/cert-manager-istio-csr-deployment.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istioCsrCertManagerIstioCsrLeasesRoleYaml = []byte(`kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    app.kubernetes.io/name: cert-manager-istio-csr
    app.kubernetes.io/instance: cert-manager-istio-csr
    app.kubernetes.io/version: v0.14.0
    app.kubernetes.io/managed-by: cert-manager-operator
  name: cert-manager-istio-csr-leases
  namespace: istio-system
rules:
  - apiGroups:
      - coordination.k8s.io
    resources:
      - leases
    verbs:
      - get
      - create
      - update
      - watch
      - list
  - apiGroups:
      - ""
    resources:
      - events
    verbs:
      - create
`)

func istioCsrCertManagerIstioCsrLeasesRoleYamlBytes() ([]byte, error) {
	return _istioCsrCertManagerIstioCsrLeasesRoleYaml, nil
}

func istioCsrCertManagerIstioCsrLeasesRoleYaml() (*asset, error) {
	bytes, err := istioCsrCertManagerIstioCsrLeasesRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-csr/cert-manager-istio-csr-leases-role.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istioCsrCertManagerIstioCsrLeasesRolebindingYaml = []byte(`kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: cert-manager-istio-csr-leases
  namespace: istio-system
  labels:
    app.kubernetes.io/name: cert-manager-istio-csr
    app.kubernetes.io/instance: cert-manager-istio-csr
    app.kubernetes.io/version: v0.14.0
    app.kubernetes.io/managed-by: cert-manager-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cert-manager-istio-csr-leases
subjects:
  - kind: ServiceAccount
    name: cert-manager-istio-csr
    namespace: cert-manager
`)

func istioCsrCertManagerIstioCsrLeasesRolebindingYamlBytes() ([]byte, error) {
	return _istioCsrCertManagerIstioCsrLeasesRolebindingYaml, nil
}

func istioCsrCertManagerIstioCsrLeasesRolebindingYaml() (*asset, error) {
	bytes, err := istioCsrCertManagerIstioCsrLeasesRolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-csr/cert-manager-istio-csr-leases-rolebinding.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istioCsrCertManagerIstioCsrRoleYaml = []byte(`kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    app.kubernetes.io/name: cert-manager-istio-csr
    app.kubernetes.io/instance: cert-manager-istio-csr
    app.kubernetes.io/version: v0.14.0
    app.kubernetes.io/managed-by: cert-manager-operator
  name: cert-manager-istio-csr
  namespace: istio-system
rules:
  - apiGroups:
      - cert-manager.io
    resources:
      - certificaterequests
    verbs:
      - get
      - list
      - create
      - update
      - delete
      - watch
  - apiGroups:
      - ""
    resources:
      - events
    verbs:
      - create
`)

func istioCsrCertManagerIstioCsrRoleYamlBytes() ([]byte, error) {
	return _istioCsrCertManagerIstioCsrRoleYaml, nil
}

func istioCsrCertManagerIstioCsrRoleYaml() (*asset, error) {
	bytes, err := istioCsrCertManagerIstioCsrRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-csr/cert-manager-istio-csr-role.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istioCsrCertManagerIstioCsrRolebindingYaml = []byte(`kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: cert-manager-istio-csr
  namespace: istio-system
  labels:
    app.kubernetes.io/name: cert-manager-istio-csr
    app.kubernetes.io/instance: cert-manager-istio-csr
    app.kubernetes.io/version: v0.14.0
    app.kubernetes.io/managed-by: cert-manager-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cert-manager-istio-csr
subjects:
  - kind: ServiceAccount
    name: cert-manager-istio-csr
    namespace: cert-manager
`)

func istioCsrCertManagerIstioCsrRolebindingYamlBytes() ([]byte, error) {
	return _istioCsrCertManagerIstioCsrRolebindingYaml, nil
}

func istioCsrCertManagerIstioCsrRolebindingYaml() (*asset, error) {
	bytes, err := istioCsrCertManagerIstioCsrRolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-csr/cert-manager-istio-csr-rolebinding.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istioCsrCertManagerIstioCsrServiceYaml = []byte(`apiVersion: v1
kind: Service
metadata:
  name: cert-manager-istio-csr
  namespace: cert-manager
  labels:
    app: cert-manager-istio-csr
    app.kubernetes.io/name: cert-manager-istio-csr
    app.kubernetes.io/instance: cert-manager-istio-csr
    app.kubernetes.io/version: v0.14.0
    app.kubernetes.io/managed-by: cert-manager-operator
spec:
  type: ClusterIP
  ports:
    - port: 443
      targetPort: 6443
      protocol: TCP
      name: web
  selector:
    app: cert-manager-istio-csr
`)

func istioCsrCertManagerIstioCsrServiceYamlBytes() ([]byte, error) {
	return _istioCsrCertManagerIstioCsrServiceYaml, nil
}

func istioCsrCertManagerIstioCsrServiceYaml() (*asset, error) {
	bytes, err := istioCsrCertManagerIstioCsrServiceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-csr/cert-manager-istio-csr-service.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istioCsrCertManagerIstioCsrServiceaccountYaml = []byte(`apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    app.kubernetes.io/name: cert-manager-istio-csr
    app.kubernetes.io/instance: cert-manager-istio-csr
    app.kubernetes.io/version: v0.14.0
    app.kubernetes.io/managed-by: cert-manager-operator
  name: cert-manager-istio-csr
  namespace: cert-manager
`)

func istioCsrCertManagerIstioCsrServiceaccountYamlBytes() ([]byte, error) {
	return _istioCsrCertManagerIstioCsrServiceaccountYaml, nil
}

func istioCsrCertManagerIstioCsrServiceaccountYaml() (*asset, error) {
	bytes, err := istioCsrCertManagerIstioCsrServiceaccountYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-csr/cert-manager-istio-csr-serviceaccount.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istioCsrIstiodCertificateYaml = []byte(`apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: istiod
  namespace: istio-system
  labels:
    app.kubernetes.io/name: cert-manager-istio-csr
    app.kubernetes.io/instance: cert-manager-istio-csr
    app.kubernetes.io/version: v0.14.0
    app.kubernetes.io/managed-by: cert-manager-operator
spec:
  commonName: istiod.istio-system.svc
  dnsNames:
    - istiod.istio-system.svc
  uris:
    - spiffe://cluster.local/ns/istio-system/sa/istiod-service-account
  secretName: istiod-tls
  duration: 1h
  renewBefore: 30m
  privateKey:
    rotationPolicy: Always
    algorithm: RSA
    size: 2048
  revisionHistoryLimit: 1
  issuerRef:
    name: istio-ca
    kind: Issuer
    group: cert-manager.io
`)

func istioCsrIstiodCertificateYamlBytes() ([]byte, error) {
	return _istioCsrIstiodCertificateYaml, nil
}

func istioCsrIstiodCertificateYaml() (*asset, error) {
	bytes, err := istioCsrIstiodCertificateYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-csr/istiod-certificate.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"cert-manager-deployment/cainjector/cert-manager-cainjector-cr.yaml":                               certManagerDeploymentCainjectorCertManagerCainjectorCrYaml,
	"cert-manager-deployment/cainjector/cert-manager-cainjector-crb.yaml":                              certManagerDeploymentCainjectorCertManagerCainjectorCrbYaml,
	"cert-manager-deployment/cainjector/cert-manager-cainjector-deployment.yaml":                       certManagerDeploymentCainjectorCertManagerCainjectorDeploymentYaml,
	"cert-manager-deployment/cainjector/cert-manager-cainjector-leaderelection-rb.yaml":                certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRbYaml,
	"cert-manager-deployment/cainjector/cert-manager-cainjector-leaderelection-role.yaml":              certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRoleYaml,
	"cert-manager-deployment/cainjector/cert-manager-cainjector-sa.yaml":                               certManagerDeploymentCainjectorCertManagerCainjectorSaYaml,
	"cert-manager-deployment/cainjector/cert-manager-cainjector-svc.yaml":                              certManagerDeploymentCainjectorCertManagerCainjectorSvcYaml,
	"cert-manager-deployment/cert-manager/cert-manager-controller-approve-cert-manager-io-cr.yaml":     certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrYaml,
	"cert-manager-deployment/cert-manager/cert-manager-controller-approve-cert-manager-io-crb.yaml":    certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrbYaml,
	"cert-manager-deployment/cert-manager/cert-manager-controller-certificatesigningrequests-cr.yaml":  certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrYaml,
	"cert-manager-deployment/cert-manager/cert-manager-controller-certificatesigningrequests-crb.yaml": certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrbYaml,
	"cert-manager-deployment/cert-manager-namespace.yaml":                                              certManagerDeploymentCertManagerNamespaceYaml,
	"cert-manager-deployment/controller/cert-manager-cert-manager-tokenrequest-rb.yaml":                certManagerDeploymentControllerCertManagerCertManagerTokenrequestRbYaml,
	"cert-manager-deployment/controller/cert-manager-cluster-view-cr.yaml":                             certManagerDeploymentControllerCertManagerClusterViewCrYaml,
	"cert-manager-deployment/controller/cert-manager-controller-certificates-cr.yaml":                  certManagerDeploymentControllerCertManagerControllerCertificatesCrYaml,
	"cert-manager-deployment/controller/cert-manager-controller-certificates-crb.yaml":                 certManagerDeploymentControllerCertManagerControllerCertificatesCrbYaml,
	"cert-manager-deployment/controller/cert-manager-controller-challenges-cr.yaml":                    certManagerDeploymentControllerCertManagerControllerChallengesCrYaml,
	"cert-manager-deployment/controller/cert-manager-controller-challenges-crb.yaml":                   certManagerDeploymentControllerCertManagerControllerChallengesCrbYaml,
	"cert-manager-deployment/controller/cert-manager-controller-clusterissuers-cr.yaml":                certManagerDeploymentControllerCertManagerControllerClusterissuersCrYaml,
	"cert-manager-deployment/controller/cert-manager-controller-clusterissuers-crb.yaml":               certManagerDeploymentControllerCertManagerControllerClusterissuersCrbYaml,
	"cert-manager-deployment/controller/cert-manager-controller-ingress-shim-cr.yaml":                  certManagerDeploymentControllerCertManagerControllerIngressShimCrYaml,
	"cert-manager-deployment/controller/cert-manager-controller-ingress-shim-crb.yaml":                 certManagerDeploymentControllerCertManagerControllerIngressShimCrbYaml,
	"cert-manager-deployment/controller/cert-manager-controller-issuers-cr.yaml":                       certManagerDeploymentControllerCertManagerControllerIssuersCrYaml,
	"cert-manager-deployment/controller/cert-manager-controller-issuers-crb.yaml":                      certManagerDeploymentControllerCertManagerControllerIssuersCrbYaml,
	"cert-manager-deployment/controller/cert-manager-controller-orders-cr.yaml":                        certManagerDeploymentControllerCertManagerControllerOrdersCrYaml,
	"cert-manager-deployment/controller/cert-manager-controller-orders-crb.yaml":                       certManagerDeploymentControllerCertManagerControllerOrdersCrbYaml,
	"cert-manager-deployment/controller/cert-manager-deployment.yaml":                                  certManagerDeploymentControllerCertManagerDeploymentYaml,
	"cert-manager-deployment/controller/cert-manager-edit-cr.yaml":                                     certManagerDeploymentControllerCertManagerEditCrYaml,
	"cert-manager-deployment/controller/cert-manager-leaderelection-rb.yaml":                           certManagerDeploymentControllerCertManagerLeaderelectionRbYaml,
	"cert-manager-deployment/controller/cert-manager-leaderelection-role.yaml":                         certManagerDeploymentControllerCertManagerLeaderelectionRoleYaml,
	"cert-manager-deployment/controller/cert-manager-sa.yaml":                                          certManagerDeploymentControllerCertManagerSaYaml,
	"cert-manager-deployment/controller/cert-manager-svc.yaml":                                         certManagerDeploymentControllerCertManagerSvcYaml,
	"cert-manager-deployment/controller/cert-manager-tokenrequest-role.yaml":                           certManagerDeploymentControllerCertManagerTokenrequestRoleYaml,
	"cert-manager-deployment/controller/cert-manager-view-cr.yaml":                                     certManagerDeploymentControllerCertManagerViewCrYaml,
	"cert-manager-deployment/webhook/cert-manager-webhook-deployment.yaml":                             certManagerDeploymentWebhookCertManagerWebhookDeploymentYaml,
	"cert-manager-deployment/webhook/cert-manager-webhook-dynamic-serving-rb.yaml":                     certManagerDeploymentWebhookCertManagerWebhookDynamicServingRbYaml,
	"cert-manager-deployment/webhook/cert-manager-webhook-dynamic-serving-role.yaml":                   certManagerDeploymentWebhookCertManagerWebhookDynamicServingRoleYaml,
	"cert-manager-deployment/webhook/cert-manager-webhook-mutatingwebhookconfiguration.yaml":           certManagerDeploymentWebhookCertManagerWebhookMutatingwebhookconfigurationYaml,
	"cert-manager-deployment/webhook/cert-manager-webhook-sa.yaml":                                     certManagerDeploymentWebhookCertManagerWebhookSaYaml,
	"cert-manager-deployment/webhook/cert-manager-webhook-subjectaccessreviews-cr.yaml":                certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrYaml,
	"cert-manager-deployment/webhook/cert-manager-webhook-subjectaccessreviews-crb.yaml":               certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrbYaml,
	"cert-manager-deployment/webhook/cert-manager-webhook-svc.yaml":                                    certManagerDeploymentWebhookCertManagerWebhookSvcYaml,
	"cert-manager-deployment/webhook/cert-manager-webhook-validatingwebhookconfiguration.yaml":         certManagerDeploymentWebhookCertManagerWebhookValidatingwebhookconfigurationYaml,
	"istio-csr/cert-manager-istio-csr-clusterrole.yaml":                                                istioCsrCertManagerIstioCsrClusterroleYaml,
	"istio-csr/cert-manager-istio-csr-clusterrolebinding.yaml":                                         istioCsrCertManagerIstioCsrClusterrolebindingYaml,
	"istio-csr/cert-manager-istio-csr-deployment.yaml":                                                 istioCsrCertManagerIstioCsrDeploymentYaml,
	"istio-csr/cert-manager-istio-csr-leases-role.yaml":                                                istioCsrCertManagerIstioCsrLeasesRoleYaml,
	"istio-csr/cert-manager-istio-csr-leases-rolebinding.yaml":                                         istioCsrCertManagerIstioCsrLeasesRolebindingYaml,
	"istio-csr/cert-manager-istio-csr-role.yaml":                                                       istioCsrCertManagerIstioCsrRoleYaml,
	"istio-csr/cert-manager-istio-csr-rolebinding.yaml":                                                istioCsrCertManagerIstioCsrRolebindingYaml,
	"istio-csr/cert-manager-istio-csr-service.yaml":                                                    istioCsrCertManagerIstioCsrServiceYaml,
	"istio-csr/cert-manager-istio-csr-serviceaccount.yaml":                                             istioCsrCertManagerIstioCsrServiceaccountYaml,
	"istio-csr/istiod-certificate.yaml":                                                                istioCsrIstiodCertificateYaml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//
//	data/
//	  foo.txt
//	  img/
//	    a.png
//	    b.png
//
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"cert-manager-deployment": {nil, map[string]*bintree{
		"cainjector": {nil, map[string]*bintree{
			"cert-manager-cainjector-cr.yaml":                  {certManagerDeploymentCainjectorCertManagerCainjectorCrYaml, map[string]*bintree{}},
			"cert-manager-cainjector-crb.yaml":                 {certManagerDeploymentCainjectorCertManagerCainjectorCrbYaml, map[string]*bintree{}},
			"cert-manager-cainjector-deployment.yaml":          {certManagerDeploymentCainjectorCertManagerCainjectorDeploymentYaml, map[string]*bintree{}},
			"cert-manager-cainjector-leaderelection-rb.yaml":   {certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRbYaml, map[string]*bintree{}},
			"cert-manager-cainjector-leaderelection-role.yaml": {certManagerDeploymentCainjectorCertManagerCainjectorLeaderelectionRoleYaml, map[string]*bintree{}},
			"cert-manager-cainjector-sa.yaml":                  {certManagerDeploymentCainjectorCertManagerCainjectorSaYaml, map[string]*bintree{}},
			"cert-manager-cainjector-svc.yaml":                 {certManagerDeploymentCainjectorCertManagerCainjectorSvcYaml, map[string]*bintree{}},
		}},
		"cert-manager": {nil, map[string]*bintree{
			"cert-manager-controller-approve-cert-manager-io-cr.yaml":     {certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrYaml, map[string]*bintree{}},
			"cert-manager-controller-approve-cert-manager-io-crb.yaml":    {certManagerDeploymentCertManagerCertManagerControllerApproveCertManagerIoCrbYaml, map[string]*bintree{}},
			"cert-manager-controller-certificatesigningrequests-cr.yaml":  {certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrYaml, map[string]*bintree{}},
			"cert-manager-controller-certificatesigningrequests-crb.yaml": {certManagerDeploymentCertManagerCertManagerControllerCertificatesigningrequestsCrbYaml, map[string]*bintree{}},
		}},
		"cert-manager-namespace.yaml": {certManagerDeploymentCertManagerNamespaceYaml, map[string]*bintree{}},
		"controller": {nil, map[string]*bintree{
			"cert-manager-cert-manager-tokenrequest-rb.yaml":  {certManagerDeploymentControllerCertManagerCertManagerTokenrequestRbYaml, map[string]*bintree{}},
			"cert-manager-cluster-view-cr.yaml":               {certManagerDeploymentControllerCertManagerClusterViewCrYaml, map[string]*bintree{}},
			"cert-manager-controller-certificates-cr.yaml":    {certManagerDeploymentControllerCertManagerControllerCertificatesCrYaml, map[string]*bintree{}},
			"cert-manager-controller-certificates-crb.yaml":   {certManagerDeploymentControllerCertManagerControllerCertificatesCrbYaml, map[string]*bintree{}},
			"cert-manager-controller-challenges-cr.yaml":      {certManagerDeploymentControllerCertManagerControllerChallengesCrYaml, map[string]*bintree{}},
			"cert-manager-controller-challenges-crb.yaml":     {certManagerDeploymentControllerCertManagerControllerChallengesCrbYaml, map[string]*bintree{}},
			"cert-manager-controller-clusterissuers-cr.yaml":  {certManagerDeploymentControllerCertManagerControllerClusterissuersCrYaml, map[string]*bintree{}},
			"cert-manager-controller-clusterissuers-crb.yaml": {certManagerDeploymentControllerCertManagerControllerClusterissuersCrbYaml, map[string]*bintree{}},
			"cert-manager-controller-ingress-shim-cr.yaml":    {certManagerDeploymentControllerCertManagerControllerIngressShimCrYaml, map[string]*bintree{}},
			"cert-manager-controller-ingress-shim-crb.yaml":   {certManagerDeploymentControllerCertManagerControllerIngressShimCrbYaml, map[string]*bintree{}},
			"cert-manager-controller-issuers-cr.yaml":         {certManagerDeploymentControllerCertManagerControllerIssuersCrYaml, map[string]*bintree{}},
			"cert-manager-controller-issuers-crb.yaml":        {certManagerDeploymentControllerCertManagerControllerIssuersCrbYaml, map[string]*bintree{}},
			"cert-manager-controller-orders-cr.yaml":          {certManagerDeploymentControllerCertManagerControllerOrdersCrYaml, map[string]*bintree{}},
			"cert-manager-controller-orders-crb.yaml":         {certManagerDeploymentControllerCertManagerControllerOrdersCrbYaml, map[string]*bintree{}},
			"cert-manager-deployment.yaml":                    {certManagerDeploymentControllerCertManagerDeploymentYaml, map[string]*bintree{}},
			"cert-manager-edit-cr.yaml":                       {certManagerDeploymentControllerCertManagerEditCrYaml, map[string]*bintree{}},
			"cert-manager-leaderelection-rb.yaml":             {certManagerDeploymentControllerCertManagerLeaderelectionRbYaml, map[string]*bintree{}},
			"cert-manager-leaderelection-role.yaml":           {certManagerDeploymentControllerCertManagerLeaderelectionRoleYaml, map[string]*bintree{}},
			"cert-manager-sa.yaml":                            {certManagerDeploymentControllerCertManagerSaYaml, map[string]*bintree{}},
			"cert-manager-svc.yaml":                           {certManagerDeploymentControllerCertManagerSvcYaml, map[string]*bintree{}},
			"cert-manager-tokenrequest-role.yaml":             {certManagerDeploymentControllerCertManagerTokenrequestRoleYaml, map[string]*bintree{}},
			"cert-manager-view-cr.yaml":                       {certManagerDeploymentControllerCertManagerViewCrYaml, map[string]*bintree{}},
		}},
		"webhook": {nil, map[string]*bintree{
			"cert-manager-webhook-deployment.yaml":                     {certManagerDeploymentWebhookCertManagerWebhookDeploymentYaml, map[string]*bintree{}},
			"cert-manager-webhook-dynamic-serving-rb.yaml":             {certManagerDeploymentWebhookCertManagerWebhookDynamicServingRbYaml, map[string]*bintree{}},
			"cert-manager-webhook-dynamic-serving-role.yaml":           {certManagerDeploymentWebhookCertManagerWebhookDynamicServingRoleYaml, map[string]*bintree{}},
			"cert-manager-webhook-mutatingwebhookconfiguration.yaml":   {certManagerDeploymentWebhookCertManagerWebhookMutatingwebhookconfigurationYaml, map[string]*bintree{}},
			"cert-manager-webhook-sa.yaml":                             {certManagerDeploymentWebhookCertManagerWebhookSaYaml, map[string]*bintree{}},
			"cert-manager-webhook-subjectaccessreviews-cr.yaml":        {certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrYaml, map[string]*bintree{}},
			"cert-manager-webhook-subjectaccessreviews-crb.yaml":       {certManagerDeploymentWebhookCertManagerWebhookSubjectaccessreviewsCrbYaml, map[string]*bintree{}},
			"cert-manager-webhook-svc.yaml":                            {certManagerDeploymentWebhookCertManagerWebhookSvcYaml, map[string]*bintree{}},
			"cert-manager-webhook-validatingwebhookconfiguration.yaml": {certManagerDeploymentWebhookCertManagerWebhookValidatingwebhookconfigurationYaml, map[string]*bintree{}},
		}},
	}},
	"istio-csr": {nil, map[string]*bintree{
		"cert-manager-istio-csr-clusterrole.yaml":        {istioCsrCertManagerIstioCsrClusterroleYaml, map[string]*bintree{}},
		"cert-manager-istio-csr-clusterrolebinding.yaml": {istioCsrCertManagerIstioCsrClusterrolebindingYaml, map[string]*bintree{}},
		"cert-manager-istio-csr-deployment.yaml":         {istioCsrCertManagerIstioCsrDeploymentYaml, map[string]*bintree{}},
		"cert-manager-istio-csr-leases-role.yaml":        {istioCsrCertManagerIstioCsrLeasesRoleYaml, map[string]*bintree{}},
		"cert-manager-istio-csr-leases-rolebinding.yaml": {istioCsrCertManagerIstioCsrLeasesRolebindingYaml, map[string]*bintree{}},
		"cert-manager-istio-csr-role.yaml":               {istioCsrCertManagerIstioCsrRoleYaml, map[string]*bintree{}},
		"cert-manager-istio-csr-rolebinding.yaml":        {istioCsrCertManagerIstioCsrRolebindingYaml, map[string]*bintree{}},
		"cert-manager-istio-csr-service.yaml":            {istioCsrCertManagerIstioCsrServiceYaml, map[string]*bintree{}},
		"cert-manager-istio-csr-serviceaccount.yaml":     {istioCsrCertManagerIstioCsrServiceaccountYaml, map[string]*bintree{}},
		"istiod-certificate.yaml":                        {istioCsrIstiodCertificateYaml, map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
