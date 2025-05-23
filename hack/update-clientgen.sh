#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${BASH_SOURCE})/..
CODEGEN_PKG=${CODEGEN_PKG:-$(cd ${SCRIPT_ROOT}; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../../../k8s.io/code-generator)}

source "${CODEGEN_PKG}/kube_codegen.sh"

API_GROUP_VERSIONS="
operator
"
for group in ${API_GROUP_VERSIONS};  do
  echo "# Processing ${group} ..."
  kube::codegen::gen_client \
      --with-watch \
      --with-applyconfig \
      --applyconfig-name "applyconfigurations" \
      --applyconfig-externals "github.com/openshift/api/operator/v1.OperatorSpec:github.com/openshift/client-go/operator/applyconfigurations/operator/v1,github.com/openshift/api/operator/v1.OperatorStatus:github.com/openshift/client-go/operator/applyconfigurations/operator/v1,github.com/openshift/api/operator/v1.OperatorCondition:github.com/openshift/client-go/operator/applyconfigurations/operator/v1,github.com/openshift/api/operator/v1.GenerationStatus:github.com/openshift/client-go/operator/applyconfigurations/operator/v1" \
      --applyconfig-openapi-schema "vendor/github.com/openshift/api/openapi/openapi.json" \
      --one-input-api "${group}" \
      --output-pkg github.com/openshift/cert-manager-operator/pkg/"${group%\/*}" \
      --output-dir "${SCRIPT_ROOT}/pkg/${group}" \
      --plural-exceptions "DNS:DNSes,DNSList:DNSList,SecurityContextConstraints:SecurityContextConstraints" \
      --boilerplate "${SCRIPT_ROOT}/hack/empty.txt" \
      "${SCRIPT_ROOT}/api"
done


