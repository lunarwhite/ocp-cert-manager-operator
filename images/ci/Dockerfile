FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.20 AS builder
WORKDIR /go/src/github.com/openshift/cert-manager-operator

# build operator
COPY . .
RUN make build --warn-undefined-variables

FROM registry.access.redhat.com/ubi9-minimal:9.4
COPY --from=builder /go/src/github.com/openshift/cert-manager-operator/cert-manager-operator /usr/bin/

USER 65532:65532

ENTRYPOINT ["/usr/bin/cert-manager-operator"]
