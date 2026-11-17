#!/usr/bin/bash
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly overlay="${repository_root}/deploy/kustomize/overlays/i09-local-readiness"
readonly image='otel/opentelemetry-collector-contrib:0.159.0@sha256:1f2c54a30e713fac6b3ae77a1ec84010c2007e29ced8ec666214fc2f6739c1cc'
: "${OPENPC_I09_TMP_ROOT:?OPENPC_I09_TMP_ROOT is required}"
: "${DOCKER_CONFIG:?DOCKER_CONFIG is required}"
case "${OPENPC_I09_TMP_ROOT}" in
  "${repository_root}" | "${repository_root}"/*) echo 'temporary root must be outside repository' >&2; exit 64 ;;
esac
readonly run_root="$(mktemp -d "${OPENPC_I09_TMP_ROOT}/i09-kubernetes.XXXXXX")"
readonly rendered="${run_root}/rendered.yaml"
started_cluster=false
namespace_created=false
cleanup() {
  if [[ "${namespace_created}" == true ]]; then kubectl delete namespace openpc-i09-local-readiness --wait=true --timeout=60s >/dev/null 2>&1 || true; fi
  if [[ "${started_cluster}" == true ]]; then minikube stop >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

test "$(kubectl version --client -o json | jq -r '.clientVersion.gitVersion')" = 'v1.36.2'
kubectl kustomize "${overlay}" --load-restrictor LoadRestrictionsNone >"${rendered}"
python3 "${repository_root}/tests/recovery/i09_kubernetes_oci_test.py"
if [[ "$(minikube status -o json 2>/dev/null | jq -r '.Host' || true)" != Running ]]; then
  minikube start --driver=docker --kubernetes-version=v1.36.2 >/dev/null
  started_cluster=true
fi
test "$(kubectl version -o json | jq -r '.serverVersion.gitVersion')" = 'v1.36.2'
minikube image load "${image}" >/dev/null
kubectl apply -f "${overlay}/namespace.yaml" >/dev/null
namespace_created=true
kubectl apply --dry-run=server -f "${rendered}" >/dev/null
kubectl apply -f "${rendered}" >/dev/null
kubectl rollout status deployment/openpc-i09-otel -n openpc-i09-local-readiness --timeout=120s >/dev/null
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=openpc-i09-otel -n openpc-i09-local-readiness --timeout=60s >/dev/null
pod_json="$(kubectl get pod -l app.kubernetes.io/name=openpc-i09-otel -n openpc-i09-local-readiness -o json)"
test "$(jq -r '.items|length' <<<"${pod_json}")" = 1
test "$(jq -r '.items[0].spec.containers[0].image' <<<"${pod_json}")" = "${image}"
kubectl delete namespace openpc-i09-local-readiness --wait=true --timeout=60s >/dev/null
namespace_created=false
if [[ "${started_cluster}" == true ]]; then minikube stop >/dev/null; started_cluster=false; fi

jq -n \
  --arg renderedSha256 "$(sha256sum "${rendered}" | cut -d' ' -f1)" \
  --arg image "${image}" \
  '{schemaVersion:"1.0",status:"PASS",kubernetes:{client:"v1.36.2",server:"v1.36.2",serverDryRun:true,rolloutReady:true},oci:{image:$image,platform:"linux/amd64",digestVerified:true,runtimeClosure:"COLLECTOR_ONLY"},security:{nonRoot:true,readOnlyRoot:true,capabilitiesDropped:true,seccomp:true,leastPrivilegeServiceAccount:true,defaultDeny:true,noSecretBytes:true,boundedResources:true,independentProbes:true},renderedSha256:$renderedSha256,cleanup:"PASS_NAMESPACE_REMOVED_AND_ORIGINAL_CLUSTER_STATE_RESTORED",claimCeiling:"LOCAL_KUBERNETES_AND_OCI_TECHNICAL_PROOF_ONLY; ARM64_PROVIDER_SIGNED_PRODUCTION_EXTERNAL_NOT_PROVEN_OPEN"}' \
  | tee "${run_root}/i09-kubernetes-oci-result.json" "${OPENPC_I09_TMP_ROOT}/i09-kubernetes-oci-result.json"
