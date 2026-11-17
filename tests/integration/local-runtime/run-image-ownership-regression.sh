#!/usr/bin/env bash
set -euo pipefail
export COMPOSE_PARALLEL_LIMIT=1
repository_root="$(git rev-parse --show-toplevel)"
source "$repository_root/scripts/maintenance/local-runtime-images.sh"
openpc_require_execution image-build
# Exercise the same closed seven-service image policy in an isolated test tag namespace.
openpc_image_tag() { printf 'openpc-r1-runner-test/%s:local' "$1"; }
regression_root="$(mktemp -d "${OPENPC_LOCAL_RUNTIME_TMP_ROOT:?}/image-ownership.XXXXXX")"
project="openpc-local-e2e-image-$(openssl rand -hex 6)"
evidence_root="$regression_root/evidence"
mkdir -p "$evidence_root" "$regression_root/data" "$regression_root/secrets"
export OPENPC_LOCAL_DATA_ROOT="$regression_root/data" OPENPC_LOCAL_SECRET_ROOT="$regression_root/secrets"
compose=(docker compose -p "$project" -f "$regression_root/compose.json")
protected=""
cleanup() {
  local status=$?
  trap - EXIT
  if [ -n "$protected" ] && docker inspect "$protected" >/dev/null 2>&1; then
    [ "$(docker inspect -f '{{index .Config.Labels "io.openpc.test.owner"}}' "$protected")" = "$regression_root" ] && docker rm "$protected" >/dev/null || status=99
  fi
  if [ -f "$regression_root/compose.json" ]; then "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || status=99; fi
  openpc_stop_owned_builder || status=99
  if [ "$status" -eq 0 ]; then
    # These fixture images are temporary outputs, distinct from the retained dev tags.
    for service in "${openpc_build_services[@]}"; do
      id="$(docker image inspect -f '{{.Id}}' "$(openpc_image_tag "$service")")"
      [ "$(docker image inspect -f '{{index .Config.Labels "io.openpc.image.owner"}}' "$id")" = "$openpc_image_owner" ] || { status=99; continue; }
      [ -z "$(docker ps -aq --filter "ancestor=$id")" ] || { status=99; continue; }
      docker image rm "$id" >/dev/null || status=99
    done
  fi
  if [ "$status" -eq 0 ]; then rm -rf -- "$regression_root"; else printf 'OPENPC_IMAGE_REGRESSION_RETAINED|%s\n' "$regression_root" >&2; fi
  exit "$status"
}
trap cleanup EXIT
# No build or cache mutation may occur after unsafe disk admission.
if OPENPC_LOCAL_RUNTIME_PEAK_DISK_GIB=999999 openpc_storage_preflight; then
  echo 'Unsafe estimated peak was admitted' >&2;exit 1
fi
openpc_storage_preflight
cat > "$regression_root/Dockerfile" <<'DOCKERFILE'
FROM docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7
COPY source-marker /source-marker
ENTRYPOINT ["sh", "-c", "cp /source-marker /state/readback; sleep 3600"]
DOCKERFILE
# Derive labels/service identities from the actual Compose contract; only fixture build/runtime inputs differ.
docker compose -f "$repository_root/deploy/compose/local/compose.yaml" config --format json | \
 node --input-type=module -e '
import fs from "node:fs";
let input="";for await(const chunk of process.stdin) input+=chunk;
const original=JSON.parse(input),root=process.argv[1],services={},volumes={};
for(const [name,service] of Object.entries(original.services)) {
 if(!service.build) continue;
 if(service.image!==`openpc-r1-dev/${name}:local`) throw new Error("unstable product image contract");
 services[name]={image:`openpc-r1-runner-test/${name}:local`,build:{context:root,dockerfile:"Dockerfile",labels:service.build.labels},
  labels:{"io.openpc.test.owner":root},cpus:0.25,mem_limit:"64m",volumes:[`${name}:/state`],
  healthcheck:{test:["CMD","sh","-c","test -s /state/readback"],interval:"1s",timeout:"1s",retries:15}};
 volumes[name]={labels:{"io.openpc.test.owner":root}};
}
if(Object.keys(services).length!==7) throw new Error("wrong image service count");
fs.writeFileSync(`${root}/compose.json`,JSON.stringify({services,volumes,networks:{default:{labels:{"io.openpc.test.owner":root}}}}));
' "$regression_root"
original_builder="$(docker buildx ls | awk '/\*/ {print $1}')"
first_image=''
for iteration in first second; do
  printf '%s\n' "$iteration" > "$regression_root/source-marker"
  project="openpc-local-e2e-image-$(openssl rand -hex 6)"
  compose=(docker compose -p "$project" -f "$regression_root/compose.json")
  openpc_prior_images=();openpc_built_images=()
  openpc_prepare_builder
  openpc_record_prior_images
  for service in "${openpc_build_services[@]}"; do
    "${compose[@]}" build --builder "$openpc_builder" "$service"
  done
  openpc_capture_built_images
  openpc_assert_no_project_images
  openpc_stop_owned_builder
  "${compose[@]}" up -d --wait --force-recreate --no-build --pull never
  openpc_verify_running_images
  for service in "${openpc_build_services[@]}"; do
    test "$("${compose[@]}" exec -T "$service" cat /state/readback)" = "$iteration"
  done
  if [ "$iteration" = first ]; then
    first_image="${openpc_built_images[control-api]}"
  else
    [ "$first_image" != "${openpc_built_images[control-api]}" ]
    # A container referencing an exact prior ID protects it from retirement.
    protected="$(docker create --label "io.openpc.test.owner=$regression_root" "$first_image")"
    openpc_retire_replaced_images
    docker image inspect "$first_image" >/dev/null
    docker rm "$protected" >/dev/null
    protected=""
  fi
  "${compose[@]}" restart control-api
  test "$("${compose[@]}" exec -T control-api cat /state/readback)" = "$iteration"
  "${compose[@]}" down --volumes --remove-orphans
  [ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ]
  [ -z "$(docker network ls -q --filter "label=com.docker.compose.project=$project")" ]
  [ -z "$(docker volume ls -q --filter "label=com.docker.compose.project=$project")" ]
  openpc_assert_no_project_images
  openpc_retire_replaced_images
  [ "$(docker image ls --format '{{.Repository}}:{{.Tag}}' --filter 'reference=openpc-r1-runner-test/*:local' | wc -l)" -eq 7 ]
  printf 'OPENPC_STABLE_IMAGE_RUN|PASS|%s|project=%s|tags=7|source-readback|restart|owned-cleanup\n' "$iteration" "$project"
done
[ "$original_builder" = "$(docker buildx ls | awk '/\*/ {print $1}')" ]
if docker image inspect "$first_image" >/dev/null 2>&1; then echo 'unreferenced exact prior image was retained after success' >&2; exit 1; fi
printf 'OPENPC_STABLE_IMAGE_POLICY|PASS|two-projects|seven-tags|source-change|referenced-image-preserved|prior-id-retired|default-builder-unchanged|disk-denial\n'
