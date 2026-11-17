#!/usr/bin/env bash
# Source this at an execution boundary; never change the user's shell defaults.
openpc_use_project_toolchain() {
  local repository pins required_node required_pnpm candidate actual selected=""
  local -a candidates=()
  repository=$(git rev-parse --path-format=absolute --git-common-dir) || return
  repository=$(dirname "$repository")
  pins=$(python3 - "$repository/package.json" <<'PY'
import json, re, sys
with open(sys.argv[1]) as source:
    package = json.load(source)
versions = [package['engines']['node'], package['engines']['pnpm']]
if not all(re.fullmatch(r'\d+\.\d+\.\d+', version) for version in versions):
    raise SystemExit('OpenPC requires exact Node and pnpm versions.')
if package.get('packageManager') != 'pnpm@' + versions[1]:
    raise SystemExit('OpenPC pnpm pins disagree.')
print(*versions)
PY
  ) || return 69
  read -r required_node required_pnpm <<< "$pins"
  if [[ -n ${OPENPC_NODE_BIN:-} ]]; then
    # An explicit override is authoritative and must fail if wrong, not fall back.
    candidates=("$OPENPC_NODE_BIN")
  else
    candidate=$(command -v node || true)
    [[ -z $candidate ]] || candidates+=("$candidate")
    candidates+=("${NVM_DIR:-$HOME/.nvm}/versions/node/v$required_node/bin/node")
  fi
  for candidate in "${candidates[@]}"; do
    [[ $candidate = /* && -x $candidate && ! -d $candidate ]] || continue
    actual=$(timeout 10s "$candidate" --version 2>/dev/null) || continue
    if [[ $actual = "v$required_node" ]]; then selected=$candidate; break; fi
  done
  if [[ -z $selected ]]; then
    printf 'OpenPC requires installed Node %s; set OPENPC_NODE_BIN to its absolute executable. No workload started.\n' "$required_node" >&2
    return 69
  fi
  export PATH="$(dirname "$selected"):$PATH"
  hash -r
  candidate=$(command -v node || true)
  if [[ -z $candidate || $(realpath -e "$candidate") != "$(realpath -e "$selected")" ]]; then
    echo 'The selected executable must resolve as node for child processes. No workload started.' >&2
    return 69
  fi
  candidate=$(command -v pnpm || true)
  if [[ -z $candidate ]]; then
    echo 'The pinned pnpm executable is unavailable. No workload started.' >&2
    return 69
  fi
  # Validation may use installed Corepack, but must never download or prompt.
  actual=$(COREPACK_ENABLE_NETWORK=0 COREPACK_ENABLE_DOWNLOAD_PROMPT=0 COREPACK_ENABLE_AUTO_PIN=0 \
    timeout 15s "$candidate" --version 2>/dev/null) || actual=""
  if [[ $actual != "$required_pnpm" ]]; then
    printf 'OpenPC requires installed pnpm %s; found %s. No workload started.\n' "$required_pnpm" "${actual:-unavailable}" >&2
    return 69
  fi
  export COREPACK_ENABLE_DOWNLOAD_PROMPT=0 COREPACK_ENABLE_AUTO_PIN=0
  printf 'OPENPC_TOOLCHAIN|node=%s|pnpm=%s\n' "$required_node" "$required_pnpm" >&2
}
