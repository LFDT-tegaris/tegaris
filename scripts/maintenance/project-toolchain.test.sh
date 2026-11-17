#!/usr/bin/env bash
# Tiny process-boundary regressions; no dependency installation or containers.
set -euo pipefail
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository=$(git rev-parse --show-toplevel)
common_dir=$(git rev-parse --path-format=absolute --git-common-dir)
fixture_parent="$(dirname "$(dirname "$common_dir")")/Agents/tmp"
fixture=$(mktemp -d "$fixture_parent/openpc-toolchain-test.XXXXXXXX")
trap 'rm -rf -- "$fixture"' EXIT
cp "$repository/package.json" "$fixture/package.json"
printf 'packages: []\n' > "$fixture/pnpm-workspace.yaml"
git -C "$fixture" init -q
mkdir -p "$fixture/wrong" "$fixture/pinned"
printf '#!/usr/bin/env bash\nprintf "v26.7.0\\n"\n' > "$fixture/wrong/node"
chmod +x "$fixture/wrong/node"
source "$directory/project-toolchain.sh"
cd "$fixture"
openpc_use_project_toolchain
real_node=$(command -v node)
expected_node=$(node -p 'require("./package.json").engines.node')
expected_pnpm=$(node -p 'require("./package.json").engines.pnpm')

# A fresh shell whose first Node is wrong selects the existing exact NVM version.
PATH="$fixture/wrong:$PATH" bash -c '
  source "$1/project-toolchain.sh"
  openpc_use_project_toolchain
  test "$(node --version)" = "v$2"
  test "$(pnpm --version)" = "$3"
  bash -c '\''test "$(node --version)" = "v$1"'\'' _ "$2"
' _ "$directory" "$expected_node" "$expected_pnpm"

expect_status() {
  local expected=$1 actual=0
  shift
  "$@" || actual=$?
  [[ $actual = "$expected" ]] || { echo "Expected $expected, got $actual" >&2; exit 1; }
}
expect_status 69 env OPENPC_NODE_BIN="$fixture/wrong/node" bash -c \
  'source "$1/project-toolchain.sh"; openpc_use_project_toolchain && touch "$2/forbidden"' _ "$directory" "$fixture"
expect_status 69 env OPENPC_NODE_BIN="$fixture/absent" bash -c \
  'source "$1/project-toolchain.sh"; openpc_use_project_toolchain && touch "$2/forbidden"' _ "$directory" "$fixture"

# An executable alias outside the selected node directory must not leave child
# commands resolving the ambient Node. Prefer rejection to an unsafe PATH claim.
mkdir "$fixture/alias"
ln -s "$real_node" "$fixture/alias/node24"
expect_status 69 env PATH="$fixture/wrong:$PATH" OPENPC_NODE_BIN="$fixture/alias/node24" bash -c \
  'source "$1/project-toolchain.sh"; openpc_use_project_toolchain && touch "$2/forbidden"' _ "$directory" "$fixture"

# An installed-looking wrong pnpm must not be accepted or downloaded over.
ln -s "$real_node" "$fixture/pinned/node"
printf '#!/usr/bin/env bash\nprintf "99.0.0\\n"\n' > "$fixture/pinned/pnpm"
chmod +x "$fixture/pinned/pnpm"
expect_status 69 env OPENPC_NODE_BIN="$fixture/pinned/node" bash -c \
  'source "$1/project-toolchain.sh"; openpc_use_project_toolchain && touch "$2/forbidden"' _ "$directory" "$fixture"
[[ ! -e $fixture/forbidden ]]

# Invalid admission is rejected before command dispatch or scope creation.
for args in \
  '--profile unknown' \
  '--profile governance --external-memory-gib 7' \
  '--profile database --external-memory-gib 1' \
  '--profile focused --memory-gib 2' \
  '--profile image-build --peak-disk-gib 10' \
  '--profile focused --reserve-disk-gib 49'; do
  read -r -a flags <<< "$args"
  expect_status 64 bash "$directory/run-bounded.sh" "${flags[@]}" -- touch "$fixture/forbidden"
done
[[ ! -e $fixture/forbidden ]]
cd "$repository"
# Exercise supported scripts themselves, before any Docker call or fixture work.
# Invalid explicit toolchains must never get as far as dependency dispatch.
for entry in \
  tests/integration/identity/run-participant-readback.sh \
  tests/integration/local-runtime/run-compose-e2e.sh \
  tests/integration/local-runtime/run-control-migration-upgrade.sh \
  tests/integration/local-runtime/run-image-ownership-regression.sh \
  tests/integration/policy/run-postgres18-trace-owner-proof.sh \
  tests/integration/policy/run-postgres18-nonsuperuser-migration-proof.sh \
  tests/integration/facts/run-postgres18-gate3-proof.sh \
  tests/integration/indexers/run-candidate-store.sh; do
  expect_status 69 env OPENPC_NODE_BIN="$fixture/wrong/node" bash "$entry"
done
printf 'PASS: exact Node/pnpm selection, inherited child toolchain, invalid overrides fail before workload, profile minima\n'
