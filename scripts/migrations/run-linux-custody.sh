#!/usr/bin/env bash
# Real source/archive component tests, always against the compact installer.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
[[ $(uname -s) == Linux ]] || { echo 'Custody qualification requires Linux' >&2; exit 78; }
test -f migrations/postgres/baseline-v1/install.sql
test ! -e migrations/postgres/policy/0000_yummy_plazm.sql
exec bash scripts/maintenance/run-project.sh --profile database --memory-gib 8 --peak-disk-gib 40 -- \
  bash tests/integration/identity/run-participant-readback.sh \
  tests/integration/identity/postgres-runtime-artifact-source.test.ts
