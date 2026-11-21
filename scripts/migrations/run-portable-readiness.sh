#!/usr/bin/env bash
# Dependency-free contract checks; never a substitute for full setup or custody.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
node --input-type=module -e '
import fs from "node:fs";
const required = JSON.parse(fs.readFileSync("package.json", "utf8")).engines.node;
if (process.versions.node !== required) throw Error(`Use pinned Node ${required}`);
'
python3 scripts/migrations/check-size.py
python3 -m unittest discover -s tests/migration -p 'test_*.py'
node --test --test-concurrency=1 \
  tests/migration/legacy-inputs.test.mjs \
  tests/migration/policy-readiness.test.mjs \
  tests/migration/setup-gate.test.mjs \
  tests/migration/custody-gate.test.mjs \
  tests/migration/custody-vm.test.mjs \
  tests/integration/local-runtime/qa-sandbox.test.mjs \
  tests/integration/local-runtime/qa-public-origin.test.mjs \
  tests/integration/local-runtime/oidc-signin.test.mjs \
  tests/integration/local-runtime/browser-scenarios.test.mjs \
  tests/integration/local-runtime/rpc-result.test.mjs \
  tests/recovery/profile-authentication.test.mjs \
  tests/recovery/profile-authentication-package.test.mjs \
  tests/recovery/recovery-result.test.mjs \
  tests/recovery/recovery-package.test.mjs
node --test --test-name-pattern='ordinary CI reaches the governed hold|ordinary CI executes installation configuration' \
  tests/integration/ci/invocation.test.mjs
