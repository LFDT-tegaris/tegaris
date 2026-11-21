#!/bin/bash
set -euo pipefail
umask 077
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo"
source scripts/maintenance/local-runtime-images.sh
openpc_require_execution database
test_files=(
  tests/integration/local-runtime/control-installation.test.mjs
  tests/integration/local-runtime/runtime-fact-initial-trust.test.mjs
  tests/integration/local-runtime/qa-sandbox-postgres.test.mjs
  tests/integration/identity/postgres-catalog-runtime.test.ts
  tests/integration/identity/postgres-policy-set.test.ts
  tests/integration/identity/postgres-assignment-resume.test.ts
  tests/integration/identity/postgres-oidc-binding.test.ts
  tests/integration/identity/postgres-session-contexts.test.ts
  tests/integration/identity/postgres-identity-binding.test.ts
  tests/integration/identity/postgres-first-administrator.test.ts
  tests/integration/identity/postgres-invitation-journey.test.ts
  tests/integration/identity/postgres-governed-initial-enrollment.test.ts
  tests/integration/identity/postgres-recovery-reenrollment.test.ts
  tests/integration/identity/postgres-recovery-journey.test.ts
  tests/integration/identity/postgres-discovery-approval-resume.test.ts
  tests/integration/identity/postgres-webauthn-replacement.test.ts
  tests/integration/identity/postgres-workload-certificate-rotation.test.ts
  tests/integration/identity/postgres-workload-credential-continuity.test.ts
  tests/integration/identity/postgres-runtime-credential-handover-workload.test.ts
  tests/integration/identity/postgres-group-journey.test.ts
  tests/integration/identity/postgres-directory-journey.test.ts
  tests/integration/identity/postgres-role-journey.test.ts
  tests/integration/identity/postgres-runtime-snapshot.test.ts
  tests/integration/identity/postgres-runtime-target-profile.test.ts
  tests/integration/identity/postgres-platform-context.test.ts
  tests/integration/identity/postgres-identity-envelope-signing.test.ts
  tests/integration/identity/postgres-platform-envelope-scope.test.ts
  tests/integration/identity/postgres-root-expiry-installation.test.ts
  tests/integration/identity/postgres-root-expiry-recovery.test.ts
  tests/integration/identity/postgres-envelope-proposal.test.ts
  tests/integration/identity/postgres-wallet-binding.test.ts
  tests/integration/identity/postgres-setup-workbench.test.ts
  tests/integration/identity/postgres-deployment-policy.test.ts
  tests/integration/identity/postgres-native-value.test.ts
  tests/integration/identity/postgres-cigl-settings.test.ts
  tests/integration/policy/postgres18-runtime.test.ts
  tests/integration/identity/postgres-cigl-grants.test.ts
  tests/integration/identity/postgres-evidence-custody.test.ts
  tests/integration/identity/postgres-evidence-fact-delivery.test.ts
  tests/integration/identity/postgres-fleet-fact-admission.test.ts
  tests/integration/identity/postgres-fact-consumer-profile.test.ts
  tests/integration/identity/postgres-evidence-remote-archive.test.ts
  tests/integration/identity/postgres-evidence-remote-runtime.test.ts
  tests/integration/identity/postgres-evidence-remote-restore.test.ts
  tests/integration/identity/postgres-evidence-remote-upgrade.test.ts
  tests/integration/identity/postgres-evidence-protected-remote-archive.test.ts
  tests/integration/identity/postgres-evidence-holds.test.ts
  tests/integration/identity/postgres-evidence-deletion.test.ts
  tests/integration/identity/postgres-evidence-deletion-continuation.test.ts
  tests/integration/identity/postgres-evidence-deletion-eligibility.test.ts
  tests/integration/identity/postgres-runtime-artifact-fence.test.ts
  tests/integration/identity/postgres-runtime-artifact-references.test.ts
  tests/integration/identity/postgres-runtime-artifact-custody.test.ts
  tests/integration/identity/postgres-runtime-artifact-source.test.ts
  tests/integration/identity/postgres-notification-completion-worker.test.ts
  tests/integration/identity/postgres-notification-async-custody.test.ts
  tests/integration/identity/postgres-target-disposition.test.ts
  tests/integration/identity/postgres-retention-policy.test.ts
  tests/integration/identity/postgres-evidence-export.test.ts
  tests/integration/identity/postgres-evidence-kms.test.ts
  tests/integration/identity/postgres-evidence-authentication.test.ts
  tests/integration/identity/postgres-secret-recipient.test.ts
  tests/integration/identity/postgres-secret-delivery.test.ts
  tests/integration/identity/postgres-evidence-protected.test.ts
  tests/integration/identity/postgres-evidence-raw-deletion.test.ts
  tests/integration/identity/postgres-evidence-projection-deletion.test.ts
  tests/integration/identity/postgres-notification-receipt-contract.test.ts
  tests/integration/local-runtime/notification-gateway-fixture.test.mjs
  tests/integration/identity/postgres-configuration-step-up.test.ts
  tests/integration/identity/postgres-operations-generation.test.ts
  tests/integration/identity/postgres-public-operations-source.test.ts
  tests/integration/identity/postgres-operations-qualification-key-custody.test.ts
  tests/integration/identity/postgres-operations-qualification-deployment.test.ts
  tests/integration/identity/postgres-operations-secret-binding.test.ts
  tests/integration/identity/postgres-notification-journey.test.ts
  tests/integration/identity/postgres-notification-endpoint-journey.test.ts
  tests/integration/identity/postgres-notification-delivery-cancellation.test.ts
  tests/integration/identity/postgres-notification-delivery-publication.test.ts
  tests/integration/identity/postgres-work-item-receipt-contract.test.ts
  tests/integration/identity/postgres-work-item-journey.test.ts
  tests/integration/identity/postgres-evidence-store-retirement.test.ts
  source-policy-compilation
)
if [ "$#" -gt 0 ]; then test_files=("$@"); fi
if [[ ${#test_files[@]} == 1 && ${test_files[0]} == tests/integration/local-runtime/qa-sandbox-postgres.test.mjs ]]; then
  node --test tests/integration/local-runtime/qa-sandbox.test.mjs
fi
test_filter=()
if [[ ${OPENPC_QUALIFICATION_DEPLOYMENT_DIAGNOSTIC:-0} != 0 ]]; then
  [[ ${OPENPC_QUALIFICATION_DEPLOYMENT_DIAGNOSTIC} == 1 && ${#test_files[@]} == 1 && ${test_files[0]} == tests/integration/identity/postgres-operations-qualification-deployment.test.ts ]] || exit 96
  test_filter=(--testNamePattern '^native deployment native-original-restart$')
  printf 'OPENPC_QUALIFICATION_DEPLOYMENT_DIAGNOSTIC|selected=native-original-restart|aggregate-acceptance=false\n'
fi
# The wallet journey includes its real Rust consumer. Admit its possible cold
# build before starting any database or independent sibling.
wallet_interop=0
snapshot_interop=0
secret_consumer_interop=0
deployment_interop=0
native_value_interop=0
cigl_settings_interop=0
source_policy_interop=0
fleet_profile_interop=0
target_issuance_interop=0
notification_completion_bridge=0
envelope_activation_interop=0
for test_file in "${test_files[@]}"; do
  if [[ "$test_file" == tests/integration/identity/postgres-envelope-proposal.test.ts ]]; then
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --memory-gib 8 --peak-disk-gib 40 --reuse -- true
    envelope_activation_interop=1
  fi
  if [[ "$test_file" == tests/integration/identity/postgres-notification-completion-worker.test.ts || "$test_file" == tests/integration/identity/postgres-evidence-kms.test.ts ]]; then
    notification_completion_bridge=1
  fi
  if [[ "$test_file" == tests/integration/identity/postgres-target-disposition.test.ts ]]; then
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --memory-gib 8 --peak-disk-gib 40 --reuse -- true
    target_issuance_interop=1
  fi
  if [[ "$test_file" == tests/integration/identity/postgres-secret-delivery.test.ts ]]; then
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --external-memory-gib 1.5 --reuse -- true
    secret_consumer_interop=1
  fi
  if [[ "$test_file" == tests/integration/identity/postgres-fleet-fact-admission.test.ts || "$test_file" == tests/integration/identity/postgres-fact-consumer-profile.test.ts ]]; then
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --memory-gib 8 --peak-disk-gib 40 --reuse -- true
    fleet_profile_interop=1
  fi
  if [[ "$test_file" == source-policy-compilation ]]; then
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --memory-gib 8 --peak-disk-gib 40 --reuse -- true
    source_policy_interop=1
  fi
  if [[ "$test_file" == tests/integration/identity/postgres-runtime-artifact-source.test.ts ]]; then
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --memory-gib 8 --peak-disk-gib 40 --reuse -- true
  fi
  if [[ "$test_file" == tests/integration/identity/postgres-runtime-snapshot.test.ts ]]; then
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --peak-disk-gib 40 --reuse -- true
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --memory-gib 8 --peak-disk-gib 40 --reuse -- true
    snapshot_interop=1
  fi
  if [[ "$test_file" == tests/integration/identity/postgres-wallet-binding.test.ts ]]; then
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --peak-disk-gib 40 --reuse -- true
    wallet_interop=1
  fi
  if [[ "$test_file" == tests/integration/identity/postgres-deployment-policy.test.ts ]]; then
    # This scenario compiles the real Rust consumer as well as running PostgreSQL.
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --memory-gib 8 --peak-disk-gib 40 --reuse -- true
    deployment_interop=1
  fi
  if [[ "$test_file" == tests/integration/identity/postgres-cigl-settings.test.ts ]]; then
    cigl_settings_interop=1
  fi
  if [[ "$test_file" == tests/integration/policy/postgres18-runtime.test.ts ]]; then
    # The I02 governed-settings path also consumes the real Rust evaluator.
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --memory-gib 8 --peak-disk-gib 40 --reuse -- true
  fi
  if [[ "$test_file" == tests/integration/identity/postgres-native-value.test.ts || "$test_file" == tests/integration/identity/postgres-cigl-settings.test.ts || "$test_file" == tests/integration/identity/postgres-cigl-grants.test.ts || "$test_file" == tests/integration/policy/postgres18-runtime.test.ts ]]; then
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --peak-disk-gib 40 --reuse -- true
    native_value_interop=1
  fi
done
# Files own independent initial trust and may revoke it. Never share their database.
# Keep the inherited heavy lock, serialize peaks, and preserve any sibling failure.
if [ "${#test_files[@]}" -gt 1 ]; then
  aggregate=0
  for test_file in "${test_files[@]}"; do
    if bash "$repo/tests/integration/identity/run-participant-readback.sh" "$test_file"; then
      printf 'OPENPC_IDENTITY_SCENARIO|PASS|%s\n' "$test_file"
    else
      scenario_status=$?
      aggregate=1
      printf 'OPENPC_IDENTITY_SCENARIO|FAIL|%s|exit=%s\n' "$test_file" "$scenario_status" >&2
    fi
  done
  exit "$aggregate"
fi
# Pure shared contracts run before allocating a database, applying migrations or
# acquiring live authority. Keep actual SQL/receipt/HTTP acceptance below.
case "${test_files[0]}" in
  tests/integration/identity/postgres-runtime-credential-handover-workload.test.ts)
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-runtime-credential-handover-workload.test.ts tests/integration/identity/runtime-credential-handover-inputs.test.ts
    pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/runtime-credential-handover-inputs.test.ts --testNamePattern '^signs a finite initial native-test credential without extending an existing signed leaf$'
    ;;
  tests/integration/identity/postgres-workload-credential-continuity.test.ts)
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-workload-credential-continuity.test.ts
    pnpm exec vitest run --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-workload-credential-continuity.test.ts --testNamePattern '^(authenticates independent expired and current continuity certificates before database allocation|binds a prepared authority once to the exact runtime target without changing its signed identity)$'
    ;;
  tests/integration/identity/postgres-workload-certificate-rotation.test.ts)
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-workload-certificate-rotation.test.ts
    pnpm exec vitest run --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-workload-certificate-rotation.test.ts --testNamePattern '^authenticates independent expired and current workload fixture certificates before database allocation$'
    ;;
  tests/integration/identity/postgres-runtime-target-profile.test.ts)
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-runtime-target-profile.test.ts
    ;;
  tests/integration/identity/postgres-envelope-proposal.test.ts)
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-envelope-proposal.test.ts
    node --test tests/integration/identity/identity-envelope-proposal-upgrade.test.mjs
    pnpm exec vitest run --config tests/integration/identity/vitest.config.ts --maxWorkers=1 tests/integration/identity/postgres-envelope-proposal.test.ts --testNamePattern 'authenticates envelope lifecycle installation inputs'
    ;;
  tests/integration/identity/postgres-root-expiry-recovery.test.ts)
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=begin|owner=finite-root-recovery\n'
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-root-expiry-recovery.test.ts
    pnpm --dir services/identity-service exec vitest run --maxWorkers=1 --config vitest.config.ts src/db/root-expiry-recovery-guards.test.ts src/db/platform-recovery-installation.test.ts src/domain/local-root-expiry-recovery.test.ts
    pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-root-expiry-installation.test.ts tests/integration/identity/postgres-root-expiry-recovery.test.ts --testNamePattern '^(authenticates Root-expiry installation sources before allocating PostgreSQL|binds Root-expiry installation to its owned database|rejects Root-expiry installation target|authenticates finite Root recovery sources before database allocation|signs finite Root recovery authenticator assertions)'
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=passed|owner=finite-root-recovery\n'
    ;;
  tests/integration/identity/postgres-root-expiry-installation.test.ts)
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=begin|owner=root-expiry-installation\n'
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-root-expiry-installation.test.ts
    pnpm --dir services/identity-service exec vitest run --maxWorkers=1 --config vitest.config.ts src/domain/local-root-expiry-recovery.test.ts src/db/platform-recovery-installation.test.ts
    pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-root-expiry-installation.test.ts --testNamePattern '^(authenticates Root-expiry installation sources before allocating PostgreSQL|binds Root-expiry installation to its owned database|rejects Root-expiry installation target)'
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=passed|owner=root-expiry-installation\n'
    ;;
  tests/integration/identity/postgres-platform-envelope-scope.test.ts)
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-platform-envelope-scope.test.ts
    pnpm --dir packages/security-kernel exec vitest run --maxWorkers=1 src/identity-envelope/platform-scope.test.ts
    pnpm exec vitest run --config tests/integration/identity/vitest.config.ts --maxWorkers=1 tests/integration/identity/postgres-platform-envelope-scope.test.ts --testNamePattern 'authenticates Platform installation sources'
    ;;
  tests/integration/identity/postgres-identity-envelope-signing.test.ts)
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-identity-envelope-signing.test.ts
    pnpm --dir packages/security-kernel generate:check
    pnpm --dir packages/security-kernel exec vitest run --maxWorkers=1 src/identity-envelope/signing-trust.test.ts scripts/identity-envelope-profile.test.mjs
    ;;
  tests/integration/identity/postgres-notification-async-custody.test.ts)
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-notification-async-custody.test.ts tests/integration/identity/notification-async-worker-cases.ts
    async_checks=(src/notifications/async-worker-policy.test.ts src/notifications/async-worker-guards.test.ts src/notifications/async-worker.test.ts src/notifications/delivery-start-preparation-guards.test.ts src/notifications/delivery-cancellation-state.test.ts)
    for check in "${async_checks[@]}"; do [[ -f "services/control-api/$check" ]] || exit 96; done
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts "${async_checks[@]}"
    ;;
  tests/integration/identity/postgres-target-disposition.test.ts)
    pnpm exec tsc --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-target-disposition.test.ts
    ;;
  tests/integration/identity/postgres-runtime-artifact-fence.test.ts)
    pnpm exec tsc --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-runtime-artifact-fence.test.ts
    ;;
  tests/integration/identity/postgres-runtime-artifact-source.test.ts)
    pnpm exec tsc --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-runtime-artifact-source.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence/runtime-artifact-disposition-state.test.ts src/configuration/problem.test.ts
    pnpm --dir services/identity-service exec vitest run --maxWorkers=1 --config vitest.config.ts src/db/function-grants.test.ts
    pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-runtime-artifact-source.test.ts --testNamePattern '^(validates source-disposition request inputs before database allocation|classifies only exact runtime-source producer contention)$'
    cargo test -p openpc-fleet-controller --lib --locked --offline runtime_artifact_source
    cargo test -p openpc-fleet-controller --lib --locked --offline physical_retirement_consumes_real_typescript_profile_cose_trust_state_and_event
    ;;
  tests/integration/identity/postgres-notification-completion-worker.test.ts)
    pnpm exec tsc --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-notification-completion-worker.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/notifications/completion-worker-installation-contract.test.ts src/notifications/completion-worker-installation-guards.test.ts src/notifications/completion-worker-installation.test.ts src/notifications/completion-disposition-registration.test.ts
    pnpm --dir packages/security-kernel exec vitest run --maxWorkers=1 --config vitest.config.ts src/notification-gateway/codec.test.ts src/notification-gateway/completion-worker-contract.test.ts
    ;;
  tests/integration/identity/postgres-runtime-artifact-custody.test.ts)
    pnpm exec tsc --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-runtime-artifact-custody.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence/runtime-artifact-archive-contract.test.ts src/evidence/runtime-artifact-archive-custody.test.ts src/evidence/runtime-artifact-archive-guards.test.ts src/evidence/runtime-artifact-retirement.test.ts src/evidence/runtime-artifact-retirement-guards.test.ts src/evidence/candidate-archive/source.test.ts
    ;;
  tests/integration/identity/postgres-runtime-artifact-references.test.ts)
    pnpm exec tsc --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-runtime-artifact-references.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence/runtime-artifact-references.test.ts src/evidence/runtime-artifact-archive-contract.test.ts
    ;;
  tests/integration/identity/postgres-operations-qualification-deployment.test.ts)
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=begin|owner=qualification-deployment\n'
    bash "$repo/scripts/maintenance/run-bounded.sh" --profile database --external-memory-gib 1.5 --reuse -- true
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-operations-qualification-deployment.test.ts services/identity-service/src/domain/qualification-deployment-peer.ts services/identity-service/src/domain/qualification-deployment-peer.test.ts
    node --import tsx --test scripts/operations/installation-process-observation.test.mjs scripts/operations/qualification-deployment-observation.test.mjs
    pnpm --dir services/identity-service exec vitest run --maxWorkers=1 --config vitest.config.ts src/domain/qualification-deployment-peer.test.ts
    pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-operations-qualification-deployment.test.ts
    # The ordinary runtime suite has already built its owned Identity image.
    # Freeze its inspected ID before PostgreSQL; the native fixture verifies
    # ownership and actual container custody, without a source-build claim.
    OPENPC_QUALIFICATION_DEPLOYMENT_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$(openpc_image_tag identity-service)")
    [[ $OPENPC_QUALIFICATION_DEPLOYMENT_IMAGE_ID =~ ^sha256:[0-9a-f]{64}$ ]]
    export OPENPC_QUALIFICATION_DEPLOYMENT_IMAGE_ID
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=passed|owner=qualification-deployment\n'
    ;;
  tests/integration/identity/postgres-operations-qualification-key-custody.test.ts)
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=begin|owner=qualification-key-custody\n'
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-operations-qualification-key-custody.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/notifications/delivery-outcome-publication-shared.test.ts
    (
      preflight_parent=${OPENPC_LOCAL_RUNTIME_TMP_ROOT:?External runtime scratch is required}
      [[ "$preflight_parent" = /* && ! -L "$preflight_parent" && "$(realpath -e "$preflight_parent")" = "$preflight_parent" ]]
      preflight_root=$(mktemp -d "$preflight_parent/qualification-key-preflight.XXXXXX")
      trap 'status=$?; if [[ $status == 0 ]]; then rm -rf -- "$preflight_root"; else printf "Diagnostics retained: %s\n" "$preflight_root"; fi; exit "$status"' EXIT
      export OPENPC_TEST_TMP_ROOT=$preflight_root
      pnpm --dir services/identity-service exec vitest run --maxWorkers=1 --config vitest.config.ts src/domain/qualification-key-provider.test.ts src/domain/http-qualification-key-provider.test.ts src/domain/qualification-key-custody-peer.test.ts src/domain/pinned-signing-transport.test.ts src/domain/http-notification-receipt-provider.test.ts
      node --import tsx --test tests/integration/local-runtime/rpc-retirement-signing.test.mjs
    )
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=passed|owner=qualification-key-custody\n'
    ;;
  tests/integration/identity/postgres-public-operations-source.test.ts)
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=begin|owner=public-operations-source\n'
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-public-operations-source.test.ts
    node --import tsx --test scripts/operations/public-operations-source.test.mjs
    pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-public-operations-source.test.ts --testNamePattern '^authenticates public source bytes and a real signed installation before database allocation$'
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=passed|owner=public-operations-source\n'
    ;;
  tests/integration/identity/postgres-operations-secret-binding.test.ts|tests/integration/identity/postgres-operations-generation.test.ts)
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=begin|owner=operations-generation\n'
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-operations-generation.test.ts tests/integration/identity/postgres-operations-secret-binding.test.ts tests/integration/identity/postgres-operations-provider-retry-qualification.test.ts tests/integration/identity/postgres-operations-provider-retry-probe-source.test.ts tests/integration/identity/postgres-operations-provider-retry-input.test.ts
    pnpm --filter @openpc/security-kernel generate:check
    pnpm --dir packages/security-kernel exec vitest run --maxWorkers=1 --config vitest.config.ts src/operations-configuration/site-document.test.ts src/operations-configuration/secret-resolution.test.ts src/operations-configuration/qualification-wire.test.ts src/operations-configuration/provider-retry-qualification.test.ts src/operations-configuration/notification-async.test.ts src/operations-configuration/provider-retry-input.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/notifications/async-admission.test.ts
    pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-operations-generation.test.ts --testNamePattern '^validates actual signed operations generation inputs before PostgreSQL allocation$'
    node --import tsx --test scripts/operations/installation-config.test.mjs scripts/operations/installation-effective-projection.test.mjs
    pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-operations-secret-binding.test.ts
    pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-operations-provider-retry-qualification.test.ts --testNamePattern '^rejects missing authority/executed-input fixture before allocating PostgreSQL$'
    pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-operations-provider-retry-probe-source.test.ts --testNamePattern '^rejects incomplete, mixed-format and caller-eligibility probe source references before PostgreSQL$'
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=passed|owner=operations-generation\n'
    ;;
  tests/integration/identity/postgres-evidence-kms.test.ts)
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=begin|owner=evidence-kms\n'
    pnpm exec tsc --ignoreConfig --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --types node --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-evidence-kms.test.ts tests/integration/identity/notification-async-worker-cases.ts services/identity-service/src/domain/notification-receipt-provider.test.ts services/identity-service/src/domain/notification-cancellation-receipt-provider.test.ts services/identity-service/src/domain/notification-outcome-receipt-provider.test.ts services/identity-service/src/domain/http-notification-receipt-provider.test.ts services/control-api/src/notifications/receipt-signer-installation.test.ts services/control-api/src/notifications/delivery-failure-work-contract.test.ts services/control-api/src/notifications/receipt-signer-guards.test.ts services/control-api/src/notifications/delivery-signing-contract.test.ts services/control-api/src/notifications/delivery-signing-state.test.ts services/control-api/src/notifications/delivery-signing-runtime.test.ts services/control-api/src/notifications/delivery-signing-guards.test.ts services/control-api/src/notifications/delivery-start-atomic.test.ts services/control-api/src/notifications/delivery-dispatch-state.test.ts services/control-api/src/notifications/delivery-dispatch-guards.test.ts tests/integration/identity/notification-delivery-dispatch-cases.ts services/control-api/src/notifications/delivery-start-atomic-guards.test.ts services/control-api/src/notifications/delivery-material-context.test.ts services/control-api/src/notifications/delivery-material.test.ts services/control-api/src/notifications/delivery-provider.test.ts services/control-api/src/notifications/gateway-adapter.test.ts services/control-api/src/notifications/gateway-contracts.test.ts tests/integration/identity/notification-delivery-provider-cases.ts
    pnpm --dir packages/security-kernel exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence-kms/codec.test.ts src/notification-gateway/codec.test.ts src/notification-gateway/worker-contract.test.ts src/operations-configuration/notification-async.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/notifications/async-admission.test.ts src/notifications/async-worker-policy.test.ts src/notifications/async-worker-guards.test.ts src/notifications/async-worker.test.ts src/notifications/delivery-runtime.test.ts src/notifications/packaged-delivery-runtime.test.ts src/notifications/packaged-verification-runtime.test.ts
    pnpm --dir services/identity-service exec vitest run --maxWorkers=1 --config vitest.config.ts src/domain/evidence-key-recipient.test.ts src/db/notification-outbox-dispatch.test.ts src/domain/notification-receipt-provider.test.ts src/domain/notification-cancellation-receipt-provider.test.ts src/domain/notification-outcome-receipt-provider.test.ts src/domain/http-notification-receipt-provider.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence/kms-contracts.test.ts src/notifications/payload-reference.test.ts src/notifications/delivery-material.test.ts src/notifications/delivery-material-context.test.ts src/notifications/receipt-signer-installation.test.ts src/notifications/delivery-failure-work-contract.test.ts src/notifications/receipt-signer-guards.test.ts src/evidence/kms-state.test.ts src/evidence/notification-payload-crypto.test.ts src/evidence/notification-key-custody.test.ts src/evidence/notification-payload-retirement-source.test.ts src/evidence/notification-payload-reader.test.ts src/notifications/routing-installation-contract.test.ts src/notifications/template-renderer.test.ts src/notifications/occurrence-contract.test.ts src/notifications/occurrence-state.test.ts src/notifications/occurrence-runtime.test.ts src/notifications/receipt-guards.test.ts src/notifications/delivery-start-state.test.ts src/notifications/delivery-cancellation-contract.test.ts src/notifications/delivery-cancellation-state.test.ts src/notifications/delivery-outcome-contract.test.ts src/notifications/delivery-outcome-state.test.ts src/notifications/delivery-outcome-runtime.test.ts src/notifications/delivery-outcome-guards.test.ts src/notifications/delivery-outcome-publication-contract.test.ts src/notifications/delivery-outcome-publication.test.ts src/notifications/delivery-outcome-publication-guards.test.ts src/notifications/delivery-outcome-publication-shared.test.ts src/evidence/notification-outcome-source.test.ts src/notifications/delivery-start-guards.test.ts src/notifications/delivery-signing-contract.test.ts src/notifications/delivery-signing-state.test.ts src/notifications/delivery-signing-runtime.test.ts src/notifications/delivery-signing-guards.test.ts src/notifications/delivery-start-atomic.test.ts src/notifications/delivery-dispatch-state.test.ts src/notifications/delivery-dispatch-guards.test.ts src/notifications/delivery-start-atomic-guards.test.ts src/notifications/delivery-start-preparation.test.ts src/notifications/delivery-start-preparation-guards.test.ts src/notifications/delivery-adapter-context.test.ts src/notifications/delivery-policy.test.ts src/notifications/delivery-provider.test.ts src/notifications/gateway-adapter.test.ts src/notifications/gateway-contracts.test.ts
    pnpm --dir services/identity-service exec vitest run --maxWorkers=1 --config vitest.config.ts src/domain/notification-completion-worker.test.ts src/domain/notification-completion-disposition-provider.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/notifications/completion-disposition-contract.test.ts src/notifications/completion-disposition-state.test.ts src/notifications/completion-disposition-signer.test.ts src/notifications/completion-disposition-runtime.test.ts src/notifications/completion-disposition-publication.test.ts src/notifications/completion-disposition-guards.test.ts src/notifications/completion-disposition-effect-guards.test.ts src/notifications/completion-disposition-registration.test.ts
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=passed|owner=evidence-kms\n'
    ;;
  tests/integration/policy/postgres18-runtime.test.ts)
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/configuration/cigl/settings-contract.test.ts
    ;;
  tests/integration/identity/postgres-configuration-step-up.test.ts)
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/configuration/local-authorization-contract.test.ts
    ;;
  tests/integration/identity/postgres-secret-recipient.test.ts|tests/integration/identity/postgres-secret-delivery.test.ts)
    pnpm --filter @openpc/security-kernel exec vitest run src/secret-recipient/profile.test.ts
    if [[ "${test_files[0]}" == tests/integration/identity/postgres-secret-delivery.test.ts ]]; then
      node --check tests/integration/identity/secret-delivery-process.mjs
      node --check tests/integration/identity/secret-consumer-process.mjs
      node --import tsx --input-type=module -e 'await import("./scripts/operations/test-fact-secret-consumer.mjs")'
      node --import tsx --test --test-name-pattern="delivery rejects|delivery snapshots|invalid synthetic material" scripts/operations/test-fact-secret-delivery.test.mjs
    fi
    ;;
  tests/integration/identity/postgres-fleet-fact-admission.test.ts|tests/integration/identity/postgres-fact-consumer-profile.test.ts)
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=begin|owner=fleet-fact-admission\n'
    node packages/security-kernel/scripts/generate-business-transition.mjs --check
    pnpm --dir packages/security-kernel exec vitest run --maxWorkers=1 --config vitest.config.ts src/fact-consumer/profile.test.ts src/fact-consumer/failure.test.ts
    pnpm --dir services/identity-service exec vitest run --maxWorkers=1 --config vitest.config.ts src/db/function-grants.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence/fact-failure-source.test.ts
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=passed|owner=fleet-fact-admission\n'
    ;;
  tests/integration/identity/postgres-notification-*.test.ts|tests/integration/local-runtime/notification-gateway-fixture.test.mjs)
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=begin|owner=notification-contracts\n'
    pnpm exec tsc --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-notification-endpoint-journey.test.ts tests/integration/identity/postgres-notification-delivery-cancellation.test.ts
    node packages/security-kernel/scripts/generate-business-transition.mjs --check
    pnpm --dir packages/security-kernel exec vitest run --maxWorkers=1 --config vitest.config.ts src/notification-gateway/codec.test.ts src/notification-gateway/worker-contract.test.ts
    pnpm --dir services/identity-service exec vitest run --maxWorkers=1 --config vitest.config.ts src/db/function-grants.test.ts src/db/notification-outbox-dispatch.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/notifications/contracts.test.ts src/notifications/business-state.test.ts src/notifications/gateway-contracts.test.ts src/notifications/delivery-start-contract.test.ts src/notifications/delivery-start-transition.test.ts src/notifications/endpoint-binding.test.ts src/notifications/endpoint-business-state.test.ts src/notifications/endpoint-owner-contract.test.ts src/notifications/routing-installation-contract.test.ts src/notifications/template-renderer.test.ts src/notifications/occurrence-contract.test.ts src/notifications/occurrence-state.test.ts src/notifications/occurrence-runtime.test.ts src/notifications/receipt-guards.test.ts src/notifications/delivery-start-state.test.ts src/notifications/delivery-cancellation-contract.test.ts src/notifications/delivery-cancellation-state.test.ts src/notifications/delivery-outcome-contract.test.ts src/notifications/delivery-outcome-state.test.ts src/notifications/delivery-outcome-runtime.test.ts src/notifications/delivery-outcome-guards.test.ts src/notifications/delivery-outcome-publication-contract.test.ts src/notifications/delivery-outcome-publication.test.ts src/notifications/delivery-outcome-publication-guards.test.ts src/notifications/delivery-outcome-publication-shared.test.ts src/evidence/notification-outcome-source.test.ts src/notifications/delivery-start-guards.test.ts src/notifications/delivery-signing-contract.test.ts src/notifications/delivery-signing-state.test.ts src/notifications/delivery-signing-runtime.test.ts src/notifications/delivery-signing-guards.test.ts src/notifications/delivery-start-atomic.test.ts src/notifications/delivery-dispatch-state.test.ts src/notifications/delivery-dispatch-guards.test.ts src/notifications/delivery-start-atomic-guards.test.ts src/notifications/delivery-start-preparation.test.ts src/notifications/delivery-start-preparation-guards.test.ts src/notifications/delivery-adapter-context.test.ts src/notifications/delivery-policy.test.ts src/notifications/delivery-provider.test.ts src/notifications/gateway-adapter.test.ts src/notifications/gateway-contracts.test.ts
    if [[ "${test_files[0]}" == tests/integration/identity/postgres-notification-endpoint-journey.test.ts ]]; then
      pnpm exec tsc --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/notification-routing-installation-cases.ts
      pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/configuration/notification-verification-contract.test.ts src/notifications/endpoint-admission.test.ts src/notifications/endpoint-verification-state.test.ts src/notifications/endpoint-verification-provider.test.ts src/notifications/endpoint-repository.test.ts src/notifications/endpoint-verification-workflow.test.ts src/notifications/endpoint-verification-runtime.test.ts src/notifications/endpoint-http.test.ts
      pnpm --dir services/identity-service exec vitest run --maxWorkers=1 --config vitest.config.ts src/domain/notification-secret-recipient.test.ts src/domain/notification-credential-material.test.ts src/domain/notification-workload-transport.test.ts
    fi
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=passed|owner=notification-contracts\n'
    ;;
  tests/integration/identity/postgres-work-item-*.test.ts)
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=begin|owner=work-item-contracts\n'
    node packages/security-kernel/scripts/generate-business-transition.mjs --check
    pnpm --dir services/identity-service exec vitest run --maxWorkers=1 --config vitest.config.ts src/db/function-grants.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/configuration/persistence/business-state/work-item.test.ts
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=passed|owner=work-item-contracts\n'
    ;;
  tests/integration/identity/postgres-evidence-*.test.ts|tests/integration/identity/postgres-retention-policy.test.ts)
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=begin|owner=evidence-contracts\n'
    node packages/security-kernel/scripts/generate-business-transition.mjs --check
    pnpm --dir services/identity-service exec vitest run --maxWorkers=1 --config vitest.config.ts src/db/function-grants.test.ts
    pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence/hold-contracts.test.ts
    if [[ "${test_files[0]}" == tests/integration/identity/postgres-evidence-export.test.ts ]]; then
      pnpm exec tsc --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --target es2024 --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/identity/postgres-evidence-export.test.ts
      pnpm --dir packages/security-kernel exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence-export/codec.test.ts
      pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence/export-producer-installation.test.ts src/notifications/source-reader.test.ts src/notifications/published-source.test.ts src/notifications/worker-installation-contract.test.ts
    fi
    if [[ "${test_files[0]}" == tests/integration/identity/postgres-evidence-fact-delivery.test.ts ]]; then
      pnpm --dir packages/security-kernel exec vitest run --maxWorkers=1 --config vitest.config.ts src/fact-consumer/profile.test.ts
      pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence/fact-delivery-contract.test.ts src/evidence/provenance.test.ts
    fi
    if [[ "${test_files[0]}" == tests/integration/identity/postgres-evidence-store-retirement.test.ts ]]; then
      pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence/store-retirement-wire.test.ts src/evidence/store-retirement-preflight.test.ts src/evidence/store-retirement-selection.test.ts src/evidence/store-retirement-contracts.test.ts src/evidence/store-retirement-dispatcher.test.ts src/evidence/store-retirement-business-state.test.ts src/evidence/store-retirement-installation.test.ts
    fi
    if [[ "${test_files[0]}" == tests/integration/identity/postgres-evidence-projection-deletion.test.ts ]]; then
      pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence/rpc-retirement.test.ts src/evidence/rpc-search-retirement.test.ts src/evidence/provenance.test.ts src/evidence/deletion-business-state.test.ts
      pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-evidence-projection-deletion.test.ts --testNamePattern '^validates exact evidence signing inputs before database allocation$'
    fi
    pnpm --dir services/module-registry exec vitest run --maxWorkers=1 --config ../../tests/integration/policy/vitest.config.ts tests/integration/policy/approval-candidate-contract.test.ts
    if [[ "${test_files[0]}" == tests/integration/identity/postgres-evidence-protected.test.ts || "${test_files[0]}" == tests/integration/identity/postgres-evidence-raw-deletion.test.ts ]]; then
      pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence/protected-crypto.test.ts src/evidence/protected-vault.test.ts src/evidence/custody.test.ts
    fi
    if [[ "${test_files[0]}" == tests/integration/identity/postgres-evidence-remote-*.test.ts || "${test_files[0]}" == tests/integration/identity/postgres-evidence-protected-remote-archive.test.ts ]]; then
      pnpm --dir packages/security-kernel exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence-archive/codec.test.ts
      pnpm --dir services/control-api exec vitest run --maxWorkers=1 --config vitest.config.ts src/evidence/remote-archive-authority.test.ts src/evidence/protected-remote-archive.test.ts
    fi
    printf 'OPENPC_IDENTITY_PREFLIGHT|event=passed|owner=evidence-contracts\n'
    ;;
esac
scratch_parent="${OPENPC_LOCAL_RUNTIME_TMP_ROOT:?External runtime scratch is required}"
[[ "$scratch_parent" = /* && ! -L "$scratch_parent" ]] || exit 73
mkdir -p "$scratch_parent"
[[ "$(realpath -e "$scratch_parent")" = "$scratch_parent" ]] || exit 73
root=$(mktemp -d "$scratch_parent/participant-readback.XXXXXX")
export OPENPC_TEST_TMP_ROOT="$root"
if [ "$envelope_activation_interop" = 1 ]; then
  export OPENPC_ENVELOPE_ACTIVATION_PUBLIC_FIXTURE="${OPENPC_ENVELOPE_ACTIVATION_PUBLIC_FIXTURE:-$root/envelope-activation-public.json}"
fi
export OPENPC_RUNTIME_ARTIFACT_SOURCE_SOCKET_DIRECTORY="$root"
if [ "$wallet_interop" = 1 ]; then
  export OPENPC_ASTRA07_WALLET_PUBLICATION_FIXTURE="$root/wallet-publication.json"
fi
if [ "$snapshot_interop" = 1 ]; then
  export OPENPC_ASTRA05_PUBLICATION_FIXTURE="$root/identity-publication.json"
fi
if [ "$deployment_interop" = 1 ]; then
  export OPENPC_ASTRA08_DEPLOYMENT_PUBLICATION_FIXTURE="$root/deployment-publication.json"
fi
if [ "$cigl_settings_interop" = 1 ]; then
  export OPENPC_CIGL_SETTINGS_PUBLICATION_FIXTURE="$root/cigl-settings-publication.json"
fi
container=openpc-participant-readback-$$
created=0
openpc_readback_keep_failure_state() {
  [[ "$status" != 0 ]] || return 1
  # Failed cleanup leaves resource ownership unresolved. Retain its keys too.
  [[ "$status" == 99 ]] && return 0
  local selected_readback
  for selected_readback in "${test_files[@]}"; do
    case "$selected_readback" in
      tests/integration/identity/postgres-governed-initial-enrollment.test.ts | tests/integration/identity/postgres-envelope-proposal.test.ts | tests/integration/local-runtime/runtime-fact-initial-trust.test.mjs | tests/integration/identity/postgres-runtime-target-profile.test.ts | tests/integration/identity/postgres-workload-certificate-rotation.test.ts | tests/integration/identity/postgres-workload-credential-continuity.test.ts | tests/integration/identity/postgres-runtime-credential-handover-workload.test.ts | tests/integration/identity/postgres-platform-envelope-scope.test.ts | tests/integration/identity/postgres-root-expiry-installation.test.ts | tests/integration/identity/postgres-root-expiry-recovery.test.ts)
        return 0 ;;
    esac
  done
  return 1
}
cleanup() {
  status=$?
  trap - EXIT
  if [[ "$status" != 0 && -f "$root/migrations.log" && -f "${repo:-}/scripts/migrations/report-failure.py" ]]; then
    python3 "$repo/scripts/migrations/report-failure.py" "$root/migrations.log" >&2 || true
  fi
  if [ "$created" = 1 ]; then
    docker logs "$container" > "$root/postgres.log" 2>&1 || true
    if [ "$(docker inspect -f '{{index .Config.Labels "io.openpc.test-owner"}}' "$container")" != "$root" ]; then
      status=99
    else
      for owned in $(docker ps -aq --filter "label=io.openpc.test-owner=$root"); do
        if openpc_readback_keep_failure_state; then
          # Signing and installation can commit before a later assertion fails.
          # Preserve their original database and keys for diagnosis.
          if ! docker stop "$owned" >/dev/null; then status=99; fi
        else
          if ! docker rm -fv "$owned" >/dev/null; then status=99; fi
        fi
      done
    fi
  fi
  if ! openpc_readback_keep_failure_state; then
    rm -rf -- "$root/secrets"
  fi
  if [ "$status" = 0 ]; then rm -rf -- "$root"; else echo "Diagnostics retained: $root"; fi
  exit "$status"
}
trap cleanup EXIT
if [ "$envelope_activation_interop" = 1 ]; then
  # Compile before database setup or any short-lived business authority.
  cargo test -p pc-policy-core --lib --locked --offline --no-run
fi
if [ "$deployment_interop" = 1 ] || [ "$native_value_interop" = 1 ]; then
  cargo build -p openpc-policy-compiler --bin openpc-policy-evaluator --locked --offline
fi
if [ "$cigl_settings_interop" = 1 ] || [ "$source_policy_interop" = 1 ] || [ "$target_issuance_interop" = 1 ]; then
  cargo test -p openpc-fleet-controller --lib --locked --offline --no-run
fi

if [ "$snapshot_interop" = 1 ]; then
  # Compile both consumers before PostgreSQL starts; the live mTLS test executes
  # the ready test binary while the real Identity server is listening.
  cargo test -p openpc-runtime-agent --lib --locked --offline --no-run
fi
if [ "$snapshot_interop" = 1 ] || [ "$fleet_profile_interop" = 1 ]; then
  cargo test -p openpc-fact-service --lib --locked --offline --no-run --message-format=json > "$root/fact-test-build.json"
  OPENPC_FACT_WORKLOAD_TEST_BINARY=$(node --input-type=module -e '
    import {readFileSync} from "node:fs";
    const builds=readFileSync(process.argv[1],"utf8").trim().split("\n").map(line=>JSON.parse(line));
    const test=builds.find(value=>value.reason==="compiler-artifact" && value.target.name==="openpc_fact_service" && value.profile.test && value.executable);
    if (!test) process.exit(1);
    process.stdout.write(test.executable);
  ' "$root/fact-test-build.json")
  export OPENPC_FACT_WORKLOAD_TEST_BINARY
fi
if [ "$fleet_profile_interop" = 1 ]; then
  pnpm --dir packages/security-kernel exec vitest run --maxWorkers=1 --config vitest.config.ts src/fact-consumer/profile.test.ts src/fact-consumer/failure.test.ts --testNamePattern="native (failure|profile) wire interoperability"
fi
mkdir "$root/secrets"
password=$(openssl rand -hex 24)
for secret in candidate_index_pg_password fact_bridge_reader_db_password control_pg_password identity_runtime_db_password participant_runtime_db_password policy_runtime_db_password control_api_runtime_db_password control_worker_runtime_db_password; do
  printf '%s\n' "$password" > "$root/secrets/$secret"
done
if [ "$target_issuance_interop" = 1 ]; then
  # Privileged initial native bridge trust; no business state is seeded.
  openssl rand -hex 32 > "$root/secrets/runtime_target_disposition_key"
fi
if [[ "${test_files[0]}" == tests/integration/identity/postgres-runtime-artifact-source.test.ts ]]; then
  # Distinct host bridge keys, bound later to the actual installed native login.
  openssl rand -hex 32 > "$root/secrets/fleet_fact_admission_key"
  openssl rand -hex 32 > "$root/secrets/runtime_target_disposition_key"
fi
if [ "$notification_completion_bridge" = 1 ]; then
  openssl rand -hex 32 > "$root/secrets/notification_completion_identity_admission_key"
  export OPENPC_NOTIFICATION_COMPLETION_TEST_KEY_FILE="$root/secrets/notification_completion_identity_admission_key"
fi
postgres_command=(postgres)
if [[ "${test_files[0]}" == tests/integration/identity/postgres-runtime-artifact-source.test.ts ]]; then
  # The same-database recovery case drops and recreates the full catalogue in
  # one transaction. Provision its lock table at server startup; keep the same
  # 1 GiB container cap and never alter an existing installation's settings.
  postgres_command=(postgres -c max_locks_per_transaction=1024)
fi
docker run -d --name "$container" --memory 1g --memory-swap 1g --cpus 1 --pids-limit 256 --label "io.openpc.test-owner=$root" \
  -p 127.0.0.1::5432 -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB=openpc_control \
  -v "$root/secrets:/run/secrets:ro" -v "$repo/migrations/postgres:/migrations/postgres:ro" \
  -v "$repo/deploy/compose/local/migrate.sh:/local/migrate.sh:ro" \
  docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7 "${postgres_command[@]}" >/dev/null
created=1
if [[ "${test_files[0]}" == tests/integration/identity/postgres-platform-envelope-scope.test.ts || "${test_files[0]}" == tests/integration/identity/postgres-root-expiry-installation.test.ts || "${test_files[0]}" == tests/integration/identity/postgres-root-expiry-recovery.test.ts ]]; then
  export OPENPC_PLATFORM_SCOPE_CONTAINER="$container"
fi
if [[ "${test_files[0]}" == tests/integration/identity/postgres-envelope-proposal.test.ts ]]; then
  export OPENPC_ENVELOPE_PROPOSAL_CONTAINER="$container"
fi
for attempt in $(seq 1 60); do
  if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres -d openpc_control >/dev/null 2>&1; then break; fi
  [ "$attempt" -lt 60 ] || exit 1
  sleep 1
done
if [[ "${test_files[0]}" == tests/integration/identity/postgres-runtime-artifact-source.test.ts ]]; then
  lock_slots=$(docker exec "$container" psql -XqAt -v ON_ERROR_STOP=1 -U postgres -d openpc_control -c 'SHOW max_locks_per_transaction')
  [[ "$lock_slots" == 1024 ]] || { echo 'Custody restore lock capacity unavailable' >&2; exit 1; }
  printf 'ISOLATED_CUSTODY_POSTGRES|max_locks_per_transaction=%s|container_memory=1g\n' "$lock_slots"
fi
if [[ "${test_files[0]}" == tests/integration/identity/postgres-evidence-remote-upgrade.test.ts || "${test_files[0]}" == tests/integration/identity/postgres-identity-envelope-signing.test.ts || "${test_files[0]}" == tests/integration/identity/postgres-platform-envelope-scope.test.ts || "${test_files[0]}" == tests/integration/identity/postgres-envelope-proposal.test.ts ]]; then
  # Use unmodified predecessor files through the same installer. Keep today's
  # read-only migration mount on the database for the test's actual upgrade.
  predecessor="$root/predecessor"
  for lane in identity policy control-api; do
    mkdir -p "$predecessor/$lane"
    for path in "$repo/migrations/postgres/$lane/"[0-9][0-9][0-9][0-9]_*.sql; do
      name=${path##*/}
      if [[ "${test_files[0]}" == tests/integration/identity/postgres-evidence-remote-upgrade.test.ts && $lane == control-api && ${name%%_*} > 0081 ]]; then continue; fi
      if [[ "${test_files[0]}" == tests/integration/identity/postgres-identity-envelope-signing.test.ts && $lane == identity && ${name%%_*} > 0104 ]]; then continue; fi
      if [[ "${test_files[0]}" == tests/integration/identity/postgres-platform-envelope-scope.test.ts && $lane == identity && ${name%%_*} > 0105 ]]; then continue; fi
      if [[ "${test_files[0]}" == tests/integration/identity/postgres-envelope-proposal.test.ts && $lane == identity && ${name%%_*} > 0106 ]]; then continue; fi
      cp "$path" "$predecessor/$lane/"
    done
  done
  test -f "$predecessor/control-api/0081_deployment_projection_fence.sql"
  if [[ "${test_files[0]}" == tests/integration/identity/postgres-identity-envelope-signing.test.ts ]]; then
    test -f "$predecessor/identity/0104_runtime_retirement_resume_binding.sql"
    export OPENPC_IDENTITY_ENVELOPE_UPGRADE_CONTAINER="$container"
  fi
  if [[ "${test_files[0]}" == tests/integration/identity/postgres-platform-envelope-scope.test.ts ]]; then
    test -f "$predecessor/identity/0105_burly_praxagora.sql"
  fi
  if [[ "${test_files[0]}" == tests/integration/identity/postgres-envelope-proposal.test.ts ]]; then
    test -f "$predecessor/identity/0106_eminent_rachel_grey.sql"
  fi
  docker run --rm --name "$container-migrate" --memory 128m --memory-swap 128m --cpus 0.5 --pids-limit 64 \
    --network "container:$container" --label "io.openpc.test-owner=$root" \
    -e PGHOST=127.0.0.1 -e PGUSER=postgres -e PGDATABASE=openpc_control \
    -v "$predecessor:/migrations/postgres:ro" -v "$repo/deploy/compose/local/migrate.sh:/local/migrate.sh:ro" \
    -v "$root/secrets:/run/secrets:ro" \
    docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7 \
    sh /local/migrate.sh control > "$root/migrations.log" 2>&1
else
  control_mode=control
  if [[ "${test_files[0]}" == tests/integration/local-runtime/control-installation.test.mjs || ${test_files[0]} == tests/integration/local-runtime/qa-sandbox-postgres.test.mjs ]]; then
    control_mode=control-installation
    export OPENPC_CONTROL_INSTALLATION_TEST_CONTAINER="$container"
  elif [[ ${#test_files[@]} == 1 && ${test_files[0]} == tests/integration/identity/postgres-discovery-approval-resume.test.ts ]]; then
    control_mode=control-installation
  fi
  docker exec -e PGHOST=127.0.0.1 -e PGUSER=postgres -e PGDATABASE=openpc_control "$container" sh /local/migrate.sh "$control_mode" > "$root/migrations.log" 2>&1
fi
platform_login=openpc_test_platform
fact_reader_login=openpc_fact_authority_test_reader
if [[ -f "$repo/migrations/postgres/baseline-v1/install.sql" ]]; then
  # Use the installed actors with the same parent grants. Extra test roles
  # would deliberately violate the compact baseline's frozen role catalogue.
  platform_login=openpc_participant_runtime
  fact_reader_login=openpc_source_control_reader
else
docker exec -i "$container" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d openpc_control <<SQL
CREATE ROLE openpc_test_platform LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$password';
GRANT openpc_control_runtime, openpc_control_platform_runtime TO openpc_test_platform;
CREATE ROLE openpc_fact_authority_test_reader LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$password';
GRANT openpc_control_reader TO openpc_fact_authority_test_reader;
SQL
fi
if [[ "$snapshot_interop" = 1 || "$secret_consumer_interop" = 1 ]]; then
  # Real isolated candidate store for the Fact consumer connection lifecycle.
  # Initial database/role installation only; no candidate or business state seed.
  docker exec -i "$container" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d openpc_control <<'SQL'
CREATE ROLE openpc_candidate_index NOLOGIN;
CREATE DATABASE openpc_candidate_index;
SQL
  docker exec -e PGHOST=127.0.0.1 -e PGUSER=postgres -e PGDATABASE=openpc_candidate_index "$container" sh /local/migrate.sh candidate_index > "$root/candidate-migrations.log" 2>&1
fi
port=$(docker port "$container" 5432/tcp)
port=${port##*:}
export OPENPC_I02_ADMIN_DATABASE_URL="postgresql://postgres:$password@127.0.0.1:$port/openpc_control"
export OPENPC_I02_RUNTIME_DATABASE_URL="postgresql://openpc_identity_runtime:$password@127.0.0.1:$port/openpc_control"
export OPENPC_I02_PLATFORM_RUNTIME_DATABASE_URL="postgresql://$platform_login:$password@127.0.0.1:$port/openpc_control"
export OPENPC_ASTRA05_ADMIN_DATABASE_URL="$OPENPC_I02_ADMIN_DATABASE_URL"
export OPENPC_ASTRA05_RUNTIME_DATABASE_URL="$OPENPC_I02_RUNTIME_DATABASE_URL"
if [[ "$snapshot_interop" = 1 || "$secret_consumer_interop" = 1 ]]; then
  export OPENPC_FACT_CANDIDATE_SESSION_TEST_URL="postgresql://openpc_fact_bridge_reader:$password@127.0.0.1:$port/openpc_candidate_index"
fi
export OPENPC_FACT_WORKLOAD_TEST_READER_URL="postgresql://$fact_reader_login:$password@127.0.0.1:$port/openpc_control"
export OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL="postgresql://openpc_local_control_worker:$password@127.0.0.1:$port/openpc_control"
cd "$repo"
if [ "$source_policy_interop" = 1 ]; then
  cargo test -p openpc-fleet-controller --lib --locked --offline \
    postgres_publication_observation_defers_lifecycle_before_source_or_effect -- --include-ignored | tee "$root/publication-lifecycle-contention.log"
  cargo test -p openpc-fleet-controller --lib --locked --offline \
    postgres_cigl_claim_defers_only_unclaimed_lifecycle_contention -- --include-ignored | tee "$root/cigl-claim-contention.log"
  cargo test -p openpc-fleet-controller --lib --locked --offline \
    postgres_source_policy_resolution_with_initial_reference_rows -- --include-ignored | tee "$root/source-policy-consumer.log"
  exit 0
fi
if [[ "${test_files[0]}" == tests/integration/local-runtime/control-installation.test.mjs || ${test_files[0]} == tests/integration/local-runtime/qa-sandbox-postgres.test.mjs ]]; then
  node --test "${test_files[0]}" | tee "$root/test.log"
elif [[ "${test_files[0]}" == tests/integration/local-runtime/notification-gateway-fixture.test.mjs || "${test_files[0]}" == tests/integration/local-runtime/runtime-fact-initial-trust.test.mjs ]]; then
  node --import tsx --test "${test_files[0]}" | tee "$root/test.log"
elif [[ "${test_files[0]}" == tests/integration/policy/postgres18-runtime.test.ts ]]; then
  # This distinct I02 owner is skipped under the I03 URLs. Select it explicitly
  # with the policy config; the Identity include glob cannot discover this file.
  pnpm exec vitest run --config tests/integration/policy/vitest.config.ts "${test_files[@]}" \
    --testNamePattern 'changes a CIGL binding through governed publication after the preflight fence releases' | tee "$root/test.log"
else
  pnpm exec vitest run --config tests/integration/identity/vitest.config.ts "${test_files[@]}" "${test_filter[@]}" | tee "$root/test.log"
fi
# Initial trust verification is independent of executed provider qualification.
# Keep the latter's missing fixture/owner explicit; this corpus never admits it.
if [[ "${test_files[0]}" == tests/integration/identity/postgres-runtime-artifact-source.test.ts ]]; then
  export OPENPC_RUNTIME_SOURCE_RECOVERY_CONTAINER="$container"
  export OPENPC_RUNTIME_SOURCE_RECOVERY_OWNER="$root"
  cargo test -p openpc-fleet-controller --lib --locked --offline \
    runtime_artifact_source::postgres_tests:: -- --include-ignored --test-threads=1 --nocapture | tee "$root/runtime-source-native.log"
fi
if [[ "${test_files[0]}" == tests/integration/identity/postgres-operations-generation.test.ts ]]; then
  pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-operations-provider-retry-qualification.test.ts \
    --testNamePattern '^verifies installed async trust on the actual scoped transaction without granting qualification$' | tee "$root/async-trust.log"
  pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-operations-provider-retry-probe-source.test.ts \
    --testNamePattern '^denies probe read-action writes under composed installed policies$' | tee "$root/probe-read-action.log"
  pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts tests/integration/identity/postgres-operations-provider-retry-input.test.ts | tee "$root/provider-input.log"
fi
if [ "$envelope_activation_interop" = 1 ]; then
  test -s "$OPENPC_ENVELOPE_ACTIVATION_PUBLIC_FIXTURE"
  cargo test -p pc-policy-core --lib --locked --offline \
    identity_envelope::tests::postgres_envelope_activation_original_wire -- --exact --include-ignored | tee "$root/envelope-native.log"
  rg -q '^test identity_envelope::tests::postgres_envelope_activation_original_wire \.\.\. ok$' "$root/envelope-native.log"
fi
if [ "$snapshot_interop" = 1 ]; then
  test -s "$OPENPC_ASTRA05_PUBLICATION_FIXTURE"
  cargo test -p openpc-runtime-agent --lib --locked --offline \
    postgres_tls_publication_is_admitted_by_the_real_target_identity_owner | tee "$root/identity-consumer.log"
fi
if [ "$target_issuance_interop" = 1 ]; then
  cargo test -p openpc-fleet-controller --lib --locked --offline \
    postgres_first_issue_ -- --include-ignored | tee "$root/target-issuance-consumer.log"
  cargo test -p openpc-fleet-controller --lib --locked --offline \
    postgres_current_read_ -- --include-ignored | tee "$root/target-current-read.log"
  rg -q '^test target_disposition::current_read_tests::postgres_current_read_busy_retry_releases_original_locks \.\.\. ok$' "$root/target-current-read.log"
  rg -q '^test target_disposition::current_read_tests::postgres_current_read_retry_rejects_denial_exhaustion_and_lost_rollback \.\.\. ok$' "$root/target-current-read.log"
fi
if [ "$wallet_interop" = 1 ]; then
  test -s "$OPENPC_ASTRA07_WALLET_PUBLICATION_FIXTURE"
  cargo test -p openpc-runtime-agent --lib --locked --offline \
    governed_wallet_publication_binds_recovered_signer_without_granting_permission | tee "$root/wallet-consumer.log"
fi
if [ "$deployment_interop" = 1 ]; then
  test -s "$OPENPC_ASTRA08_DEPLOYMENT_PUBLICATION_FIXTURE"
  cargo test -p openpc-fleet-controller --lib --locked --offline \
    postgres_published_deployment_compiles_for_the_installed_scope -- --include-ignored | tee "$root/deployment-consumer.log"
  cargo test -p openpc-runtime-agent --lib --locked --offline \
    published_deployment_has_signed_target_custody_after_restart -- --include-ignored | tee "$root/deployment-custody.log"
fi

if [ "$cigl_settings_interop" = 1 ]; then
  test -s "$OPENPC_CIGL_SETTINGS_PUBLICATION_FIXTURE"
  cargo test -p openpc-fleet-controller --lib --locked --offline \
    postgres_cigl_settings_source_requires_exact_public_provenance -- --include-ignored | tee "$root/cigl-settings-consumer.log"
fi
