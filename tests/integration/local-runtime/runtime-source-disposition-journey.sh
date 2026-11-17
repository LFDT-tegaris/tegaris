# Sourced after real module enablement and workload discovery. The initial
# indexer is not qualified; importing it does not create runtime/Fact work.
openpc_require_inputs root compose worker_container participant_id privacy_domain_id evidence_root
source_journey() {
  node --import tsx tests/integration/local-runtime/runtime-source-disposition-journey.mjs "$1" "$root" "$(openpc_compose_json)" "${@:2}"
}
source_case=${OPENPC_RUNTIME_SOURCE_DISPOSITION_CASE:-original}
[[ $source_case == original || $source_case == live-replay ]] || return 96
source_disposition_evidence="$evidence_root/runtime-source-disposition"
source_key_prefix=runtime-source
if [[ $source_case == live-replay ]]; then
  [[ -z ${OPENPC_RUNTIME_SOURCE_DISPOSITION_RESUME:-} ]] || return 96
  source_disposition_evidence+=/live-replay
  source_key_prefix=runtime-source-live-replay
fi
source_disposition_restart() {
  "${compose[@]}" restart control-worker control-api >/dev/null
  "${compose[@]}" up -d --wait --no-deps --no-build --pull never control-worker control-api >/dev/null
  openpc_verify_running_images control-worker control-api
  configuration_get "$source_disposition_evidence/restart-readback.json" "http://127.0.0.1:8080/api/v1/evidence-deletions/runtime-sources/$disposition_urn"
  assert_json_equal "$native_readback" "$source_disposition_evidence/restart-readback.json"
  source_journey verify "$source_disposition_evidence/restart-readback.json"
}
# Recovery reads the committed original without replaying its expired authority.
if [[ ${OPENPC_RUNTIME_SOURCE_DISPOSITION_RESUME:-} == restart ]]; then
  disposition_urn="$(operation_field "$source_disposition_evidence/admission.json" resourceRef)"
  native_readback="$source_disposition_evidence/restart-before.json"
  configuration_get "$native_readback" "http://127.0.0.1:8080/api/v1/evidence-deletions/runtime-sources/$disposition_urn"
  source_journey verify "$native_readback"
  source_disposition_restart
  return
fi
if [[ ${OPENPC_RUNTIME_SOURCE_DISPOSITION_RESUME:-} == governed || ${OPENPC_RUNTIME_SOURCE_DISPOSITION_RESUME:-} == native ]]; then
  node --import tsx tests/integration/local-runtime/runtime-source-disposition-recovery.mjs committed "$root"
  retention_urn="$(operation_field "$source_disposition_evidence/retention-recovered.json" resourceRef)"
elif [[ ${OPENPC_RUNTIME_SOURCE_DISPOSITION_RESUME:-} == archived ]]; then
  node --import tsx tests/integration/local-runtime/runtime-source-disposition-recovery.mjs resume "$root"
  retention_urn="$(operation_field "$source_disposition_evidence/retention-recovered.json" resourceRef)"
else
  [[ -z ${OPENPC_RUNTIME_SOURCE_DISPOSITION_RESUME:-} ]] || return 96
source_journey fixture preflight 018f0000-0000-7000-8000-000000008182 -
indexer_action=ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1
indexer_body="$(node - "$source_disposition_evidence/preflight.json" "$participant_id" "$(action_digest "$indexer_action")" <<'JS'
const fs=require('node:fs'),[file,participant,actionIntentDigest]=process.argv.slice(2),v=JSON.parse(fs.readFileSync(file));
process.stdout.write(JSON.stringify({participantId:`urn:openpc:participant:${participant}`,actionIntentId:'ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1',actionIntentDigest,
reason:'Register the indexer input before adding its projection.',engine:'CLIENT_INDEXER',engineVersion:'1.0.0',methodProfileDigest:v.indexerArtifactDigest}));
JS
)"
configuration_post "$source_disposition_evidence/indexer.json" "$indexer_body" \
  http://127.0.0.1:8080/api/v1/indexer-profiles "${source_key_prefix}-indexer-0001"
indexer_urn="$(operation_field "$source_disposition_evidence/indexer.json" resourceRef)"
source_journey fixture old "${indexer_urn##*:}" -
source_journey import old

# A separate meaningful public resource extends the source. The new bytes
# deselect the original through the installed importer, never a direct UPDATE.
projection_action=ACT-PROJECTION_PLANS_CREATE_RESOURCE-V1
projection_body="$(node - "$source_disposition_evidence/preflight.json" "$indexer_urn" "$(action_digest "$projection_action")" <<'JS'
const fs=require('node:fs'),[file,indexerProfileId,actionIntentDigest]=process.argv.slice(2),v=JSON.parse(fs.readFileSync(file));
process.stdout.write(JSON.stringify({actionIntentId:'ACT-PROJECTION_PLANS_CREATE_RESOURCE-V1',actionIntentDigest,reason:'Add a projection to the registered indexer source.',indexerProfileId,planDigest:v.projectionArtifactDigest,readiness:'UNKNOWN'}));
JS
)"
configuration_post "$source_disposition_evidence/projection.json" "$projection_body" \
  http://127.0.0.1:8080/api/v1/projection-plans "${source_key_prefix}-projection-0001"
projection_urn="$(operation_field "$source_disposition_evidence/projection.json" resourceRef)"
source_journey fixture successor "${indexer_urn##*:}" "${projection_urn##*:}"
source_journey import successor
source_journey archive

if [[ $source_case == live-replay ]]; then
  node --import tsx tests/integration/local-runtime/runtime-source-disposition-recovery.mjs committed "$root"
  retention_urn="$(operation_field "$evidence_root/runtime-source-disposition/retention-recovered.json" resourceRef)"
else
retention_action=ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1
retention_body="$(node - "$participant_id" "$(action_digest "$retention_action")" <<'JS'
const [participant,actionIntentDigest]=process.argv.slice(2);
process.stdout.write(JSON.stringify({participantId:`urn:openpc:participant:${participant}`,actionIntentId:'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1',actionIntentDigest,
reason:'Require durable source archive before runtime artifact retirement.',predecessorPolicyId:null,
policy:{dataClass:'RUNTIME_ARTIFACT',policyVersion:'1.0.0',retentionPeriodMs:'0',localGraceMs:'0',sinkQuorum:1,deletionMode:'ROW_DELETE',makerCheckerRequired:true}}));
JS
)"
approved_configuration_post "$source_disposition_evidence/retention.json" "$retention_body" \
  http://127.0.0.1:8080/api/v1/retention-policies runtime-source-retention-0001 '' POST runtime-source-retention
retention_urn="$(operation_field "$source_disposition_evidence/retention.json" resourceRef)"
fi
fi
if [[ ${OPENPC_RUNTIME_SOURCE_DISPOSITION_RESUME:-} != native ]]; then
node --import tsx tests/integration/local-runtime/runtime-source-disposition-selection.mjs "$root" "$retention_urn" "$source_case"
source_journey plan successor "$retention_urn"
source_journey plan old "$retention_urn"
fi
disposition_action=ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1
disposition_body="$(node - "$source_disposition_evidence/old-plan.json" "$participant_id" "$(action_digest "$disposition_action")" <<'JS'
const fs=require('node:fs'),[file,participant,actionIntentDigest]=process.argv.slice(2),v=JSON.parse(fs.readFileSync(file));
process.stdout.write(JSON.stringify({participantId:`urn:openpc:participant:${participant}`,selection:v.selection,actionIntentId:'ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1',actionIntentDigest,reason:'Permanently withdraw the unused superseded source while retaining its archive.'}));
JS
)"
if [[ ${OPENPC_RUNTIME_SOURCE_DISPOSITION_RESUME:-} != native ]]; then
approved_configuration_post "$source_disposition_evidence/admission.json" "$disposition_body" \
  http://127.0.0.1:8080/api/v1/evidence-deletions/runtime-sources "${source_key_prefix}-disposition-0001" '' POST "${source_key_prefix}-disposition"
# The original WebAuthn proof must still be live for exact replay.
source_journey effect before-replay
configuration_post "$source_disposition_evidence/replay.json" "$disposition_body" \
  http://127.0.0.1:8080/api/v1/evidence-deletions/runtime-sources "${source_key_prefix}-disposition-0001"
assert_json_equal "$source_disposition_evidence/admission.json" "$source_disposition_evidence/replay.json"
source_journey effect after-replay
else
# A committed disposition already denied new use. Its exact public owner must
# authenticate the saved operation before observing native reconciliation.
disposition_urn="$(operation_field "$source_disposition_evidence/admission.json" resourceRef)"
configuration_get "$source_disposition_evidence/native-resume-before.json" "http://127.0.0.1:8080/api/v1/evidence-deletions/runtime-sources/$disposition_urn"
source_journey reconcile "$source_disposition_evidence/native-resume-before.json"
fi
disposition_urn="$(operation_field "$source_disposition_evidence/admission.json" resourceRef)"
native_readback="$source_disposition_evidence/native-readback.json"
if [[ ${OPENPC_RUNTIME_SOURCE_DISPOSITION_RESUME:-} == native ]]; then
  native_readback="$source_disposition_evidence/native-reconciled-readback.json"
fi
for source_poll in $(seq 1 120); do
  configuration_get "$native_readback" "http://127.0.0.1:8080/api/v1/evidence-deletions/runtime-sources/$disposition_urn"
  if node -e 'const v=JSON.parse(require("node:fs").readFileSync(process.argv[1]));process.exit(v.nativeState==="DENIED"?0:1)' "$native_readback"; then break; fi
  [[ $source_poll != 120 ]] || return 96
  sleep 0.25
done
source_journey verify "$native_readback"
source_disposition_restart
