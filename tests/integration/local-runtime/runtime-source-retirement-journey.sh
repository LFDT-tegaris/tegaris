# Sourced only after the original public disposition and native denial pass.
# Native recovery only observes committed retirement. Approval recovery preserves
# the original intent and obtains a successor only through its public owner.
openpc_require_inputs root compose worker_container participant_id privacy_domain_id evidence_root
retirement_journey() {
  node --import tsx tests/integration/local-runtime/runtime-source-retirement-journey.mjs "$1" "$root" "$(openpc_compose_json)" "${@:2}"
}
retirement_output="$evidence_root/runtime-source-disposition/physical-retirement"
retirement_resume=${OPENPC_RUNTIME_SOURCE_RETIREMENT_RESUME:-}
[[ -z $retirement_resume || $retirement_resume == native || $retirement_resume == approval ]] || return 96
if [[ -z $retirement_resume ]]; then
  node --import tsx tests/integration/local-runtime/runtime-source-disposition-selection.mjs "$root" "$retention_urn" original retirement
  retirement_journey plan
  retirement_action=ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1
  retirement_body="$(node - "$retirement_output/plan.json" "$participant_id" "$(action_digest "$retirement_action")" <<'JS'
const fs=require('node:fs'),[file,participant,actionIntentDigest]=process.argv.slice(2),plan=JSON.parse(fs.readFileSync(file));
process.stdout.write(JSON.stringify({participantId:`urn:openpc:participant:${participant}`,selection:plan.selection,beforeDigest:plan.beforeDigest,
actionIntentId:'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1',actionIntentDigest,
reason:'Retire the withdrawn original input while preserving its signed archive and ordered successor.'}));
JS
)"
  retirement_journey validate-body "$retirement_body"
  approved_configuration_post "$retirement_output/admission.json" "$retirement_body" \
    http://127.0.0.1:8080/api/v1/evidence-deletions/runtime-batches runtime-source-retirement-0001 '' POST runtime-source-retirement
  retirement_journey effect before-replay
  configuration_post "$retirement_output/replay.json" "$retirement_body" \
    http://127.0.0.1:8080/api/v1/evidence-deletions/runtime-batches runtime-source-retirement-0001
  assert_json_equal "$retirement_output/admission.json" "$retirement_output/replay.json"
  retirement_journey effect after-replay
elif [[ $retirement_resume == approval ]]; then
  node --import tsx tests/integration/local-runtime/runtime-source-retirement-recovery.mjs resume "$root" "$(openpc_compose_json)"
fi
node --import tsx tests/integration/local-runtime/runtime-source-retirement-recovery.mjs committed "$root"
retirement_journey verify native
retirement_journey continuation
"${compose[@]}" restart control-worker control-api >/dev/null
"${compose[@]}" up -d --wait --no-deps --no-build --pull never control-worker control-api >/dev/null
openpc_verify_running_images control-worker control-api
retirement_journey verify restart
