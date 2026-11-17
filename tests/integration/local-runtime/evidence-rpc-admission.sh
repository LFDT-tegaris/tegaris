# Stable grants and browser setup precede the bounded live Fact/RPC window.
"${compose[@]}" stop runtime-target runtime-envoy >/dev/null
"${compose[@]}" up -d --wait --no-deps --no-build --pull never participant-service
# Install only initial Fact grantability for the already acquired candidate.
node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs "$secret_root" "$evidence_root" "$participant_id" bootstrap-runtime-fact-trust "$privacy_domain_id"
openpc_rpc_fact_input_preflight
openpc_reconcile_fact_bridge_identity "$owned_data" "$participant_id" "$privacy_domain_id" "$owned_data/runtime/tls/ads-client.pem" "$owned_data/runtime/tls/ads-client.key"
node --import tsx tests/integration/local-runtime/evidence-rpc-fact.mjs authentication "$root" "$evidence_root"
openpc_first_policy_actors
rpc_source_generation=${OPENPC_RPC_SOURCE_GENERATION:-2}
[[ $rpc_source_generation =~ ^[0-9]+$ && $rpc_source_generation -ge 2 ]] || exit 96
rpc_source_suffix=''
[[ $rpc_source_generation == 2 ]] || rpc_source_suffix="-$rpc_source_generation"
rpc_acquisition_root="$evidence_root/rpc-acquisition$rpc_source_suffix"
openpc_phase_begin fact-governance
assignment_file="$rpc_acquisition_root/assignment-input.json"
assignment_id="$(fixture_value "$assignment_file" body assignmentId)"
body="$(node -e 'process.stdout.write(JSON.stringify(require(process.argv[1]).body))' "$assignment_file")"
candidate="$(node -e 'process.stdout.write(JSON.stringify(require(process.argv[1]).candidate))' "$assignment_file")"
if [[ ! -e $rpc_acquisition_root/assignment-result.json ]]; then
  approved_identity_mutation "$rpc_acquisition_root/assignment-result.json" "$body" "$candidate" "http://127.0.0.1:8080/v1/participants/$participant_id/assignments" "rpc-fact-assignment-$assignment_id" "$assignment_id" 0 "rpc-fact-$assignment_id" 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
fi
operator_assertion_step_up ACT-PARTICIPANTS_READ_RESOURCE-V1 "$assignment_id" "$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$candidate")" "rpc-fact-grant-read-$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
node --import tsx --input-type=module - "$evidence_root" "$rpc_source_suffix" <<'JS'
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {localOperationId} from './services/identity-service/src/domain/local-operation-id.ts';
const root=process.argv[2],suffix=process.argv[3],load=async p=>JSON.parse(await readFile(root+'/'+p+'.json','utf8'));
const input=await load(`rpc-source${suffix}-policy-input`),actors=await load('deployment-intent-actors'),assignment=await load(`rpc-acquisition${suffix}/assignment-input`);
const response=await fetch(`http://127.0.0.1:8080/v1/participants/${input.participantId}/assignments/${assignment.body.assignmentId}`,{headers:{Authorization:'Bearer '+actors.maker.sessionToken,'OpenPC-Participant-ID':'urn:openpc:participant:'+input.participantId,'OpenPC-Privacy-Domain-ID':'urn:openpc:privacy-domain:'+input.privacyDomainId,'X-Request-ID':localOperationId(),'X-Correlation-ID':localOperationId()}});
assert.equal(response.status,200);const value=(await response.json()).effect;
for(const key of ['principalId','roleId','authorityEnvelopeId','capabilityIds','resourceIds','privacyDomainIds','actionIntentIds','riskClasses','makerCheckerRequired','stepUpRequired','onwardDelegationDepth']) assert.deepEqual(value[key],assignment.body[key]);
assert.equal(value.id,assignment.body.assignmentId);assert.equal(value.state,'ACTIVE');
await writeFile(root+`/rpc-acquisition${suffix}/assignment-readback.json`,JSON.stringify(value),{mode:0o600});
console.log('OPENPC_RPC_FACT_GRANT|PASS|public-approval|exact-workload-candidate|platform-bound');
JS
reader_file="$rpc_acquisition_root/artifact-reader-assignment-input.json"
reader_id="$(fixture_value "$reader_file" body assignmentId)"
reader_body="$(node -e 'process.stdout.write(JSON.stringify(require(process.argv[1]).body))' "$reader_file")"
reader_candidate="$(node -e 'process.stdout.write(JSON.stringify(require(process.argv[1]).candidate))' "$reader_file")"
if [[ ! -e $rpc_acquisition_root/artifact-reader-assignment-result.json ]]; then
  approved_identity_mutation "$rpc_acquisition_root/artifact-reader-assignment-result.json" "$reader_body" "$reader_candidate" "http://127.0.0.1:8080/v1/participants/$participant_id/assignments" "rpc-fact-reader-$reader_id" "$reader_id" 0 "rpc-fact-reader-$reader_id" 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
fi
# Contract simulation reads current roles and envelopes from Participant.
"${compose[@]}" --profile astra05 up -d --wait --no-deps --no-build --pull never participant-service runtime-envoy
# All stable preparation precedes the fresh Fact admission.
node --import tsx tests/integration/local-runtime/evidence-rpc-policy.mjs "$secret_root" "$evidence_root" catalogue
# Browser verification advances the real authenticator counter. Read it back
# before the following action-bound shell assertions.
openpc_first_policy_actors
checker_assertion_step_up ACT-FACT_ARTIFACTS_READ_RESOURCE-V1 "$assignment_id" "$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$candidate")" "rpc-fact-read-$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
operator_assertion_step_up ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1 "$assignment_id" "$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$candidate")" "rpc-fact-admit-$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
openpc_phase_end fact-governance 0
if [[ ${OPENPC_FACT_QUARANTINE_ONLY:-0} == 1 ]]; then
  "${compose[@]}" stop control-worker >/dev/null
  export OPENPC_POLICY_SET_COMPOSE_JSON="$(openpc_compose_json)"
  openpc_phase_begin native-fleet-quarantine
  node --import tsx tests/integration/local-runtime/evidence-fleet-quarantine.mjs "$root" "$evidence_root"
  openpc_phase_end native-fleet-quarantine 0
  openpc_phase_begin source-withdrawal-checkpoint
  node --import tsx tests/integration/local-runtime/evidence-fact-withdrawal-recovery.mjs "$root" "$evidence_root" "$(openpc_compose_json)"
  openpc_phase_end source-withdrawal-checkpoint 0
  return 0
fi
openpc_phase_begin live-authority
export OPENPC_FIRST_POLICY_ACTIVATE=1
export OPENPC_POLICY_SET_COMPOSE_JSON="$(openpc_compose_json)"
node --import tsx tests/integration/local-runtime/evidence-rpc-journey.mjs "$root" "$evidence_root"
openpc_phase_end live-authority 0
target_id="$(node -e 'process.stdout.write(require(process.argv[1]).targetId)' "$evidence_root/discovery-credential-input.json")"
# RPC execution and custody run at the activated boundary before slow final browser/restart checks.
printf 'OPENPC_ISOLATED_RPC|PASS|governed-successor|real-runtime|custody|browser-export\n'
