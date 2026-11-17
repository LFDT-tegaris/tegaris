# Public contract configuration and exact read capability for the first-policy scope.
openpc_phase_begin rpc-configuration
"${compose[@]}" stop runtime-target runtime-envoy >/dev/null
"${compose[@]}" up -d --wait --no-deps --no-build --pull never participant-service
openpc_first_policy_actors
node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs "$secret_root" "$evidence_root" "$participant_id" bootstrap-runtime-read-trust "$privacy_domain_id"
for definition in 'abi ABI_ARTIFACTS abi-artifacts' 'logical LOGICAL_CONTRACT_ASSETS logical-contract-assets' 'binding CONTRACT_RUNTIME_BINDINGS contract-runtime-bindings' 'rules TYPED_ARGUMENT_RULE_VERSIONS typed-argument-rule-versions' 'method CONTRACT_METHOD_POLICIES contract-method-policies'; do
  read -r item family route <<< "$definition"
  node --import tsx tests/integration/local-runtime/evidence-rpc-policy-input.mjs "$item" "$evidence_root" "$(action_digest "ACT-${family}_CREATE_RESOURCE-V1")"
  input_file="$evidence_root/rpc-$item-input.json"
  output_file="$evidence_root/rpc-$item-operation.json"
  body="$(node -e 'process.stdout.write(JSON.stringify(require(process.argv[1]).body))' "$input_file")"
  if [[ ! -e $output_file ]]; then
    approved_configuration_post "$output_file" "$body" "http://127.0.0.1:8080/api/v1/$route" "evidence-rpc-$privacy_domain_id-$item-distinct-v1" '' POST "rpc-distinct-$privacy_domain_id-$item"
  fi
  resource="$(operation_field "$output_file" resourceRef)"
  operator_assertion_step_up "ACT-${family}_READ_RESOURCE-V1" "${resource##*:}" "$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$body")" "rpc-read-$item-$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  configuration_get "$evidence_root/rpc-$item-resource.json" "http://127.0.0.1:8080/api/v1/$route/$resource"
  printf 'OPENPC_RPC_CONFIGURATION|PASS|%s|public-governance-readback\n' "$item"
done
node --import tsx tests/integration/local-runtime/evidence-rpc-policy-input.mjs assignment "$evidence_root"
assignment_file="$evidence_root/rpc-assignment-input.json"
assignment_id="$(fixture_value "$assignment_file" body assignmentId)"
body="$(node -e 'process.stdout.write(JSON.stringify(require(process.argv[1]).body))' "$assignment_file")"
candidate="$(node -e 'process.stdout.write(JSON.stringify(require(process.argv[1]).candidate))' "$assignment_file")"
if [[ ! -e $evidence_root/rpc-assignment-result.json ]]; then
  approved_identity_mutation "$evidence_root/rpc-assignment-result.json" "$body" "$candidate" "http://127.0.0.1:8080/v1/participants/$participant_id/assignments" "evidence-rpc-assignment-$assignment_id" "$assignment_id" 0 "rpc-$assignment_id" 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
fi
operator_assertion_step_up ACT-PARTICIPANTS_READ_RESOURCE-V1 "$assignment_id" "$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$candidate")" "rpc-assignment-read-$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
node --input-type=module - "$evidence_root" <<'JS'
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
const root=process.argv[2],load=async name=>JSON.parse(await readFile(root+'/'+name+'.json','utf8'));
const input=await load('policy-set-input'),actors=await load('deployment-intent-actors'),assignment=await load('rpc-assignment-input');
const response=await fetch(`http://127.0.0.1:8080/v1/participants/${input.participantId}/assignments/${assignment.body.assignmentId}`,{headers:{Authorization:'Bearer '+actors.maker.sessionToken,'OpenPC-Participant-ID':'urn:openpc:participant:'+input.participantId,'OpenPC-Privacy-Domain-ID':'urn:openpc:privacy-domain:'+input.privacyDomainId,'X-Request-ID':randomUUID(),'X-Correlation-ID':randomUUID()}});
assert.equal(response.status,200);const readback=await response.json(),value=readback.effect;assert.equal(value.id,assignment.body.assignmentId);assert.equal(value.state,'ACTIVE');assert.deepEqual(value.capabilityIds,['CALL_RESULT_DISCLOSURE']);assert.deepEqual(value.resourceIds,assignment.body.resourceIds);assert.deepEqual(value.privacyDomainIds,[input.privacyDomainId]);
await writeFile(root+'/rpc-assignment-readback.json',JSON.stringify(value),{mode:0o600});
console.log('OPENPC_RPC_CONFIGURATION|PASS|one-workload-one-binding|public-assignment|no-runtime-publication');
JS
openpc_phase_end rpc-configuration 0
source tests/integration/local-runtime/evidence-rpc-source-journey.sh
