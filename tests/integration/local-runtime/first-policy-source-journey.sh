# Sourced by the first-policy journey after governed target discovery.
fixture() {
 local label=$1 provider=$2 indexer=$3 projection=$4
 docker exec -e OPENPC_LOCAL_FIXTURE_SCOPE "$worker_container" /usr/local/bin/openpc-control-worker local-fixture "$provider" "$indexer" "$projection" "$workload_id" > "$evidence_root/$label-base.json"
 node - "$evidence_root/$label-base.json" "$owned_data/provider-probe-source/$label-base.cbor" <<'JS'
const fs=require('node:fs');const [input,path]=process.argv.slice(2);const data=JSON.parse(fs.readFileSync(input));
fs.writeFileSync(`${path}.next`,Buffer.from(data.configurationCborHex,'hex'),{mode:0o444});fs.renameSync(`${path}.next`,path);
JS
 docker exec "$worker_container" /usr/local/bin/openpc-control-worker local-indexer-input "/provider-sources/$label-base.cbor" "$indexer" "$projection" "$provider" /provider-sources/acquisition.json 1 1 > "$evidence_root/$label.json"
}
# Continue only the original durable intent; never manufacture fresh keys.
existing_configuration() {
 local output=$1 action=$2 key=$3 retained
 retained="$(printf '%s\n' "select terminal_state||'|'||(result_payload->>'operationId') from control.idempotency_record where participant_id=:'pid' and privacy_domain_id=:'privacy' and principal_id=:'principal' and action_intent_id=:'action' and idempotency_key=:'key';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v pid="$participant_id" -v privacy="$privacy_domain_id" -v principal="$operator_principal_id" -v action="$action" -v key="$key")" || exit 95
 [[ -n $retained ]] || return 1
 [[ $retained == COMMITTED\|* && $retained != *$'\n'* ]] || exit 95
 configuration_get "$output" "http://127.0.0.1:8080/api/v1/operations/${retained#*|}" || exit 95
 poll_configuration_operation "${retained#*|}" "$output" || exit 95
 return 0
}
# A supplied identity selects an already completed public renewal; it grants no readiness.
if [[ -n ${OPENPC_FIRST_POLICY_PROVIDER_OPERATION:-} ]]; then
  [[ $OPENPC_FIRST_POLICY_PROVIDER_OPERATION =~ ^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || return 96
  provider_urn=$(operation_field "$evidence_root/configuration-provider.json" resourceRef)
  indexer_urn=$(operation_field "$evidence_root/configuration-indexer.json" resourceRef)
  projection_urn=$(operation_field "$evidence_root/configuration-projection.json" resourceRef)
  provider_id=${provider_urn##*:}; indexer_id=${indexer_urn##*:}; projection_id=${projection_urn##*:}
  configuration_fixture=$(cat "$evidence_root/source-configuration.json")
  fixture source-resume-preflight "$provider_id" "$indexer_id" "$projection_id"
  node - "$evidence_root/source-configuration.json" "$evidence_root/source-resume-preflight.json" <<'JS'
const fs=require('node:fs'),a=require('node:assert/strict');const [before,current]=process.argv.slice(2).map(p=>JSON.parse(fs.readFileSync(p)));
for(const field of ['providerArtifactDigest','indexerArtifactDigest','projectionArtifactDigest','configurationCborHex'])a.equal(current[field],before[field]);
JS
else
fixture source-preflight 018f0000-0000-7000-8000-000000008181 018f0000-0000-7000-8000-000000008182 018f0000-0000-7000-8000-000000008183
initial_configuration_fixture="$(cat "$evidence_root/source-preflight.json")"
printf 'OPENPC_BOOTSTRAP_SOURCE_INPUT|PASS|real-packaged-parser|isolated-scope|external-TLS|no-business-write\n'

indexer_action=ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1
indexer_action_digest="$(action_digest "$indexer_action")"
indexer_body="{\"participantId\":\"urn:openpc:participant:$participant_id\",\"actionIntentId\":\"$indexer_action\",\"actionIntentDigest\":\"$indexer_action_digest\",\"reason\":\"Local client indexer profile.\",\"engine\":\"CLIENT_INDEXER\",\"engineVersion\":\"1.0.0\",\"methodProfileDigest\":\"$(json_value "$initial_configuration_fixture" indexerArtifactDigest)\"}"
indexer_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$indexer_body")"
if ! existing_configuration "$evidence_root/configuration-indexer.json" "$indexer_action" configuration-indexer-create-0001; then
configuration_post "$evidence_root/configuration-indexer.json" "$indexer_body" \
  http://127.0.0.1:53003/api/v1/indexer-profiles configuration-indexer-create-0001
fi
test "$(operation_field "$evidence_root/configuration-indexer.json" state)" = SUCCEEDED
indexer_urn="$(operation_field "$evidence_root/configuration-indexer.json" resourceRef)"
indexer_id="${indexer_urn##*:}"
configuration_get "$evidence_root/configuration-indexer-resource.json" \
  "http://127.0.0.1:53003/api/v1/indexer-profiles/$indexer_urn"
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.indexerProfileId!==process.argv[2]||v.authority!=="CANDIDATE_ONLY"||v.state!=="REGISTERED"||v.revision!=="1")process.exit(1)' \
  "$evidence_root/configuration-indexer-resource.json" "$indexer_urn"

provider_action=ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1
provider_action_digest="$(action_digest "$provider_action")"
provider_body="{\"participantId\":\"urn:openpc:participant:$participant_id\",\"actionIntentId\":\"$provider_action\",\"actionIntentDigest\":\"$provider_action_digest\",\"reason\":\"Local qualified provider profile.\",\"chainId\":\"31337\",\"endpointSecretRef\":\"urn:openpc:secret:018f0000-0000-7000-8000-000000000930\",\"behaviorFingerprint\":\"$(json_value "$initial_configuration_fixture" providerArtifactDigest)\"}"
provider_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$provider_body")"
if ! existing_configuration "$evidence_root/configuration-provider.json" "$provider_action" configuration-provider-create-0001; then
approved_configuration_post "$evidence_root/configuration-provider.json" "$provider_body" \
  http://127.0.0.1:53003/api/v1/provider-profiles configuration-provider-create-0001 "" POST 1
fi
test "$(operation_field "$evidence_root/configuration-provider.json" state)" = SUCCEEDED
provider_urn="$(operation_field "$evidence_root/configuration-provider.json" resourceRef)"
provider_id="${provider_urn##*:}"
configuration_get "$evidence_root/configuration-provider-resource.json" \
  "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn"
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.providerProfileId!==process.argv[2]||v.authority!=="NEVER_GRANTS"||v.state!=="REGISTERED"||v.revision!=="1")process.exit(1)' \
  "$evidence_root/configuration-provider-resource.json" "$provider_urn"

projection_action=ACT-PROJECTION_PLANS_CREATE_RESOURCE-V1
projection_action_digest="$(action_digest "$projection_action")"
projection_body="{\"actionIntentId\":\"$projection_action\",\"actionIntentDigest\":\"$projection_action_digest\",\"reason\":\"Local projection plan.\",\"indexerProfileId\":\"$indexer_urn\",\"planDigest\":\"$(json_value "$initial_configuration_fixture" projectionArtifactDigest)\",\"readiness\":\"UNKNOWN\"}"
projection_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$projection_body")"
if ! existing_configuration "$evidence_root/configuration-projection.json" "$projection_action" configuration-projection-create-0001; then
configuration_post "$evidence_root/configuration-projection.json" "$projection_body" \
  http://127.0.0.1:53003/api/v1/projection-plans configuration-projection-create-0001
fi
projection_urn="$(operation_field "$evidence_root/configuration-projection.json" resourceRef)"
projection_id="${projection_urn##*:}"

fixture source-configuration "$provider_id" "$indexer_id" "$projection_id"
node --input-type=module - "$root" "$(openpc_compose_json)" "$openpc_network_gateway" <<'JS'
import {importOriginalSource} from './tests/integration/local-runtime/runtime-source-import-journey.mjs';
const [root,command,gateway]=process.argv.slice(2);
await importOriginalSource({root,compose:JSON.parse(command),gateway});
JS
worker_container="$("${compose[@]}" ps -q control-worker)"
configuration_fixture="$(cat "$evidence_root/source-configuration.json")"
fi
if [[ -n ${OPENPC_FIRST_POLICY_PROVIDER_OPERATION:-} ]]; then
  provider_operation_id=$OPENPC_FIRST_POLICY_PROVIDER_OPERATION
  poll_configuration_operation "$provider_operation_id" "$evidence_root/configuration-provider-renewed-operation.json"
  node - "$evidence_root/configuration-provider-renewed-operation.json" "$provider_urn" "$provider_operation_id" <<'JS'
const fs=require('node:fs'),a=require('node:assert/strict'),v=JSON.parse(fs.readFileSync(process.argv[2]));
a.equal(v.operationId,process.argv[4]);a.equal(v.resourceRef,process.argv[3]);a.equal(v.actionIntentId,'ACT-PROVIDER_APPROVE_QUALIFICATION-V1');a.equal(v.state,'SUCCEEDED');
JS
  configuration_get "$evidence_root/configuration-provider-renewed-qualified-resource.json" "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn"
  node tests/integration/local-runtime/provider-probe-readback.mjs "$secret_root" "$owned_data" "$provider_id" "$provider_operation_id" current "$(operation_field "$evidence_root/configuration-provider-renewed-qualified-resource.json" revision)"
else
provider_qualify_action=ACT-PROVIDER_APPROVE_QUALIFICATION-V1
provider_qualification_output="$evidence_root/configuration-provider-qualified.json"
if [[ -s $evidence_root/configuration-provider-qualified-approval.json ]]; then
  provider_qualification_output="$evidence_root/configuration-provider-qualified-resumed.json"
fi
if ! existing_configuration "$provider_qualification_output" "$provider_qualify_action" configuration-provider-qualify-0001; then
provider_qualify_digest="$(action_digest "$provider_qualify_action")"
for probe_poll in $(seq 1 90); do
  configuration_get "$evidence_root/configuration-provider-observed.json" \
    "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn"
  if node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));process.exit(v.state==="SHADOW"&&v.revision==="2"?0:1)' \
    "$evidence_root/configuration-provider-observed.json"; then break; fi
  if [ "$probe_poll" = 90 ]; then echo 'Live provider observation did not publish' >&2; exit 1; fi
  sleep 1
done
provider_qualify_body="{\"actionIntentId\":\"$provider_qualify_action\",\"actionIntentDigest\":\"$provider_qualify_digest\",\"reason\":\"Review live local provider observation.\",\"targetRef\":\"$provider_urn\",\"expectedRevision\":\"2\",\"inputDigest\":\"$(json_value "$configuration_fixture" providerArtifactDigest)\"}"
if [[ -s $evidence_root/configuration-provider-qualified-approval.json ]]; then
  resume_approved_configuration "$provider_qualification_output" "$provider_qualify_body" "$provider_qualify_body" \
    "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn/qualify" \
    configuration-provider-qualify-0001 "$provider_id" \
    "$(operation_field "$evidence_root/configuration-provider-qualified-approval.json" resourceRef)" provider-qualification 2
else
approved_configuration_post "$evidence_root/configuration-provider-qualified.json" "$provider_qualify_body" \
  "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn/qualify" \
  configuration-provider-qualify-0001 \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$provider_id" 2)" POST 2
fi
fi
provider_operation_id="$(operation_field "$provider_qualification_output" operationId)"
poll_configuration_operation "$provider_operation_id" "$evidence_root/configuration-provider-operation.json"
configuration_get "$evidence_root/configuration-provider-qualified-resource.json" \
  "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn"
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.state!=="QUALIFIED"||v.revision!=="4")process.exit(1)' \
  "$evidence_root/configuration-provider-qualified-resource.json"
node tests/integration/local-runtime/provider-probe-readback.mjs "$secret_root" "$owned_data" "$provider_id"

fi

indexer_admit_action=ACT-INDEXER_APPROVE_PROFILE-V1
if ! existing_configuration "$evidence_root/configuration-indexer-admitted.json" "$indexer_admit_action" configuration-indexer-admit-0001; then
configuration_get "$evidence_root/configuration-indexer-admission-source.json" "http://127.0.0.1:53003/api/v1/indexer-profiles/$indexer_urn"
node - "$evidence_root/configuration-indexer-admission-source.json" "$indexer_urn" "$(json_value "$configuration_fixture" indexerArtifactDigest)" <<'JS'
const fs=require('node:fs'),a=require('node:assert/strict'),v=JSON.parse(fs.readFileSync(process.argv[2]));
a.equal(v.indexerProfileId,process.argv[3]);a.equal(v.state,'REGISTERED');a.equal(v.revision,'1');a.equal(v.methodProfileDigest,process.argv[4]);
JS
indexer_admit_digest="$(action_digest "$indexer_admit_action")"
indexer_admit_body="{\"actionIntentId\":\"$indexer_admit_action\",\"actionIntentDigest\":\"$indexer_admit_digest\",\"reason\":\"Admit local indexer profile.\",\"targetRef\":\"$indexer_urn\",\"expectedRevision\":\"1\",\"inputDigest\":\"$(json_value "$configuration_fixture" indexerArtifactDigest)\"}"
approved_configuration_post "$evidence_root/configuration-indexer-admitted.json" "$indexer_admit_body" \
  "http://127.0.0.1:53003/api/v1/indexer-profiles/$indexer_urn/admit" \
  configuration-indexer-admit-0001 \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$indexer_id" 1)" POST 3
fi
indexer_operation_id="$(operation_field "$evidence_root/configuration-indexer-admitted.json" operationId)"
poll_configuration_operation "$indexer_operation_id" "$evidence_root/configuration-indexer-operation.json"

projection_recover_action=ACT-INDEXER_RECOVER_PLAN-V1
if ! existing_configuration "$evidence_root/configuration-projection-validated.json" "$projection_recover_action" configuration-projection-recover-0001; then
configuration_get "$evidence_root/configuration-projection-recovery-source.json" "http://127.0.0.1:53003/api/v1/projection-plans/$projection_urn"
node - "$evidence_root/configuration-projection-recovery-source.json" "$projection_urn" "$(json_value "$configuration_fixture" projectionArtifactDigest)" <<'JS'
const fs=require('node:fs'),a=require('node:assert/strict'),v=JSON.parse(fs.readFileSync(process.argv[2]));
a.equal(v.projectionPlanId,process.argv[3]);a.equal(v.state,'DRAFT');a.equal(v.revision,'1');a.equal(v.planDigest,process.argv[4]);a.equal(v.readiness,'UNKNOWN');
JS
projection_recover_digest="$(action_digest "$projection_recover_action")"
projection_recover_body="{\"actionIntentId\":\"$projection_recover_action\",\"actionIntentDigest\":\"$projection_recover_digest\",\"reason\":\"Validate local projection plan.\",\"targetRef\":\"$projection_urn\",\"expectedRevision\":\"1\",\"inputDigest\":\"$(json_value "$configuration_fixture" projectionArtifactDigest)\"}"
projection_recover_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$projection_recover_body")"
configuration_post "$evidence_root/configuration-projection-validated.json" "$projection_recover_body" \
  "http://127.0.0.1:53003/api/v1/projection-plans/$projection_urn/recover" \
  configuration-projection-recover-0001 \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$projection_id" 1)"
fi
projection_operation_id="$(operation_field "$evidence_root/configuration-projection-validated.json" operationId)"
poll_configuration_operation "$projection_operation_id" "$evidence_root/configuration-projection-operation.json"


configuration_get "$evidence_root/configuration-indexer-qualified-resource.json" "http://127.0.0.1:8080/api/v1/indexer-profiles/$indexer_urn"
configuration_get "$evidence_root/configuration-projection-validated-resource.json" "http://127.0.0.1:8080/api/v1/projection-plans/$projection_urn"
node --import tsx tests/integration/local-runtime/first-policy-source-readback.mjs "$root" "${OPENPC_FIRST_POLICY_PROVIDER_OPERATION:-}"
