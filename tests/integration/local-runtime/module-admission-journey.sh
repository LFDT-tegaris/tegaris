#!/usr/bin/env bash
# Sourced by the owned Compose journey after real identity and WebAuthn enrollment.
# Verify manifest and dependency admission before the first install and enable.
module_full_acceptance=${OPENPC_LOCAL_RUNTIME_MODULES_ONLY:-0}
module_create_action=ACT-MODULES_CREATE_RESOURCE-V1
module_create_digest="$(action_digest "$module_create_action")"
module_catalog="$data_root/module-releases/catalog.json"
module_collection() {
  [[ $module_full_acceptance == 1 ]] || return 0
  OPENPC_MODULE_LIST_OPERATOR="$configuration_operator_session" \
  OPENPC_MODULE_LIST_CHECKER="$configuration_checker_session" \
  OPENPC_MODULE_LIST_DENIED="$(local_identity_session viewer)" \
    node --import tsx tests/integration/local-runtime/module-admission-receipts.mjs \
      "$secret_root" "$participant_id" "$privacy_domain_id" "$evidence_root" "collection-$1" "$module_catalog"
}
module_registration_body() {
  node -e '
    const fs=require("fs"),path=require("path");
    const [catalogPath,index,actionIntentId,actionIntentDigest]=process.argv.slice(1);
    const entry=JSON.parse(fs.readFileSync(catalogPath)).releases[Number(index)];
    const manifest=JSON.parse(fs.readFileSync(path.join(path.dirname(catalogPath),entry.manifestBytes)));
    process.stdout.write(JSON.stringify({name:manifest.metadata.id,semanticVersion:manifest.metadata.version,
      manifestDigest:entry.manifestDigest,supportProfile:"R1",actionIntentId,actionIntentDigest,
      reason:"Register a verified local release without activating runtime authority."}));
  ' "$module_catalog" "$1" "$module_create_action" "$module_create_digest"
}
module_selection="$(node tests/integration/local-runtime/module-release-selection.mjs "$module_catalog")"
read -r -a module_indices <<< "$module_selection"
module_release_count=${#module_indices[@]}
if [[ $module_full_acceptance == 1 ]]; then test "$module_release_count" = 25; fi
module_collection empty
module_last_index=${module_indices[${#module_indices[@]}-1]}
if [[ $module_full_acceptance == 1 ]]; then
module_forged_body="$(node -e 'const body=JSON.parse(process.argv[1]);body.signerState="ACTIVE";body.state="ACTIVE";body.dependencyClosed=true;process.stdout.write(JSON.stringify(body));' "$(module_registration_body 0)")"
configuration_post "$evidence_root/module-caller-authority-denied.json" "$module_forged_body" \
  http://127.0.0.1:8080/api/v1/modules module-caller-authority-0001 '' POST 400
module_missing_body="$(node -e 'const body=JSON.parse(process.argv[1]);body.reason="Reject registration before its exact dependencies are admitted.";process.stdout.write(JSON.stringify(body));' "$(module_registration_body "$module_last_index")")"
approved_configuration_post "$evidence_root/module-missing-dependency.json" "$module_missing_body" \
  http://127.0.0.1:8080/api/v1/modules module-missing-dependency-0001 '' POST 39 403
node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1]));if(p.code!=="PC-MODULE-7001")throw Error(JSON.stringify(p));' \
  "$evidence_root/module-missing-dependency.json"
test "$(printf '%s\n' 'select count(*) from control.module_installation;' | \
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -U openpc_control -d openpc_control)" = 0

fi

for module_index in "${module_indices[@]}"; do
  module_body="$(module_registration_body "$module_index")"
  module_output="$evidence_root/module-admission-$module_index.json"
  # A retained committed response is reconciled through public readback below.
  # Failed or ambiguous output is not a checkpoint and requires diagnosis.
  if [[ ! -f $module_output ]] || ! node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));process.exit(v.state==="SUCCEEDED"&&typeof v.resourceRef==="string"?0:1)' "$module_output"; then
    if [[ $module_index == "${OPENPC_LOCAL_MODULE_RESUME_INDEX:-0}" && ( $module_full_acceptance == 1 || -n ${OPENPC_LOCAL_MODULE_RESUME_INDEX:-} ) ]]; then
      # Real approval first; the browser waits for its unmodified proof expiry,
      # resumes the same intent, then commits and reconciles its original key.
      approved_configuration_post "$module_output" "$module_body" \
        http://127.0.0.1:8080/api/v1/modules "module-admission-$module_index-0001" '' POST "module-admission-$module_index" 202 1 approve-only
      node --input-type=module - "$evidence_root" "$operator_principal_id" "$operator_credential_id" "$operator_private_key_path" \
        "$checker_principal_id" "$checker_credential_id" "$checker_private_key_path" <<'JS'
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
const [root,makerId,makerCredential,makerKey,checkerId,checkerCredential,checkerKey]=process.argv.slice(2);
await writeFile(join(root,'deployment-intent-actors.json'),JSON.stringify({
  maker:{principalId:makerId,credentialId:makerCredential,privateKeyPath:makerKey},
  checker:{principalId:checkerId,credentialId:checkerCredential,privateKeyPath:checkerKey},
}),{mode:0o600});
JS
      module_resume_approval="$(operation_field "${module_output%.json}-approval.json" resourceRef)"
      node --import tsx tests/integration/local-runtime/approval-resume-browser.mjs \
        "$secret_root" "$evidence_root" "$participant_id" "$privacy_domain_id" "${module_resume_approval##*:}" "$project" --wait-for-expiry
      configuration_operator_session="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1])).maker.sessionToken)' "$evidence_root/deployment-intent-actors.json")"
      configuration_checker_session="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1])).checker.sessionToken)' "$evidence_root/deployment-intent-actors.json")"
      checker_session_id="${configuration_checker_session#*.}"
      next_operator_sign_count="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1])).maker.nextSignCount)' "$evidence_root/deployment-intent-actors.json")"
      next_checker_sign_count="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1])).checker.nextSignCount)' "$evidence_root/deployment-intent-actors.json")"
    else
    approved_configuration_post "$module_output" "$module_body" \
      http://127.0.0.1:8080/api/v1/modules "module-admission-$module_index-0001" '' POST "module-admission-$module_index"
    fi
  fi
  module_urn="$(operation_field "$module_output" resourceRef)"
  policy_get "$evidence_root/module-read-$module_index.json" \
    "http://127.0.0.1:8080/api/v1/modules/$module_urn" "$configuration_operator_session"
  node -e '
    const assert=require("assert/strict"),fs=require("fs");
    const module=JSON.parse(fs.readFileSync(process.argv[1])),request=JSON.parse(process.argv[2]);
    assert.equal(module.name,request.name);assert.equal(module.manifestDigest,request.manifestDigest);
    assert.equal(module.state,"REGISTERED");assert.equal(module.revision,"1");
    assert.deepEqual(Object.keys(module).sort(),["moduleId","name","semanticVersion","manifestDigest","state","supportProfile","revision","createdAt","updatedAt"].sort());
  ' "$evidence_root/module-read-$module_index.json" "$module_body"
  if [[ "$module_index" == 0 && $module_full_acceptance == 1 ]]; then
    for module_boundary in participant privacy; do
      module_scope_participant="$participant_id"
      module_scope_privacy="$privacy_domain_id"
      if [ "$module_boundary" = participant ]; then
        module_scope_participant=018f0000-0000-7000-8000-000000000102
      else
        module_scope_privacy=018f0000-0000-7000-8000-000000000202
      fi
      module_denied_status="$(curl -sS -o "$evidence_root/module-$module_boundary-denied.json" -w '%{http_code}' \
        -H "Cookie: __Host-openpc_session=$configuration_operator_session" -H 'OpenPC-API-Version: 1' \
        -H "OpenPC-Participant-ID: urn:openpc:participant:$module_scope_participant" \
        -H "OpenPC-Privacy-Domain-ID: urn:openpc:privacy-domain:$module_scope_privacy" \
        -H "X-Request-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
        -H "X-Correlation-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
        "http://127.0.0.1:8080/api/v1/modules/$module_urn")"
      test "$module_denied_status" = 403
      node -e 'const p=require("fs").readFileSync(process.argv[1],"utf8");if(p.includes("manifestDigest")||p.includes("pc.foundation.kernel"))throw Error("module disclosure");' \
        "$evidence_root/module-$module_boundary-denied.json"
    done
  fi
  if [[ $module_full_acceptance == 1 ]]; then
  configuration_post "$evidence_root/module-replay-$module_index.json" "$module_body" \
    http://127.0.0.1:8080/api/v1/modules "module-admission-$module_index-0001"
  assert_json_equal "$module_output" "$evidence_root/module-replay-$module_index.json"
  fi
done

module_collection registered
module_durable_state="$(printf '%s\n' \
  "select count(*)||'|'||count(*) filter(where installation.state='ADMITTED' and installation.active_manifest_digest is null and configuration.active=false and configuration.generation=1 and installation.admission_dependency_digest is not null and version.release_payload_cbor is not null) from control.module_installation installation join control.module_version version using(module_version_id) join control.module_configuration_generation configuration using(module_installation_id) where installation.participant_id=:'participant_id' and installation.privacy_domain_id=:'privacy_domain_id';" | \
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -U openpc_control -d openpc_control \
      -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id")"
test "$module_durable_state" = "$module_release_count|$module_release_count"
node --import tsx tests/integration/local-runtime/module-admission-receipts.mjs \
  "$secret_root" "$participant_id" "$privacy_domain_id" "$evidence_root" admitted "$module_catalog"
if [[ $module_full_acceptance == 1 ]]; then
"${compose[@]}" restart policy-service control-api >/dev/null
"${compose[@]}" up -d --wait policy-service control-api >/dev/null
module_collection restart-registered
for module_index in "${module_indices[@]}"; do
  module_urn="$(operation_field "$evidence_root/module-admission-$module_index.json" resourceRef)"
  policy_get "$evidence_root/module-restart-$module_index.json" \
    "http://127.0.0.1:8080/api/v1/modules/$module_urn" "$configuration_operator_session"
  assert_json_equal "$evidence_root/module-read-$module_index.json" "$evidence_root/module-restart-$module_index.json"
done
node --import tsx tests/integration/local-runtime/module-admission-receipts.mjs \
  "$secret_root" "$participant_id" "$privacy_domain_id" "$evidence_root" admitted "$module_catalog"
printf 'OPENPC_MODULE_ADMISSION|PASS|signed_release=%s|approval=public|step_up=webauthn|missing_dependency=denied|scope=isolated|effect=inert|replay=idempotent|restart=readback\n' "$module_release_count"

fi

# Initial lifecycle reuses these admitted identities and ordinary public
# candidates, approvals and authenticators. No module state is seeded.
module_lifecycle_command() {
  local index=$1 path=$2 expected=${3:-202} suffix=${4:-main} module_urn module_read body etag action output
  module_urn="$(operation_field "$evidence_root/module-admission-$index.json" resourceRef)"
  module_read="$evidence_root/module-$path-$index-$suffix-before.json"
  policy_get "$module_read" "http://127.0.0.1:8080/api/v1/modules/$module_urn" "$configuration_operator_session"
  action=ACT-MODULE_CREATE_INSTALL-V1
  if [[ $path == activate ]]; then action=ACT-MODULE_ACTIVATE_RESOURCE-V1; fi
  body="$(node -e 'const fs=require("fs"),c=require("crypto"),m=JSON.parse(fs.readFileSync(process.argv[1])),hash=v=>"sha256:"+c.createHash("sha256").update(JSON.stringify(v,Object.keys(v).sort())).digest("hex");process.stdout.write(JSON.stringify({actionIntentId:process.argv[2],actionIntentDigest:process.argv[3],targetRef:m.moduleId,expectedRevision:m.revision,inputDigest:hash({targetRef:m.moduleId,expectedRevision:m.revision,manifestDigest:m.manifestDigest}),reason:`Govern the exact initial module generation: ${process.argv[4]} ${process.argv[5]}.`}));' "$module_read" "$action" "$(action_digest "$action")" "$path" "$suffix")"
  etag="\"$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$(node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));process.stdout.write(JSON.stringify({resourceId:v.moduleId.split(":").at(-1),revision:v.revision}))' "$module_read")")\""
  output="$evidence_root/module-$path-$index-$suffix.json"
  approved_configuration_post "$output" "$body" "http://127.0.0.1:8080/api/v1/modules/$module_urn/$path" \
    "module-$path-$index-$suffix-0001" "$etag" POST "module-$path-$index-$suffix" "$expected"
  if [[ $expected != 202 ]]; then return; fi
  if [[ $module_full_acceptance == 1 ]]; then
  configuration_post "${output%.json}-replay.json" "$body" "http://127.0.0.1:8080/api/v1/modules/$module_urn/$path" \
    "module-$path-$index-$suffix-0001" "$etag" POST 202
  assert_json_equal "$output" "${output%.json}-replay.json"
  configuration_post "${output%.json}-altered-replay.json" "$(node -e 'const v=JSON.parse(process.argv[1]);v.reason="Altered module lifecycle replay";process.stdout.write(JSON.stringify(v));' "$body")" \
    "http://127.0.0.1:8080/api/v1/modules/$module_urn/$path" "module-$path-$index-$suffix-0001" "$etag" POST 412
  fi
  policy_get "${output%.json}-read.json" "http://127.0.0.1:8080/api/v1/modules/$module_urn" "$configuration_operator_session"
  node -e 'const a=require("assert/strict"),fs=require("fs"),before=JSON.parse(fs.readFileSync(process.argv[1])),after=JSON.parse(fs.readFileSync(process.argv[2]));a.equal(after.moduleId,before.moduleId);a.equal(after.manifestDigest,before.manifestDigest);a.equal(BigInt(after.revision),BigInt(before.revision)+1n);a.equal(after.state,process.argv[3]==="install"?"INSTALLED":"ACTIVE");' "$module_read" "${output%.json}-read.json" "$path"
}
if [[ $module_full_acceptance == 1 ]]; then module_lifecycle_command "$module_last_index" install 403 early-dependent; fi
for module_index in "${module_indices[@]}"; do
  module_lifecycle_command "$module_index" install
done
test "$(printf '%s\n' "select count(*) from control.module_installation i join control.module_configuration_generation c using(module_installation_id) where i.participant_id=:'participant_id' and i.privacy_domain_id=:'privacy_domain_id' and i.state='INSTALLED_DISABLED' and i.active_manifest_digest is null and c.active=false;" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id")" = "$module_release_count"
module_collection installed
if [[ $module_full_acceptance == 1 ]]; then module_lifecycle_command "$module_last_index" activate 403 early-dependent; fi
for module_index in "${module_indices[@]}"; do
  module_lifecycle_command "$module_index" activate
done
module_collection active
if [[ $module_full_acceptance == 1 ]]; then
"${compose[@]}" restart policy-service control-api >/dev/null
"${compose[@]}" up -d --wait --no-build --pull never policy-service control-api >/dev/null
module_collection restart-active
for module_index in "${module_indices[@]}"; do
  module_urn="$(operation_field "$evidence_root/module-admission-$module_index.json" resourceRef)"
  policy_get "$evidence_root/module-active-restart-$module_index.json" "http://127.0.0.1:8080/api/v1/modules/$module_urn" "$configuration_operator_session"
  assert_json_equal "$evidence_root/module-activate-$module_index-main-read.json" "$evidence_root/module-active-restart-$module_index.json"
done
printf 'OPENPC_MODULE_INITIAL_LIFECYCLE|PASS|closure=%s|install=inert|enable=exact-generation|approval=public|step-up=webauthn|early-dependent=denied|replay=exact|restart=readback\n' "$module_release_count"
else
  printf 'OPENPC_MODULE_LIFECYCLE_SETUP|PASS|closure=%s|public-admission-install-enable|accepted-regressions=reused\n' "$module_release_count"
fi
node --import tsx tests/integration/local-runtime/module-admission-receipts.mjs \
  "$secret_root" "$participant_id" "$privacy_domain_id" "$evidence_root" enabled "$module_catalog"
