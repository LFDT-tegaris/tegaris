#!/usr/bin/env bash
# Existing clean runtime gate: real public commands, mTLS Identity, target PDS,
# global address custody and Broker. Only the external chain is controlled.
with_deployment_actors() {
  local operator_principal_id checker_principal_id operator_credential_id checker_credential_id
  local operator_private_key_path checker_private_key_path configuration_operator_session configuration_checker_session
  local next_operator_sign_count next_checker_sign_count checker_session_id
  operator_principal_id="$(fixture_value "$evidence_root/deployment-intent-actors.json" maker principalId)"
  checker_principal_id="$(fixture_value "$evidence_root/deployment-intent-actors.json" checker principalId)"
  operator_credential_id="$(fixture_value "$evidence_root/deployment-intent-actors.json" maker credentialId)"
  checker_credential_id="$(fixture_value "$evidence_root/deployment-intent-actors.json" checker credentialId)"
  operator_private_key_path="$(fixture_value "$evidence_root/deployment-intent-actors.json" maker privateKeyPath)"
  checker_private_key_path="$(fixture_value "$evidence_root/deployment-intent-actors.json" checker privateKeyPath)"
  configuration_operator_session="$(fixture_value "$evidence_root/deployment-intent-actors.json" maker sessionToken)"
  configuration_checker_session="$(fixture_value "$evidence_root/deployment-intent-actors.json" checker sessionToken)"
  checker_session_id="${configuration_checker_session#*.}"
  next_operator_sign_count="$(printf '%s\n' "select authenticator_sign_count+1 from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v credential_id="$operator_credential_id")"
  next_checker_sign_count="$(printf '%s\n' "select authenticator_sign_count+1 from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v credential_id="$checker_credential_id")"
  "$@"
}

prepare_deployment_submission() {
  "${compose[@]}" up -d --wait --no-build --pull never participant-service >/dev/null
  openpc_wait_participant_gateway
  node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs "$secret_root" "$evidence_root" "$participant_id"
  with_deployment_actors prepare_deployment_submission_authority
  # Policy browser checks and Participant writes are complete. Subsequent
  # public commands route directly to Identity, Policy and Control API owners.
  openpc_report_container_memory authority-ready $("${compose[@]}" ps -q participant-service admin-web)
  "${compose[@]}" stop participant-service admin-web >/dev/null
}

prepare_deployment_submission_authority() {
  local wallet_body wallet_candidate delegation_id delegation_body delegation_candidate parent_id deployment_policy_ids
  deployment_execution_wallet_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  wallet_body="$(node -e 'const fs=require("fs"),[path,walletBindingId]=process.argv.slice(1),w=JSON.parse(fs.readFileSync(path));process.stdout.write(JSON.stringify({walletBindingId,subjectId:"018f0000-0000-7000-8000-000000000190",chainId:"31337",walletAddress:w.sender}));' "$evidence_root/deployment-wallet.json" "$deployment_execution_wallet_id")"
  wallet_candidate="$(node -e 'process.stdout.write(JSON.stringify({...JSON.parse(process.argv[1]),participantId:process.argv[2]}))' "$wallet_body" "$participant_id")"
  approved_identity_mutation "$evidence_root/deployment-execution-wallet.json" "$wallet_body" "$wallet_candidate" \
    http://127.0.0.1:8080/v1/identity/wallet-bindings deployment-execution-wallet-0001 "$deployment_execution_wallet_id" 0 deployment-execution-wallet 201
  parent_id="$(fixture_value "$evidence_root/deployment-intent-actors.json" maker runtimeAssignmentId)"
  deployment_policy_ids="$(node -e 'const fs=require("fs"),root=process.argv[1];process.stdout.write(JSON.stringify(["","-CREATE","-CREATE2","-CREATE3"].map(s=>JSON.parse(fs.readFileSync(`${root}/configuration-deployment${s}-policy-resource.json`)).deploymentPolicyId.split(":").at(-1))));' "$evidence_root")"
  for capability in SIGNED_TRANSACTION_SUBMISSION OPERATION_STATUS_DISCLOSURE; do
    delegation_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
    delegation_body="$(node -e 'const [delegationId,parentId,capability,resource]=process.argv.slice(1);process.stdout.write(JSON.stringify({delegationId,parentId,granteeId:"018f0000-0000-7000-8000-000000000190",scopeDigest:"sha256:"+require("crypto").createHash("sha256").update(delegationId).digest("hex"),privacyDomainIds:["018f0000-0000-7000-8000-000000000201"],actionIntentIds:[],capabilityIds:[capability],resourceIds:capability==="SIGNED_TRANSACTION_SUBMISSION"?JSON.parse(resource).sort():["*"],riskClasses:["HIGH"],validFrom:new Date(Date.now()-60000).toISOString(),validUntil:"2030-01-01T00:00:00.000Z",makerCheckerRequired:false,stepUpRequired:false,onwardDelegationDepth:0}));' "$delegation_id" "$parent_id" "$capability" "$deployment_policy_ids")"
    delegation_candidate="$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({id:v.delegationId,participantId:process.argv[2],grantorId:process.argv[3],state:"ACTIVE",delegationEpoch:"0",...v}));' "$delegation_body" "$participant_id" "$operator_principal_id")"
    approved_identity_mutation "$evidence_root/deployment-$capability.json" "$delegation_body" "$delegation_candidate" \
      "http://127.0.0.1:8080/v1/participants/$participant_id/delegations" "deployment-$capability-0001" "$delegation_id" 0 "deployment-$capability" 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
  done
}

deployment_status() {
  local output=$1 expected=${2:-200} body status
  # Governance between observations can consume the lease checked at phase
  # entry. Renew through the public owner before this independent status read.
  if [[ $expected == 200 ]]; then deployment_require_runtime_window; fi
  refresh_runtime_assertion "$evidence_root/deployment-runtime-identity.json" || return
  body="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"pc_getOperationStatus\",\"params\":[\"urn:openpc:operation:$deployment_command_id\"]}"
  status="$(curl -sS --tlsv1.3 --tls-max 1.3 --cacert "$secret_root/identity_mtls_ca.pem" \
    --cert "$secret_root/identity_mtls_rotated_cert.pem" --key "$secret_root/identity_mtls_rotated_key.pem" \
    -H 'Content-Type: application/json' -H "x-openpc-identity-assertion: $runtime_assertion_hex" \
    --data "$body" -o "$output" -w '%{http_code}' https://localhost:18545/rpc)"
  if [[ $status != "$expected" ]]; then
    printf 'OPENPC_DEPLOYMENT_STATUS|FAIL|output=%s|expected=%s|actual=%s\n' "$output" "$expected" "$status" >&2
    cat "$output" >&2
    return 1
  fi
}

deployment_management_result() {
  local expected=$1 output="$evidence_root/deployment-$deployment_case-management-$1.json" actual=''
  for _ in {1..60}; do
    configuration_get "$output" "http://127.0.0.1:53003/api/v1/deployment-submissions/$deployment_submission_urn"
    actual="$(operation_field "$output" state)"
    [[ $actual == "$expected" ]] && break
    sleep 0.5
  done
  test "$actual" = "$expected"
  configuration_get "$output-operation.json" "http://127.0.0.1:53003/api/v1/operations/$deployment_command_id"
  node -e '
    const fs=require("fs"),assert=require("assert/strict"),[path,walletPath,expected,noSend]=process.argv.slice(1),v=JSON.parse(fs.readFileSync(path)),op=JSON.parse(fs.readFileSync(`${path}-operation.json`)),w=JSON.parse(fs.readFileSync(walletPath));
    assert.equal(v.state,expected);assert.equal(op.state,expected);assert.equal(op.truthState,v.truthState);assert.equal(v.runtimePermission,"NONE");
    if(noSend==="true") {assert.equal(expected,"FAILED");assert.equal(v.truthState,"FAILED");for(const field of ["attempt","occurrence","invalidation","association"])assert.equal(v[field],null);assert.equal(v.associationCurrent,false);}
    else {
    assert.equal(v.attempt.signedTransactionHash,w.transactionHash.slice(2));assert.equal(v.attempt.attemptOrdinal,1);assert.equal(v.attempt.automaticRetryAllowed,false);
    if(expected==="SUCCEEDED") {assert.equal(v.occurrence.derivedContractAddress,w.expectedAddress);assert.equal(v.occurrence.finality,"FINALIZED");if(w.mechanism==="CREATE3"){assert.equal(v.occurrence.creationMechanism,"CREATE3");assert.equal(v.occurrence.childCreationAttempts,2);}assert.equal(v.association.occurrenceDigest,v.occurrence.semanticDigest);assert.equal(v.association.controllerGeneration,1);assert.equal(v.association.state,"ACTIVE");assert.equal(v.associationCurrent,true);assert.equal(v.invalidation,null);}
    else {assert.equal(v.occurrence,null);assert.equal(v.association.state,"SUSPENDED_REORG");assert.equal(v.associationCurrent,false);assert.equal(v.invalidation.occurrenceDigest,v.association.occurrenceDigest);}
    }
    if(/private|logs|initCode|signedTransaction\"/.test(JSON.stringify(v)))throw Error("private result disclosure");
  ' "$output" "$deployment_wallet_path" "$expected" "${2:-false}"
}

deployment_installed_expiry() {
  docker exec "$("${compose[@]}" ps -q runtime-target)" cat "/runtime/agent/$target_id/activation.json" |
    cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- --lifetime
}

deployment_fact_remaining_ms() {
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])),until=Number(v.freshUntilMs);if(v.outcome!=="PRESENT"||!Number.isSafeInteger(until))throw Error("fact freshness unavailable");process.stdout.write(String(until-Date.now()));' \
    "${deployment_fact_path:-$evidence_root/typed-policy-fact.json}"
}

deployment_provider_remaining_ms() {
  local remaining
  remaining="$(printf '%s\n' "select floor(extract(epoch from (observation.valid_until-clock_timestamp()))*1000)::bigint from control.provider_profile provider join control.provider_probe_observation observation on observation.observation_id=provider.qualification_observation_id and observation.provider_profile_id=provider.provider_profile_id where provider.provider_profile_id=:'provider_id' and provider.participant_id=:'participant_id' and provider.privacy_domain_id=:'privacy_domain_id';" | \
    docker exec -i "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control \
      -v provider_id="$provider_id" -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id")"
  [[ $remaining =~ ^-?[0-9]+$ ]] || { echo 'Provider qualification lifetime unavailable' >&2; return 1; }
  printf '%s' "$remaining"
}

deployment_refresh_provider_qualification() {
  local prefix revision fingerprint body observed
  prefix="deployment-provider-renew-$deployment_runtime_renewals"
  configuration_get "$evidence_root/$prefix-before.json" "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn"
  revision="$(operation_field "$evidence_root/$prefix-before.json" revision)"
  fingerprint="$(operation_field "$evidence_root/$prefix-before.json" behaviorFingerprint)"
  body="$(node -e 'const [actionIntentDigest,expectedRevision,replacementDigest]=process.argv.slice(1);process.stdout.write(JSON.stringify({actionIntentId:"ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1",actionIntentDigest,expectedRevision,replacementDigest,reason:"Obtain a fresh provider observation and independent qualification without extending old proof."}));' "$(action_digest ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1)" "$revision" "$fingerprint")"
  approved_configuration_post "$evidence_root/$prefix-reset.json" "$body" \
    "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn" "$prefix-reset-0001" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$provider_id" "$revision")" PATCH "$prefix-reset"
  observed=''
  for _ in {1..90}; do
    configuration_get "$evidence_root/$prefix-observed.json" "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn"
    observed="$(operation_field "$evidence_root/$prefix-observed.json" state)"
    [[ $observed == SHADOW ]] && break
    sleep 1
  done
  [[ $observed == SHADOW ]]
  revision="$(operation_field "$evidence_root/$prefix-observed.json" revision)"
  body="$(node -e 'const [actionIntentDigest,targetRef,expectedRevision,inputDigest]=process.argv.slice(1);process.stdout.write(JSON.stringify({actionIntentId:"ACT-PROVIDER_APPROVE_QUALIFICATION-V1",actionIntentDigest,targetRef,expectedRevision,inputDigest,reason:"Approve the fresh independently acquired provider observation."}));' "$(action_digest ACT-PROVIDER_APPROVE_QUALIFICATION-V1)" "$provider_urn" "$revision" "$fingerprint")"
  approved_configuration_post "$evidence_root/$prefix-qualified.json" "$body" \
    "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn/qualify" "$prefix-qualify-0001" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$provider_id" "$revision")" POST "$prefix-qualify"
  configuration_get "$evidence_root/$prefix-after.json" "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn"
  [[ $(operation_field "$evidence_root/$prefix-after.json" state) == QUALIFIED ]]
  (( $(deployment_provider_remaining_ms) >= 300000 ))
  printf 'OPENPC_DEPLOYMENT_PROVIDER_RENEWAL|PASS|fresh-live-probe|public-approval-qualification|original-expiry-preserved\n'
}

deployment_publication_remaining_ms() {
  node -e 'const fs=require("fs"),root=process.argv[1],deadlines=["","-CREATE","-CREATE2","-CREATE3"].map(s=>Date.parse(JSON.parse(fs.readFileSync(`${root}/configuration-deployment${s}-policy-resource.json`)).definition.expiresAt));if(deadlines.some(v=>!Number.isFinite(v)))throw Error("deployment publication lifetime unavailable");process.stdout.write(String(Math.min(...deadlines)-Date.now()));' "$evidence_root"
}

deployment_delegate_renewed_policies() {
  local delegation_id parent_id deployment_policy_ids body candidate prefix participant_was_running
  participant_was_running=$("${compose[@]}" ps --status running -q participant-service)
  # Delegation routes to Participant Service, which observation normally stops.
  "${compose[@]}" up -d --wait --no-deps --no-build --pull never participant-service >/dev/null
  openpc_wait_participant_gateway
  prefix="deployment-policy-renew-$deployment_runtime_renewals"
  delegation_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  parent_id="$(fixture_value "$evidence_root/deployment-intent-actors.json" maker runtimeAssignmentId)"
  deployment_policy_ids="$(node -e 'const fs=require("fs"),root=process.argv[1];process.stdout.write(JSON.stringify(["","-CREATE","-CREATE2","-CREATE3"].map(s=>JSON.parse(fs.readFileSync(`${root}/configuration-deployment${s}-policy-resource.json`)).deploymentPolicyId.split(":").at(-1))));' "$evidence_root")"
  body="$(node -e 'const [delegationId,parentId,resource]=process.argv.slice(1);process.stdout.write(JSON.stringify({delegationId,parentId,granteeId:"018f0000-0000-7000-8000-000000000190",scopeDigest:"sha256:"+require("crypto").createHash("sha256").update(delegationId).digest("hex"),privacyDomainIds:["018f0000-0000-7000-8000-000000000201"],actionIntentIds:[],capabilityIds:["SIGNED_TRANSACTION_SUBMISSION"],resourceIds:JSON.parse(resource).sort(),riskClasses:["HIGH"],validFrom:new Date(Date.now()-60000).toISOString(),validUntil:"2030-01-01T00:00:00.000Z",makerCheckerRequired:false,stepUpRequired:false,onwardDelegationDepth:0}));' "$delegation_id" "$parent_id" "$deployment_policy_ids")"
  candidate="$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({id:v.delegationId,participantId:process.argv[2],grantorId:process.argv[3],state:"ACTIVE",delegationEpoch:"0",...v}));' "$body" "$participant_id" "$operator_principal_id")"
  approved_identity_mutation "$evidence_root/$prefix-delegation.json" "$body" "$candidate" \
    "http://127.0.0.1:8080/v1/participants/$participant_id/delegations" "$prefix-delegation-0001" "$delegation_id" 0 "$prefix-delegation" 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
  if [[ -z $participant_was_running ]]; then "${compose[@]}" stop participant-service >/dev/null; fi
}

deployment_refresh_publications() {
  local prefix renewal_root suffix name body urn
  local suffixes=('')
  if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_ONLY:-0} != 1 ]]; then suffixes+=(-CREATE -CREATE2 -CREATE3); fi
  prefix="deployment-policy-renew-$deployment_runtime_renewals"
  renewal_root="$evidence_root/$prefix"
  mkdir -m 700 "$renewal_root"
  for suffix in "${suffixes[@]}"; do
    name="configuration-deployment$suffix-policy-resource.json"
    cp "$evidence_root/$name" "$renewal_root/original-$name"
    body="$(node -e 'const fs=require("fs"),[path,actionIntentDigest]=process.argv.slice(1),v=JSON.parse(fs.readFileSync(path)).definition,m=/^(\d+)\.(\d+)\.(\d+)$/.exec(v.profileVersion);if(!m||Number(m[3])>=1000)throw Error("deployment publication version rejected");v.profileVersion=`${m[1]}.${m[2]}.${Number(m[3])+1}`;v.expiresAt=new Date(Date.now()+3600000).toISOString();process.stdout.write(JSON.stringify({actionIntentId:"ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1",actionIntentDigest,reason:"Publish a fresh bounded deployment policy version; preserve the expired original.",definition:v}));' "$renewal_root/original-$name" "$(action_digest ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1)")"
    approved_configuration_post "$renewal_root/command$suffix.json" "$body" \
      http://127.0.0.1:53003/api/v1/deployment-policies "$prefix$suffix-0001" '' POST "$prefix$suffix"
    urn="$(operation_field "$renewal_root/command$suffix.json" resourceRef)"
    configuration_get "$renewal_root/$name" "http://127.0.0.1:53003/api/v1/deployment-policies/$urn"
    node -e 'const fs=require("fs"),assert=require("assert/strict"),[a,b]=process.argv.slice(1).map(p=>JSON.parse(fs.readFileSync(p)));assert.notEqual(a.deploymentPolicyId,b.deploymentPolicyId);assert.ok(Date.parse(b.definition.expiresAt)>Date.parse(a.definition.expiresAt));delete a.definition.expiresAt;delete b.definition.expiresAt;delete a.definition.profileVersion;delete b.definition.profileVersion;assert.deepEqual(a.definition,b.definition);' "$renewal_root/original-$name" "$renewal_root/$name"
  done
  # Switch only the harness's source references after every public publication
  # succeeds. Original rows and their immutable deadlines remain intact.
  for suffix in "${suffixes[@]}"; do
    name="configuration-deployment$suffix-policy-resource.json"
    cp "$renewal_root/$name" "$evidence_root/$name"
  done
  if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_ONLY:-0} == 1 ]]; then
    printf 'OPENPC_CIGL_DEPLOYMENT_SOURCE_RENEWAL|PASS|new-immutable-version|public-approval|original-expiry-preserved\n'
    return
  fi
  with_deployment_actors deployment_delegate_renewed_policies
  deployment_direct_urn="$(operation_field "$evidence_root/configuration-deployment-policy-resource.json" deploymentPolicyId)"
  case "${deployment_case:-direct}" in
    CREATE|CREATE2|CREATE3) deployment_urn="$(operation_field "$evidence_root/configuration-deployment-$deployment_case-policy-resource.json" deploymentPolicyId)" ;;
    *) deployment_urn=$deployment_direct_urn ;;
  esac
  printf 'OPENPC_DEPLOYMENT_PUBLICATION_RENEWAL|PASS|new-immutable-versions|public-approval|exact-restricted-workload-delegation|original-expiry-preserved\n'
}

deployment_refresh_runtime_sources() {
  local remaining provider_remaining publication_remaining
  remaining="$(deployment_fact_remaining_ms)"
  provider_remaining="$(deployment_provider_remaining_ms)"
  publication_remaining="$(deployment_publication_remaining_ms)"
  (( remaining < 300000 || provider_remaining < 300000 || publication_remaining < 300000 )) || return 0
  local operator_principal_id checker_principal_id operator_credential_id checker_credential_id
  local operator_private_key_path checker_private_key_path configuration_operator_session configuration_checker_session
  local next_operator_sign_count next_checker_sign_count checker_session_id
  operator_principal_id="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator principalId)"
  checker_principal_id="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker principalId)"
  operator_credential_id="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator credentialId)"
  checker_credential_id="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker credentialId)"
  operator_private_key_path="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator privateKeyPath)"
  checker_private_key_path="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker privateKeyPath)"
  configuration_operator_session="$(local_identity_session operator)"
  configuration_checker_session="$(local_identity_session viewer)"
  checker_session_id="${configuration_checker_session#*.}"
  next_operator_sign_count="$(printf '%s\n' "select authenticator_sign_count+1 from control.credential where credential_id=:'credential_id';" | docker exec -i "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$operator_credential_id")"
  next_checker_sign_count="$(printf '%s\n' "select authenticator_sign_count+1 from control.credential where credential_id=:'credential_id';" | docker exec -i "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$checker_credential_id")"
  if (( provider_remaining < 300000 )); then deployment_refresh_provider_qualification; fi
  deployment_runtime_owner_session=$configuration_operator_session
  if (( publication_remaining < 300000 )); then deployment_refresh_publications; fi
  (( remaining < 300000 || publication_remaining < 300000 )) || return 0
  deployment_refresh_fact
}

deployment_refresh_fact() {
  local sequence renewal_root
  sequence="$(node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])),m=/^astra04-membership-generation-([1-9][0-9]*)$/.exec(v.generationId);if(!m||Number(m[1])>=1000)throw Error("fact source sequence rejected");process.stdout.write(String(Number(m[1])+1));' "${deployment_fact_path:-$evidence_root/typed-policy-fact.json}")"
  renewal_root="$evidence_root/fact-renewal-$sequence"
  mkdir -m 700 "$renewal_root"
  # Preserve the original simulation and source evidence. Only immutable inputs
  # needed by the existing authoring/simulation owner travel into this renewal.
  local source
  local sources=(configuration-contract-read-resource.json configuration-contract-method-resource.json configuration-deployment-policy-resource.json deployment-wallet.json)
  if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_ONLY:-0} == 1 ]]; then
    sources+=(configuration-contract-read-b-resource.json)
  else
    sources+=(configuration-deployment-CREATE-policy-resource.json configuration-deployment-CREATE2-policy-resource.json configuration-deployment-CREATE3-policy-resource.json)
  fi
  for source in "${sources[@]}"; do
    cp "$evidence_root/$source" "$renewal_root/$source"
  done
  local evidence_root=$renewal_root typed_policy_input typed_policy_body
  cargo run --quiet --locked --offline -p openpc-fact-service --example policy_simulation_fixture -- \
    "$secret_root" "$participant_id" "$privacy_domain_id" admit "$sequence" > "$evidence_root/typed-policy-fact.json"
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs prepare \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session" "$((sequence - 1))"
  typed_policy_input="$(<"$evidence_root/typed-policy-inputs.json")"
  typed_policy_body="$(node -e 'const input=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({policySetId:"urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920",semanticVersion:input.semanticVersion,normalizedPolicyDigest:input.semanticDigest,dependencyClosureDigest:input.dependencyDigest,actionIntentId:"ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1",actionIntentDigest:process.argv[2],reason:"Publish a fresh admitted source observation without extending old fact authority."}));' "$typed_policy_input" "$(action_digest ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1)")"
  policy_mutation "$evidence_root/typed-policy-version.json" "$typed_policy_body" \
    http://127.0.0.1:8080/api/v1/policy-versions "deployment-fact-version-$sequence-0001" "$configuration_operator_session"
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs simulate \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  refresh_runtime_assertion "$evidence_root/deployment-runtime-identity.json"
  publish_runtime_policy "deployment-fact-$sequence"
  deployment_runtime_owner_session=$configuration_operator_session
  deployment_fact_path="$renewal_root/typed-policy-fact.json"
  if [[ -n ${cigl_renewal_occurrence_ref:-} ]]; then
    printf 'OPENPC_CIGL_FACT_RENEWAL|PASS|sequence=%s|fresh-admission|approved-published-source|profiled-activation-pending\n' "$sequence"
  else
    printf 'OPENPC_DEPLOYMENT_FACT_RENEWAL|PASS|sequence=%s|fresh-admission|public-policy-approval-publication-activation|original-expiry-preserved\n' "$sequence"
  fi
}

deployment_renew_runtime() {
  local renewal_path="$evidence_root/deployment-renew-$((deployment_runtime_renewals + 1))"
  # Expired Identity material must not be extended by the harness. Authenticate
  # again, then use the existing public target-update owner for a fresh capsule.
  node -e 'const delay=Math.max(0,Number(BigInt(process.argv[1])/1000000n)-Date.now()+100);if(delay>60000)throw Error("unexpected identity lifetime");setTimeout(()=>{},delay);' "$deployment_runtime_expiry_ns"
  if [[ -n ${deployment_command_id:-} ]]; then
    deployment_status "$renewal_path-expired-status.json" 403
    node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.error?.data?.pcCode!=="PC-RUNTIME-3001"||v.error?.data?.truthState!=="DENIED")throw Error("expired lease did not fail closed");' "$renewal_path-expired-status.json"
  fi
  deployment_reactivate_runtime
}

deployment_wait_fresh_identity() {
  local output=$1 deadline=$((SECONDS + 65))
  # The owner may renew its head before the previous snapshot expires. Poll
  # actual authenticated publications; sleeping until old expiry can miss it.
  while (( SECONDS < deadline )); do
    refresh_runtime_assertion "$output" || return
    if node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])),remaining=Number(BigInt(v.runtime.expiresAtNs)/1000000n)-Date.now();if(remaining>60000)throw Error("unexpected identity lifetime");process.exit(remaining>=55000?0:1)' "$output"; then return 0; fi
    sleep 1
  done
  echo 'Identity publication has insufficient recovery lifetime' >&2
  return 1
}

deployment_reactivate_runtime() {
  local source_refresh=${1:-deployment_refresh_runtime_sources}
  case "$source_refresh" in deployment_refresh_runtime_sources|cigl_require_browser_sources) ;; *) return 1 ;; esac
  local configuration_operator_session=$deployment_runtime_owner_session
  local renewal_revision renewal_digest renewal_body renewal_path
  deployment_runtime_renewals=$((deployment_runtime_renewals + 1))
  renewal_path="$evidence_root/deployment-renew-$deployment_runtime_renewals"
  openpc_report_container_memory deployment-lease-expired $("${compose[@]}" ps -q runtime-target)
  "${compose[@]}" stop runtime-target >/dev/null
  "$source_refresh"
  configuration_operator_session=$deployment_runtime_owner_session
  deployment_wait_fresh_identity "$evidence_root/deployment-runtime-identity.json"
  configuration_get "$renewal_path-target.json" "http://127.0.0.1:8080/api/v1/runtime-targets/$target_urn"
  renewal_revision="$(operation_field "$renewal_path-target.json" revision)"
  # Read only: the command owner independently recomputes and validates this
  # configuration candidate. No activation or intermediate state is seeded.
  renewal_digest="$(printf '%s\n' "BEGIN;" "select openpc.set_request_context('PARTICIPANT',:'participant_id'::uuid,:'privacy_domain_id'::uuid,uuidv7(),'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',true) as context \\gset" "select 'sha256:'||encode(sha256(configuration.configuration_digest||policy.generation_digest||convert_to(provider.behavior_fingerprint,'UTF8')||convert_to(projection.plan_digest,'UTF8')||convert_to(target.runtime_target_id::text,'UTF8')),'hex') from control.runtime_target target join control.module_installation installation on installation.participant_id=target.participant_id and installation.privacy_domain_id=target.privacy_domain_id and installation.state='ENABLED' join control.module_version version on version.module_version_id=installation.module_version_id join control.module_registration module on module.module_id=version.module_id and module.module_id='pc.config.assets' join control.runtime_configuration_input_current configuration on configuration.module_installation_id=installation.module_installation_id and configuration.active=true join control.policy_generation policy on policy.participant_id=target.participant_id and policy.privacy_domain_id=target.privacy_domain_id and policy.state='ACTIVE' and policy.active=true join control.provider_profile provider on provider.participant_id=target.participant_id and provider.privacy_domain_id=target.privacy_domain_id and provider.state in ('QUALIFIED','ACTIVE') join control.projection_plan projection on projection.participant_id=target.participant_id and projection.privacy_domain_id=target.privacy_domain_id and projection.state in ('VALIDATED','RUNNING') and projection.readiness='READY' where target.runtime_target_id=:'target_id';" "COMMIT;" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" -v target_id="$target_id")"
  [[ $renewal_digest =~ ^sha256:[0-9a-f]{64}$ ]]
  renewal_body="$(node -e 'const [actionIntentDigest,expectedRevision,replacementDigest]=process.argv.slice(1);process.stdout.write(JSON.stringify({actionIntentId:"ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1",actionIntentDigest,expectedRevision,replacementDigest,reason:"Renew current target custody for observation of a started deployment."}));' "$(action_digest ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1)" "$renewal_revision" "$renewal_digest")"
  configuration_post "$renewal_path-command.json" "$renewal_body" \
    "http://127.0.0.1:8080/api/v1/runtime-targets/$target_urn" "deployment-renew-runtime-$deployment_runtime_renewals-0001" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$target_id" "$renewal_revision")" PATCH
  configuration_get "$renewal_path-active.json" "http://127.0.0.1:8080/api/v1/runtime-targets/$target_urn"
  node -e 'const fs=require("fs"),[before,after]=process.argv.slice(1).map(p=>JSON.parse(fs.readFileSync(p)));if(after.state!=="ACTIVE_MATCHED"||!after.xdsVersionDigest||before.xdsVersionDigest===after.xdsVersionDigest)throw Error("renewal reused a proxy acknowledgement version");' "$renewal_path-target.json" "$renewal_path-active.json"
  start_runtime_target
  deployment_runtime_expiry_ns="$(deployment_installed_expiry)"
  if [[ -n ${deployment_command_id:-} ]]; then deployment_status "$renewal_path-status.json"; fi
}

deployment_require_runtime_window() {
  local minimum_ms=${1:-20000}
  # The next observation or restart/readback must fit in the real lease.
  # If it is near expiry, exercise the same public renewal owner first.
  if ! node -e 'process.exit(Number(BigInt(process.argv[1])/1000000n)-Date.now()>=Number(process.argv[2])?0:1)' "$deployment_runtime_expiry_ns" "$minimum_ms"; then
    deployment_renew_runtime
  fi
  node -e 'const remaining=Number(BigInt(process.argv[1])/1000000n)-Date.now(),minimum=Number(process.argv[2]);if(remaining<minimum)throw Error(`runtime phase requires ${minimum}ms; only ${remaining}ms remain`);' "$deployment_runtime_expiry_ns" "$minimum_ms"
}

deployment_chain_phase() {
  deployment_require_runtime_window
  node -e 'const fs=require("fs"),[file,phase]=process.argv.slice(1),v=JSON.parse(fs.readFileSync(file));v.phase=phase;fs.writeFileSync(file,JSON.stringify(v));' "$data_root/rpc-provider/deployment-scenario.json" "$1"
}

deployment_wait_observation() {
  local expected=$1 kind=${2:-observation} container
  container="$("${compose[@]}" ps -q runtime-target)"
  for _ in {1..80}; do
    if docker exec "$container" cat "/runtime/broker/$target_id/submission.journal" 2>/dev/null | node -e '
      const fs=require("fs"),[id,expected,kind]=process.argv.slice(1),b=fs.readFileSync(0);let o=0,found;
      while(o+4<=b.length){const n=b.readUInt32BE(o);if(o+4+n>b.length)break;const {record:r}=JSON.parse(b.subarray(o+4,o+4+n));o+=4+n;if(r.command_id!==id)continue;if(kind==="record"&&r.state===expected)found=expected;else if(kind==="observation"&&r.observation)found=r.observation.state?.observation;}process.exit(found===expected?0:1);
    ' "$deployment_command_id" "$expected" "$kind"; then return 0; fi
    sleep 0.25
  done
  echo "OPENPC_DEPLOYMENT_OBSERVATION|FAIL|expected=$expected" >&2
  "${compose[@]}" logs --no-color --tail 50 control-worker runtime-target >&2
  return 1
}

run_deployment_workbench() {
  local deployment_runtime_owner_session
  local deployment_runtime_renewals=${deployment_runtime_renewals:-0}
  local deployment_fact_path=${deployment_fact_path:-"$evidence_root/typed-policy-fact.json"}
  local deployment_runtime_expiry_ns deployment_command_id deployment_case compose_json
  local deployment_direct_urn=$deployment_urn deployment_urn=$deployment_urn deployment_wallet_path
  local -a browser_cases
  deployment_runtime_owner_session=$configuration_operator_session
  deployment_command_id=''
  read -r -a browser_cases <<< "${OPENPC_TRANSACTION_BROWSER_CASES:-direct CREATE CREATE2 CREATE3 native replacement}"
  for deployment_case in "${browser_cases[@]}"; do
    case "$deployment_case" in direct|CREATE|CREATE2|CREATE3|native|replacement) ;; *) echo 'Unsupported transaction browser case' >&2; return 1 ;; esac
  done
  # One browser process at a time. Each case has distinct signed bytes/nonces;
  # deterministic deployments also have distinct factory/salt inputs.
  "${compose[@]}" up -d --wait --no-build --pull never admin-web >/dev/null
  compose_json="$(node -e 'process.stdout.write(JSON.stringify(process.argv.slice(1)))' "${openpc_target_compose_command[@]}")"
  for deployment_case in "${browser_cases[@]}"; do
    case "$deployment_case" in
      direct) deployment_urn=$deployment_direct_urn; deployment_wallet_path="$evidence_root/deployment-wallet.json" ;;
      native) deployment_urn=$deployment_direct_urn; deployment_wallet_path="$evidence_root/deployment-wallet-native.json" ;;
      replacement) deployment_urn=$deployment_direct_urn; deployment_wallet_path="$evidence_root/deployment-wallet-replacement-original.json" ;;
      *) deployment_wallet_path="$evidence_root/deployment-wallet-$deployment_case.json"
         deployment_urn="$(operation_field "$evidence_root/configuration-deployment-$deployment_case-policy-resource.json" deploymentPolicyId)" ;;
    esac
    # Renew before preparing the case; never carry a prepared intent across a
    # generation change. A failed case stops this dependent shared-runtime lane.
    deployment_runtime_expiry_ns="$(deployment_installed_expiry)"
    if (( $(deployment_fact_remaining_ms) < 300000 || $(deployment_provider_remaining_ms) < 300000 || $(deployment_publication_remaining_ms) < 300000 )); then deployment_renew_runtime; fi
    deployment_require_runtime_window 45000
    test "$(deployment_send_count)" = 0
    node -e 'const fs=require("fs"),wallet=JSON.parse(fs.readFileSync(process.argv[1]));fs.writeFileSync(process.argv[2],JSON.stringify({wallet,phase:"pending",loseResponse:true,abandonPreflight:false}),{mode:0o600});' \
      "$deployment_wallet_path" "$data_root/rpc-provider/deployment-scenario.json"
    OPENPC_TRANSACTION_BROWSER_CASE="$deployment_case" \
      OPENPC_TRANSACTION_BROWSER_LEASE_EXPIRY_NS="$deployment_runtime_expiry_ns" \
      node tests/integration/local-runtime/transaction-workbench-browser.mjs \
        "$secret_root" "$evidence_root" "$data_root" "$deployment_urn" "$target_urn" "$deployment_execution_wallet_id" "$compose_json"
  done
  if [[ ${OPENPC_R11_CLI:-0} == 1 ]]; then run_transaction_cli; fi
}

run_transaction_cli() {
  local deployment_runtime_owner_session=$configuration_operator_session
  local deployment_runtime_renewals=${deployment_runtime_renewals:-0}
  local deployment_fact_path=${deployment_fact_path:-"$evidence_root/typed-policy-fact.json"}
  local deployment_runtime_expiry_ns deployment_command_id=''
  local deployment_wallet_path="$evidence_root/deployment-wallet-cli.json"
  local deployment_urn
  deployment_urn="$(operation_field "$evidence_root/configuration-deployment-policy-resource.json" deploymentPolicyId)"
  "${compose[@]}" up -d --wait --no-build --pull never admin-web >/dev/null
  # Source renewal may need workload delegation through the existing harness
  # actors. Their retained sessions expire independently of the CLI profiles.
  node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs "$secret_root" "$evidence_root" "$participant_id" authenticate
  node --import tsx tests/integration/local-runtime/transaction-cli.mjs authenticate "$secret_root" "$evidence_root" "$data_root"
  # A distinct nonce gives this client its own durable business state.
  cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
    "$secret_root/deployment-wallet.key" TRANSACTION_CREATE 22 0 2 1 > "$deployment_wallet_path"
  deployment_runtime_expiry_ns="$(deployment_installed_expiry)"
  if (( $(deployment_fact_remaining_ms) < 300000 || $(deployment_provider_remaining_ms) < 300000 || $(deployment_publication_remaining_ms) < 300000 )); then deployment_renew_runtime; fi
  deployment_require_runtime_window 45000
  test "$(deployment_send_count)" = 0
  node -e 'const fs=require("fs"),wallet=JSON.parse(fs.readFileSync(process.argv[1]));fs.writeFileSync(process.argv[2],JSON.stringify({wallet,phase:"pending",loseResponse:true,abandonPreflight:false}),{mode:0o600});' \
    "$deployment_wallet_path" "$data_root/rpc-provider/deployment-scenario.json"
  node --import tsx tests/integration/local-runtime/transaction-cli.mjs submit "$secret_root" "$evidence_root" "$data_root" "$deployment_urn" "$target_urn" "$deployment_execution_wallet_id"
  "${compose[@]}" restart control-worker runtime-target >/dev/null
  node --import tsx tests/integration/local-runtime/transaction-cli.mjs readback "$secret_root" "$evidence_root" "$data_root"
  node --import tsx tests/integration/local-runtime/transaction-cli.mjs native "$secret_root" "$evidence_root" "$data_root" "$deployment_urn" "$target_urn" "$deployment_execution_wallet_id"
  node --import tsx tests/integration/local-runtime/transaction-cli.mjs cigl "$secret_root" "$evidence_root" "$data_root"
  node --import tsx tests/integration/local-runtime/transaction-cli.mjs lifecycle "$secret_root" "$evidence_root" "$data_root"
  node --import tsx tests/integration/local-runtime/transaction-cli.mjs resources "$secret_root" "$evidence_root" "$data_root" "$deployment_urn" "$target_urn" "$deployment_execution_wallet_id"
  node --import tsx tests/integration/local-runtime/transaction-cli.mjs stale "$secret_root" "$evidence_root" "$data_root"
}

run_deployment_submission() {
  local deployment_runtime_owner_session=$configuration_operator_session
  local deployment_runtime_renewals=${deployment_runtime_renewals:-0} deployment_case deployment_wallet_path
  local deployment_fact_path="${deployment_fact_path:-$evidence_root/typed-policy-fact.json}"
  local deployment_direct_urn=$deployment_urn deployment_urn=$deployment_urn
  local deployment_abandon_preflight
  local -a deployment_cases
  read -r -a deployment_cases <<< "${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_CASES:-direct CREATE CREATE2 CREATE3 native no-send expired replacement native-revoked}"
  if (( ${#deployment_cases[@]} == 0 )); then echo 'Deployment acceptance requires at least one case' >&2; return 1; fi
  for deployment_case in "${deployment_cases[@]}"; do
    case "$deployment_case" in direct|CREATE|CREATE2|CREATE3|native|no-send|expired|replacement|native-revoked) ;; *) echo 'Unsupported deployment acceptance case' >&2; return 1 ;; esac
  done
  for deployment_case in "${deployment_cases[@]}"; do
    deployment_abandon_preflight=false
    if [[ $deployment_case == direct ]]; then
      deployment_urn=$deployment_direct_urn
      deployment_wallet_path="$evidence_root/deployment-wallet.json"
    elif [[ $deployment_case == no-send ]]; then
      deployment_urn=$deployment_direct_urn
      deployment_wallet_path="$evidence_root/deployment-wallet-no-send.json"
      deployment_abandon_preflight=true
    elif [[ $deployment_case == native || $deployment_case == native-revoked ]]; then
      deployment_urn=$deployment_direct_urn
      deployment_wallet_path="$evidence_root/deployment-wallet-$deployment_case.json"
    elif [[ $deployment_case == expired ]]; then
      deployment_urn=$deployment_direct_urn
      deployment_wallet_path="$evidence_root/deployment-wallet-expired.json"
    elif [[ $deployment_case == replacement ]]; then
      deployment_urn=$deployment_direct_urn
      deployment_wallet_path="$evidence_root/deployment-wallet-replacement-original.json"
    else
      deployment_wallet_path="$evidence_root/deployment-wallet-$deployment_case.json"
      deployment_urn="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1])).deploymentPolicyId)' "$evidence_root/configuration-deployment-$deployment_case-policy-resource.json")"
    fi
    with_deployment_actors run_deployment_submission_command
  done
}

deployment_send_count() {
  node -e 'const fs=require("fs"),[file,walletPath]=process.argv.slice(1),wallet=JSON.parse(fs.readFileSync(walletPath));if(!fs.existsSync(file)){process.stdout.write("0");}else{process.stdout.write(String(fs.readFileSync(file,"utf8").trim().split("\n").filter(Boolean).map(JSON.parse).filter(v=>v.transactionHash===wallet.transactionHash).length));}' "$data_root/rpc-provider/deployment-submissions.jsonl" "$deployment_wallet_path"
}

run_deployment_submission_command() {
  # A preceding no-send case has no runtime operation to observe. Each case
  # acquires its own command only after the public submission is accepted.
  local deployment_command_id=''
  local intent_body intent_urn submit_body count probe_seen deployment_submission_urn
  local native_body native_urn native_reuse_body native_conflict_intent_urn native_conflict_submit_body
  local native_conflict_command_id native_conflict_submission_urn
  local deployment_runtime_expiry_ns
  printf 'OPENPC_DEPLOYMENT_SUBMISSION|%s|BEGIN\n' "$deployment_case"
  deployment_runtime_expiry_ns="$(deployment_installed_expiry)"
  # Renew source-backed policy before binding a new intent when the remaining
  # source window cannot cover an expiry/recovery scenario.
  if (( $(deployment_fact_remaining_ms) < 300000 || $(deployment_provider_remaining_ms) < 300000 || $(deployment_publication_remaining_ms) < 300000 )); then deployment_renew_runtime; fi
  # Two public approval cycles plus final preflight need their own lease window.
  # Renew before preparation binds its target generation, never between an
  # approved intent and its submission merely to extend that intent's authority.
  deployment_require_runtime_window 30000
  node -e 'const fs=require("fs"),wallet=JSON.parse(fs.readFileSync(process.argv[1]));fs.writeFileSync(process.argv[2],JSON.stringify({wallet,phase:"pending",loseResponse:true,abandonPreflight:process.argv[3]==="true"}),{mode:0o600});' \
    "$deployment_wallet_path" "$data_root/rpc-provider/deployment-scenario.json" "$deployment_abandon_preflight"
  intent_body="$(node -e 'const fs=require("fs"),[file,deploymentPolicyId,runtimeTargetId,walletId,actionIntentDigest]=process.argv.slice(1),wallet=JSON.parse(fs.readFileSync(file));process.stdout.write(JSON.stringify({actionIntentId:"ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1",actionIntentDigest,reason:"Prepare exact governed workload deployment.",deploymentPolicyId,runtimeTargetId,walletBindingId:`urn:openpc:resource:${walletId}`,executionWorkloadId:"urn:openpc:workload:018f0000-0000-7000-8000-000000000191",signingPayload:wallet.signingPayload}));' \
    "$deployment_wallet_path" "$deployment_urn" "$target_urn" "$deployment_execution_wallet_id" "$(action_digest ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1)")"
  if [[ $deployment_case == native || $deployment_case == expired || $deployment_case == native-revoked ]]; then
    local native_prefix="native-value"
    if [[ $deployment_case != native ]]; then native_prefix="native-value-$deployment_case"; fi
    # Deployment approval cannot create Native Value authority. No preparation,
    # reservation or provider send may result from this positive ungranted value.
    approved_configuration_post "$evidence_root/$native_prefix-missing-denied.json" "$intent_body" \
      http://127.0.0.1:8080/api/v1/deployment-intents "$native_prefix-missing-0001" '' POST "$native_prefix-missing" 400 0
    test "$(deployment_send_count)" = 0
    native_body="$(node -e 'const [walletBindingId,actionIntentDigest]=process.argv.slice(1);process.stdout.write(JSON.stringify({actionIntentId:"ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1",actionIntentDigest,reason:"Authorize this workload endowment independently of deployment permission.",walletBindingId:`urn:openpc:resource:${walletBindingId}`,executionWorkloadId:"urn:openpc:workload:018f0000-0000-7000-8000-000000000191",chainId:"31337",networkId:"openpc-local",genesisDigest:"sha256:"+"11".repeat(32),amountMode:"EXACT",maxAmountWei:"10",validUntil:new Date(Date.now()+240000).toISOString()}));' \
      "$deployment_execution_wallet_id" "$(action_digest ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1)")"
    approved_configuration_post "$evidence_root/$native_prefix-authorization.json" "$native_body" \
      http://127.0.0.1:8080/api/v1/native-value-authorizations "$native_prefix-authorization-0001" '' POST "$native_prefix-authorization"
    native_urn="$(operation_field "$evidence_root/$native_prefix-authorization.json" resourceRef)"
    configuration_get "$evidence_root/$native_prefix-unused.json" "http://127.0.0.1:8080/api/v1/native-value-authorizations/$native_urn"
    node -e 'const assert=require("assert/strict"),v=JSON.parse(require("fs").readFileSync(process.argv[1])),d=JSON.parse(Buffer.from(v.authorizationDocument.slice(2),"hex"));assert.equal(v.state,"UNUSED");assert.equal(v.runtimePermission,"NONE");assert.equal(d.actorSubjectId,"018f0000-0000-7000-8000-000000000190");assert.equal(d.used,false);assert.equal(d.oneUse,true);assert.equal(d.maxAmountWei,"10");' "$evidence_root/$native_prefix-unused.json"
    intent_body="$(node -e 'process.stdout.write(JSON.stringify({...JSON.parse(process.argv[1]),nativeValueAuthorizationId:process.argv[2]}))' "$intent_body" "$native_urn")"
    # Native issuance has independent authority and does not bind the target
    # generation. Renew after its approval cycle, before preparation captures
    # that generation. Never extend an already prepared intent's authority.
    deployment_require_runtime_window 30000
  fi
  approved_configuration_post "$evidence_root/deployment-$deployment_case-execution-intent.json" "$intent_body" \
    http://127.0.0.1:8080/api/v1/deployment-intents "deployment-$deployment_case-execution-intent-0001" '' POST "$deployment_case-execution-intent"
  intent_urn="$(operation_field "$evidence_root/deployment-$deployment_case-execution-intent.json" resourceRef)"
  configuration_get "$evidence_root/deployment-$deployment_case-execution-intent-read.json" \
    "http://127.0.0.1:8080/api/v1/deployment-intents/$intent_urn"
  node -e 'const fs=require("fs"),assert=require("assert/strict"),[path,walletPath]=process.argv.slice(1),v=JSON.parse(fs.readFileSync(path)),w=JSON.parse(fs.readFileSync(walletPath)),intent=JSON.parse(Buffer.from(v.intentDocument.slice(2),"hex"));assert.equal(v.authority,"NONE");assert.equal(v.state,"DRAFT");assert.equal(v.signingPayload,w.signingPayload);assert.equal(v.sender,w.sender);assert.equal(v.expectedContractAddress,w.mechanism==="CREATE"?null:w.expectedAddress);assert.equal(intent.destination,w.mechanism==="TRANSACTION_CREATE"?null:w.factoryAddress);assert.equal(intent.initCode,w.initCode);' \
    "$evidence_root/deployment-$deployment_case-execution-intent-read.json" "$deployment_wallet_path"
  if [[ $deployment_case == native ]]; then
    # Two independently approved intents can reference the same unused grant.
    # The global reservation must reject the losing command durably later.
    native_reuse_body="$(node -e 'const fs=require("fs"),v=JSON.parse(process.argv[1]),wallet=JSON.parse(fs.readFileSync(process.argv[2]));v.signingPayload=wallet.signingPayload;process.stdout.write(JSON.stringify(v));' "$intent_body" "$evidence_root/deployment-wallet-native-reuse.json")"
    approved_configuration_post "$evidence_root/native-value-competing-intent.json" "$native_reuse_body" \
      http://127.0.0.1:8080/api/v1/deployment-intents native-value-competing-intent-0001 '' POST native-competing-intent
    native_conflict_intent_urn="$(operation_field "$evidence_root/native-value-competing-intent.json" resourceRef)"
    native_conflict_submit_body="$(node -e 'const fs=require("fs"),[path,deploymentIntentId,actionIntentDigest]=process.argv.slice(1);process.stdout.write(JSON.stringify({actionIntentId:"ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1",actionIntentDigest,reason:"Resolve a competing approved one-use grant claim.",deploymentIntentId,signedTransaction:JSON.parse(fs.readFileSync(path)).signedTransaction}));' \
      "$evidence_root/deployment-wallet-native-reuse.json" "$native_conflict_intent_urn" "$(action_digest ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1)")"
  fi
  submit_body="$(node -e 'const fs=require("fs"),[file,deploymentIntentId,actionIntentDigest]=process.argv.slice(1);process.stdout.write(JSON.stringify({actionIntentId:"ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1",actionIntentDigest,reason:"Submit the exact approved deployment once.",deploymentIntentId,signedTransaction:JSON.parse(fs.readFileSync(file)).signedTransaction}));' \
    "$deployment_wallet_path" "$intent_urn" "$(action_digest ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1)")"
  if [[ $deployment_case == native-revoked ]]; then
    deployment_revoked_native "$submit_body" "$intent_body"
    return
  fi
  if [[ $deployment_case == expired || $deployment_case == native ]]; then
    # Stop only the execution owner. Approval and submission still use the real
    # public owners; no intermediate command or expiry state is seeded.
    "${compose[@]}" stop control-worker >/dev/null
  fi
  approved_configuration_post "$evidence_root/deployment-$deployment_case-execution-command.json" "$submit_body" \
    http://127.0.0.1:8080/api/v1/deployment-submissions "deployment-$deployment_case-execution-command-0001" '' POST "$deployment_case-execution-command" 202 0
  deployment_command_id="$(operation_field "$evidence_root/deployment-$deployment_case-execution-command.json" operationId)"
  deployment_submission_urn="$(operation_field "$evidence_root/deployment-$deployment_case-execution-command.json" resourceRef)"
  if [[ $deployment_case == expired ]]; then
    deployment_expired_command "$submit_body"
    return
  fi
  if [[ $deployment_abandon_preflight == true ]]; then
    deployment_abandoned_handoff "$submit_body"
    return
  fi
  if [[ $deployment_case == native ]]; then
    # Both public commands are approved before either can consume the grant.
    approved_configuration_post "$evidence_root/native-value-competing-command.json" "$native_conflict_submit_body" \
      http://127.0.0.1:8080/api/v1/deployment-submissions native-value-competing-command-0001 '' POST native-competing-command 202 0
    native_conflict_command_id="$(operation_field "$evidence_root/native-value-competing-command.json" operationId)"
    native_conflict_submission_urn="$(operation_field "$evidence_root/native-value-competing-command.json" resourceRef)"
    # Command replay requires current authorization. Exercise exact
    # replay while WebAuthn is fresh; later expiry recovery uses durable GETs.
    configuration_post "$evidence_root/native-value-competing-command-early-replay.json" "$native_conflict_submit_body" \
      http://127.0.0.1:8080/api/v1/deployment-submissions native-value-competing-command-0001 '' POST 202 "$configuration_operator_session" 0
    assert_json_equal "$evidence_root/native-value-competing-command.json" "$evidence_root/native-value-competing-command-early-replay.json"
    configuration_post "$evidence_root/deployment-native-command-early-replay.json" "$submit_body" \
      http://127.0.0.1:8080/api/v1/deployment-submissions deployment-native-execution-command-0001 '' POST 202 "$configuration_operator_session" 0
    assert_json_equal "$evidence_root/deployment-native-execution-command.json" "$evidence_root/deployment-native-command-early-replay.json"
    configuration_get "$evidence_root/native-value-before-competing-claims.json" "http://127.0.0.1:8080/api/v1/native-value-authorizations/$native_urn"
    node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])),until=Date.parse(v.validUntil);if(v.state!=="UNUSED"||!Number.isFinite(until)||until<=Date.now())throw Error("competing claims require current unused authority");' "$evidence_root/native-value-before-competing-claims.json"
    node --import tsx tests/integration/local-runtime/deployment-policy-journey.mjs native-concurrency \
      "$secret_root" "$participant_id" "$privacy_domain_id" "$deployment_command_id" "$native_conflict_command_id"
    "${compose[@]}" start control-worker >/dev/null
  fi
  for _ in {1..80}; do
    [[ $(deployment_send_count) == 1 ]] && break
    sleep 0.25
  done
  count="$(deployment_send_count)"
  if [[ $count != 1 ]]; then
    printf 'OPENPC_DEPLOYMENT_SUBMISSION|%s|FAIL|expected_sends=1|actual_sends=%s\n' "$deployment_case" "$count" >&2
    return 1
  fi
  deployment_wait_observation AMBIGUOUS record
  if [[ $deployment_case == replacement || $deployment_case == replacement-* ]]; then
    deployment_replace_pending "$intent_body" "$submit_body"
    return
  fi
  if [[ $deployment_case == native ]]; then
    # Custody already crossed STARTED and the external provider saw this exact
    # transaction. Elapsing its preparation deadline must preserve ambiguity.
    deployment_wait_preparation_expiry "$evidence_root/deployment-native-execution-intent-read.json"
    deployment_require_runtime_window
    configuration_get "$evidence_root/native-value-consumed.json" "http://127.0.0.1:8080/api/v1/native-value-authorizations/$native_urn"
    node -e 'const fs=require("fs"),assert=require("assert/strict"),[before,after,intentPath]=process.argv.slice(1).map(p=>JSON.parse(fs.readFileSync(p))),d=JSON.parse(Buffer.from(after.authorizationDocument.slice(2),"hex")),intent=JSON.parse(Buffer.from(intentPath.intentDocument.slice(2),"hex"));assert.equal(after.state,"CONSUMED");assert.equal(d.used,true);assert.equal(after.issuedAuthorizationDigest,before.authorizationDigest);assert.notEqual(after.authorizationDigest,before.authorizationDigest);assert.equal(intent.valueWei,"10");assert.equal("sha256:"+intent.nativeValueAuthorizationDigest,before.authorizationDigest);' \
      "$evidence_root/native-value-unused.json" "$evidence_root/native-value-consumed.json" "$evidence_root/deployment-native-execution-intent-read.json"
    deployment_native_conflict_result before
    native_reuse_body="$(node -e 'process.stdout.write(JSON.stringify({...JSON.parse(process.argv[1]),reason:"Reject a fresh preparation after grant consumption."}))' "$native_reuse_body")"
    approved_configuration_post "$evidence_root/native-value-reuse-denied.json" "$native_reuse_body" \
      http://127.0.0.1:8080/api/v1/deployment-intents native-value-reuse-0001 '' POST native-value-reuse 403 0
    test "$(deployment_send_count)" = 1
  fi
  deployment_continue_observation "$submit_body"
}

# Retained continuation starts from the existing command and exact provider
# transaction. An omitted submission body permits readback/reconciliation only;
# it never creates a new intent or replays an expired approval.
deployment_continue_observation() {
  local submit_body=${1:-}
  openpc_require_inputs deployment_command_id deployment_submission_urn deployment_wallet_path
  test "$(deployment_send_count)" = 1
  deployment_status "$evidence_root/deployment-$deployment_case-response-lost-status.json"
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])).result;if(!v||!["WRITE_AMBIGUITY","ACCEPTED"].includes(v.state)||v.truthState==="SUCCESS")throw Error("lost response claimed success");' "$evidence_root/deployment-$deployment_case-response-lost-status.json"
  configuration_get "$evidence_root/deployment-$deployment_case-management-before-finality.json" \
    "http://127.0.0.1:53003/api/v1/deployment-submissions/$deployment_submission_urn"
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.state==="SUCCEEDED"||v.truthState==="SUCCESS"||v.occurrence!==null||v.association!==null||v.associationCurrent||v.runtimePermission!=="NONE")throw Error("non-final deployment acquired control");' \
    "$evidence_root/deployment-$deployment_case-management-before-finality.json"
  openpc_report_container_memory deployment-ambiguous $("${compose[@]}" ps -q control-worker runtime-target)
  # Drop Envoy's in-memory listener too: completed non-CIGL generations must
  # restore their authenticated transport without another activation or send.
  "${compose[@]}" restart control-worker runtime-envoy runtime-target >/dev/null
  start_runtime_target
  deployment_require_runtime_window
  if [[ $deployment_case == native ]]; then
    configuration_get "$evidence_root/native-value-consumed-restart.json" "http://127.0.0.1:8080/api/v1/native-value-authorizations/$native_urn"
    assert_json_equal "$evidence_root/native-value-consumed.json" "$evidence_root/native-value-consumed-restart.json"
    deployment_native_conflict_result restart
    assert_json_equal "$evidence_root/deployment-native-conflict-before-management-FAILED.json" "$evidence_root/deployment-native-conflict-restart-management-FAILED.json"
  fi
  deployment_wait_observation MEMPOOL_OBSERVED
  deployment_status "$evidence_root/deployment-$deployment_case-restart-status.json"
  if [[ $deployment_case != native && -n $submit_body ]]; then
    configuration_post "$evidence_root/deployment-$deployment_case-execution-command-replay.json" "$submit_body" \
      http://127.0.0.1:8080/api/v1/deployment-submissions "deployment-$deployment_case-execution-command-0001" '' POST 202 "$configuration_operator_session" 0
    assert_json_equal "$evidence_root/deployment-$deployment_case-execution-command.json" "$evidence_root/deployment-$deployment_case-execution-command-replay.json"
  fi
  if [[ $deployment_case == direct ]]; then
    deployment_renew_runtime
  else
    deployment_require_runtime_window
  fi
  deployment_complete_observation
}

# Resume after the original lost-response/restart/expiry prerequisites have
# passed. The caller verifies retained ownership and refreshes authority first;
# this phase observes the original command and never submits a transaction.
deployment_complete_observation() {
  local phase probe_seen count
  openpc_require_inputs deployment_command_id deployment_submission_urn deployment_wallet_path
  test "$(deployment_send_count)" = 1
  local -a deployment_faults=(wrong-address wrong-code)
  if [[ $deployment_case == CREATE3 ]]; then deployment_faults+=(wrong-helper); fi
  for phase in "${deployment_faults[@]}"; do
    deployment_chain_phase "$phase"
    probe_seen=0
    for _ in {1..40}; do
      if node -e 'const fs=require("fs"),[file,phase,walletPath]=process.argv.slice(1),wallet=JSON.parse(fs.readFileSync(walletPath));if(!fs.existsSync(file))process.exit(1);const rows=fs.readFileSync(file,"utf8").trim().split("\n").filter(Boolean).map(JSON.parse);process.exit(rows.some(v=>v.transactionHash===wallet.transactionHash&&v.phase===phase&&(phase!=="wrong-helper"||v.address===wallet.helperAddress)&&v.method===(["wrong-helper","wrong-code"].includes(phase)?"eth_getCode":wallet.mechanism==="TRANSACTION_CREATE"?"eth_getTransactionReceipt":"debug_traceTransaction"))?0:1);' "$data_root/rpc-provider/deployment-observations.jsonl" "$phase" "$deployment_wallet_path"; then probe_seen=1; break; fi
      sleep 0.25
    done
    test "$probe_seen" = 1
    deployment_wait_observation MEMPOOL_OBSERVED
  done
  deployment_chain_phase included
  deployment_wait_observation INCLUDED
  deployment_status "$evidence_root/deployment-$deployment_case-included-status.json"
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])).result;if(v.truthState==="SUCCESS"||v.state==="CONFIRMED")throw Error("inclusion claimed finality");' "$evidence_root/deployment-$deployment_case-included-status.json"
  deployment_chain_phase reorg
  deployment_wait_observation REORGED
  deployment_status "$evidence_root/deployment-$deployment_case-reorg-status.json"
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])).result;if(v.state!=="REORG")throw Error("reorg not disclosed");' "$evidence_root/deployment-$deployment_case-reorg-status.json"
  deployment_chain_phase included
  deployment_wait_observation INCLUDED
  deployment_chain_phase safe
  deployment_wait_observation SAFE
  deployment_chain_phase finalized
  deployment_wait_observation FINALIZED
  deployment_status "$evidence_root/deployment-$deployment_case-finalized-status.json"
  node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1])).result,w=JSON.parse(fs.readFileSync(process.argv[2]));if(v.state!=="CONFIRMED"||v.truthState!=="SUCCESS"||v.signedTransactionHash!==w.transactionHash)throw Error("final exact result unavailable");if(/private|logs|initCode|signedTransaction\"/.test(JSON.stringify(v)))throw Error("private result disclosure");' "$evidence_root/deployment-$deployment_case-finalized-status.json" "$deployment_wallet_path"
  deployment_management_result SUCCEEDED
  if [[ $deployment_case == direct ]]; then
    deployment_finalized_retirement
  fi
  deployment_complete_finalized_readback
}

deployment_complete_finalized_readback() {
  local count
  openpc_require_inputs deployment_command_id deployment_submission_urn deployment_wallet_path
  # The direct case checks repeated expiry and activation on this same ADS
  # stream. Factory cases reuse that shared-owner regression and still renew
  # through the public owner whenever their own recovery needs a fresh lease.
  if [[ $deployment_case == direct ]]; then
    deployment_renew_runtime
  else
    deployment_require_runtime_window
  fi
  openpc_report_container_memory deployment-finalized $("${compose[@]}" ps -q runtime-target)
  "${compose[@]}" restart runtime-target control-worker >/dev/null
  start_runtime_target
  deployment_require_runtime_window
  deployment_status "$evidence_root/deployment-$deployment_case-final-restart-status.json"
  assert_json_equal "$evidence_root/deployment-$deployment_case-finalized-status.json" "$evidence_root/deployment-$deployment_case-final-restart-status.json"
  cp "$evidence_root/deployment-$deployment_case-management-SUCCEEDED.json" "$evidence_root/deployment-$deployment_case-management-before-restart.json"
  deployment_management_result SUCCEEDED
  assert_json_equal "$evidence_root/deployment-$deployment_case-management-before-restart.json" "$evidence_root/deployment-$deployment_case-management-SUCCEEDED.json"
  local denied_status
  denied_status="$(curl -sS -o "$evidence_root/deployment-$deployment_case-foreign-maker.json" -w '%{http_code}' \
    -H "Cookie: __Host-openpc_session=$configuration_checker_session" -H 'OpenPC-API-Version: 1' \
    -H "OpenPC-Participant-ID: urn:openpc:participant:$participant_id" \
    -H "X-Request-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
    -H "X-Correlation-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
    "http://127.0.0.1:53003/api/v1/deployment-submissions/$deployment_submission_urn")"
  [[ $denied_status == 403 || $denied_status == 404 ]]
  local invalidation_phase=invalidated-code
  if [[ $deployment_case == direct ]]; then invalidation_phase=invalidated-reorg; fi
  if [[ $deployment_case == CREATE3 ]]; then invalidation_phase=invalidated-helper; fi
  deployment_chain_phase "$invalidation_phase"
  deployment_management_result FAILED
  "${compose[@]}" restart control-worker >/dev/null
  cp "$evidence_root/deployment-$deployment_case-management-FAILED.json" "$evidence_root/deployment-$deployment_case-management-before-suspension-restart.json"
  deployment_management_result FAILED
  assert_json_equal "$evidence_root/deployment-$deployment_case-management-before-suspension-restart.json" "$evidence_root/deployment-$deployment_case-management-FAILED.json"
  count="$(deployment_send_count)"
  test "$count" = 1
  docker exec "$("${compose[@]}" ps -q runtime-target)" cat "/runtime/broker/$target_id/submission.journal" | node -e '
    const fs=require("fs"),b=fs.readFileSync(0),id=process.argv[1],states=[];let o=0;
    while(o<b.length){const n=b.readUInt32BE(o),{record:r}=JSON.parse(b.subarray(o+4,o+4+n));o+=4+n;if(r.command_id===id){if(r.provider_instance_id!=="local-provider-instance")throw Error("registered profile substituted for provider instance");states.push(r.state);}}
    if(states.filter(v=>v==="STARTED").length!==1||states.indexOf("PREPARED")<0||states.indexOf("STARTED")<=states.indexOf("PREPARED")||states.indexOf("AMBIGUOUS")<=states.indexOf("STARTED"))throw Error("durable one-use response-loss sequence missing");
  ' "$deployment_command_id"
  printf 'OPENPC_DEPLOYMENT_SUBMISSION|%s|PASS|public-workload-wallet|separate-submit-status-grants|fresh-approved-intent-command|global-handoff|pds-broker|one-send|response-loss|restart|inclusion-distinct-from-finality|reorg|exact-address-code|filtered-status\n' "$deployment_case"
}

# The existing direct deployment is currently finalized here. Retire its
# derived operator view before the ordinary later invalidation, preserving all
# original source/custody and leaving the reorg acceptance below mandatory.
deployment_finalized_retirement() {
  local resume_mode=${1:-}
  case "$resume_mode" in ''|--resume-finalized) ;; *) return 1 ;; esac
  "${compose[@]}" stop runtime-target control-worker >/dev/null
  "${compose[@]}" up -d --wait --no-build --pull never admin-web >/dev/null
  openpc_phase_begin deployment-retirement
  node --import tsx tests/integration/local-runtime/evidence-deployment-retirement.mjs \
    "$secret_root" "$evidence_root" "$data_root" "$participant_id" "$privacy_domain_id" \
    "$(openpc_compose_json)" ${resume_mode:+"$resume_mode"}
  openpc_phase_end deployment-retirement 0
  "${compose[@]}" stop admin-web >/dev/null
  "${compose[@]}" up -d --wait --no-deps --no-build --pull never control-worker >/dev/null
  # Browser governance/recovery can outlive the original capsule. The public
  # renewal owner must restore current custody before restarting the target.
  deployment_reactivate_runtime
}

# This extends the same authenticated deployment journey and its external RPC;
# preparation, approval, custody, send and projections all use existing owners.
deployment_replace_pending() {
  local original_intent_body=$1 original_submit_body=$2
  local original_command=$deployment_command_id original_submission=$deployment_submission_urn
  local original_wallet=$deployment_wallet_path bump_intent bump_body bump_submission
  local bump_wallet="${deployment_replacement_wallet_prefix:-$evidence_root/deployment-wallet-replacement}-bump.json" body phase
  local base="$evidence_root/deployment-$deployment_case"
  deployment_wait_observation MEMPOOL_OBSERVED
  deployment_status "$base-original-pending.json"
  body="$(node -e 'const fs=require("fs"),v=JSON.parse(process.argv[1]);v.signingPayload=JSON.parse(fs.readFileSync(process.argv[2])).signingPayload;v.reason="Independently approve an exact fee increase for the pending deployment.";process.stdout.write(JSON.stringify(v));' "$original_intent_body" "$bump_wallet")"
  approved_configuration_post "$base-bump-intent.json" "$body" \
    http://127.0.0.1:8080/api/v1/deployment-intents "${deployment_case}-bump-intent-0001" '' POST "${deployment_case}-bump-intent"
  bump_intent="$(operation_field "$base-bump-intent.json" resourceRef)"
  bump_body="$(node -e 'const fs=require("fs"),v=JSON.parse(process.argv[1]);v.deploymentIntentId=process.argv[2];v.predecessorOperationId=`urn:openpc:operation:${process.argv[3]}`;v.signedTransaction=JSON.parse(fs.readFileSync(process.argv[4])).signedTransaction;v.reason="Submit the separately approved fee bump once on the original route.";process.stdout.write(JSON.stringify(v));' "$original_submit_body" "$bump_intent" "$original_command" "$bump_wallet")"
  # Altering signed effects cannot borrow an exact fresh preparation.
  body="$(node -e 'const fs=require("fs"),v=JSON.parse(process.argv[1]);v.signedTransaction=JSON.parse(fs.readFileSync(process.argv[2])).wrongInitCode;process.stdout.write(JSON.stringify(v));' "$bump_body" "$bump_wallet")"
  approved_configuration_post "$base-changed-effect-denied.json" "$body" \
    http://127.0.0.1:8080/api/v1/deployment-submissions "${deployment_case}-changed-effect-0001" '' POST "${deployment_case}-changed-effect" 400 0
  test "$(deployment_send_count)" = 1
  node -e 'const fs=require("fs"),file=process.argv[1],v=JSON.parse(fs.readFileSync(file));v.replacement=JSON.parse(fs.readFileSync(process.argv[2]));fs.writeFileSync(file,JSON.stringify(v));' \
    "$data_root/rpc-provider/deployment-scenario.json" "$bump_wallet"
  approved_configuration_post "$base-bump-command.json" "$bump_body" \
    http://127.0.0.1:8080/api/v1/deployment-submissions "${deployment_case}-bump-command-0001" '' POST "${deployment_case}-bump-command" 202 0
  deployment_command_id="$(operation_field "$base-bump-command.json" operationId)"
  bump_submission="$(operation_field "$base-bump-command.json" resourceRef)"
  deployment_submission_urn=$bump_submission
  deployment_wallet_path=$bump_wallet
  for _ in {1..80}; do
    [[ $(deployment_send_count) == 1 ]] && break
    sleep 0.25
  done
  test "$(deployment_send_count)" = 1
  deployment_wait_observation AMBIGUOUS record
  deployment_status "$base-bump-response-lost.json"
  node -e 'const assert=require("assert/strict"),v=JSON.parse(require("fs").readFileSync(process.argv[1])).result;assert.ok(["WRITE_AMBIGUITY","ACCEPTED"].includes(v.state));assert.notEqual(v.truthState,"SUCCESS");' "$base-bump-response-lost.json"
  configuration_post "$base-bump-replay.json" "$bump_body" \
    http://127.0.0.1:8080/api/v1/deployment-submissions "${deployment_case}-bump-command-0001" '' POST 202 "$configuration_operator_session" 0
  assert_json_equal "$base-bump-command.json" "$base-bump-replay.json"
  configuration_post "$base-original-replay.json" "$original_submit_body" \
    http://127.0.0.1:8080/api/v1/deployment-submissions "deployment-$deployment_case-execution-command-0001" '' POST 202 "$configuration_operator_session" 0
  assert_json_equal "$base-execution-command.json" "$base-original-replay.json"
  # An altered replay is rejected by the ordinary candidate/idempotency owner.
  body="$(node -e 'const v=JSON.parse(process.argv[1]);v.reason="Altered approved replacement replay";process.stdout.write(JSON.stringify(v));' "$bump_body")"
  configuration_post "$base-altered-replay.json" "$body" \
    http://127.0.0.1:8080/api/v1/deployment-submissions "${deployment_case}-bump-command-0001" '' POST 412 "$configuration_operator_session" 0
  "${compose[@]}" restart control-worker runtime-target >/dev/null
  start_runtime_target
  deployment_require_runtime_window
  deployment_wait_observation MEMPOOL_OBSERVED
  deployment_status "$base-bump-restart.json"
  deployment_replacement_original_status "$base-original-restart.json" "$original_command"
  deployment_replacement_observations "$original_command" "$original_submission" "$original_wallet" "$bump_body" "$original_intent_body"
}

deployment_replacement_observations() {
  local original_command=$1 original_submission=$2 original_wallet=$3 bump_body=$4 original_intent_body=$5
  local phase base="$evidence_root/deployment-$deployment_case"
  for phase in included safe finalized; do
    deployment_chain_phase "$phase"
    deployment_wait_observation "${phase^^}"
    deployment_status "$base-bump-$phase.json"
    deployment_replacement_original_status "$base-original-$phase.json" "$original_command"
    node -e 'const fs=require("fs"),assert=require("assert/strict"),v=JSON.parse(fs.readFileSync(process.argv[1])).result,w=JSON.parse(fs.readFileSync(process.argv[2]));assert.equal(v.state,"REJECTED");assert.equal(v.truthState,"CONFLICTING");assert.equal(v.signedTransactionHash,w.transactionHash);' "$base-original-$phase.json" "$original_wallet"
  done
  deployment_management_result SUCCEEDED
  for _ in {1..60}; do
    configuration_get "$base-original-management-finalized.json" "http://127.0.0.1:53003/api/v1/deployment-submissions/$original_submission"
    [[ $(operation_field "$base-original-management-finalized.json" state) == FAILED ]] && break
    sleep 0.25
  done
  node -e 'const fs=require("fs"),assert=require("assert/strict"),v=JSON.parse(fs.readFileSync(process.argv[1])),w=JSON.parse(fs.readFileSync(process.argv[2]));assert.equal(v.state,"FAILED");assert.equal(v.truthState,"FAILED");assert.equal(v.attempt.signedTransactionHash,w.transactionHash.slice(2));assert.equal(v.occurrence,null);assert.equal(v.association,null);assert.equal(v.runtimePermission,"NONE");' "$base-original-management-finalized.json" "$original_wallet"
  deployment_replacement_recovery "$original_command" "$original_submission" "$original_wallet" "$bump_body" "$original_intent_body"
}

deployment_replacement_recovery() {
  local original_command=$1 original_submission=$2 original_wallet=$3 bump_body=$4 original_intent_body=$5
  local base="$evidence_root/deployment-$deployment_case" bump_wallet=$deployment_wallet_path body
  "${compose[@]}" restart control-worker runtime-target >/dev/null
  start_runtime_target
  deployment_require_runtime_window
  deployment_replacement_original_status "$base-original-final-restart.json" "$original_command"
  assert_json_equal "$base-original-finalized.json" "$base-original-final-restart.json"
  deployment_chain_phase invalidated-reorg
  deployment_wait_observation REORGED
  deployment_status "$base-bump-reorg.json"
  deployment_replacement_original_status "$base-original-reorg.json" "$original_command"
  node -e 'const fs=require("fs"),assert=require("assert/strict"),a=JSON.parse(fs.readFileSync(process.argv[1])).result,b=JSON.parse(fs.readFileSync(process.argv[2])).result;assert.equal(b.state,"REORG");assert.notEqual(a.truthState,"CONFLICTING");' "$base-original-reorg.json" "$base-bump-reorg.json"
  deployment_management_result FAILED
  for _ in {1..60}; do
    configuration_get "$base-original-management-reorg.json" "http://127.0.0.1:53003/api/v1/deployment-submissions/$original_submission"
    [[ $(operation_field "$base-original-management-reorg.json" state) == WRITE_AMBIGUITY ]] && break
    sleep 0.25
  done
  node -e 'const fs=require("fs"),assert=require("assert/strict"),v=JSON.parse(fs.readFileSync(process.argv[1]));assert.equal(v.state,"WRITE_AMBIGUITY");assert.equal(v.truthState,"WRITE_AMBIGUITY");assert.equal(v.occurrence,null);assert.equal(v.association,null);assert.equal(v.runtimePermission,"NONE");' "$base-original-management-reorg.json"
  # Renew only after the completed sender/finality path. Fresh preparations
  # cannot evade the permanent one-successor link, even after a reorg.
  deployment_require_runtime_window 30000
  body="$(node -e 'const fs=require("fs"),v=JSON.parse(process.argv[1]);v.signingPayload=JSON.parse(fs.readFileSync(process.argv[2])).signingPayload;v.reason="Deny fees above the current policy ceiling.";process.stdout.write(JSON.stringify(v));' "$original_intent_body" "${deployment_replacement_wallet_prefix:-$evidence_root/deployment-wallet-replacement}-ceiling.json")"
  approved_configuration_post "$base-fee-ceiling-denied.json" "$body" \
    http://127.0.0.1:8080/api/v1/deployment-intents "${deployment_case}-fee-ceiling-0001" '' POST "${deployment_case}-fee-ceiling" 400 0
  body="$(node -e 'const fs=require("fs"),v=JSON.parse(process.argv[1]);v.signingPayload=JSON.parse(fs.readFileSync(process.argv[2])).signingPayload;v.reason="Prepare a second fee increase for a permanent custody denial.";process.stdout.write(JSON.stringify(v));' "$original_intent_body" "${deployment_replacement_wallet_prefix:-$evidence_root/deployment-wallet-replacement}-second.json")"
  approved_configuration_post "$base-second-intent.json" "$body" \
    http://127.0.0.1:8080/api/v1/deployment-intents "${deployment_case}-second-intent-0001" '' POST "${deployment_case}-second-intent"
  body="$(node -e 'const fs=require("fs"),v=JSON.parse(process.argv[1]);v.deploymentIntentId=process.argv[2];v.signedTransaction=JSON.parse(fs.readFileSync(process.argv[3])).signedTransaction;v.reason="Deny a second successor despite independent approval.";process.stdout.write(JSON.stringify(v));' "$bump_body" "$(operation_field "$base-second-intent.json" resourceRef)" "${deployment_replacement_wallet_prefix:-$evidence_root/deployment-wallet-replacement}-second.json")"
  approved_configuration_post "$base-second-successor-denied.json" "$body" \
    http://127.0.0.1:8080/api/v1/deployment-submissions "${deployment_case}-second-successor-0001" '' POST "${deployment_case}-second-successor" 403 0
  # Predecessor custody remains permanent across response loss, restart and
  # reorg. Neither hash may receive another automatic sender attempt.
  node -e 'const fs=require("fs"),assert=require("assert/strict"),[file,...wallets]=process.argv.slice(1),rows=fs.readFileSync(file,"utf8").trim().split("\n").map(JSON.parse);for(const path of wallets){const wallet=JSON.parse(fs.readFileSync(path));assert.equal(rows.filter(row=>row.transactionHash===wallet.transactionHash).length,1);}' "$data_root/rpc-provider/deployment-submissions.jsonl" "$original_wallet" "$bump_wallet"
  printf 'OPENPC_DEPLOYMENT_REPLACEMENT|PASS|approval=fresh|effect=exact|fees=bounded|successor=one|send=one-per-hash|replay=exact|response-loss=ambiguous|restart=durable|supersession=observed|reorg=no-resend\n'
}

deployment_replacement_original_status() {
  local deployment_command_id=$2
  deployment_status "$1"
}

deployment_native_conflict_result() {
  # Check the winning transaction before selecting the rejected command's
  # distinct transaction. The rejected command must have zero provider sends.
  test "$(deployment_send_count)" = 1
  local deployment_case="native-conflict-$1"
  local deployment_command_id="$native_conflict_command_id"
  local deployment_submission_urn="$native_conflict_submission_urn"
  local deployment_wallet_path="$evidence_root/deployment-wallet-native-reuse.json"
  deployment_management_result FAILED true
  test "$(deployment_send_count)" = 0
  local events
  events="$(printf '%s\n' "select count(*) from control.outbox_event event
    join control.mutation_candidate candidate on candidate.resource_id=event.aggregate_id
      and candidate.participant_id=event.participant_id and candidate.privacy_domain_id=event.privacy_domain_id
    join control.deployment_result result on result.command_id=candidate.consumed_operation_id
      and result.participant_id=candidate.participant_id and result.privacy_domain_id=candidate.privacy_domain_id
    where candidate.consumed_operation_id=:'command_id' and result.sequence=1
      and event.event_type='openpc.deployment.reservation.rejected.v1' and event.aggregate_type='deployment-result'
      and event.aggregate_sequence=1 and event.payload_digest=sha256(event.payload_cbor);" |
    docker exec -i "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v command_id="$deployment_command_id")"
  test "$events" = 1
}

deployment_revoked_native() {
  local submit_body=$1 intent_body=$2
  approved_identity_mutation "$evidence_root/native-value-revoked-wallet.json" '{}' \
    "{\"walletBindingId\":\"$deployment_execution_wallet_id\",\"state\":\"REVOKED\"}" \
    "http://127.0.0.1:8080/v1/identity/wallet-bindings/$deployment_execution_wallet_id/revoke" \
    native-value-wallet-revoke-0001 "$deployment_execution_wallet_id" 1 native-value-wallet-revoke 200
  configuration_get "$evidence_root/native-value-revoked-current.json" \
    "http://127.0.0.1:8080/api/v1/native-value-authorizations/$native_urn"
  node -e 'const fs=require("fs"),g=JSON.parse(fs.readFileSync(process.argv[1])),i=JSON.parse(fs.readFileSync(process.argv[2]));if(g.state!=="INVALIDATED"||Date.parse(g.validUntil)<=Date.now()||Date.parse(i.expiresAt)<=Date.now())throw Error("revocation test requires unexpired grant and intent");' \
    "$evidence_root/native-value-revoked-current.json" "$evidence_root/deployment-native-revoked-execution-intent-read.json"
  approved_configuration_post "$evidence_root/native-value-revoked-submit-denied.json" "$submit_body" \
    http://127.0.0.1:8080/api/v1/deployment-submissions native-value-revoked-submit-0001 '' POST native-revoked-submit 403 0
  intent_body="$(node -e 'const v=JSON.parse(process.argv[1]);v.reason="Reject an unexpired Native Value authorization after public wallet revocation.";process.stdout.write(JSON.stringify(v));' "$intent_body")"
  approved_configuration_post "$evidence_root/native-value-revoked-prepare-denied.json" "$intent_body" \
    http://127.0.0.1:8080/api/v1/deployment-intents native-value-revoked-prepare-0001 '' POST native-revoked-prepare 403 0
  test "$(deployment_send_count)" = 0
  local held
  held="$(printf '%s\n' "select count(*) from control.deployment_address_reservation where native_value_authorization_id=:'authorization';" | \
    docker exec -i "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v authorization="${native_urn##*:}")"
  test "$held" = 0
  printf 'OPENPC_NATIVE_VALUE_REVOCATION|PASS|public-wallet-revocation|grant-and-intent=unexpired|stale-submit=denied|fresh-prepare=denied|reservation=none|provider-sends=zero\n'
}

deployment_wait_preparation_expiry() {
  node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1])),expires=Date.parse(v.expiresAt),issued=Date.parse(v.createdAt),delay=Math.max(0,expires-Date.now()+200);if(!Number.isFinite(delay)||expires<=issued||expires-issued>300000||delay>300200)throw Error("unexpected preparation lifetime");const wait=()=>{const remaining=expires-Date.now()+200;if(remaining>0)setTimeout(wait,Math.min(10000,remaining));};wait();' \
    "$1"
}

deployment_expired_command() {
  local submit_body=$1
  configuration_get "$evidence_root/deployment-expired-queued.json" \
    "http://127.0.0.1:53003/api/v1/deployment-submissions/$deployment_submission_urn"
  node -e 'const fs=require("fs"),assert=require("assert/strict"),v=JSON.parse(fs.readFileSync(process.argv[1]));assert.equal(v.state,"ACCEPTED");assert.equal(v.attempt,null);' \
    "$evidence_root/deployment-expired-queued.json"
  test "$(deployment_send_count)" = 0
  deployment_wait_preparation_expiry "$evidence_root/deployment-expired-execution-intent-read.json"
  "${compose[@]}" start control-worker >/dev/null
  deployment_management_result FAILED true
  cp "$evidence_root/deployment-expired-management-FAILED.json" "$evidence_root/deployment-expired-before-restart.json"
  configuration_post "$evidence_root/deployment-expired-command-replay.json" "$submit_body" \
    http://127.0.0.1:8080/api/v1/deployment-submissions deployment-expired-execution-command-0001 '' POST 202 "$configuration_operator_session" 0
  assert_json_equal "$evidence_root/deployment-expired-execution-command.json" "$evidence_root/deployment-expired-command-replay.json"
  "${compose[@]}" restart control-worker >/dev/null
  deployment_management_result FAILED true
  assert_json_equal "$evidence_root/deployment-expired-before-restart.json" "$evidence_root/deployment-expired-management-FAILED.json"
  test "$(deployment_send_count)" = 0
  local durable
  durable="$(printf '%s\n' "select count(*) from control.deployment_result result
    join control.mutation_candidate candidate on candidate.consumed_operation_id=result.command_id
    join control.deployment_intent intent on 'urn:openpc:resource:'||intent.deployment_intent_id::text=candidate.candidate_document->>'deploymentIntentId'
    where result.command_id=:'command_id' and result.sequence=1
      and convert_from(result.signed_bytes,'UTF8')::jsonb->'claims'->>'reason'='PREPARATION_EXPIRED'
      and (convert_from(result.signed_bytes,'UTF8')::jsonb->'claims'->>'observedAt')::timestamptz>=intent.expires_at
      and not exists(select 1 from control.deployment_address_reservation where command_id=result.command_id)
      and (select count(*) from control.outbox_event event where event.aggregate_id=candidate.resource_id
        and event.event_type='openpc.deployment.reservation.rejected.v1' and event.aggregate_sequence=1
        and event.payload_digest=sha256(event.payload_cbor))=1;" |
    docker exec -i "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v command_id="$deployment_command_id")"
  test "$durable" = 1
  configuration_get "$evidence_root/native-value-expired-after-deadline.json" \
    "http://127.0.0.1:8080/api/v1/native-value-authorizations/$native_urn"
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(!["UNUSED","EXPIRED"].includes(v.state)||v.runtimePermission!=="NONE")throw Error("pre-custody expiry consumed Native Value authority");' "$evidence_root/native-value-expired-after-deadline.json"
  printf 'OPENPC_DEPLOYMENT_SUBMISSION|expired|PASS|native-positive-value|public-approved-command|worker-stopped-before-handoff|real-expiry|grant-unconsumed|zero-sends|no-reservation|no-attempt|no-association|one-event|failed-readback|replay|restart\n'
}

# An interrupted real worker abandons the Envoy request during a delayed
# external trace call. Internal admission remains real; the journal reaper
# must retain a terminal no-send result, and restart must never dispatch it.
deployment_abandoned_handoff() {
  local submit_body=$1 observed=0
  for _ in {1..80}; do
    if node -e 'const fs=require("fs"),[file,walletFile]=process.argv.slice(1),wallet=JSON.parse(fs.readFileSync(walletFile));if(!fs.existsSync(file))process.exit(1);process.exit(fs.readFileSync(file,"utf8").trim().split("\n").filter(Boolean).map(JSON.parse).some(v=>v.transactionHash===wallet.transactionHash&&v.abandonedPreflight===true)?0:1);' \
      "$data_root/rpc-provider/deployment-observations.jsonl" "$deployment_wallet_path"; then observed=1; break; fi
    sleep 0.1
  done
  test "$observed" = 1
  "${compose[@]}" stop -t 0 control-worker >/dev/null
  deployment_wait_observation FAILED_PRE_START record
  test "$(deployment_send_count)" = 0
  "${compose[@]}" start control-worker >/dev/null
  deployment_management_result FAILED true
  configuration_post "$evidence_root/deployment-$deployment_case-command-replay.json" "$submit_body" \
    http://127.0.0.1:8080/api/v1/deployment-submissions "deployment-$deployment_case-execution-command-0001" '' POST 202 "$configuration_operator_session" 0
  assert_json_equal "$evidence_root/deployment-$deployment_case-execution-command.json" "$evidence_root/deployment-$deployment_case-command-replay.json"
  cp "$evidence_root/deployment-$deployment_case-management-FAILED.json" "$evidence_root/deployment-$deployment_case-before-restart.json"
  deployment_require_runtime_window
  "${compose[@]}" restart runtime-target control-worker >/dev/null
  start_runtime_target
  deployment_management_result FAILED true
  assert_json_equal "$evidence_root/deployment-$deployment_case-before-restart.json" "$evidence_root/deployment-$deployment_case-management-FAILED.json"
  test "$(deployment_send_count)" = 0
  docker exec "$("${compose[@]}" ps -q runtime-target)" cat "/runtime/broker/$target_id/submission.journal" | node -e '
    const fs=require("fs"),b=fs.readFileSync(0),id=process.argv[1],states=[];let o=0;
    while(o<b.length){const n=b.readUInt32BE(o),{record:r}=JSON.parse(b.subarray(o+4,o+4+n));o+=4+n;if(r.command_id===id)states.push(r.state);}
    if(states.includes("STARTED")||states.at(-1)!=="FAILED_PRE_START"||states.filter(s=>s==="PREPARED").length!==1)throw Error("no-send custody changed or retried");
  ' "$deployment_command_id"
  printf 'OPENPC_DEPLOYMENT_SUBMISSION|no-send|PASS|public-approved-command|worker-interruption|zero-sends|no-attempt|no-association|failed-readback|replay|restart\n'
}
