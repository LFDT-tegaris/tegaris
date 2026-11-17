# Sourced by the existing resource-guarded Compose runner. Only external chain
# behavior and initial trust are fixtures; every business transition is public.
cigl_input() { node tests/integration/local-runtime/cigl-activation-journey.mjs "$1" "$evidence_root" "${@:2}"; }
cigl_etag() {
  local resource
  resource="$(json_value "$1" targetRef)"
  node tests/integration/local-runtime/configuration-fixture.mjs etag \
    "${resource#urn:openpc:resource:}" "$(json_value "$1" expectedRevision)"
}

prepare_cigl_resources() {
  openssl rand 32 > "$secret_root/cigl-wallet.key"
  cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
    "$secret_root/cigl-wallet.key" CIGL_CALL > "$evidence_root/cigl-wallet.json"
  cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
    "$secret_root/cigl-wallet.key" CIGL_CALL 10 > "$evidence_root/cigl-renewed-wallet.json"
  cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
    "$secret_root/cigl-wallet.key" CIGL_CALL 11 > "$evidence_root/cigl-next-wallet.json"
  cp "$evidence_root/cigl-wallet.json" "$data_root/rpc-provider/cigl-wallet.json"
  local body ref
  body="$(cigl_input settings "$(action_digest ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1)")"
  if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_BROWSER:-0} == 1 ]]; then
    "${compose[@]}" up -d --wait --no-build --pull never participant-service admin-web >/dev/null
    node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs "$secret_root" "$evidence_root" "$participant_id" bootstrap-review
    node tests/integration/local-runtime/transaction-cigl-browser.mjs settings "$secret_root" "$evidence_root" "$body"
  else
    approved_configuration_post "$evidence_root/cigl-settings.json" "$body" \
      http://127.0.0.1:53003/api/v1/cigl-settings cigl-settings-0001 '' POST cigl-settings
    ref="$(operation_field "$evidence_root/cigl-settings.json" resourceRef)"
    configuration_get "$evidence_root/cigl-settings-resource.json" "http://127.0.0.1:53003/api/v1/cigl-settings/$ref"
  fi
  OPENPC_LOCAL_CIGL_SETTINGS_CBOR_HEX="$(operation_field "$evidence_root/cigl-settings-resource.json" configurationArtifactCbor)"
  export OPENPC_LOCAL_CIGL_SETTINGS_CBOR_HEX="${OPENPC_LOCAL_CIGL_SETTINGS_CBOR_HEX#0x}"
}

prepare_cigl_authority() {
  source tests/integration/local-runtime/deployment-submission-journey.sh
  "${compose[@]}" up -d --wait --no-build --pull never participant-service >/dev/null
  if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_BROWSER:-0} == 1 ]]; then
    node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs "$secret_root" "$evidence_root" "$participant_id" grant-runtime
  else
    node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs "$secret_root" "$evidence_root" "$participant_id"
  fi
  with_deployment_actors prepare_cigl_actor_authority
  "${compose[@]}" stop participant-service admin-web >/dev/null
}

prepare_cigl_actor_authority() {
  local wallet_id body candidate delegation_id parent
  wallet_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  body="$(node -e 'const fs=require("fs"),[path,walletBindingId,subjectId]=process.argv.slice(1);process.stdout.write(JSON.stringify({walletBindingId,subjectId,chainId:"31337",walletAddress:JSON.parse(fs.readFileSync(path)).sender}));' "$evidence_root/cigl-wallet.json" "$wallet_id" "$workload_principal_id")"
  candidate="$(node -e 'process.stdout.write(JSON.stringify({...JSON.parse(process.argv[1]),participantId:process.argv[2]}))' "$body" "$participant_id")"
  approved_identity_mutation "$evidence_root/cigl-wallet-binding.json" "$body" "$candidate" \
    http://127.0.0.1:8080/v1/identity/wallet-bindings cigl-wallet-0001 "$wallet_id" 0 cigl-wallet 201
  parent="$(fixture_value "$evidence_root/deployment-intent-actors.json" maker runtimeAssignmentId)"
  delegation_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  body="$(node -e 'const [delegationId,parentId,granteeId,resource]=process.argv.slice(1);process.stdout.write(JSON.stringify({delegationId,parentId,granteeId,scopeDigest:"sha256:"+require("crypto").createHash("sha256").update(delegationId).digest("hex"),privacyDomainIds:["018f0000-0000-7000-8000-000000000201"],actionIntentIds:[],capabilityIds:["SIGNED_TRANSACTION_SUBMISSION"],resourceIds:[resource],riskClasses:["HIGH"],validFrom:new Date(Date.now()-60000).toISOString(),validUntil:"2030-01-01T00:00:00.000Z",makerCheckerRequired:false,stepUpRequired:false,onwardDelegationDepth:0}));' "$delegation_id" "$parent" "$workload_principal_id" "${binding_urn##*:}")"
  candidate="$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({id:v.delegationId,participantId:process.argv[2],grantorId:process.argv[3],state:"ACTIVE",delegationEpoch:"0",...v}));' "$body" "$participant_id" "$operator_principal_id")"
  approved_identity_mutation "$evidence_root/cigl-submission-delegation.json" "$body" "$candidate" \
    "http://127.0.0.1:8080/v1/participants/$participant_id/delegations" cigl-submission-0001 "$delegation_id" 0 cigl-submission 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
  delegation_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  body="$(node -e 'const v=JSON.parse(process.argv[1]);v.delegationId=process.argv[2];v.capabilityIds=["OPERATION_STATUS_DISCLOSURE"];v.resourceIds=["*"];v.scopeDigest="sha256:"+require("crypto").createHash("sha256").update(v.delegationId).digest("hex");process.stdout.write(JSON.stringify(v));' "$body" "$delegation_id")"
  candidate="$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({id:v.delegationId,participantId:process.argv[2],grantorId:process.argv[3],state:"ACTIVE",delegationEpoch:"0",...v}));' "$body" "$participant_id" "$operator_principal_id")"
  approved_identity_mutation "$evidence_root/cigl-status-delegation.json" "$body" "$candidate" \
    "http://127.0.0.1:8080/v1/participants/$participant_id/delegations" cigl-status-0001 "$delegation_id" 0 cigl-status 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
}

cigl_target_request() {
  local output=$1 path=$2 body=$3
  curl -sS --max-time 8 --tlsv1.3 --tls-max 1.3 --cacert "$secret_root/identity_mtls_ca.pem" \
    --cert "$secret_root/identity_mtls_rotated_cert.pem" --key "$secret_root/identity_mtls_rotated_key.pem" \
    -H 'Content-Type: application/json' -H "x-openpc-identity-assertion: $runtime_assertion_hex" \
    --data "$body" -o "$output" -w '%{http_code}' "https://localhost:18545$path"
}

cigl_activate_profile() {
  local phase source_file before_file target_file body operation status
  phase=$1
  source_file=$2
  before_file=$3
  target_file=$4
  refresh_runtime_assertion "$evidence_root/${phase}-identity.json"
  # Publication must use a real, sufficiently fresh Identity snapshot. Wait
  # out a nearly expired head; never extend its signed validity in the harness.
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])),remaining=Number(BigInt(v.runtime.expiresAtNs)/1000000n)-Date.now();if(remaining>60000)throw Error("unexpected identity lifetime");setTimeout(()=>{},remaining<45000?Math.max(0,remaining)+100:0);' "$evidence_root/${phase}-identity.json"
  refresh_runtime_assertion "$evidence_root/${phase}-identity.json"
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(Number(BigInt(v.runtime.expiresAtNs)/1000000n)-Date.now()<45000)throw Error("insufficient CIGL activation lifetime");' "$evidence_root/${phase}-identity.json"
  body="$(cigl_input activation "$(action_digest ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1)" "$source_file")"
  approved_configuration_post "$evidence_root/${phase}-queued.json" "$body" \
    "http://127.0.0.1:53003/api/v1/runtime-targets/$target_urn/cigl-profiles" "$phase-0001" "$(cigl_etag "$body")" POST "$phase" 202 0
  operation="$(operation_field "$evidence_root/${phase}-queued.json" operationId)"
  # A real mTLS request observes Envoy's generation. Neither the harness nor
  # Fleet fabricates readiness, an activation receipt or a request ACK.
  for _ in {1..100}; do
    cigl_target_request "$evidence_root/${phase}-convergence-response.json" "$analysis_path" "$analysis_body" >/dev/null || true
    configuration_get "$evidence_root/${phase}-operation.json" "http://127.0.0.1:53003/api/v1/operations/$operation"
    status="$(operation_field "$evidence_root/${phase}-operation.json" state)"
    [[ $status == SUCCEEDED ]] && break
    [[ $status != FAILED ]] || { cat "$evidence_root/${phase}-operation.json" >&2; return 1; }
    sleep 0.25
  done
  [[ $status == SUCCEEDED ]]
  configuration_get "$evidence_root/$target_file" "http://127.0.0.1:53003/api/v1/runtime-targets/$target_urn"
  cigl_input active "$before_file" "$target_file" "$phase-operation.json"
}

cigl_revoke_and_recover() {
  local prefix identity_file target_file grant_revision body status provider_count analysis_body
  prefix=$1
  identity_file=$2
  target_file=$3
  grant_revision=$4
  # Use the fresh nonce as the canary. An already consumed canonical nonce can
  # deny before invalidation reaches the target and cannot prove revocation.
  analysis_body="$(node -e 'process.stdout.write(JSON.stringify({signedTransaction:JSON.parse(process.argv[1]).params[0]}))' "$new_submission_body")"
  [[ $(cigl_target_request "$evidence_root/${prefix}-before-revocation.json" "$analysis_path" "$analysis_body") == 200 ]]
  body="$(cigl_input grant-status "$(action_digest ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1)" "$grant" "$grant_revision" DISABLED)"
  approved_configuration_post "$evidence_root/${prefix}-grant-disabled.json" "$body" \
    "http://127.0.0.1:53003/api/v1/cigl-grants/$grant/status" "${prefix}-grant-disabled-0001" "$(cigl_etag "$body")" POST "${prefix}-grant-disabled"
  for _ in {1..40}; do
    status="$(cigl_target_request "$evidence_root/${prefix}-denied.json" "$analysis_path" "$analysis_body")"
    [[ $status == 403 ]] && break
    sleep 0.25
  done
  [[ $status == 403 ]]
  cigl_input denied "${prefix}-denied.json"
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(BigInt(Date.now())*1000000n>=BigInt(v.runtime.expiresAtNs))throw Error("expiry cannot establish source invalidation acceptance");' "$evidence_root/$identity_file"
  # REQ-SR01-B0-LEDGER-SEM-164 preserves the original durable outcome before
  # current policy/route admission. Receipt replay never authorizes another send.
  [[ $(cigl_target_request "$evidence_root/${prefix}-revoked-replay.json" /rpc "$submission_body") == 200 ]]
  cigl_input replayed "${prefix}-revoked-replay.json"
  [[ $(cigl_target_request "$evidence_root/${prefix}-revoked-renewed-replay.json" /rpc "$renewed_submission_body") == 200 ]]
  cigl_input replayed "${prefix}-revoked-renewed-replay.json" cigl-renewed-submitted.json
  provider_count="$(wc -l < "$data_root/rpc-provider/requests.jsonl")"
  [[ $(cigl_target_request "$evidence_root/${prefix}-revoked-new-submit.json" /rpc "$new_submission_body") == 403 ]]
  cigl_input denied "${prefix}-revoked-new-submit.json"
  cigl_input no-submission-preflight "$data_root/rpc-provider/requests.jsonl" "$provider_count"
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(BigInt(Date.now())*1000000n>=BigInt(v.runtime.expiresAtNs))throw Error("expiry cannot establish new-submission invalidation acceptance");' "$evidence_root/$identity_file"
  cigl_input one-send-per-hash "$data_root/rpc-provider/cigl-submissions.jsonl" cigl-wallet.json cigl-renewed-wallet.json
  "${compose[@]}" restart runtime-target control-worker control-api runtime-envoy >/dev/null
  start_runtime_target
  refresh_runtime_assertion "$evidence_root/${prefix}-restart-identity.json"
  [[ $(cigl_target_request "$evidence_root/${prefix}-restart-denied.json" "$analysis_path" "$analysis_body") == 403 ]]
  cigl_input denied "${prefix}-restart-denied.json"
  provider_count="$(wc -l < "$data_root/rpc-provider/requests.jsonl")"
  [[ $(cigl_target_request "$evidence_root/${prefix}-restart-new-submit.json" /rpc "$new_submission_body") == 403 ]]
  cigl_input denied "${prefix}-restart-new-submit.json"
  cigl_input no-submission-preflight "$data_root/rpc-provider/requests.jsonl" "$provider_count"
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(BigInt(Date.now())*1000000n>=BigInt(v.runtime.expiresAtNs))throw Error("expiry cannot establish restart invalidation acceptance");' "$evidence_root/$identity_file"
  [[ $(cigl_target_request "$evidence_root/${prefix}-restart-replay.json" /rpc "$submission_body") == 200 ]]
  cigl_input replayed "${prefix}-restart-replay.json"
  [[ $(cigl_target_request "$evidence_root/${prefix}-restart-renewed-replay.json" /rpc "$renewed_submission_body") == 200 ]]
  cigl_input replayed "${prefix}-restart-renewed-replay.json" cigl-renewed-submitted.json
  cigl_input one-send-per-hash "$data_root/rpc-provider/cigl-submissions.jsonl" cigl-wallet.json cigl-renewed-wallet.json
  configuration_get "$evidence_root/${prefix}-restart-target.json" "http://127.0.0.1:53003/api/v1/runtime-targets/$target_urn"
  node -e 'const fs=require("fs"),a=JSON.parse(fs.readFileSync(process.argv[1])),b=JSON.parse(fs.readFileSync(process.argv[2]));require("assert/strict").equal(a.activeGenerationDigest,b.activeGenerationDigest);' "$evidence_root/$target_file" "$evidence_root/${prefix}-restart-target.json"
}

cigl_post_mine_acceptance() {
  local body status confirmed=0
  # Only the external chain changes. Internal authority and durable results
  # still come from public commands, the real target and its recovery owner.
  node -e 'const fs=require("fs"),w=JSON.parse(fs.readFileSync(process.argv[1]));fs.writeFileSync(process.argv[2],JSON.stringify({transactionHash:w.transactionHash,diverged:true}),{mode:0o600});' \
    "$evidence_root/cigl-wallet.json" "$data_root/rpc-provider/cigl-mined.json"
  body="$(node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));process.stdout.write(JSON.stringify({jsonrpc:"2.0",id:5,method:"pc_getOperationStatus",params:[v.result.operationId]}));' "$evidence_root/cigl-submitted.json")"
  for _ in {1..60}; do
    status="$(cigl_target_request "$evidence_root/cigl-postmine-status.json" /rpc "$body")"
    [[ $status == 200 ]] || { cat "$evidence_root/cigl-postmine-status.json" >&2; return 1; }
    if node -e 'process.exit(JSON.parse(require("fs").readFileSync(process.argv[1])).result?.state==="CONFIRMED"?0:1)' "$evidence_root/cigl-postmine-status.json"; then confirmed=1; break; fi
    sleep 0.2
  done
  [[ $confirmed == 1 ]]
  "${compose[@]}" exec -T runtime-target cat "/runtime/broker/$target_id/submission.journal" > "$evidence_root/cigl-postmine.journal"
  cigl_input postmine cigl-postmine-status.json "$evidence_root/cigl-postmine.journal"
  "${compose[@]}" restart runtime-target >/dev/null
  start_runtime_target
  [[ $(cigl_target_request "$evidence_root/cigl-postmine-restart-status.json" /rpc "$body") == 200 ]]
  "${compose[@]}" exec -T runtime-target cat "/runtime/broker/$target_id/submission.journal" > "$evidence_root/cigl-postmine-restart.journal"
  cigl_input postmine cigl-postmine-restart-status.json "$evidence_root/cigl-postmine-restart.journal"
  cigl_input replayed cigl-postmine-restart-status.json cigl-postmine-status.json
  cigl_input one-send-per-hash "$data_root/rpc-provider/cigl-submissions.jsonl" cigl-wallet.json
  printf 'OPENPC_CIGL_POSTMINE|PASS|public-authority|exact-mined-trace|durable-divergence|public-effect-readback|restart|no-resend\n'
}

run_cigl_activation() {
  local body analysis grant status operation submission_body renewed_submission_body new_submission_body analysis_body analysis_path nested_read_body provider_count
  refresh_runtime_assertion "$evidence_root/cigl-runtime-identity.json"
  submission_body="$(node -e 'const w=JSON.parse(require("fs").readFileSync(process.argv[1]));process.stdout.write(JSON.stringify({jsonrpc:"2.0",id:3,method:"eth_sendRawTransaction",params:[w.signedTransaction]}))' "$evidence_root/cigl-wallet.json")"
  renewed_submission_body="$(node -e 'const fs=require("fs"),a=JSON.parse(fs.readFileSync(process.argv[1])),b=JSON.parse(fs.readFileSync(process.argv[2])),assert=require("assert/strict");assert.equal(a.sender,b.sender);assert.equal(a.calldata,b.calldata);assert.equal(a.destination,b.destination);assert.equal(b.nonce,a.nonce+1);assert.notEqual(a.transactionHash,b.transactionHash);process.stdout.write(JSON.stringify({jsonrpc:"2.0",id:4,method:"eth_sendRawTransaction",params:[b.signedTransaction]}))' "$evidence_root/cigl-wallet.json" "$evidence_root/cigl-renewed-wallet.json")"
  new_submission_body="$(node -e 'const fs=require("fs"),a=JSON.parse(fs.readFileSync(process.argv[1])),b=JSON.parse(fs.readFileSync(process.argv[2])),assert=require("assert/strict");assert.equal(a.sender,b.sender);assert.equal(a.calldata,b.calldata);assert.equal(a.destination,b.destination);assert.equal(b.nonce,a.nonce+1);assert.notEqual(a.transactionHash,b.transactionHash);process.stdout.write(JSON.stringify({jsonrpc:"2.0",id:4,method:"eth_sendRawTransaction",params:[b.signedTransaction]}))' "$evidence_root/cigl-renewed-wallet.json" "$evidence_root/cigl-next-wallet.json")"
  [[ $(cigl_target_request "$evidence_root/cigl-before-profile.json" /rpc "$submission_body") == 403 ]]
  cigl_input denied cigl-before-profile.json
  [[ ! -e "$data_root/rpc-provider/cigl-submissions.jsonl" ]]
  configuration_get "$evidence_root/cigl-base-target.json" "http://127.0.0.1:53003/api/v1/runtime-targets/$target_urn"
  body="$(cigl_input analysis "$(action_digest ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1)" "$workload_id")"
  approved_configuration_post "$evidence_root/cigl-analysis-created.json" "$body" \
    http://127.0.0.1:53003/api/v1/cigl-analyses cigl-analysis-0001 '' POST cigl-analysis
  analysis="$(operation_field "$evidence_root/cigl-analysis-created.json" resourceRef)"
  body="$(node -e 'process.stdout.write(JSON.stringify({signedTransaction:JSON.parse(require("fs").readFileSync(process.argv[1])).signedTransaction}))' "$evidence_root/cigl-wallet.json")"
  analysis_body="$body"
  analysis_path="/api/v1/cigl-analyses/$analysis/observe"
  status="$(cigl_target_request "$evidence_root/cigl-target-observation.json" "$analysis_path" "$analysis_body")"
  [[ $status == 200 ]] || { cat "$evidence_root/cigl-target-observation.json" >&2; return 1; }
  body="$(cigl_input observe "$(action_digest ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1)" "$analysis")"
  approved_configuration_post "$evidence_root/cigl-observation-operation.json" "$body" \
    "http://127.0.0.1:53003/api/v1/cigl-analyses/$analysis/observation" cigl-observation-0001 "$(cigl_etag "$body")" POST cigl-observation
  configuration_get "$evidence_root/cigl-analysis-observed.json" "http://127.0.0.1:53003/api/v1/cigl-analyses/$analysis"
  body="$(cigl_input grant "$(action_digest ACT-CIGL_GRANTS_CREATE_RESOURCE-V1)" "$workload_id")"
  approved_configuration_post "$evidence_root/cigl-grant-created.json" "$body" \
    http://127.0.0.1:53003/api/v1/cigl-grants cigl-grant-create-0001 '' POST cigl-grant
  grant="$(operation_field "$evidence_root/cigl-grant-created.json" resourceRef)"
  body="$(cigl_input grant-status "$(action_digest ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1)" "$grant" 1 ACTIVE)"
  approved_configuration_post "$evidence_root/cigl-grant-active.json" "$body" \
    "http://127.0.0.1:53003/api/v1/cigl-grants/$grant/status" cigl-grant-active-0001 "$(cigl_etag "$body")" POST cigl-grant-active
  body="$(cigl_input review "$(action_digest ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1)")"
  approved_configuration_post "$evidence_root/cigl-review-operation.json" "$body" \
    "http://127.0.0.1:53003/api/v1/cigl-analyses/$analysis/review" cigl-review-0001 "$(cigl_etag "$body")" POST cigl-review
  operation="$(operation_field "$evidence_root/cigl-review-operation.json" operationId)"
  poll_configuration_operation "$operation" "$evidence_root/cigl-compilation-operation.json"
  configuration_get "$evidence_root/cigl-analysis-compiled.json" "http://127.0.0.1:53003/api/v1/cigl-analyses/$analysis"
  [[ ! -e "$data_root/rpc-provider/cigl-submissions.jsonl" ]]
  cigl_activate_profile cigl-activation cigl-analysis-compiled.json cigl-base-target.json cigl-active-target.json
  configuration_get "$evidence_root/cigl-installed-analysis.json" "http://127.0.0.1:53003/api/v1/cigl-analyses/$analysis"
  cigl_input installed-lineage
  # Both observation and the actual signed transaction use the installed profile.
  [[ $(cigl_target_request "$evidence_root/cigl-active-observation.json" "$analysis_path" "$analysis_body") == 200 ]]
  # Its nested RAW_SUBMISSION grant cannot enable a caller-facing read route.
  # Read-profile selector/identity acceptance remains with the existing read gate.
  nested_read_body="$(node -e 'const v=JSON.parse(process.argv[1]);v.params[0].to="0x"+"22".repeat(20);v.params[0].data="0x70a08231"+"00".repeat(12)+"22".repeat(20);process.stdout.write(JSON.stringify(v));' "$runtime_request_body")"
  provider_count="$(wc -l < "$data_root/rpc-provider/requests.jsonl")"
  [[ $(cigl_target_request "$evidence_root/cigl-nested-direct-read.json" /rpc "$nested_read_body") == 403 ]]
  cigl_input denied cigl-nested-direct-read.json
  [[ $(wc -l < "$data_root/rpc-provider/requests.jsonl") == "$provider_count" ]]
  [[ $(cigl_target_request "$evidence_root/cigl-submitted.json" /rpc "$submission_body") == 200 ]]
  cigl_input submitted
  [[ $(wc -l < "$data_root/rpc-provider/cigl-submissions.jsonl") == 1 ]]
  if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_POSTMINE_ONLY:-0} == 1 ]]; then
    cigl_post_mine_acceptance
    return
  fi
  # The external fixture independently rejects any receipt query for another
  # hash. Observe through the journal's pinned write profile without resending.
  for _ in {1..30}; do
    if node -e 'const fs=require("fs");process.exit(fs.readFileSync(process.argv[1],"utf8").trim().split("\n").some(line=>JSON.parse(line).method==="eth_getTransactionReceipt")?0:1)' "$data_root/rpc-provider/requests.jsonl"; then
      break
    fi
    sleep 0.25
  done
  node -e 'const fs=require("fs");require("assert/strict").ok(fs.readFileSync(process.argv[1],"utf8").trim().split("\n").some(line=>JSON.parse(line).method==="eth_getTransactionReceipt"));' "$data_root/rpc-provider/requests.jsonl"
  # Let the original signed authority expire. A new Identity assertion alone
  # must not renew the target; renewal uses the public profile activation owner.
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])),remaining=Number(BigInt(v.runtime.expiresAtNs)/1000000n)-Date.now();if(remaining>60000)throw Error("unexpected identity lifetime");setTimeout(()=>{},Math.max(0,remaining)+100);' "$evidence_root/cigl-activation-identity.json"
  refresh_runtime_assertion "$evidence_root/cigl-expired-identity.json"
  [[ $(cigl_target_request "$evidence_root/cigl-expired-denied.json" "$analysis_path" "$analysis_body") == 403 ]]
  cigl_input denied cigl-expired-denied.json
  [[ $(cigl_target_request "$evidence_root/cigl-expired-replay.json" /rpc "$submission_body") == 200 ]]
  cigl_input replayed cigl-expired-replay.json
  configuration_get "$evidence_root/cigl-renewal-source.json" "http://127.0.0.1:53003/api/v1/cigl-analyses/$analysis"
  cigl_input installed-lineage cigl-renewal-source.json cigl-active-target.json
  cigl_activate_profile cigl-renewal cigl-renewal-source.json cigl-active-target.json cigl-renewed-target.json
  configuration_get "$evidence_root/cigl-renewed-analysis.json" "http://127.0.0.1:53003/api/v1/cigl-analyses/$analysis"
  cigl_input installed-lineage cigl-renewed-analysis.json cigl-renewed-target.json
  # Only the external chain fixture advances its nonce. All permission and
  # target-generation transitions above came from the public internal owners.
  cp "$evidence_root/cigl-renewed-wallet.json" "$data_root/rpc-provider/cigl-renewed-wallet.json"
  [[ $(cigl_target_request "$evidence_root/cigl-renewed-submitted.json" /rpc "$renewed_submission_body") == 200 ]]
  cigl_input submitted cigl-renewed-submitted.json cigl-renewed-wallet.json
  cigl_input one-send-per-hash "$data_root/rpc-provider/cigl-submissions.jsonl" cigl-wallet.json cigl-renewed-wallet.json
  cigl_revoke_and_recover cigl cigl-renewal-identity.json cigl-renewed-target.json 2
  printf 'OPENPC_CIGL_ACTIVATION|PASS|public-review|shared-grant|actual-target-effect|expired-authority|public-renewal|two-distinct-sends|source-revocation|restart-denial\n'
}

# Browser review needs a complete observation/compilation window on one signed
# generation. Expiry still fails at the real owner; renewal happens beforehand.
cigl_require_browser_sources() {
  local publication_renewed=0
  if (( $(deployment_provider_remaining_ms) < 300000 )); then deployment_refresh_provider_qualification; fi
  if ! node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));process.exit(Date.parse(v.definition.expiresAt)-Date.now()>=300000?0:1)' "$evidence_root/configuration-deployment-policy-resource.json"; then
    deployment_refresh_publications
    publication_renewed=1
  fi
  if (( $(deployment_fact_remaining_ms) < 300000 || publication_renewed == 1 )); then deployment_refresh_fact; fi
}

prepare_cigl_browser_window() {
  local deployment_runtime_owner_session=$configuration_operator_session
  local deployment_runtime_renewals=${deployment_runtime_renewals:-9000}
  local deployment_fact_path=${deployment_fact_path:-"$evidence_root/typed-policy-fact.json"}
  local deployment_runtime_expiry_ns
  deployment_reactivate_runtime cigl_require_browser_sources
  deployment_runtime_expiry_ns="$(deployment_installed_expiry)"
  node -e 'if(Number(BigInt(process.argv[1])/1000000n)-Date.now()<45000)throw Error("CIGL browser requires a complete signed runtime window");' "$deployment_runtime_expiry_ns"
  printf 'OPENPC_CIGL_BROWSER_WINDOW|PASS|public-target-renewal|original-lifetimes-preserved\n'
}

# A source refresh for an installed graph stages the existing policy occurrence;
# only the separately approved CIGL command may dispatch the combined renewal.
cigl_stage_policy_renewal() {
  local prefix=$1 occurrence_ref=$2 generation_digest=$3 revision body occurrence_id
  occurrence_id=${occurrence_ref##*:}
  policy_get "$evidence_root/$prefix-renewal-before.json"     "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_ref" "$configuration_operator_session"
  revision="$(operation_field "$evidence_root/$prefix-renewal-before.json" revision)"
  body="$(node -e 'const [targetRef,expectedRevision,replacementDigest,actionIntentDigest]=process.argv.slice(1);process.stdout.write(JSON.stringify({expectedRevision,replacementDigest,actionIntentId:"ACT-ACTIVATION_OCCURRENCES_UPDATE_RESOURCE-V1",actionIntentDigest,reason:"Rebind the unstarted occurrence to a newly approved immutable source release for governed profile renewal."}));' "$occurrence_ref" "$revision" "$generation_digest" "$(action_digest ACT-ACTIVATION_OCCURRENCES_UPDATE_RESOURCE-V1)")"
  policy_mutation "$evidence_root/$prefix-renewal-update.json" "$body"     "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_ref" "$prefix-profile-renewal-update-0001"     "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$occurrence_id" "$revision")" PATCH
  policy_get "$evidence_root/$prefix-renewal-requested.json"     "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_ref" "$configuration_operator_session"
  cigl_policy_renewal_path="$evidence_root/cigl-policy-renewal.json"
  node -e 'const fs=require("fs"),[path,out]=process.argv.slice(1),v=JSON.parse(fs.readFileSync(path));if(v.state!=="REQUESTED"||v.matchedTargetCount!=="0")throw Error("renewal must remain unstarted");fs.writeFileSync(out,JSON.stringify({activationOccurrenceRef:v.activationOccurrenceId,expectedRevision:v.revision,policyGenerationDigest:v.targetGenerationDigest}),{mode:0o600});'     "$evidence_root/$prefix-renewal-requested.json" "$cigl_policy_renewal_path"
  printf 'OPENPC_CIGL_POLICY_RENEWAL_STAGED|PASS|existing-occurrence|approved-published-release|no-generic-activation\n'
}
