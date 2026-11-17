#!/usr/bin/env bash
# Sourced after the real deployment publication reaches the authenticated target.
# Deployment-intent preparation is immutable and grants no submission authority.
node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs "$secret_root" "$evidence_root" "$participant_id"
run_deployment_intent_journey() {
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
  next_operator_sign_count="$(fixture_value "$evidence_root/deployment-intent-actors.json" maker nextSignCount)"
  next_checker_sign_count="$(fixture_value "$evidence_root/deployment-intent-actors.json" checker nextSignCount)"
  checker_session_id="${configuration_checker_session#*.}"
  deployment_wallet_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  deployment_wallet_body="$(node -e '
    const [file,walletBindingId,subjectId]=process.argv.slice(1);
    const wallet=JSON.parse(require("fs").readFileSync(file));
    process.stdout.write(JSON.stringify({walletBindingId,subjectId,chainId:"31337",walletAddress:wallet.sender}));
  ' "$evidence_root/deployment-wallet.json" "$deployment_wallet_id" "$operator_principal_id")"
  deployment_wallet_candidate="$(node -e 'process.stdout.write(JSON.stringify({...JSON.parse(process.argv[1]),participantId:process.argv[2]}))' "$deployment_wallet_body" "$participant_id")"
  approved_identity_mutation "$evidence_root/deployment-wallet-binding.json" "$deployment_wallet_body" \
    "$deployment_wallet_candidate" http://127.0.0.1:8080/v1/identity/wallet-bindings \
    deployment-wallet-binding-0001 "$deployment_wallet_id" 0 deployment-wallet 201
  deployment_intent_body="$(node -e '
    const [file,deploymentPolicyId,runtimeTargetId,walletBindingId,actionIntentDigest]=process.argv.slice(1);
    const wallet=JSON.parse(require("fs").readFileSync(file));
    process.stdout.write(JSON.stringify({actionIntentId:"ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1",actionIntentDigest,
      reason:"Prepare the exact published deployment without submission authority.",deploymentPolicyId,runtimeTargetId,
      walletBindingId:`urn:openpc:resource:${walletBindingId}`,signingPayload:wallet.signingPayload}));
  ' "$evidence_root/deployment-wallet.json" "$deployment_urn" "$target_urn" "$deployment_wallet_id" \
    "$(action_digest ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1)")"
  deployment_intent_injected="$(node -e 'process.stdout.write(JSON.stringify({...JSON.parse(process.argv[1]),ready:true}))' "$deployment_intent_body")"
  configuration_post "$evidence_root/deployment-intent-injection-denied.json" "$deployment_intent_injected" \
    http://127.0.0.1:8080/api/v1/deployment-intents deployment-intent-injection-0001 '' POST 400
  approved_configuration_post "$evidence_root/deployment-intent-create.json" "$deployment_intent_body" \
    http://127.0.0.1:8080/api/v1/deployment-intents deployment-intent-create-0001 '' POST deployment-intent
  deployment_intent_urn="$(operation_field "$evidence_root/deployment-intent-create.json" resourceRef)"
  configuration_get "$evidence_root/deployment-intent-read.json" \
    "http://127.0.0.1:8080/api/v1/deployment-intents/$deployment_intent_urn"
  node -e '
    const fs=require("fs"),assert=require("assert/strict");
    const [file,walletFile,bodyText,participantId,actor]=process.argv.slice(1);
    const actual=JSON.parse(fs.readFileSync(file)),wallet=JSON.parse(fs.readFileSync(walletFile)),body=JSON.parse(bodyText);
    assert.equal(actual.authority,"NONE");assert.equal(actual.state,"DRAFT");assert.equal(actual.revision,"1");
    assert.equal(actual.sender,wallet.sender);assert.equal(actual.signingPayload,wallet.signingPayload);
    assert.equal(actual.expectedContractAddress,wallet.expectedAddress);assert.equal(actual.chainId,"31337");
    for(const key of ["deploymentPolicyId","runtimeTargetId","walletBindingId"])assert.equal(actual[key],body[key]);
    const intent=JSON.parse(Buffer.from(actual.intentDocument.slice(2),"hex").toString("utf8"));
    assert.equal(intent.participantId,participantId);assert.equal(intent.actorSubjectId,actor);
    assert.equal(intent.expectedContractAddress,wallet.expectedAddress);assert.equal(intent.destination,null);
    assert.equal(intent.valueWei,"0");assert.equal(intent.initCode,wallet.initCode);
    assert.equal(`sha256:${intent.semanticDigest}`,actual.intentDigest);
    assert.equal(intent.nativeValueAuthorizationDigest,null);
    assert.ok(Date.parse(actual.expiresAt)>Date.parse(actual.createdAt));
    assert.ok(Date.parse(actual.expiresAt)-Date.parse(actual.createdAt)<=300000);
    for(const key of ["preparedRecord","authorityDigest","creationAuthorityDigest","approvalSetDigest","providerCredential"])assert.equal(key in actual,false);
  ' "$evidence_root/deployment-intent-read.json" "$evidence_root/deployment-wallet.json" \
    "$deployment_intent_body" "$participant_id" "$operator_principal_id"

  for deployment_scope in participant privacy actor; do
    deployment_scope_participant="$participant_id"
    deployment_scope_privacy="$privacy_domain_id"
    deployment_scope_session="$configuration_operator_session"
    if [ "$deployment_scope" = participant ]; then deployment_scope_participant=018f0000-0000-7000-8000-000000000102; fi
    if [ "$deployment_scope" = privacy ]; then deployment_scope_privacy=018f0000-0000-7000-8000-000000000202; fi
    if [ "$deployment_scope" = actor ]; then deployment_scope_session="$configuration_checker_session"; fi
    deployment_scope_status="$(curl -sS -o "$evidence_root/deployment-intent-$deployment_scope-denied.json" -w '%{http_code}' \
      -H "Cookie: __Host-openpc_session=$deployment_scope_session" -H 'OpenPC-API-Version: 1' \
      -H "OpenPC-Participant-ID: urn:openpc:participant:$deployment_scope_participant" \
      -H "OpenPC-Privacy-Domain-ID: urn:openpc:privacy-domain:$deployment_scope_privacy" \
      -H "X-Request-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
      -H "X-Correlation-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
      "http://127.0.0.1:8080/api/v1/deployment-intents/$deployment_intent_urn")"
    test "$deployment_scope_status" = 403
    node -e 'const text=require("fs").readFileSync(process.argv[1],"utf8");if(/signingPayload|intentDocument|expectedContractAddress/.test(text))throw Error("deployment identity disclosure");' \
      "$evidence_root/deployment-intent-$deployment_scope-denied.json"
  done

  deployment_signed_body="$(node -e 'const fs=require("fs"),body=JSON.parse(process.argv[1]);body.signingPayload=JSON.parse(fs.readFileSync(process.argv[2])).signedTransaction;process.stdout.write(JSON.stringify(body));' "$deployment_intent_body" "$evidence_root/deployment-wallet.json")"
  approved_configuration_post "$evidence_root/deployment-intent-signed-payload-denied.json" "$deployment_signed_body" \
    http://127.0.0.1:8080/api/v1/deployment-intents deployment-intent-signed-0001 '' POST deployment-signed-intent 400

  "${compose[@]}" restart control-api >/dev/null
  "${compose[@]}" up -d --wait --no-build --pull never control-api >/dev/null
  configuration_get "$evidence_root/deployment-intent-restart-read.json" \
    "http://127.0.0.1:8080/api/v1/deployment-intents/$deployment_intent_urn"
  assert_json_equal "$evidence_root/deployment-intent-read.json" "$evidence_root/deployment-intent-restart-read.json"
  configuration_post "$evidence_root/deployment-intent-replay.json" "$deployment_intent_body" \
    http://127.0.0.1:8080/api/v1/deployment-intents deployment-intent-create-0001
  assert_json_equal "$evidence_root/deployment-intent-create.json" "$evidence_root/deployment-intent-replay.json"

  # Revocation leaves the historical draft readable; it cannot confer current authority.
  approved_identity_mutation "$evidence_root/deployment-wallet-revoked.json" '{}' \
    "{\"walletBindingId\":\"$deployment_wallet_id\",\"state\":\"REVOKED\"}" \
    "http://127.0.0.1:8080/v1/identity/wallet-bindings/$deployment_wallet_id/revoke" \
    deployment-wallet-revoke-0001 "$deployment_wallet_id" 1 deployment-wallet-revoke 200
  # Revocation invalidates the wallet subject's current sessions and epoch.
  deployment_old_session_status="$(curl -sS -o "$evidence_root/deployment-intent-old-session-denied.json" -w '%{http_code}' \
    -H "Cookie: __Host-openpc_session=$configuration_operator_session" -H 'OpenPC-API-Version: 1' \
    -H "OpenPC-Participant-ID: urn:openpc:participant:$participant_id" \
    -H "X-Request-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
    -H "X-Correlation-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
    "http://127.0.0.1:8080/api/v1/deployment-intents/$deployment_intent_urn")"
  [[ "$deployment_old_session_status" = 401 || "$deployment_old_session_status" = 403 ]]
  node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs "$secret_root" "$evidence_root" "$participant_id" authenticate
  configuration_operator_session="$(fixture_value "$evidence_root/deployment-intent-actors.json" maker sessionToken)"
  configuration_checker_session="$(fixture_value "$evidence_root/deployment-intent-actors.json" checker sessionToken)"
  next_operator_sign_count="$(fixture_value "$evidence_root/deployment-intent-actors.json" maker nextSignCount)"
  next_checker_sign_count="$(fixture_value "$evidence_root/deployment-intent-actors.json" checker nextSignCount)"
  checker_session_id="${configuration_checker_session#*.}"
  configuration_get "$evidence_root/deployment-intent-revoked-wallet-read.json" \
    "http://127.0.0.1:8080/api/v1/deployment-intents/$deployment_intent_urn"
  node -e '
    const fs=require("fs"),assert=require("assert/strict");
    const before=JSON.parse(fs.readFileSync(process.argv[1])),after=JSON.parse(fs.readFileSync(process.argv[2]));
    assert.equal(after.state,Date.now()>=Date.parse(after.expiresAt)?"EXPIRED":"DRAFT");
    assert.deepEqual({...after,state:before.state},before);
  ' "$evidence_root/deployment-intent-read.json" "$evidence_root/deployment-intent-revoked-wallet-read.json"
  deployment_revoked_body="$(node -e 'const body=JSON.parse(process.argv[1]);body.reason="Deny a new draft for a revoked wallet.";process.stdout.write(JSON.stringify(body));' "$deployment_intent_body")"
  approved_configuration_post "$evidence_root/deployment-intent-revoked-wallet-denied.json" "$deployment_revoked_body" \
    http://127.0.0.1:8080/api/v1/deployment-intents deployment-intent-revoked-0001 '' POST deployment-revoked-intent 409

  deployment_intent_count="$(printf '%s\n' \
    "select count(*)||'|'||(select count(*) from control.outbox_event where participant_id=:'participant_id' and aggregate_type='deployment-intent' and event_type='openpc.deployment.intent.prepared.v1') from control.deployment_intent where participant_id=:'participant_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v participant_id="$participant_id")"
  test "$deployment_intent_count" = '1|1'
  deployment_intent_guard_log="$evidence_root/deployment-intent-immutable-denied.txt"
  if printf '%s\n' "update control.deployment_intent set expires_at=expires_at+interval '1 second' where deployment_intent_id=:'intent_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control \
        -v intent_id="${deployment_intent_urn##*:}" > "$deployment_intent_guard_log" 2>&1; then
    echo 'OPENPC_DEPLOYMENT_INTENT|FAIL|immutable preparation was changed' >&2
    exit 1
  fi
  rg -q 'PC-DATA-6004' "$deployment_intent_guard_log"
  printf 'OPENPC_DEPLOYMENT_INTENT|PASS|public-wallet|exact-published-target|approved-draft|authority-none|scope-isolation|signed-payload-denied|restart-replay|wallet-revocation|old-session-denied|fresh-oidc-readback|immutable|one-effect\n'
}
run_deployment_intent_journey
unset -f run_deployment_intent_journey
