# Sourced by the owned Compose runner after authentication and authenticator trust.
role_id=018f0000-0000-7000-8000-000000000802
role_assignment_id=018f0000-0000-7000-8000-000000000803
role_action=ACT-PARTICIPANTS_UPDATE_RESOURCE-V1
role_body="$(node -e '
  process.stdout.write(JSON.stringify({roleId:process.argv[1],displayName:"Participant auditors",
    actionIntentIds:["ACT-PARTICIPANTS_READ_RESOURCE-V1"]}));
' "$role_id")"
role_candidate="$(node -e '
  const [body,participantId]=process.argv.slice(1);const value=JSON.parse(body);
  process.stdout.write(JSON.stringify({id:value.roleId,roleId:`urn:openpc:role:${value.roleId}`,
    participantId,displayName:value.displayName,actionIntentIds:value.actionIntentIds,state:"ACTIVE"}));
' "$role_body" "$participant_id")"
approved_identity_mutation "$evidence_root/role-created.json" "$role_body" "$role_candidate" \
  "http://127.0.0.1:8080/v1/participants/$participant_id/roles" \
  participant-role-create-0001 "$role_id" 0 role-create 201
role_approval="$(operation_field "$evidence_root/role-created-approval.json" resourceRef)"
identity_mutation_request "$evidence_root/role-create-replay.json" "$role_body" \
  "http://127.0.0.1:8080/v1/participants/$participant_id/roles" \
  participant-role-create-0001 0 "$role_action" 201 "${role_approval##*:}"
assert_json_equal "$evidence_root/role-created.json" "$evidence_root/role-create-replay.json"
node tests/integration/local-runtime/participant-role-readback.mjs active \
  "$evidence_root" "$configuration_operator_session" "$participant_id" "$privacy_domain_id" "$role_id"
"${compose[@]}" restart participant-service policy-service >/dev/null
"${compose[@]}" up -d --wait --no-build --pull never participant-service policy-service >/dev/null
node tests/integration/local-runtime/participant-role-readback.mjs restarted \
  "$evidence_root" "$configuration_operator_session" "$participant_id" "$privacy_domain_id" "$role_id"

role_assignment_body="$(node -e '
  const [assignmentId,principalId,roleId,privacyDomainId]=process.argv.slice(1);
  process.stdout.write(JSON.stringify({assignmentId,principalId,roleId:`urn:openpc:role:${roleId}`,
    authorityEnvelopeId:"018f0000-0000-7000-8000-000000000121",
    scopeDigest:`sha256:${"a7".repeat(32)}`,privacyDomainIds:[privacyDomainId],
    actionIntentIds:["ACT-PARTICIPANTS_READ_RESOURCE-V1"],resourceIds:["*"],riskClasses:["LOW"],
    validFrom:new Date(Date.now()-30*60*1000).toISOString(),validUntil:"2030-01-01T00:00:00.000Z",
    makerCheckerRequired:true,stepUpRequired:true,onwardDelegationDepth:0}));
' "$role_assignment_id" "$checker_principal_id" "$role_id" "$privacy_domain_id")"
role_assignment_candidate="$(node -e '
  const [body,participantId]=process.argv.slice(1);const value=JSON.parse(body);
  process.stdout.write(JSON.stringify({id:value.assignmentId,participantId,state:"ACTIVE",delegationEpoch:"0",...value}));
' "$role_assignment_body" "$participant_id")"
approved_identity_mutation "$evidence_root/role-assignment.json" "$role_assignment_body" "$role_assignment_candidate" \
  "http://127.0.0.1:8080/v1/participants/$participant_id/assignments" \
  participant-role-assignment-0001 "$role_assignment_id" 0 role-assignment 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
role_archive_candidate="$(node -e 'process.stdout.write(JSON.stringify({roleId:process.argv[1],state:"ARCHIVED"}))' "$role_id")"
approved_identity_mutation "$evidence_root/role-archived.json" '{}' "$role_archive_candidate" \
  "http://127.0.0.1:8080/v1/participants/$participant_id/roles/$role_id/archive" \
  participant-role-archive-0001 "$role_id" 1 role-archive 200
node tests/integration/local-runtime/participant-role-readback.mjs stale \
  "$evidence_root" "$configuration_operator_session" "$participant_id" "$privacy_domain_id" "$role_id"
configuration_operator_session="$(local_identity_session operator)"
configuration_checker_session="$(local_identity_session viewer)"
checker_session_id="${configuration_checker_session#*.}"
node tests/integration/local-runtime/participant-role-readback.mjs archived \
  "$evidence_root" "$configuration_operator_session" "$participant_id" "$privacy_domain_id" "$role_id" "$role_assignment_id"
"${compose[@]}" restart participant-service policy-service identity-service >/dev/null
"${compose[@]}" up -d --wait --no-build --pull never participant-service policy-service identity-service >/dev/null
node tests/integration/local-runtime/participant-role-readback.mjs archived \
  "$evidence_root" "$configuration_operator_session" "$participant_id" "$privacy_domain_id" "$role_id" "$role_assignment_id"
printf '%s\n' 'OPENPC_ROLE_LIFECYCLE|PASS|public-approval|webauthn|replay|restart|revocation|stale-denied'
