# Sourced after genuine module admission and governed contract configuration.
if [[ ${OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY:-0} != 1 ]]; then
openssl rand 32 > "$secret_root/deployment-wallet.key"
cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
  "$secret_root/deployment-wallet.key" > "$evidence_root/deployment-wallet.json"
deployment_body="$(node tests/integration/local-runtime/deployment-policy-journey.mjs \
  "$evidence_root/deployment-wallet.json" "$abi_urn" \
  "$(action_digest ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1)")"
approved_configuration_post "$evidence_root/configuration-deployment-policy.json" "$deployment_body" \
  http://127.0.0.1:53003/api/v1/deployment-policies configuration-deployment-policy-0001 '' POST deployment-publication
deployment_urn="$(operation_field "$evidence_root/configuration-deployment-policy.json" resourceRef)"
configuration_get "$evidence_root/configuration-deployment-policy-resource.json" \
  "http://127.0.0.1:53003/api/v1/deployment-policies/$deployment_urn"
if [[ ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY:-0} == 1 ]]; then
  cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
    "$secret_root/deployment-wallet.key" TRANSACTION_CREATE 12 > "$evidence_root/deployment-wallet-no-send.json"
  cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
    "$secret_root/deployment-wallet.key" TRANSACTION_CREATE 14 10 > "$evidence_root/deployment-wallet-native.json"
  cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
    "$secret_root/deployment-wallet.key" TRANSACTION_CREATE 15 10 > "$evidence_root/deployment-wallet-native-reuse.json"
  cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
    "$secret_root/deployment-wallet.key" TRANSACTION_CREATE 16 10 > "$evidence_root/deployment-wallet-expired.json"
  cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
    "$secret_root/deployment-wallet.key" TRANSACTION_CREATE 19 10 > "$evidence_root/deployment-wallet-native-revoked.json"
  for replacement_variant in original bump second ceiling; do
    case "$replacement_variant" in
      original) replacement_fee=2; replacement_tip=1 ;;
      bump) replacement_fee=4; replacement_tip=2 ;;
      second) replacement_fee=8; replacement_tip=3 ;;
      ceiling) replacement_fee=256; replacement_tip=3 ;;
    esac
    cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
      "$secret_root/deployment-wallet.key" TRANSACTION_CREATE 17 0 "$replacement_fee" "$replacement_tip" \
      > "$evidence_root/deployment-wallet-replacement-$replacement_variant.json"
  done
  factory_abi_fixture="$(node tests/integration/local-runtime/configuration-fixture.mjs factory-abi)"
  factory_abi_body="$(node -e 'const [base,fixture]=process.argv.slice(1).map(JSON.parse);base.abi=fixture.abi;base.abiDigest=fixture.abiDigest;base.sourceDocument=fixture.sourceDocument;base.provenance.sourceDigest=fixture.sourceDigest;base.provenance.locator="fixture://openpc-local/closed-factory-v1";process.stdout.write(JSON.stringify(base));' "$abi_body" "$factory_abi_fixture")"
  approved_configuration_post "$evidence_root/configuration-factory-abi.json" "$factory_abi_body" \
    http://127.0.0.1:53003/api/v1/abi-artifacts configuration-factory-abi-0001 '' POST factory-abi
  factory_abi_urn="$(operation_field "$evidence_root/configuration-factory-abi.json" resourceRef)"
  factory_logical_body="$(node -e 'const v=JSON.parse(process.argv[1]);v.logicalName="local.factory";v.displayName="Local Closed Factory";process.stdout.write(JSON.stringify(v));' "$logical_body")"
  approved_configuration_post "$evidence_root/configuration-factory-logical.json" "$factory_logical_body" \
    http://127.0.0.1:53003/api/v1/logical-contract-assets configuration-factory-logical-0001 '' POST factory-logical
  factory_logical_urn="$(operation_field "$evidence_root/configuration-factory-logical.json" resourceRef)"
  factory_binding_body="$(node -e 'const [base,logicalContractId,abiArtifactId,fixture]=process.argv.slice(1),v=JSON.parse(base);Object.assign(v,{logicalContractId,abiArtifactId,abiDigest:JSON.parse(fixture).abiDigest,contractAddress:"0x"+"35".repeat(20),codeDigest:"sha256:"+require("crypto").createHash("sha256").update(Buffer.from("6000","hex")).digest("hex")});process.stdout.write(JSON.stringify(v));' "$binding_body" "$factory_logical_urn" "$factory_abi_urn" "$factory_abi_fixture")"
  approved_configuration_post "$evidence_root/configuration-factory-binding.json" "$factory_binding_body" \
    http://127.0.0.1:53003/api/v1/contract-runtime-bindings configuration-factory-binding-0001 '' POST factory-binding
  factory_binding_urn="$(operation_field "$evidence_root/configuration-factory-binding.json" resourceRef)"
  for mechanism in CREATE CREATE2 CREATE3; do
    cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
      "$secret_root/deployment-wallet.key" "$mechanism" > "$evidence_root/deployment-wallet-$mechanism.json"
    factory_policy_body="$(node tests/integration/local-runtime/deployment-policy-journey.mjs \
      "$evidence_root/deployment-wallet-$mechanism.json" "$abi_urn" \
      "$(action_digest ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1)" "$factory_binding_urn")"
    approved_configuration_post "$evidence_root/configuration-deployment-$mechanism-policy.json" "$factory_policy_body" \
      http://127.0.0.1:53003/api/v1/deployment-policies "configuration-deployment-$mechanism-0001" '' POST "factory-$mechanism"
    factory_policy_urn="$(operation_field "$evidence_root/configuration-deployment-$mechanism-policy.json" resourceRef)"
    configuration_get "$evidence_root/configuration-deployment-$mechanism-policy-resource.json" \
      "http://127.0.0.1:53003/api/v1/deployment-policies/$factory_policy_urn"
  done
fi
fi
read_rpc_digest="$(node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs rpc-digest)"
read_rules_body="$(node -e '
  const body=JSON.parse(process.argv[1]);
  Object.assign(body,{reason:"Restrict balance reads to the governed account.",canonicalSignature:"balanceOf(address)",version:"2.0.0",
    rules:[{parameterPath:"inputs[0]",operandType:"ADDRESS",operator:"EQ",values:["0x1111111111111111111111111111111111111111"]}]});
  process.stdout.write(JSON.stringify(body));
' "$rules_body")"
approved_configuration_post "$evidence_root/configuration-contract-read-rules.json" "$read_rules_body" \
  http://127.0.0.1:53003/api/v1/typed-argument-rule-versions configuration-contract-read-rules-0001 '' POST 61
read_rules_urn="$(operation_field "$evidence_root/configuration-contract-read-rules.json" resourceRef)"
read_method_body="$(node -e '
  const body=JSON.parse(process.argv[1]);
  Object.assign(body,{reason:"Authorize governed balance reads.",canonicalSignature:"balanceOf(address)",
    selector:"0x70a08231",effect:"READ",approvalRequirement:"NONE",mfaRequirement:"NONE",rpcMethodPolicyDigest:process.argv[2],argumentRuleVersionId:process.argv[3]});
  process.stdout.write(JSON.stringify(body));
' "$method_body" "$read_rpc_digest" "$read_rules_urn")"
approved_configuration_post "$evidence_root/configuration-contract-read.json" "$read_method_body" \
  http://127.0.0.1:53003/api/v1/contract-method-policies configuration-contract-read-0001 '' POST 60
read_method_urn="$(operation_field "$evidence_root/configuration-contract-read.json" resourceRef)"
configuration_get "$evidence_root/configuration-contract-read-resource.json" \
  "http://127.0.0.1:53003/api/v1/contract-method-policies/$read_method_urn"
if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]]; then
  export OPENPC_RESUME_STAGE=visibility
  openpc_visibility_journey
  exit 0
fi
if [[ ${OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY:-0} == 1 ]]; then
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs visibility-prepare \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  typed_policy_input="$(<"$evidence_root/typed-policy-inputs.json")"
  typed_policy_body="$(node -e 'const [input,actionIntentDigest]=process.argv.slice(1),v=JSON.parse(input);process.stdout.write(JSON.stringify({policySetId:"urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920",semanticVersion:v.semanticVersion,semanticDocument:v.semanticDocument,actionIntentId:"ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1",actionIntentDigest,reason:"Author governed typed visibility."}));' "$typed_policy_input" "$(action_digest ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1)")"
  policy_mutation "$evidence_root/typed-policy-version.json" "$typed_policy_body" \
    http://127.0.0.1:8080/api/v1/policy-versions typed-visibility-version-0001 "$configuration_operator_session"
  policy_mutation "$evidence_root/typed-policy-version-replay.json" "$typed_policy_body" \
    http://127.0.0.1:8080/api/v1/policy-versions typed-visibility-version-0001 "$configuration_operator_session"
  assert_json_equal "$evidence_root/typed-policy-version.json" "$evidence_root/typed-policy-version-replay.json"
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs visibility-simulate \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
else
cargo run --quiet --locked --offline -p openpc-fact-service --example policy_simulation_fixture -- \
  "$secret_root" "$participant_id" "$privacy_domain_id" admit >"$evidence_root/typed-policy-fact.json"
cargo build --quiet --locked --offline -p openpc-policy-compiler --bin openpc-policy-evaluator
node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs prepare \
  "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
typed_policy_input="$(<"$evidence_root/typed-policy-inputs.json")"
typed_policy_body="$(node -e '
  const input=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({
    policySetId:"urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920",semanticVersion:"4.0.0",
    normalizedPolicyDigest:input.semanticDigest,dependencyClosureDigest:input.dependencyDigest,
    actionIntentId:"ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1",actionIntentDigest:process.argv[2],
    reason:"Create the admitted typed contract policy."}));
' "$typed_policy_input" "$(action_digest ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1)")"
policy_mutation "$evidence_root/typed-policy-version.json" "$typed_policy_body" \
  http://127.0.0.1:8080/api/v1/policy-versions typed-policy-version-0001 "$configuration_operator_session"
node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs simulate \
  "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
fi
# The deployment gate reuses accepted policy browser/restart evidence; it still
# creates and simulates its new policy through the real public owners above.
if [[ ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY:-0} != 1 && ${OPENPC_LOCAL_RUNTIME_CIGL_ONLY:-0} != 1 ]]; then
typed_browser_mode=prepare-browser
if [[ ${OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY:-0} == 1 ]]; then typed_browser_mode=visibility-browser; fi
node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs "$typed_browser_mode" \
  "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
policy_browser_counter="$(printf '%s\n' \
  "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -U openpc_control -d openpc_control \
      -v participant_id="$participant_id" -v credential_id="$operator_credential_id")"
policy_browser_screenshot="$OPENPC_LOCAL_RUNTIME_TMP_ROOT/astra04-policy-workbench-$project.png"
node tests/integration/local-runtime/policy-workbench-browser.mjs run \
  "$operator_credential_id" "$operator_private_key_path" "$policy_browser_counter" \
  "$evidence_root/typed-policy-browser-inputs.json" "$evidence_root/typed-policy-browser-storage.json" \
  "$evidence_root/typed-policy-browser-result.json" "$policy_browser_screenshot"
"${compose[@]}" restart policy-service identity-service fact-service >/dev/null
"${compose[@]}" up -d --wait policy-service identity-service fact-service >/dev/null
if [[ ${OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY:-0} != 1 ]]; then
node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs restart \
  "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
fi
node tests/integration/local-runtime/policy-workbench-browser.mjs restart \
  "$operator_credential_id" "$operator_private_key_path" "$policy_browser_counter" \
  "$evidence_root/typed-policy-browser-inputs.json" "$evidence_root/typed-policy-browser-storage.json" \
  "$evidence_root/typed-policy-browser-result.json" "$policy_browser_screenshot"
fi
typed_policy_reorg() {
  cargo run --quiet --locked --offline -p openpc-fact-service --example policy_simulation_fixture -- \
    "$secret_root" "$participant_id" "$privacy_domain_id" reorg >"$evidence_root/typed-policy-fact-reorg.json"
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs reorg \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
}

# The public lifecycle browser is shared by ordinary and typed-only acceptance.
run_policy_release_browser() {
  local -a policy_release_compose=("${compose[@]}")
  if [[ ${compose[0]} == openpc_target_compose ]]; then
    policy_release_compose=("${openpc_target_compose_command[@]}")
  fi
  policy_release_operator_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$operator_credential_id")"
  policy_release_checker_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$checker_credential_id")"
  policy_release_browser_screenshot="$OPENPC_LOCAL_RUNTIME_TMP_ROOT/astra06-policy-release-workbench-$project.png"
  OPENPC_POLICY_RELEASE_RUNTIME_ROOT="$run_root" \
    OPENPC_POLICY_RELEASE_COMPOSE_JSON="$(node -e 'process.stdout.write(JSON.stringify(process.argv.slice(1)))' "${policy_release_compose[@]}")" \
    node tests/integration/local-runtime/policy-release-workbench-browser.mjs \
    "$operator_credential_id" "$operator_private_key_path" "$policy_release_operator_sign_count" \
    "$checker_credential_id" "$checker_private_key_path" "$policy_release_checker_sign_count" \
    "$evidence_root/typed-policy-browser-inputs.json" \
    "$evidence_root/typed-policy-browser-result.json" \
    "$evidence_root/policy-release-browser-result.json" "$policy_release_browser_screenshot"
}
