# Public relationship source -> Candidate -> signed Fact -> protected event read.
openpc_relationship_visibility_journey() {
  local -x OPENPC_RELATIONSHIP_PHASE=${OPENPC_RELATIONSHIP_PHASE:-}
  if [[ -n $OPENPC_RELATIONSHIP_PHASE ]]; then
    [[ $OPENPC_RELATIONSHIP_PHASE == opening || $OPENPC_RELATIONSHIP_PHASE == closing ]] || return 96
    openpc_relationship_visibility_case
  else
    for OPENPC_RELATIONSHIP_PHASE in opening closing; do openpc_relationship_visibility_case; done
  fi
  if [[ $OPENPC_RELATIONSHIP_PHASE == closing ]]; then
    node --import tsx tests/integration/local-runtime/visibility-source-input.mjs reorg-config "$run_root" "$evidence_root" "$target_id"
    OPENPC_RELATIONSHIP_ASSERTION="$runtime_assertion_hex" \
      node --import tsx tests/integration/local-runtime/relationship-reorg.mjs "$run_root" "$evidence_root" \
        "$(docker inspect -f '{{.Image}}' "$("${compose[@]}" ps -q control-worker)")" \
        "$("${compose[@]}" ps -q runtime-target)" "$target_id" "$policy_container"
    "${compose[@]}" restart runtime-target fact-service >/dev/null
    openpc_wait_existing_service fact-service
    openpc_wait_existing_service runtime-target
    visibility_decision_snapshot > "$evidence_root/decisions-relationship-restarted.json"
    node --import tsx tests/integration/local-runtime/relationship-visibility-input.mjs restart "$run_root" "$evidence_root"
    local candidate_id
    candidate_id=$(operation_field "$evidence_root/acquisition/candidate.json" candidateId)
    printf '{"participantId":"%s","privacyDomainId":"%s","candidateIds":["%s"]}' "$participant_id" "$privacy_domain_id" "$candidate_id" | \
      docker exec -i "$policy_container" /usr/local/bin/policy_fact_reader > "$evidence_root/relationship-fact-restarted.json"
    node -e 'require("node:assert/strict").equal(require(process.argv[1]).snapshots[0].outcome,"REORG")' "$evidence_root/relationship-fact-restarted.json"
    openpc_relationship_visibility_case
    printf 'OPENPC_RELATIONSHIP_RECOVERY|PASS|durable-reorg|prior-releases-preserved|fresh-public-replacement\n'
  fi
  openpc_relationship_fact_custody
}

openpc_relationship_fact_custody() {
  openpc_require_inputs secret_root participant_id privacy_domain_id evidence_root
  local references=optional retirement=retirement
  if [[ $OPENPC_RELATIONSHIP_PHASE == closing ]]; then references=required; retirement=retirement-browser; fi
  node --import tsx tests/integration/local-runtime/evidence-fact-custody.mjs \
    "$secret_root" "$participant_id" "$privacy_domain_id" "$evidence_root" "$("${compose[@]}" ps -q control-api)" "$references" "$retirement" "${compose[@]}"
}

openpc_relationship_visibility_case() {
  local -x OPENPC_VISIBILITY_SOURCE_KIND=relationship OPENPC_VISIBILITY_RENEW_FACT=1
  local -x OPENPC_VISIBILITY_SOURCE_GENERATION=${visibility_next_source_generation:?}
  local kind action collection body resource version status variant request_id mode
  local -a variants=(after unresolved)
  if [[ $OPENPC_RELATIONSHIP_PHASE == closing ]]; then variants=(closed); fi
  for kind in abi logical binding; do
    case "$kind" in
      abi) action=ACT-ABI_ARTIFACTS_CREATE_RESOURCE-V1; collection=abi-artifacts ;;
      logical) action=ACT-LOGICAL_CONTRACT_ASSETS_CREATE_RESOURCE-V1; collection=logical-contract-assets ;;
      binding) action=ACT-CONTRACT_RUNTIME_BINDINGS_CREATE_RESOURCE-V1; collection=contract-runtime-bindings ;;
    esac
    if [[ ! -f $evidence_root/relationship-$kind.json ]]; then
      body=$(node --import tsx tests/integration/local-runtime/relationship-visibility-input.mjs "$kind-body" \
        "$run_root" "$evidence_root" "$(action_digest "$action")")
      approved_configuration_post "$evidence_root/relationship-$kind.json" "$body" \
        "http://127.0.0.1:53003/api/v1/$collection" "relationship-$kind-0002" '' POST "relationship-$kind-0002"
    fi
    resource=$(operation_field "$evidence_root/relationship-$kind.json" resourceRef)
    configuration_get "$evidence_root/relationship-$kind-resource.json" "http://127.0.0.1:53003/api/v1/$collection/$resource"
  done
  node --import tsx tests/integration/local-runtime/relationship-visibility-input.mjs source "$run_root" "$evidence_root"
  openpc_acquire_visibility_fact
  node --import tsx tests/integration/local-runtime/relationship-visibility-input.mjs policy "$run_root" "$evidence_root"
  typed_policy_input=$(<"$evidence_root/typed-policy-inputs.json")
  version=$(json_value "$typed_policy_input" semanticVersion)
  body=$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({policySetId:"urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920",semanticVersion:v.semanticVersion,semanticDocument:v.semanticDocument,actionIntentId:"ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1",actionIntentDigest:process.argv[2],reason:"Govern exact event occurrence visibility with the publicly acquired relationship Fact."}));' "$typed_policy_input" "$(action_digest ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1)")
  policy_mutation "$evidence_root/typed-policy-version.json" "$body" \
    http://127.0.0.1:8080/api/v1/policy-versions "relationship-version-$version" "$configuration_operator_session"
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs visibility-simulate \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  publish_runtime_policy "relationship-policy-$version"
  refresh_runtime_assertion "$evidence_root/identity-relationship.json"
  for variant in "${variants[@]}"; do
    case "$variant" in
      after) request_id=31; mode=AFTER_RELATIONSHIP ;;
      unresolved) request_id=32; mode=ORDERED_RELATIONSHIP ;;
      closed) request_id=33; mode=CLOSED_RELATIONSHIP ;;
    esac
    printf '%s' "$mode" > "$data_root/rpc-provider/visibility-mode"
  visibility_decision_snapshot > "$evidence_root/decisions-before-relationship-$variant.json"
  status=$(curl -sS --max-time 20 --tlsv1.3 --tls-max 1.3 --resolve localhost:18545:127.0.0.1 \
    --cacert "$secret_root/identity_mtls_ca.pem" --cert "$secret_root/identity_mtls_rotated_cert.pem" \
    --key "$secret_root/identity_mtls_rotated_key.pem" -H 'Content-Type: application/json' \
    -H "x-openpc-identity-assertion: $runtime_assertion_hex" \
    --data "{\"jsonrpc\":\"2.0\",\"id\":$request_id,\"method\":\"eth_getLogs\",\"params\":[{\"address\":\"0x1111111111111111111111111111111111111111\",\"fromBlock\":\"0xa\",\"toBlock\":\"0xa\",\"topics\":[\"0x938d2ee5be9cfb0f7270ee2eff90507e94b37625d9d2b3a61c97d30a4560b829\"]}]}" \
    -o "$evidence_root/response-relationship-$variant.json" -w '%{http_code}' https://localhost:18545/rpc)
  visibility_decision_snapshot > "$evidence_root/decisions-relationship-$variant.json"
  node --import tsx tests/integration/local-runtime/relationship-visibility-input.mjs assert-response \
    "$run_root" "$evidence_root" "$status" "$variant"
  done
  printf 'COMPLETE' > "$data_root/rpc-provider/visibility-mode"
  visibility_next_source_generation=$((OPENPC_VISIBILITY_SOURCE_GENERATION+1))
}
