# Acquire the source facts required for anchored visibility. Public owners create every
# grant, source publication, policy activation, candidate and admitted Fact.
openpc_acquire_visibility_fact() {
  local provider_id indexer_id projection_id worker_container provider_address body candidate action path revision digest entry suffix state
  local source_generation=${OPENPC_VISIBILITY_SOURCE_GENERATION:-3} reuse
  [[ $source_generation =~ ^([3-9]|[1-9][0-9])$ ]] || { echo "Invalid visibility source generation" >&2; return 1; }
  openpc_wait_existing_service candidate-index-pg
  reuse=$(node --import tsx tests/integration/local-runtime/visibility-source-input.mjs reuse "$run_root" "$evidence_root" "$target_id")
  case "$reuse" in
    REUSE) openpc_admit_visibility_fact; return ;;
    REPLACE) ;;
    *) echo "Unexpected visibility acquisition preflight result" >&2; return 1 ;;
  esac
  provider_id=$(operation_field "$evidence_root/configuration-provider-qualified.json" resourceRef)
  provider_id=${provider_id##*:}
  indexer_id=$(operation_field "$evidence_root/configuration-indexer.json" resourceRef)
  indexer_id=${indexer_id##*:}
  projection_id=$(operation_field "$evidence_root/configuration-projection.json" resourceRef)
  projection_id=${projection_id##*:}
  worker_container=$("${compose[@]}" ps -q control-worker)
  node --import tsx tests/integration/local-runtime/visibility-source-input.mjs binding "$run_root" "$evidence_root" "$target_id"
  if [[ -f $evidence_root/source-assignment.json ]]; then
    node --import tsx tests/integration/local-runtime/visibility-source-input.mjs assignment-readback \
      "$run_root" "$evidence_root" "$target_id" "$configuration_operator_session"
  else
  provider_address=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$("${compose[@]}" ps -q rpc-provider)")
  node tests/integration/local-runtime/rpc-provider-bootstrap.mjs source "$data_root" "$provider_address" state-candidates
  docker exec -e OPENPC_LOCAL_PROVIDER_PROFILE_FILE=/provider-sources/profile.json \
    "$worker_container" /usr/local/bin/openpc-control-worker local-fixture \
    "$provider_id" "$indexer_id" "$projection_id" "$workload_id" 10.2.0 > "$evidence_root/visibility-source-base.json"
  node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));fs.writeFileSync(process.argv[2]+".next",Buffer.from(v.configurationCborHex,"hex"),{mode:0o444});fs.renameSync(process.argv[2]+".next",process.argv[2]);' \
    "$evidence_root/visibility-source-base.json" "$data_root/provider-probe-source/visibility-base.cbor"
  docker exec -e OPENPC_LOCAL_INDEXER_CONTRACT_FILE=/provider-sources/visibility-binding.json \
    "$worker_container" /usr/local/bin/openpc-control-worker local-indexer-input \
    /provider-sources/visibility-base.cbor "$indexer_id" "$projection_id" "$provider_id" \
    /provider-sources/visibility-acquisition.json 2 2 --state-candidates > "$evidence_root/visibility-source-configuration.json"
  node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));fs.writeFileSync(process.argv[2]+".next",Buffer.from(v.configurationCborHex,"hex"),{mode:0o444});fs.renameSync(process.argv[2]+".next",process.argv[2]);' \
    "$evidence_root/visibility-source-configuration.json" "$data_root/provider-probe-source/runtime-configuration.cbor"

  # Reuse the canonical initial source envelope and the current governed role;
  # do not manufacture a workload assignment or relax its resource scope.
  body=$(node -e 'process.stdout.write(JSON.stringify({assignmentId:"018f0000-0000-7000-8000-000000000126",principalId:"018f0000-0000-7000-8000-000000000190",roleId:"urn:openpc:role:018f0000-0000-7000-8000-000000000801",authorityEnvelopeId:"018f0000-0000-7000-8000-000000000125",scopeDigest:"sha256:"+"b6".repeat(32),privacyDomainIds:[process.argv[1]],actionIntentIds:["ACT-RUNTIME_READ_RPC-V1"],capabilityIds:[],resourceIds:[process.argv[2]],riskClasses:["LOW"],validFrom:new Date(Date.now()-30000).toISOString(),validUntil:"2030-01-01T00:00:00.000Z",makerCheckerRequired:false,stepUpRequired:false,onwardDelegationDepth:0}));' "$privacy_domain_id" "$indexer_id")
  candidate=$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({id:v.assignmentId,participantId:process.argv[2],state:"ACTIVE",delegationEpoch:"0",...v}));' "$body" "$participant_id")
  next_operator_sign_count=$(printf '%s\n' "select (authenticator_sign_count+1)::text from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$operator_credential_id")
  approved_identity_mutation "$evidence_root/source-assignment.json" "$body" "$candidate" \
    "http://127.0.0.1:8080/v1/participants/$participant_id/assignments" \
    visibility-source-assignment-0001 018f0000-0000-7000-8000-000000000126 0 visibility-source-assignment 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
  fi

  if [[ ${OPENPC_VISIBILITY_RENEW_FACT:-0} == 1 ]]; then
    if [[ ! -f $evidence_root/visibility-source-generation${source_generation}.json ]]; then
      provider_address=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$("${compose[@]}" ps -q rpc-provider)")
      node tests/integration/local-runtime/rpc-provider-bootstrap.mjs source "$data_root" "$provider_address" state-candidates
      docker exec -e OPENPC_LOCAL_PROVIDER_PROFILE_FILE=/provider-sources/profile.json \
        "$worker_container" /usr/local/bin/openpc-control-worker local-fixture \
        "$provider_id" "$indexer_id" "$projection_id" "$workload_id" 10.2.0 > "$evidence_root/visibility-source-base-generation${source_generation}.json"
      node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));fs.writeFileSync(process.argv[2]+".next",Buffer.from(v.configurationCborHex,"hex"),{mode:0o444});fs.renameSync(process.argv[2]+".next",process.argv[2]);' \
        "$evidence_root/visibility-source-base-generation${source_generation}.json" "$data_root/provider-probe-source/visibility-base-generation${source_generation}.cbor"
      docker exec -e OPENPC_LOCAL_INDEXER_CONTRACT_FILE=/provider-sources/visibility-binding.json \
        "$worker_container" /usr/local/bin/openpc-control-worker local-indexer-input \
        "/provider-sources/visibility-base-generation${source_generation}.cbor" "$indexer_id" "$projection_id" "$provider_id" \
        /provider-sources/visibility-acquisition.json "$source_generation" 2 --state-candidates > "$evidence_root/visibility-source-generation${source_generation}.json"
    fi
    node - "$evidence_root" "$data_root/provider-probe-source/runtime-configuration.cbor" "$source_generation" <<'NODE'
const fs=require('fs'),root=process.argv[2],path=process.argv[3];
const next=JSON.parse(fs.readFileSync(root+'/visibility-source-generation'+process.argv[4]+'.json'));
fs.writeFileSync(path+'.next',Buffer.from(next.configurationCborHex,'hex'),{mode:0o444});
fs.renameSync(path+'.next',path);
fs.writeFileSync(root+'/visibility-source-configuration.json',JSON.stringify(next));
NODE
    digest=$(operation_field "$evidence_root/visibility-source-configuration.json" indexerArtifactDigest)
    if [[ ! -f $evidence_root/source-indexer-generation${source_generation}-updated.json ]]; then
      configuration_get "$evidence_root/source-indexer-renew-before.json" "http://127.0.0.1:53003/api/v1/indexer-profiles/urn:openpc:resource:$indexer_id"
      revision=$(operation_field "$evidence_root/source-indexer-renew-before.json" revision)
      action=ACT-INDEXER_PROFILES_UPDATE_RESOURCE-V1
      body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Govern generation $source_generation for fresh state acquisition.\",\"expectedRevision\":\"$revision\",\"replacementDigest\":\"$digest\"}"
      configuration_post "$evidence_root/source-indexer-generation${source_generation}-updated.json" "$body" \
        "http://127.0.0.1:53003/api/v1/indexer-profiles/urn:openpc:resource:$indexer_id" \
        visibility-indexer-generation${source_generation}-update-0001 "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$indexer_id" "$revision")" PATCH
    fi
    poll_configuration_operation "$(operation_field "$evidence_root/source-indexer-generation${source_generation}-updated.json" operationId)" "$evidence_root/source-indexer-generation${source_generation}-update-operation.json"
    digest=$(operation_field "$evidence_root/visibility-source-configuration.json" projectionArtifactDigest)
    if [[ ! -f $evidence_root/source-projection-generation${source_generation}-updated.json ]]; then
      configuration_get "$evidence_root/source-projection-renew-before.json" "http://127.0.0.1:53003/api/v1/projection-plans/urn:openpc:resource:$projection_id"
      revision=$(operation_field "$evidence_root/source-projection-renew-before.json" revision)
      action=ACT-PROJECTION_PLANS_UPDATE_RESOURCE-V1
      body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Govern generation $source_generation for fresh state acquisition.\",\"expectedRevision\":\"$revision\",\"replacementDigest\":\"$digest\"}"
      configuration_post "$evidence_root/source-projection-generation${source_generation}-updated.json" "$body" \
        "http://127.0.0.1:53003/api/v1/projection-plans/urn:openpc:resource:$projection_id" \
        visibility-projection-generation${source_generation}-update-0001 "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$projection_id" "$revision")" PATCH
    fi
    # Qualification withdrawal fences published generations irreversibly. Finish
    # provider renewal before admitting or publishing the replacement source.
    digest=$(operation_field "$evidence_root/visibility-source-configuration.json" providerArtifactDigest)
    if [[ ! -f $evidence_root/source-provider-generation${source_generation}-renewed.json ]]; then
      configuration_get "$evidence_root/source-provider-renew-before.json" "http://127.0.0.1:53003/api/v1/provider-profiles/urn:openpc:resource:$provider_id"
      revision=$(operation_field "$evidence_root/source-provider-renew-before.json" revision)
      action=ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1
      body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Govern the controlled provider profile for source generation $source_generation before publication.\",\"expectedRevision\":\"$revision\",\"replacementDigest\":\"$digest\"}"
      approved_configuration_post "$evidence_root/source-provider-generation${source_generation}-renewed.json" "$body" \
        "http://127.0.0.1:53003/api/v1/provider-profiles/urn:openpc:resource:$provider_id" \
        visibility-provider-generation${source_generation}-renew-0001 "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$provider_id" "$revision")" PATCH visibility-provider-generation${source_generation}-renew
    fi
    # The configuration owner publishes only when every resource binding matches.
    for attempt in {1..100}; do
      state=$(printf '%s\n' "begin;" "select openpc.set_request_context('PARTICIPANT',:'participant_id'::uuid,:'privacy_domain_id'::uuid,uuidv7(),'ACT-INDEXER_APPROVE_PROFILE-V1',true) as context \\gset" "select count(*) from control.runtime_configuration_input_current where participant_id=:'participant_id' and privacy_domain_id=:'privacy_domain_id' and configuration_digest=decode(:'digest','hex') and active;" "rollback;" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" -v digest="$(operation_field "$evidence_root/visibility-source-configuration.json" configurationDigest | sed 's/^sha256://')")
      [[ $state == 1 ]] && break
      sleep 0.2
    done
    test "$state" = 1
    if [[ ! -f $evidence_root/source-provider-generation${source_generation}-qualified.json ]]; then
      for attempt in {1..100}; do
        configuration_get "$evidence_root/source-provider-renew-current.json" "http://127.0.0.1:53003/api/v1/provider-profiles/urn:openpc:resource:$provider_id"
        [[ $(operation_field "$evidence_root/source-provider-renew-current.json" state) == SHADOW ]] && break
        sleep 0.2
      done
      revision=$(operation_field "$evidence_root/source-provider-renew-current.json" revision)
      action=ACT-PROVIDER_APPROVE_QUALIFICATION-V1
      body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Approve the fresh live observation of the controlled provider.\",\"targetRef\":\"urn:openpc:resource:$provider_id\",\"expectedRevision\":\"$revision\",\"inputDigest\":\"$digest\"}"
      approved_configuration_post "$evidence_root/source-provider-generation${source_generation}-qualified.json" "$body" \
        "http://127.0.0.1:53003/api/v1/provider-profiles/urn:openpc:resource:$provider_id/qualify" \
        visibility-provider-generation${source_generation}-qualify-0001 "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$provider_id" "$revision")" POST visibility-provider-generation${source_generation}-qualify
    fi
    poll_configuration_operation "$(operation_field "$evidence_root/source-provider-generation${source_generation}-qualified.json" operationId)" "$evidence_root/source-provider-operation.json"
    digest=$(operation_field "$evidence_root/visibility-source-configuration.json" indexerArtifactDigest)
    if [[ ! -f $evidence_root/source-indexer-generation${source_generation}-admitted.json ]]; then
      configuration_get "$evidence_root/source-indexer-renew-current.json" "http://127.0.0.1:53003/api/v1/indexer-profiles/urn:openpc:resource:$indexer_id"
      revision=$(operation_field "$evidence_root/source-indexer-renew-current.json" revision)
      action=ACT-INDEXER_APPROVE_PROFILE-V1
      body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Approve generation $source_generation after all configuration bindings are current.\",\"targetRef\":\"urn:openpc:resource:$indexer_id\",\"expectedRevision\":\"$revision\",\"inputDigest\":\"$digest\"}"
      approved_configuration_post "$evidence_root/source-indexer-generation${source_generation}-admitted.json" "$body" \
        "http://127.0.0.1:53003/api/v1/indexer-profiles/urn:openpc:resource:$indexer_id/admit" \
        visibility-indexer-generation${source_generation}-admit-0003 "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$indexer_id" "$revision")" POST visibility-indexer-generation${source_generation}-3
    fi
    poll_configuration_operation "$(operation_field "$evidence_root/source-indexer-generation${source_generation}-admitted.json" operationId)" "$evidence_root/source-indexer-operation.json"
    digest=$(operation_field "$evidence_root/visibility-source-configuration.json" projectionArtifactDigest)
    if [[ ! -f $evidence_root/source-projection-generation${source_generation}-recovered.json ]]; then
      configuration_get "$evidence_root/source-projection-renew-current.json" "http://127.0.0.1:53003/api/v1/projection-plans/urn:openpc:resource:$projection_id"
      revision=$(operation_field "$evidence_root/source-projection-renew-current.json" revision)
      action=ACT-INDEXER_RECOVER_PLAN-V1
      body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Validate the governed generation $source_generation plan.\",\"targetRef\":\"urn:openpc:resource:$projection_id\",\"expectedRevision\":\"$revision\",\"inputDigest\":\"$digest\"}"
      configuration_post "$evidence_root/source-projection-generation${source_generation}-recovered.json" "$body" \
        "http://127.0.0.1:53003/api/v1/projection-plans/urn:openpc:resource:$projection_id/recover" \
        visibility-projection-generation${source_generation}-recover-0001 "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$projection_id" "$revision")"
    fi
    poll_configuration_operation "$(operation_field "$evidence_root/source-projection-generation${source_generation}-recovered.json" operationId)" "$evidence_root/source-projection-operation.json"

  fi
  # Renewal already reconciled the three real resource owners above. Running
  # initial setup afterward withdraws the just-qualified provider and fences
  # that generation before its first acquisition.
  if [[ ${OPENPC_VISIBILITY_RENEW_FACT:-0} != 1 && ! -f $evidence_root/visibility-source-occurrence-activate.json ]]; then
  for entry in provider indexer projection; do
    case "$entry" in
      provider) path="provider-profiles/urn:openpc:resource:$provider_id"; action=ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1; digest=providerArtifactDigest ;;
      indexer) path="indexer-profiles/urn:openpc:resource:$indexer_id"; action=ACT-INDEXER_PROFILES_UPDATE_RESOURCE-V1; digest=indexerArtifactDigest ;;
      projection) path="projection-plans/urn:openpc:resource:$projection_id"; action=ACT-PROJECTION_PLANS_UPDATE_RESOURCE-V1; digest=projectionArtifactDigest ;;
    esac
    configuration_get "$evidence_root/source-$entry-before.json" "http://127.0.0.1:53003/api/v1/$path"
    revision=$(operation_field "$evidence_root/source-$entry-before.json" revision)
    digest=$(operation_field "$evidence_root/visibility-source-configuration.json" "$digest")
    body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Bind the exact state-read prerequisite source; current-session approval attempt 2.\",\"expectedRevision\":\"$revision\",\"replacementDigest\":\"$digest\"}"
    # CFG-OP-UPDATE-PROVIDER-PROFILE requires maker/checker plus WebAuthn.
    # Indexer/profile and projection updates require neither in the catalog.
    if [[ $entry == provider ]]; then
      approved_configuration_post "$evidence_root/source-$entry-updated.json" "$body" "http://127.0.0.1:53003/api/v1/$path" \
        "visibility-source-$entry-update-0002" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${path##*:}" "$revision")" PATCH visibility-source-provider-update-2
    else
      configuration_post "$evidence_root/source-$entry-updated.json" "$body" "http://127.0.0.1:53003/api/v1/$path" \
        "visibility-source-$entry-update-0001" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${path##*:}" "$revision")" PATCH
    fi
  done
  for entry in provider indexer projection; do
    case "$entry" in
      provider) path="provider-profiles/urn:openpc:resource:$provider_id"; action=ACT-PROVIDER_APPROVE_QUALIFICATION-V1; digest=providerArtifactDigest; suffix=qualify ;;
      indexer) path="indexer-profiles/urn:openpc:resource:$indexer_id"; action=ACT-INDEXER_APPROVE_PROFILE-V1; digest=indexerArtifactDigest; suffix=admit ;;
      projection) path="projection-plans/urn:openpc:resource:$projection_id"; action=ACT-INDEXER_RECOVER_PLAN-V1; digest=projectionArtifactDigest; suffix=recover ;;
    esac
    for attempt in {1..100}; do
      configuration_get "$evidence_root/source-$entry-current.json" "http://127.0.0.1:53003/api/v1/$path"
      state=$(operation_field "$evidence_root/source-$entry-current.json" state)
      [[ $entry != provider || $state == SHADOW ]] && break
      sleep 0.3
    done
    revision=$(operation_field "$evidence_root/source-$entry-current.json" revision)
    digest=$(operation_field "$evidence_root/visibility-source-configuration.json" "$digest")
    body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Approve the governed state-read prerequisite source.\",\"targetRef\":\"${path#*/}\",\"expectedRevision\":\"$revision\",\"inputDigest\":\"$digest\"}"
    if [[ $entry == projection ]]; then
      configuration_post "$evidence_root/source-$entry-admitted.json" "$body" "http://127.0.0.1:53003/api/v1/$path/$suffix" \
        "visibility-source-$entry-admit-0001" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${path##*:}" "$revision")"
    else
      approved_configuration_post "$evidence_root/source-$entry-admitted.json" "$body" "http://127.0.0.1:53003/api/v1/$path/$suffix" \
        "visibility-source-$entry-admit-0001" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${path##*:}" "$revision")" POST "visibility-source-$entry"
    fi
    poll_configuration_operation "$(operation_field "$evidence_root/source-$entry-admitted.json" operationId)" "$evidence_root/source-$entry-operation.json"
  done
  node --import tsx tests/integration/local-runtime/visibility-source-input.mjs policy "$run_root" "$evidence_root" "$target_id"
  typed_policy_input=$(<"$evidence_root/typed-policy-inputs.json")
  body=$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({policySetId:"urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920",semanticVersion:v.semanticVersion,semanticDocument:v.semanticDocument,actionIntentId:"ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1",actionIntentDigest:process.argv[2],reason:"Authorize one exact state acquisition prerequisite."}));' "$typed_policy_input" "$(action_digest ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1)")
  policy_mutation "$evidence_root/typed-policy-version.json" "$body" http://127.0.0.1:8080/api/v1/policy-versions visibility-source-version-0001 "$configuration_operator_session"
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs source-simulate "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  elif [[ ${OPENPC_VISIBILITY_RENEW_FACT:-0} != 1 ]]; then
    for entry in provider indexer projection; do
      operation_id=$(operation_field "$evidence_root/source-$entry-operation.json" operationId)
      configuration_get "$evidence_root/source-$entry-operation-readback.json" "http://127.0.0.1:53003/api/v1/operations/$operation_id"
      test "$(operation_field "$evidence_root/source-$entry-operation-readback.json" state)" = SUCCEEDED
    done
    typed_policy_input=$(<"$evidence_root/typed-policy-inputs.json")
  fi
  if [[ -f $evidence_root/visibility-source-current-${source_generation}-occurrence-activate.json ]]; then
    openpc_renew_visibility_runtime
  else
  if [[ ${OPENPC_VISIBILITY_RENEW_FACT:-0} != 1 ]]; then
    publish_runtime_policy visibility-source
  fi
  if [[ ${OPENPC_VISIBILITY_RENEW_FACT:-0} == 1 || -f $evidence_root/visibility-source-occurrence-resume.json ]]; then
    node --import tsx tests/integration/local-runtime/visibility-source-input.mjs policy-renewal "$run_root" "$evidence_root" "$target_id"
    typed_policy_input=$(<"$evidence_root/typed-policy-inputs.json")
    body=$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({policySetId:"urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920",semanticVersion:v.semanticVersion,semanticDocument:v.semanticDocument,actionIntentId:"ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1",actionIntentDigest:process.argv[2],reason:"Authorize block-ten acquisition and its required confirmation headers."}));' "$typed_policy_input" "$(action_digest ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1)")
    policy_mutation "$evidence_root/typed-policy-version.json" "$body" http://127.0.0.1:8080/api/v1/policy-versions visibility-source-current-${source_generation}-version-0001 "$configuration_operator_session"
    node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs source-simulate "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
    publish_runtime_policy "visibility-source-current-${source_generation}"
  fi
  fi
  node --import tsx tests/integration/local-runtime/visibility-source-input.mjs publication "$run_root" "$evidence_root" "$target_id"
  openpc_wait_existing_service runtime-target
  node --import tsx tests/integration/local-runtime/visibility-source-input.mjs acquisition "$run_root" "$evidence_root" "$target_id"
  if [[ ${OPENPC_VISIBILITY_SOURCE_KIND:-} == relationship ]]; then
    node --import tsx tests/integration/local-runtime/relationship-acquisition.mjs before "$run_root" "$evidence_root" \
      "$(docker inspect -f '{{.Image}}' "$worker_container")" "$("${compose[@]}" ps -q runtime-target)" "$target_id"
  fi
  # Execute the current image's supported acquisition service executable, using
  # the host network and the same capped, exclusively owned acceptance envelope.
  docker run --rm --network host --cpus 1 --memory 256m --memory-swap 256m --pids-limit 64 \
    --user "$(id -u):$(id -g)" -v "$run_root:$run_root:ro" \
    -e "OPENPC_ACQUISITION_CONFIG_FILE=$evidence_root/acquisition/config.json" \
    --entrypoint /usr/local/bin/openpc-acquire-candidate-batch \
    "$(docker inspect -f '{{.Image}}' "$worker_container")" > "$evidence_root/acquisition/result.json"
  if [[ ${OPENPC_VISIBILITY_SOURCE_KIND:-} == relationship ]]; then
    node --import tsx tests/integration/local-runtime/relationship-acquisition.mjs after "$run_root" "$evidence_root" \
      "$(docker inspect -f '{{.Image}}' "$worker_container")" "$("${compose[@]}" ps -q runtime-target)" "$target_id"
  fi
  openpc_admit_visibility_fact
}

openpc_admit_visibility_fact() {
  local -x OPENPC_VISIBILITY_CANDIDATE_POSITION
  local count=1
  if [[ ${OPENPC_VISIBILITY_SOURCE_KIND:-} == relationship && ${OPENPC_RELATIONSHIP_PHASE:-} == closing ]]; then count=2; fi
  # The Fact bridge consumes a complete source batch atomically and checks each
  # candidate's distinct resource grant. Prepare all grants before consumption.
  for ((OPENPC_VISIBILITY_CANDIDATE_POSITION=0; OPENPC_VISIBILITY_CANDIDATE_POSITION<count; OPENPC_VISIBILITY_CANDIDATE_POSITION++)); do
    openpc_prepare_visibility_fact_candidate
  done
  for ((OPENPC_VISIBILITY_CANDIDATE_POSITION=0; OPENPC_VISIBILITY_CANDIDATE_POSITION<count; OPENPC_VISIBILITY_CANDIDATE_POSITION++)); do
    openpc_admit_visibility_candidate
  done
}

openpc_prepare_visibility_fact_candidate() {
  local candidate_id body candidate assignment_id assignment_path
  node --import tsx tests/integration/local-runtime/visibility-source-input.mjs candidate "$run_root" "$evidence_root" "$target_id"
  [[ $(node --import tsx tests/integration/local-runtime/visibility-source-input.mjs reuse "$run_root" "$evidence_root" "$target_id") == REUSE ]] || {
    echo "OPENPC_VISIBILITY_REUSE|FAIL|current-candidate-custody-required" >&2; return 1;
  }
  candidate_id=$(operation_field "$evidence_root/acquisition/candidate.json" candidateId)
  # Replace the failed retained grant through its public revocation owner.
  if [[ -f $evidence_root/fact-source-assignment.json && ! -f $evidence_root/fact-source-assignment-revoked.json ]]; then
    approved_identity_mutation "$evidence_root/fact-source-assignment-revoked.json" '{}' \
      '{"kind":"assignment","targetId":"018f0000-0000-7000-8000-000000000129"}' \
      "http://127.0.0.1:8080/v1/participants/$participant_id/assignments/018f0000-0000-7000-8000-000000000129" \
      visibility-fact-source-revoke-0001 018f0000-0000-7000-8000-000000000129 1 visibility-fact-source-revoke 200 ACT-PARTICIPANTS_UPDATE_RESOURCE-V1 DELETE
    configuration_operator_session=$(local_identity_session operator)
    configuration_checker_session=$(local_identity_session viewer)
    checker_session_id=${configuration_checker_session#*.}
  fi
  assignment_id=$candidate_id
  assignment_path="$evidence_root/fact-bound-assignment-$candidate_id.json"
  if [[ ! -f $assignment_path && -f $evidence_root/fact-bound-assignment.json ]] && [[ $(operation_field "$evidence_root/fact-bound-assignment.json" id) == "$candidate_id" ]]; then
    cp "$evidence_root/fact-bound-assignment.json" "$assignment_path"
  fi
  # Grant admission separately from acquisition, through the public governed owner.
  if [[ ! -f $assignment_path ]]; then
    body=$(node -e 'process.stdout.write(JSON.stringify({assignmentId:process.argv[2],principalId:"018f0000-0000-7000-8000-000000000190",roleId:"urn:openpc:role:018f0000-0000-7000-8000-000000000801",authorityEnvelopeId:"018f0000-0000-7000-8000-000000000136",scopeDigest:"sha256:"+"ba".repeat(32),privacyDomainIds:[process.argv[1]],actionIntentIds:["ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1"],capabilityIds:[],resourceIds:["urn:openpc:resource:"+process.argv[2]],riskClasses:["STANDARD"],validFrom:new Date(Date.now()-30000).toISOString(),validUntil:new Date(Date.now()+86400000).toISOString(),makerCheckerRequired:false,stepUpRequired:false,onwardDelegationDepth:0}));' "$privacy_domain_id" "$candidate_id")
    candidate=$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({id:v.assignmentId,participantId:process.argv[2],state:"ACTIVE",delegationEpoch:"0",...v}));' "$body" "$participant_id")
    next_operator_sign_count=$(printf '%s\n' "select (authenticator_sign_count+1)::text from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$operator_credential_id")
    approved_identity_mutation "$assignment_path" "$body" "$candidate" \
      "http://127.0.0.1:8080/v1/participants/$participant_id/assignments" \
      "visibility-fact-bound-$candidate_id" "$assignment_id" 0 "visibility-fact-bound-$candidate_id" 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
  fi
  node --import tsx tests/integration/local-runtime/visibility-source-input.mjs fact-assignment-readback \
    "$run_root" "$evidence_root" "$target_id" "$configuration_operator_session"
}

openpc_admit_visibility_candidate() {
  local action csrf candidate_id
  node --import tsx tests/integration/local-runtime/visibility-source-input.mjs candidate "$run_root" "$evidence_root" "$target_id"
  action=ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1
  csrf=$(configuration_csrf "$action" http://127.0.0.1:8080 "$configuration_operator_session")
  node --import tsx tests/integration/local-runtime/visibility-source-input.mjs admission \
    "$run_root" "$evidence_root" "$target_id" "$configuration_operator_session" "$csrf" "$configuration_checker_session"
  candidate_id=$(operation_field "$evidence_root/acquisition/candidate.json" candidateId)
  printf '{"participantId":"%s","privacyDomainId":"%s","candidateIds":["%s"]}' \
    "$participant_id" "$privacy_domain_id" "$candidate_id" | \
    docker exec -i "$policy_container" /usr/local/bin/policy_fact_reader > "$evidence_root/visibility-fact-readback.json"
  node - "$evidence_root" <<'NODE'
const fs=require('fs'),assert=require('assert/strict'),root=process.argv[2];
const read=JSON.parse(fs.readFileSync(root+'/visibility-fact-readback.json'));
assert.equal(read.identity,'OPENPC-FACT-OWNER-READ-1');
assert.equal(read.snapshots.length,1);
const fact=read.snapshots[0];
assert.equal(fact.outcome,'PRESENT');
assert.ok(fact.freshUntilMs>Date.now());
assert.ok(fact.shardDigest);
fs.writeFileSync(root+'/typed-policy-fact.json',JSON.stringify(fact));
console.log('OPENPC_VISIBILITY_FACT|READY|public-admission|signed-current-readback');
NODE
}

openpc_renew_visibility_runtime() {
  local renewal_revision renewal_digest renewal_body renewal_path
  renewal_path="$evidence_root/source-runtime-renewal"
  node --import tsx tests/integration/local-runtime/visibility-source-input.mjs publication "$run_root" "$evidence_root" "$target_id"
  source tests/integration/local-runtime/deployment-submission-journey.sh
  deployment_wait_fresh_identity "$renewal_path-identity.json"
  configuration_get "$renewal_path-target.json" "http://127.0.0.1:8080/api/v1/runtime-targets/$target_urn"
  renewal_revision=$(operation_field "$renewal_path-target.json" revision)
  renewal_digest="$(printf '%s\n' "BEGIN;" "select openpc.set_request_context('PARTICIPANT',:'participant_id'::uuid,:'privacy_domain_id'::uuid,uuidv7(),'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',true) as context \\gset" "select 'sha256:'||encode(sha256(configuration.configuration_digest||policy.generation_digest||convert_to(provider.behavior_fingerprint,'UTF8')||convert_to(projection.plan_digest,'UTF8')||convert_to(target.runtime_target_id::text,'UTF8')),'hex') from control.runtime_target target join control.module_installation installation on installation.participant_id=target.participant_id and installation.privacy_domain_id=target.privacy_domain_id and installation.state='ENABLED' join control.module_version version on version.module_version_id=installation.module_version_id join control.module_registration module on module.module_id=version.module_id and module.module_id='pc.config.assets' join control.runtime_configuration_input_current configuration on configuration.module_installation_id=installation.module_installation_id and configuration.active=true join control.policy_generation policy on policy.participant_id=target.participant_id and policy.privacy_domain_id=target.privacy_domain_id and policy.state='ACTIVE' and policy.active=true join control.provider_profile provider on provider.participant_id=target.participant_id and provider.privacy_domain_id=target.privacy_domain_id and provider.state in ('QUALIFIED','ACTIVE') join control.projection_plan projection on projection.participant_id=target.participant_id and projection.privacy_domain_id=target.privacy_domain_id and projection.state in ('VALIDATED','RUNNING') and projection.readiness='READY' where target.runtime_target_id=:'target_id';" "COMMIT;" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" -v target_id="$target_id")"
  [[ $renewal_digest =~ ^sha256:[0-9a-f]{64}$ ]]
  renewal_body=$(node -e 'const [actionIntentDigest,expectedRevision,replacementDigest]=process.argv.slice(1);process.stdout.write(JSON.stringify({actionIntentId:"ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1",actionIntentDigest,expectedRevision,replacementDigest,reason:"Renew unchanged source runtime custody through its existing owner."}));' "$(action_digest ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1)" "$renewal_revision" "$renewal_digest")
  configuration_post "$renewal_path-command.json" "$renewal_body" \
    "http://127.0.0.1:8080/api/v1/runtime-targets/$target_urn" "visibility-runtime-renew-$renewal_revision-0001" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$target_id" "$renewal_revision")" PATCH 202 "$configuration_operator_session" 0
  "${compose[@]}" --profile astra05 up -d --no-deps --no-build --pull never runtime-target
  for attempt in {1..120}; do
    curl -sS --max-time 2 --tlsv1.3 --tls-max 1.3 \
      --cacert "$secret_root/identity_mtls_ca.pem" --cert "$secret_root/identity_mtls_rotated_cert.pem" \
      --key "$secret_root/identity_mtls_rotated_key.pem" -H 'Content-Type: application/json' \
      --data '{"jsonrpc":"2.0","id":0,"method":"openpc_invalid_observation_probe","params":[]}' \
      https://localhost:18545/rpc > "$renewal_path-probe.json" 2>/dev/null || true
    configuration_get "$renewal_path-command-operation.json" "http://127.0.0.1:53003/api/v1/operations/$(operation_field "$renewal_path-command.json" operationId)"
    if [[ $(operation_field "$renewal_path-command-operation.json" state) == SUCCEEDED ]] && \
      [[ $(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$("${compose[@]}" ps -q runtime-target)") == healthy ]]; then
  configuration_get "$renewal_path-active.json" "http://127.0.0.1:8080/api/v1/runtime-targets/$target_urn"
  node -e 'const fs=require("fs"),[before,after]=process.argv.slice(1).map(p=>JSON.parse(fs.readFileSync(p)));if(after.state!=="ACTIVE_MATCHED"||BigInt(after.revision)<=BigInt(before.revision)||!after.xdsVersionDigest||after.xdsVersionDigest===before.xdsVersionDigest||after.desiredGenerationDigest!==after.activeGenerationDigest)throw Error("runtime renewal not observed");' "$renewal_path-target.json" "$renewal_path-active.json"
      return 0
    fi
    sleep 0.25
  done
  return 1
}
