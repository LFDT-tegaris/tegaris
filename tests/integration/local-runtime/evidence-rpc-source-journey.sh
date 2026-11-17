# The successor source enables exact bound state acquisition and confirmation headers.
openpc_require_inputs root secret_root evidence_root owned_data participant_id privacy_domain_id provider_id indexer_id projection_id workload_id worker_container || return
declare -F existing_configuration >/dev/null || return 96
declare -F openpc_first_policy_actors >/dev/null || return 96
[[ ${OPENPC_FIRST_POLICY_ACTIVATE:-0} == 1 ]] || { printf 'RPC source continuation requires public policy activation\n' >&2; return 96; }
openpc_phase_begin rpc-source
export OPENPC_RPC_SOURCE_GENERATION=${OPENPC_RPC_SOURCE_GENERATION:-2}
[[ $OPENPC_RPC_SOURCE_GENERATION =~ ^[0-9]+$ && $OPENPC_RPC_SOURCE_GENERATION -ge 2 ]] || exit 96
if [[ ${OPENPC_FACT_QUARANTINE_ONLY:-0} == 1 ]]; then
  [[ $OPENPC_RPC_SOURCE_GENERATION -ge 3 ]] || { printf 'Native quarantine requires a distinct successor source\n' >&2; return 96; }
fi
rpc_source_suffix=''
[[ $OPENPC_RPC_SOURCE_GENERATION == 2 ]] || rpc_source_suffix="-$OPENPC_RPC_SOURCE_GENERATION"
rpc_source_prefix="rpc-source$rpc_source_suffix"
rpc_source_version="1.1.$((OPENPC_RPC_SOURCE_GENERATION - 2))"
openpc_first_policy_actors
node --import tsx tests/integration/local-runtime/evidence-rpc-source-input.mjs binding "$evidence_root" "$owned_data/provider-probe-source"
if [[ ! -f $evidence_root/$rpc_source_prefix-configuration.json ]]; then
  if [[ ! -d $owned_data/provider-probe-before-rpc-fact ]]; then cp -a "$owned_data/provider-probe-source" "$owned_data/provider-probe-before-rpc-fact"; fi
  provider_address="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$("${compose[@]}" ps -q rpc-provider)")"
  node tests/integration/local-runtime/rpc-provider-bootstrap.mjs source "$owned_data" "$provider_address" state-candidates
  docker exec -e OPENPC_LOCAL_FIXTURE_SCOPE -e OPENPC_LOCAL_PROVIDER_PROFILE_FILE=/provider-sources/profile.json "$worker_container" /usr/local/bin/openpc-control-worker local-fixture "$provider_id" "$indexer_id" "$projection_id" "$workload_id" "$rpc_source_version" > "$evidence_root/$rpc_source_prefix-base.json"
  node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));fs.writeFileSync(process.argv[2],Buffer.from(v.configurationCborHex,"hex"),{flag:"wx",mode:0o444});' "$evidence_root/$rpc_source_prefix-base.json" "$owned_data/provider-probe-source/$rpc_source_prefix-base.cbor"
  docker exec -e OPENPC_LOCAL_INDEXER_CONTRACT_FILE=/provider-sources/rpc-fact-binding.json "$worker_container" /usr/local/bin/openpc-control-worker local-indexer-input "/provider-sources/$rpc_source_prefix-base.cbor" "$indexer_id" "$projection_id" "$provider_id" /provider-sources/rpc-fact-acquisition.json "$OPENPC_RPC_SOURCE_GENERATION" 2 --state-candidates > "$evidence_root/$rpc_source_prefix-configuration.json"
fi
node --import tsx tests/integration/local-runtime/evidence-rpc-source-input.mjs policy "$evidence_root" "$owned_data/provider-probe-source"
node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1])),p=process.argv[2];fs.writeFileSync(p+".next",Buffer.from(v.configurationCborHex,"hex"),{mode:0o444});fs.renameSync(p+".next",p);' "$evidence_root/$rpc_source_prefix-configuration.json" "$owned_data/provider-probe-source/runtime-configuration.cbor"
source_read() {
 local kind=$1 family=$2 id=$3 path=$4
 operator_assertion_step_up "ACT-${family}_READ_RESOURCE-V1" "$id" "$(operation_field "$evidence_root/$rpc_source_prefix-configuration.json" configurationDigest)" "$rpc_source_prefix-read-$kind-$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
 configuration_get "$path" "http://127.0.0.1:8080/api/v1/$kind/urn:openpc:resource:$id"
}
source_update() {
 local name=$1 kind=$2 family=$3 id=$4 digest_field=$5 approved=$6 action digest output key revision body file
 action="ACT-${family}_UPDATE_RESOURCE-V1"; output="$evidence_root/$rpc_source_prefix-$name-update-operation.json"; key="$rpc_source_prefix-$privacy_domain_id-$name-update-v1"
 if existing_configuration "$output" "$action" "$key"; then return; fi
 file="$evidence_root/$rpc_source_prefix-$name-update-input.json"
 if [[ ! -e $file ]]; then
  source_read "$kind" "$family" "$id" "$evidence_root/$rpc_source_prefix-$name-before.json"
  revision="$(operation_field "$evidence_root/$rpc_source_prefix-$name-before.json" revision)"
  digest="$(operation_field "$evidence_root/$rpc_source_prefix-configuration.json" "$digest_field")"
  node - "$file" "$action" "$(action_digest "$action")" "$revision" "$digest" <<'JS'
const fs=require('fs');const [path,actionIntentId,actionIntentDigest,expectedRevision,replacementDigest]=process.argv.slice(2);fs.writeFileSync(path,JSON.stringify({actionIntentId,actionIntentDigest,expectedRevision,replacementDigest,reason:'Govern exact bound state acquisition and confirmation headers for the RPC evidence prerequisite.'}),{flag:'wx',mode:0o600});
JS
 fi
 body="$(cat "$file")"; revision="$(operation_field "$file" expectedRevision)"
 if [[ $approved == 1 ]]; then
  approved_configuration_post "$output" "$body" "http://127.0.0.1:8080/api/v1/$kind/urn:openpc:resource:$id" "$key" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$id" "$revision")" PATCH "$rpc_source_prefix-$privacy_domain_id-$name-update"
 else
  configuration_post "$output" "$body" "http://127.0.0.1:8080/api/v1/$kind/urn:openpc:resource:$id" "$key" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$id" "$revision")" PATCH
 fi
}
source_update indexer indexer-profiles INDEXER_PROFILES "$indexer_id" indexerArtifactDigest 0
source_update projection projection-plans PROJECTION_PLANS "$projection_id" projectionArtifactDigest 0
source_update provider provider-profiles PROVIDER_PROFILES "$provider_id" providerArtifactDigest 1
for definition in "provider provider-profiles PROVIDER_PROFILES $provider_id ACT-PROVIDER_APPROVE_QUALIFICATION-V1 providerArtifactDigest qualify 1" "indexer indexer-profiles INDEXER_PROFILES $indexer_id ACT-INDEXER_APPROVE_PROFILE-V1 indexerArtifactDigest admit 1" "projection projection-plans PROJECTION_PLANS $projection_id ACT-INDEXER_RECOVER_PLAN-V1 projectionArtifactDigest recover 0"; do
 read -r name kind family id action field suffix approved <<< "$definition"
 key="$rpc_source_prefix-$privacy_domain_id-$name-$suffix-v1"; output="$evidence_root/$rpc_source_prefix-$name-$suffix-operation.json"
 if ! existing_configuration "$output" "$action" "$key"; then
  file="$evidence_root/$rpc_source_prefix-$name-$suffix-input.json"
  if [[ ! -e $file ]]; then
   source_read "$kind" "$family" "$id" "$evidence_root/$rpc_source_prefix-$name-current.json"
   if [[ $name == provider ]]; then
    for attempt in {1..90}; do
     [[ $(operation_field "$evidence_root/$rpc_source_prefix-provider-current.json" state) == SHADOW ]] && break
     sleep 0.5
     configuration_get "$evidence_root/$rpc_source_prefix-provider-current.json" "http://127.0.0.1:8080/api/v1/$kind/urn:openpc:resource:$id"
    done
    [[ $(operation_field "$evidence_root/$rpc_source_prefix-provider-current.json" state) == SHADOW ]]
   fi
   revision="$(operation_field "$evidence_root/$rpc_source_prefix-$name-current.json" revision)"
   node - "$file" "$action" "$(action_digest "$action")" "$id" "$revision" "$(operation_field "$evidence_root/$rpc_source_prefix-configuration.json" "$field")" <<'JS'
const fs=require('fs');const [path,actionIntentId,actionIntentDigest,id,expectedRevision,inputDigest]=process.argv.slice(2);fs.writeFileSync(path,JSON.stringify({actionIntentId,actionIntentDigest,targetRef:'urn:openpc:resource:'+id,expectedRevision,inputDigest,reason:'Qualify the real state source and exact confirmation dependencies.'}),{flag:'wx',mode:0o600});
JS
  fi
  body="$(cat "$file")"; revision="$(operation_field "$file" expectedRevision)"
  if [[ $approved == 1 ]]; then
   approved_configuration_post "$output" "$body" "http://127.0.0.1:8080/api/v1/$kind/urn:openpc:resource:$id/$suffix" "$key" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$id" "$revision")" POST "$rpc_source_prefix-$privacy_domain_id-$name-$suffix"
  else
   configuration_post "$output" "$body" "http://127.0.0.1:8080/api/v1/$kind/urn:openpc:resource:$id/$suffix" "$key" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$id" "$revision")"
  fi
 fi
 source_read "$kind" "$family" "$id" "$evidence_root/$rpc_source_prefix-$name-qualified.json"
 printf 'OPENPC_RPC_SOURCE_CONFIGURATION|PASS|%s|public-owner\n' "$name"
done
node --import tsx tests/integration/local-runtime/evidence-rpc-policy.mjs "$secret_root" "$evidence_root" source
"${compose[@]}" stop participant-service >/dev/null
"${compose[@]}" --profile astra05 up -d --wait --no-deps --no-build --pull never runtime-envoy
node --import tsx tests/integration/local-runtime/first-policy-workbench-browser.mjs "$secret_root" "$evidence_root" "$evidence_root/$rpc_source_prefix-policy-input.json" "$rpc_source_prefix-policy"
node --import tsx tests/integration/local-runtime/evidence-rpc-fact.mjs acquisition "$root" "$evidence_root"
docker run --rm --network host --cpus 1 --memory 256m --memory-swap 256m --pids-limit 64 \
  --user "$(id -u):$(id -g)" -v "$root:$root:ro" \
  -e "OPENPC_ACQUISITION_CONFIG_FILE=$evidence_root/rpc-acquisition$rpc_source_suffix/config.json" \
  --entrypoint /usr/local/bin/openpc-acquire-candidate-batch \
  "${openpc_built_images[control-worker]}" > "$evidence_root/rpc-acquisition$rpc_source_suffix/result.json"
node --import tsx tests/integration/local-runtime/evidence-rpc-fact.mjs candidate "$root" "$evidence_root"
openpc_phase_end rpc-source 0
if [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE:-0} == 1 ]]; then
  # The real acquired candidate is independently archivable before Fact admission.
  # Install only the existing initial actor/signing trust for the public hold.
  openpc_phase_begin candidate-custody
  "${compose[@]}" stop runtime-target runtime-envoy control-worker fact-service >/dev/null
  "${compose[@]}" up -d --wait --no-deps --no-build --pull never participant-service
  openpc_wait_participant_gateway
  custody_actors="$evidence_root/store-retirement"
  mkdir -m 0700 "$custody_actors"
  node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs "$secret_root" "$custody_actors" "$participant_id" bootstrap-evidence-store-retirement "$privacy_domain_id" 018f0000-0000-7000-8000-000000000201 --preflight
  node --import tsx tests/integration/local-runtime/signing-provider-bootstrap.ts "$secret_root" "$root/data/signing-provider" --store-retirement "$privacy_domain_id"
  node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs "$secret_root" "$custody_actors" "$participant_id" bootstrap-evidence-store-retirement "$privacy_domain_id" 018f0000-0000-7000-8000-000000000201
  node --import tsx tests/integration/local-runtime/business-signing-bootstrap.mjs "$secret_root" "$participant_id" "$privacy_domain_id" --store-retirement-trust
  "${compose[@]}" restart signing-provider
  "${compose[@]}" up -d --wait --no-deps --no-build --pull never participant-service signing-provider control-api admin-web
  node --import tsx tests/integration/local-runtime/evidence-candidate-custody.mjs "$root" "$(openpc_compose_json)" acquisition
  openpc_phase_end candidate-custody 0
  openpc_phase_begin candidate-control-recovery
  openpc_candidate_control_recovery
  openpc_phase_end candidate-control-recovery 0
  openpc_candidate_control_restore_complete=1
  return 0
fi
source tests/integration/local-runtime/evidence-rpc-admission.sh
