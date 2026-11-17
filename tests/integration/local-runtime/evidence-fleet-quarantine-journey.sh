# The positive RPC journey has already consumed its original Fact. A distinct
# governed source generation supplies the native failure scenario, preserving
# every earlier effect and signed byte. All new state uses the same real owners.
openpc_require_inputs root secret_root evidence_root owned_data participant_id privacy_domain_id provider_id indexer_id projection_id workload_id || return
export OPENPC_RPC_SOURCE_GENERATION=3 OPENPC_FACT_QUARANTINE_ONLY=1
"${compose[@]}" stop runtime-target runtime-envoy >/dev/null
"${compose[@]}" up -d --wait --no-deps --no-build --pull never participant-service control-worker
worker_container=$("${compose[@]}" ps -q control-worker)
openpc_verify_running_images control-worker
source tests/integration/local-runtime/evidence-rpc-source-journey.sh
