# Sourced only by the explicit disposable QA branch, after verified image build.
openpc_start_qa_sandbox() {
  [[ ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} == 1 ]] || return 96
  local migration_service migration_container migration_status command_json control_pg ownership_ready
  if [[ ${OPENPC_LOCAL_QA_ROOTED_SOURCE:-0} == 1 ]]; then
    openpc_install_runtime_source || return
  fi
  "${compose[@]}" up -d --no-build --pull never control-migrate fact-migrate candidate-index-migrate || return
  for migration_service in control-migrate fact-migrate candidate-index-migrate; do
    migration_container=$("${compose[@]}" ps -aq "$migration_service") || return
    [[ -n $migration_container ]] || return 96
    # Cold schema creation on the bounded development host can take several minutes.
    migration_status=$(timeout 900 docker wait "$migration_container") || return
    [[ $migration_status == 0 ]] || return 71
  done
  control_pg=$("${compose[@]}" ps -q control-pg) || return
  [[ -n $control_pg ]] || return 96
  ownership_ready=$(docker exec "$control_pg" psql -U openpc_control -d openpc_control -Atqc \
    "SELECT pg_get_userbyid(d.datdba)='openpc_control_owner'
       AND has_schema_privilege('openpc_control_owner','public','USAGE')
       AND has_function_privilege('openpc_control_owner','public.hmac(bytea,bytea,text)','EXECUTE')
       AND pg_get_userbyid(p.proowner)='openpc_control_owner'
       AND p.prosecdef
       AND has_function_privilege('openpc_control_worker',p.oid,'EXECUTE')
       FROM pg_database d
       JOIN pg_proc p ON p.oid=to_regprocedure('openpc.begin_runtime_target_activation_confirmation(bytea,bytea,bytea)')
      WHERE d.datname=current_database()") || return 71
  if [[ $ownership_ready != t ]]; then
    printf '%s\n' 'Local QA control database activation privileges unavailable' >&2
    return 71
  fi
  node --import tsx tests/integration/local-runtime/qa-sandbox.mjs seed "$run_root" || return
  "${compose[@]}" up -d --wait --no-deps --no-build --pull never signing-provider || return
  # Only existing signing-provider initial workload/key trust; no business transitions.
  node --import tsx tests/integration/local-runtime/business-signing-bootstrap.mjs "$secret_root" \
    018f0000-0000-7000-8000-000000000101 018f0000-0000-7000-8000-000000000201 || return
  node --import tsx tests/integration/local-runtime/identity-envelope-signing-bootstrap.ts \
    "$secret_root" 018f0000-0000-7000-8000-000000000101 \
    018f0000-0000-7000-8000-000000000201 || return
  "${compose[@]}" up -d --wait --no-build --pull never admin-web participant-service control-api signing-provider workload-issuer || return
  if [[ ${OPENPC_LOCAL_QA_ROOTED_SOURCE:-0} == 1 ]]; then
    "${compose[@]}" up -d --wait --no-deps --no-build --pull never control-worker || return
    local worker_container
    worker_container=$("${compose[@]}" ps -q control-worker) || return
    node tests/integration/local-runtime/runtime-source-bootstrap.mjs verify-runtime "$run_root" "$worker_container" || return
  fi
  "${compose[@]}" up -d --wait --no-deps --no-build --pull never envoy || return
  openpc_verify_running_images identity-service participant-service policy-service fact-service control-api admin-web || return
  command_json=$(openpc_compose_json) || return
  node tests/integration/local-runtime/qa-sandbox.mjs retain "$run_root" "$command_json" || return
  openpc_qa_ready=1
}
