#!/usr/bin/env bash
# Opt-in limits for a dedicated 16-thread, 64 GB evaluation server.
openpc_capacity_settings() {
  case ${OPENPC_SERVER_CAPACITY:-0} in
    0) openpc_capacity_cpu=200; openpc_capacity_jobs=2
       openpc_capacity_builder_gib=8 ;;
    1) openpc_capacity_cpu=1400; openpc_capacity_jobs=8
       openpc_capacity_builder_gib=40 ;;
    *) echo 'OPENPC_SERVER_CAPACITY must be 0 or 1.' >&2; return 64 ;;
  esac
}

openpc_admit_server_capacity() {
  local total_kib=$1 available_kib=$2 cpus=$3 host_kib=$4 external_kib=$5
  local required_kib=$((host_kib + external_kib + 1048576))
  if (( cpus < 16 || total_kib < 60 * 1048576 || host_kib + external_kib > 56 * 1048576 || available_kib < required_kib )); then
    printf 'OPENPC_SERVER_CAPACITY|FAIL|cpus=%s|total_kib=%s|available_kib=%s|required_kib=%s|budget_limit_kib=58720256\n' \
      "$cpus" "$total_kib" "$available_kib" "$required_kib" >&2
    return 75
  fi
}

# Apply only inside an admitted runtime. Direct Compose keeps the local defaults.
openpc_runtime_database_capacity() {
  local admitted=${OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB:-0}
  case ${OPENPC_SERVER_CAPACITY:-0} in
    0) export OPENPC_LOCAL_CONTROL_PG_MEMORY=1g OPENPC_LOCAL_CONTROL_PG_SWAP=2g OPENPC_LOCAL_CONTROL_PG_CPUS=0.75 ;;
    1)
      [[ $admitted =~ ^[0-9]{1,12}$ ]] || return 64
      (( 10#$admitted >= 12 * 1048576 )) || return 75
      export OPENPC_LOCAL_CONTROL_PG_MEMORY=4g OPENPC_LOCAL_CONTROL_PG_SWAP=4g OPENPC_LOCAL_CONTROL_PG_CPUS=2
      ;;
    *) return 64 ;;
  esac
}
