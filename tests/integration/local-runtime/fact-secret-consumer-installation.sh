# Sourced by the admitted local-runtime runner, which owns images/admission/data.
# Fresh selector: OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY=1.
# After the shared image dispatcher, before static Fact credentials or business
# startup: openpc_run_fact_secret_consumer_slice FACT_IMAGE_ID IDENTITY_IMAGE_ID.
# The existing installation callable also supports an already prepared slice.
# Required globals: repository_root, run_root, data_root, secret_root, compose,
# project and owner_token (the canonical runner's original owner, not read back).
# Required shared functions: openpc_compose_json, openpc_require_heavy_lock,
# openpc_require_execution. Before ANY generic teardown, the canonical trap must:
# if openpc_fact_secret_consumer_on_exit "$status"; then
#   status=$openpc_fact_secret_exit_status
# else
#   exit "$openpc_fact_secret_exit_status"
# fi
# Hook 0 permits normal cleanup; 99 FORBIDS it. The exit-status output preserves
# the first failure (99 only when no earlier failure exists). A retention flag
# alone is insufficient: generic cleanup may skip retention after an error.

openpc_fact_secret_consumer_slice_options() {
  local variable value owned_network=0
  [[ $# == 0 || ( $# == 1 && $1 == owned-network ) ]] || return 96
  [[ $# == 0 ]] || owned_network=1
  [[ ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY:-0} == 1 ]] || return 96
  [[ ${reuse_images:-0} == 0 && -z ${refresh_from:-} ]] || return 96
  [[ -z ${OPENPC_BROWSER_SCENARIOS:-} && ${OPENPC_BROWSER_SESSION:-0} == 0 ]] || return 96
  # Fail closed on other active runtime modes, including future selectors.
  for variable in ${!OPENPC_LOCAL_RUNTIME_@}; do
    value=${!variable}
    case "$variable" in
      OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY|OPENPC_LOCAL_RUNTIME_TMP_ROOT) ;;
      OPENPC_LOCAL_RUNTIME_FACT_SECRET_OPERATIONS_ONLY|OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT|OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE|OPENPC_LOCAL_RUNTIME_NO_SCREENSHOTS)
        [[ $value == 0 || $value == 1 ]] || return 96 ;;
      OPENPC_LOCAL_RUNTIME_NETWORK_SUBNET|OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY|OPENPC_LOCAL_RUNTIME_NETWORK_OWNER|OPENPC_LOCAL_RUNTIME_NETWORK_ROOT)
        # The initial option checks reject every caller override. Only the
        # post-root preflight may consume the shared owner's generated values;
        # openpc_compose_json then verifies its actual rendered/live network.
        [[ $owned_network == 1 && ${openpc_network_phase:-} == fresh ]] || return 96
        declare -F openpc_network_check >/dev/null || return 96
        case "$variable" in
          *_SUBNET) [[ $value == "${openpc_network_subnet:-}" ]] || return 96 ;;
          *_GATEWAY) [[ $value == "${openpc_network_gateway:-}" ]] || return 96 ;;
          *_OWNER) [[ $value == "${owner_token:-}" ]] || return 96 ;;
          *_ROOT) [[ $value == "${run_root:-}" ]] || return 96 ;;
        esac ;;
      OPENPC_LOCAL_RUNTIME_CLEANUP_PROBE) [[ -z $value || $value == none ]] || return 96 ;;
      *) [[ -z $value || $value == 0 ]] || return 96 ;;
    esac
  done
}

# Validate the actual rendered dependency closure before starting any service.
# The live Node installer remains the authority for role/global-empty checks,
# authenticated recipient binding, tmpfs and native Fact consumption.
openpc_fact_secret_consumer_slice_preflight() {
  local fact_image=${1:-} identity_image=${2:-} command_json rendered inventory images
  [[ $# == 2 && $fact_image =~ ^sha256:[0-9a-f]{64}$ && $identity_image =~ ^sha256:[0-9a-f]{64}$ ]] || return 96
  openpc_fact_secret_consumer_guard "$run_root" || return
  openpc_fact_secret_consumer_slice_options owned-network || return
  command_json=$(openpc_compose_json) || return
  # Validate command paths BEFORE invoking Compose; only the committed base is
  # supported by this fresh slice, with no retained override or alternate root.
  node --input-type=module -e '
    import fs from "node:fs";
    import path from "node:path";
    try {
      const [repo, root, data, secrets, project, encoded, owner] = process.argv.slice(1);
      const directory = (p) =>
        path.isAbsolute(p) && fs.realpathSync(p) === p && fs.lstatSync(p).isDirectory();
      if (
        !directory(repo) ||
        !directory(root) ||
        data !== root + "/data" ||
        secrets !== root + "/secrets" ||
        !directory(data) ||
        !directory(secrets)
      )
        throw 0;
      const sentinel = root + "/.openpc-local-runtime-owner",
        st = fs.lstatSync(sentinel);
      if (!st.isFile() || st.nlink !== 1 || st.mode & 0o022) throw 0;
      const record = fs
        .readFileSync(sentinel, "utf8")
        .match(/^openpc-local-runtime:(openpc-local-e2e-([0-9a-f]{12})):([0-9a-f]{64})\n$/u);
      if (
        !record ||
        record[1] !== project ||
        record[3] !== owner ||
        record[3].slice(0, 12) !== record[2]
      )
        throw 0;
      const expected = [
        "docker",
        "compose",
        "-p",
        project,
        "-f",
        repo + "/deploy/compose/local/compose.yaml",
      ];
      if (JSON.stringify(JSON.parse(encoded)) !== JSON.stringify(expected)) throw 0;
      if ((fs.statSync(secrets).mode & 0o077) !== 0) throw 0;
      for (const name of ["control-pg", "fact-pg", "candidate-index-pg"]) {
        const p = data + "/" + name;
        if (!directory(p) || fs.readdirSync(p).length) throw 0;
      }
      if (
        fs
          .readdirSync(data)
          .some(
            (n) => n.startsWith("fact-secret-") || n === "fact-bridge" || n === "protected-proofs",
          )
      )
        throw 0;
    } catch {
      process.stderr.write("FACT_SECRET_SLICE|BLOCKED|fresh-inputs\n");
      process.exit(96);
    }
  ' "$repository_root" "$run_root" "$data_root" "$secret_root" "$project" "$command_json" "${owner_token:-}" || return
  for inventory in containers networks volumes; do
    case "$inventory" in
      containers) rendered=$(docker ps -aq --filter "label=com.docker.compose.project=$project") || return ;;
      networks) rendered=$(docker network ls -q --filter "label=com.docker.compose.project=$project") || return ;;
      volumes) rendered=$(docker volume ls -q --filter "label=com.docker.compose.project=$project") || return ;;
    esac
    [[ -z $rendered ]] || { printf 'FACT_SECRET_SLICE|BLOCKED|existing-project-resources\n' >&2; return 96; }
  done
  rendered=$("${compose[@]}" config --format json) || return
  node --input-type=module -e '
    import fs from "node:fs";
    try {
      const [project, data, secrets, admitted] = process.argv.slice(1);
      if (!/^[1-9][0-9]*$/u.test(admitted)) throw 0;
      const budget = BigInt(admitted) * 1024n;
      if (budget < 9n * 1024n ** 3n) throw 0;
      const config = JSON.parse(fs.readFileSync(0, "utf8"));
      if (config.name !== project) throw 0;
      const pg =
        "docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7";
      const node =
        "docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43";
      const dbs = ["control-pg", "fact-pg", "candidate-index-pg"];
      const migrations = ["control-migrate", "fact-migrate", "candidate-index-migrate"];
      const apps = ["identity-service", "oidc-emulator", "workload-issuer"];
      const caps = new Map();
      // Compose renders byte quantities as decimal strings; older supported
      // renderers also emit JSON numbers. Reject units, coercions and rounding.
      const positiveInteger = (value) => {
        if (
          typeof value === "number"
            ? !Number.isSafeInteger(value)
            : typeof value !== "string" || !/^[1-9][0-9]*$/u.test(value)
        )
          throw 0;
        const parsed = BigInt(value);
        if (parsed <= 0n || parsed > BigInt(Number.MAX_SAFE_INTEGER)) throw 0;
        return parsed;
      };
      for (const name of [...dbs, ...migrations, ...apps]) {
        const service = config.services?.[name];
        const image =
          name === "identity-service"
            ? "openpc-r1-dev/identity-service:local"
            : apps.includes(name)
              ? node
              : pg;
        if (
          !service ||
          service.image !== image ||
          service.platform !== "linux/amd64" ||
          (service.scale !== undefined && service.scale !== 1) ||
          (service.deploy?.replicas !== undefined && service.deploy.replicas !== 1)
        )
          throw 0;
        const memory = positiveInteger(service.mem_limit);
        positiveInteger(service.pids_limit);
        if (
          !["string", "number"].includes(typeof service.cpus) ||
          !Number.isFinite(Number(service.cpus)) ||
          Number(service.cpus) <= 0
        )
          throw 0;
        if (service.memswap_limit !== undefined && positiveInteger(service.memswap_limit) < memory)
          throw 0;
        caps.set(name, memory);
        const expected =
          name === "identity-service"
            ? {
                "control-migrate": "service_completed_successfully",
                "oidc-emulator": "service_healthy",
                "workload-issuer": "service_healthy",
              }
            : migrations.includes(name)
              ? { [dbs[migrations.indexOf(name)]]: "service_healthy" }
              : {};
        const dependencies = service.depends_on ?? {};
        if (
          JSON.stringify(Object.keys(dependencies).sort()) !==
          JSON.stringify(Object.keys(expected).sort())
        )
          throw 0;
        for (const [dep, condition] of Object.entries(expected))
          if (dependencies[dep]?.condition !== condition || dependencies[dep]?.required === false)
            throw 0;
        if (
          service.network_mode !== undefined ||
          JSON.stringify(Object.keys(service.networks ?? {})) !== JSON.stringify(["openpc-local"])
        )
          throw 0;
        for (const item of service.secrets ?? []) {
          const name = typeof item === "string" ? item : item.source,
            file = config.secrets?.[name]?.file;
          if (
            typeof file !== "string" ||
            !file.startsWith(secrets + "/") ||
            fs.realpathSync(file) !== file
          )
            throw 0;
          const stat = fs.lstatSync(file);
          if (!stat.isFile() || stat.nlink !== 1 || stat.mode & 0o022) throw 0;
        }
        if (dbs.includes(name)) {
          const mounts = service.volumes ?? [];
          if (
            mounts.length !== 1 ||
            mounts[0].type !== "bind" ||
            mounts[0].source !== data + "/" + name ||
            mounts[0].target !== "/var/lib/postgresql" ||
            mounts[0].read_only
          )
            throw 0;
        }
      }
      const network = config.networks?.["openpc-local"];
      if (!network || network.external || network.name !== project + "_openpc-local") throw 0;
      const sum = (names) => names.reduce((total, name) => total + caps.get(name), 0n);
      const migrationPeak = sum([...dbs, ...migrations]);
      // Three 256 MiB namespaces and the finite 64 MiB shared tmpfs. Count it
      // once in the unchanged admitted external envelope, never as new admission.
      const installationPeak = sum([...dbs, ...apps]) + 832n * 1024n ** 2n;
      if (migrationPeak > budget || installationPeak > budget) throw 0;
    } catch {
      process.stderr.write("FACT_SECRET_SLICE|BLOCKED|rendered-inputs\n");
      process.exit(96);
    }
  ' "$project" "$data_root" "$secret_root" "${OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB:-}" <<< "$rendered" || return
  images=$(docker image inspect "$fact_image" openpc-r1-dev/identity-service:local) || return
  node --input-type=module -e '
    import fs from "node:fs";
    try {
      const images = JSON.parse(fs.readFileSync(0, "utf8")),
        ids = process.argv.slice(1);
      if (!Array.isArray(images) || images.length !== 2) throw 0;
      for (const [i, name] of ["fact-service", "identity-service"].entries()) {
        const image = images[i],
          labels = image.Config?.Labels;
        if (
          image.Id !== ids[i] ||
          image.Os !== "linux" ||
          image.Architecture !== "amd64" ||
          labels?.["io.openpc.image.owner"] !== "openpc-r1-local-runtime-v1" ||
          labels?.["io.openpc.image.service"] !== name
        )
          throw 0;
      }
      if (
        images[0].Config.User !== "65532:65532" ||
        JSON.stringify(images[0].Config.Entrypoint) !==
          JSON.stringify(["/usr/local/bin/openpc-fact-local-runtime"]) ||
        (images[0].Config.Cmd ?? []).length
      )
        throw 0;
    } catch {
      process.stderr.write("FACT_SECRET_SLICE|BLOCKED|verified-images\n");
      process.exit(96);
    }
  ' "$fact_image" "$identity_image" <<< "$images" || return
  printf 'FACT_SECRET_SLICE|PASS|input-preflight|additional_external_mib=832\n'
}

openpc_run_fact_secret_consumer_slice() {
  local status
  if openpc_fact_secret_consumer_slice_start "$@"; then return 0; else status=$?; fi
  if [[ ${openpc_fact_secret_first_failure:-0} == 0 ]]; then openpc_fact_secret_first_failure=$status; fi
  printf 'FACT_SECRET_SLICE|FAIL|exit=%s\n' "$status" >&2
  return "$status"
}

openpc_fact_secret_consumer_slice_start() {
  local fact_image=${1:-} identity_image=${2:-} service container result status first=0 actual
  openpc_fact_secret_consumer_slice_preflight "$@" || return
  # Pull only pinned external prerequisites. No service, migration, publication
  # or authority is allocated before the actual input/image preflight passes.
  "${compose[@]}" pull --ignore-buildable --policy missing control-pg fact-pg candidate-index-pg oidc-emulator workload-issuer || return
  openpc_fact_secret_consumer_guard "$run_root" || return
  "${compose[@]}" up -d --no-build --pull never control-migrate fact-migrate candidate-index-migrate || return
  # Independent stores may finish after a sibling failure; none of their
  # consumers may start until all three outcomes are known and successful.
  for service in control-migrate fact-migrate candidate-index-migrate; do
    status=0
    if container=$("${compose[@]}" ps -aq "$service"); then
      if [[ $container =~ ^[0-9a-f]{64}$ ]]; then
        if actual=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}/{{index .Config.Labels "com.docker.compose.service"}}' "$container"); then
          if [[ $actual == "$project/$service" ]]; then
            if result=$(timeout 180 docker wait "$container"); then
              if [[ $result =~ ^(0|[1-9][0-9]{0,2})$ && $result -le 255 ]]; then status=$result; else status=96; fi
            else status=$?; fi
          else status=96; fi
        else status=$?; fi
      else status=96; fi
    else status=$?; fi
    if [[ $status != 0 ]]; then
      printf 'FACT_SECRET_SLICE|FAIL|migration=%s|exit=%s\n' "$service" "$status" >&2
      [[ $first != 0 ]] || first=$status
    fi
  done
  [[ $first == 0 ]] || return "$first"
  "${compose[@]}" up -d --wait --wait-timeout 120 --no-recreate --no-deps --no-build --pull never control-pg fact-pg candidate-index-pg oidc-emulator workload-issuer || return
  "${compose[@]}" up -d --wait --wait-timeout 120 --no-deps --no-build --pull never identity-service || return
  container=$("${compose[@]}" ps -q identity-service) || return
  [[ $container =~ ^[0-9a-f]{64}$ ]] || return 96
  actual=$(docker inspect --format '{{.Image}}/{{index .Config.Labels "com.docker.compose.project"}}/{{index .Config.Labels "com.docker.compose.service"}}' "$container") || return
  [[ $actual == "$identity_image/$project/identity-service" ]] || return 96
  # This existing owner builds the stable publisher bundle before acquiring
  # short-lived installed authority, then runs BOTH native-container cases.
  openpc_run_fact_secret_consumer_installation "$fact_image"
}

openpc_fact_secret_consumer_guard() {
  local owned_root=$1 expected owner ancestor
  declare -F openpc_require_heavy_lock >/dev/null || return 96
  declare -F openpc_require_execution >/dev/null || return 96
  openpc_require_heavy_lock || return
  expected="$owned_root/.openpc-local-runtime-owner"
  [[ $owned_root == /* && ! -L $owned_root && -f $expected && ! -L $expected ]] || return 96
  [[ $(realpath -e "$owned_root") == "$owned_root" ]] || return 96
  owner=${OPENPC_RUNTIME_OWNER_PID:-}
  [[ $owner =~ ^[1-9][0-9]*$ ]] || return 96
  ancestor=$BASHPID
  while [[ $ancestor -gt 1 && $ancestor != "$owner" ]]; do
    ancestor=$(awk '/^PPid:/ {print $2}' "/proc/$ancestor/status") || return 96
    [[ $ancestor =~ ^[1-9][0-9]*$ ]] || return 96
  done
  [[ $ancestor == "$owner" && $(readlink "/proc/$owner/fd/8") == "$expected" ]] || return 96
  if flock -n "$expected" true; then return 96; fi
  # Actual inherited cgroup, canonical lock, live margin and disk checks. An
  # environment flag or descriptor alone cannot admit this subjourney.
  openpc_require_execution runtime-target
}

openpc_run_fact_secret_consumer_installation() {
  local fact_image=${1:-} bundle_dir status command_json prior_retain=${OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT:-0}
  [[ $# == 1 && $fact_image =~ ^sha256:[0-9a-f]{64}$ ]] || return 96
  [[ $prior_retain == 0 || $prior_retain == 1 ]] || return 96
  [[ $data_root == "$run_root/data" && $secret_root == "$run_root/secrets" ]] || return 96
  declare -F openpc_compose_json >/dev/null || return 96
  openpc_fact_secret_consumer_guard "$run_root" || return
  command_json=$(openpc_compose_json) || return
  # Set in the parent shell before any child can allocate. SIGKILL/lost Docker
  # replies must not permit the outer EXIT trap to delete bound installation data.
  export OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=1
  openpc_fact_secret_installation_pending=1
  bundle_dir=$(mktemp -d "$data_root/fact-secret-bundle.XXXXXXXX") || return
  chmod 0755 "$bundle_dir" || return
  if pnpm --filter @openpc/identity-service exec esbuild \
    ../../tests/integration/local-runtime/fact-secret-consumer-installation.mjs \
    --bundle --platform=node --format=esm \
    --banner:js='import { createRequire } from "node:module"; const require = createRequire(import.meta.url);' \
    --outfile="$bundle_dir/publisher.mjs"; then :; else
    status=$?
    printf 'FACT_SECRET_INSTALLATION|FAIL|bundle\n' >&2
    return "$status"
  fi
  chmod 0444 "$bundle_dir/publisher.mjs" || return
  if node --import tsx "$repository_root/tests/integration/local-runtime/fact-secret-consumer-installation.mjs" \
    run "$run_root" "$command_json" "$fact_image" "$bundle_dir/publisher.mjs"; then
    openpc_fact_secret_installation_pending=0
    export OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=$prior_retain
  else
    status=$?
    printf 'FACT_SECRET_INSTALLATION|FAIL|retain-installation\n' >&2
    return "$status"
  fi
}

openpc_fact_secret_consumer_on_exit() {
  local first=${1:-0}
  # The trap supplies its captured command status. A prior dispatcher failure
  # still wins if a caller accidentally reaches EXIT with status zero.
  [[ $# -le 1 && $first =~ ^(0|[1-9][0-9]{0,2})$ && $first -le 255 ]] || first=99
  if [[ ${openpc_fact_secret_first_failure:-0} != 0 ]]; then first=$openpc_fact_secret_first_failure; fi
  openpc_fact_secret_exit_status=$first
  if openpc_fact_secret_consumer_cleanup_known; then return 0; fi
  export OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=1
  openpc_fact_secret_cleanup_blocked=1
  [[ $first != 0 ]] || openpc_fact_secret_exit_status=99
  printf 'FACT_SECRET_INSTALLATION|UNKNOWN|retained-owned-resources|first_exit=%s\n' "$first" >&2
  return 99
}

openpc_fact_secret_consumer_cleanup_known() {
  local containers volumes record token prefix sentinel="$run_root/.openpc-local-runtime-owner"
  # A lost/failed installer result may include uncertain SQL lease cleanup even
  # if Docker inventories are empty. Only its successful result clears pending.
  [[ ${openpc_fact_secret_installation_pending:-0} == 0 ]] || return 99
  [[ ! -L $run_root && $(realpath -e "$run_root") == "$run_root" && -f $sentinel && ! -L $sentinel ]] || return 99
  record=$(cat "$sentinel") || return 99
  [[ $record =~ ^openpc-local-runtime:openpc-local-e2e-([0-9a-f]{12}):([0-9a-f]{64})$ ]] || return 99
  prefix=${BASH_REMATCH[1]}
  token=${BASH_REMATCH[2]}
  [[ ${token:0:12} == "$prefix" && $record == "openpc-local-runtime:${project:-}:$token" && $token == "${owner_token:-}" ]] || return 99
  [[ $(wc -c < "$sentinel") -eq $((${#record} + 1)) && $(stat -c %h "$sentinel") == 1 ]] || return 99
  containers=$(docker ps -aq --filter label=io.openpc.fixture=fact-secret-consumer \
    --filter "label=io.openpc.fixture.owner=$token") || return 99
  volumes=$(docker volume ls -q --filter label=io.openpc.fixture=fact-secret-consumer \
    --filter "label=io.openpc.fixture.owner=$token") || return 99
  [[ -z $containers && -z $volumes ]]
}

# The persistent Node installer invokes only these fixed helper operations.
# Values in argv are non-secret paths/IDs; no credential/material enters argv.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  set -euo pipefail
  action=${1:-}
  shift || exit 96
  repository_root=$(git rev-parse --show-toplevel)
  source "$repository_root/scripts/maintenance/local-runtime-images.sh"
  case "$action" in
    guard)
      [[ $# == 1 ]] || exit 96
      openpc_fact_secret_consumer_guard "$1"
      ;;
    render)
      [[ $# == 9 ]] || exit 96
      run_root=$1
      data_root=$2
      target_id=$3
      participant=$4
      privacy=$5
      client_cert=$6
      client_key=$7
      recipient=$8
      secret_root="$run_root/secrets"
      [[ $data_root == "$run_root/data/fact-secret-"* && $(realpath -e "$data_root") == "$data_root" ]] || exit 96
      [[ $client_cert == "$run_root/secrets/fact-secret-"*/client.pem && $client_key == "${client_cert%/*}/client.key" ]] || exit 96
      [[ $recipient == "$data_root/recipient.json" ]] || exit 96
      openpc_fact_secret_consumer_guard "$run_root"
      encoded=$(node --input-type=module -e '
        const a=JSON.parse(process.argv[1]);
        if(!Array.isArray(a)||a[0]!=="docker"||a[1]!=="compose"||a.some(v=>typeof v!=="string"||/[\n\r\0]/u.test(v)))process.exit(96);
        process.stdout.write(a.join("\n"));' "$9")
      mapfile -t compose <<< "$encoded"
      export OPENPC_LOCAL_RUNTIME_FACT_SECRET_RECIPIENT_CONFIG=$recipient
      source "$repository_root/tests/integration/local-runtime/runtime-configuration.sh"
      openpc_prepare_fact_database_files
      openpc_prepare_fact_bridge "$participant" "$privacy" "$client_cert" "$client_key"
      ;;
    *) exit 96 ;;
  esac
fi
