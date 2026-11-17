"""Private provenance helper for run-compose-e2e.sh, never a journey entrypoint."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import UUID


def command(*args, **kwargs):
    return subprocess.check_output(args, text=True, timeout=60, **kwargs).strip()


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def source_paths(version=2):
    if version not in (1, 2):
        raise ValueError("unsupported source fingerprint version")
    # Version one omitted shared Rust crates. Use it only to identify a retained
    # predecessor at an explicit Git revision before an affected image build.
    crates = "crates/|" if version == 2 else ""
    return re.compile(r"^(" + crates + r"apps/|packages/|services/|generated/|schemas/|migrations/|deploy/|scripts/|tests/integration/|Cargo|rust-toolchain|package.json$|pnpm-|\.npmrc$|\.dockerignore$|tsconfig)")


def source_identity(repository):
    # Git blob identities cover unchanged files without repeatedly hashing them.
    # Include uncommitted harness edits, and allow their eventual scoped commit.
    paths = command("git", "-C", str(repository), "ls-files", "-s", "-z").split("\0")
    changed = set(command("git", "-C", str(repository), "diff", "HEAD", "--name-only", "-z").split("\0"))
    untracked = command("git", "-C", str(repository), "ls-files", "--others", "--exclude-standard", "-z").split("\0")
    relevant = source_paths()
    entries = {}
    for entry in paths:
        if not entry:
            continue
        metadata, path = entry.split("\t", 1)
        if relevant.match(path):
            entries[path] = metadata.split()[1]
    for path in changed | set(untracked):
        if path and relevant.match(path):
            source = repository / path
            entries[path] = command("git", "hash-object", "--", str(source)) if source.is_file() else "DELETED"
    return digest(json.dumps(entries, sort_keys=True))


def validate_shared_approval_refresh(before, after):
    before = before.split("openpc_prepare_fact_database_files()", 1)[0]
    after = after.split("openpc_prepare_fact_database_files()", 1)[0]
    # These newly exercised contracts use public proposals. Extending only
    # these exact dispatch cases cannot change the earlier approval lifecycle.
    retirement = "|ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1) public_candidate_readback=1 ;;"
    replacement = ") public_candidate_readback=1 ;;"
    before = before.replace(retirement, replacement, 1)
    after = after.replace(retirement, replacement, 1)
    old = "ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1|ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1) public_candidate_readback=1 ;;"
    new = "ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1|ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1|ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1|ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1) public_candidate_readback=1 ;;"
    expected = before.replace(old, new, 1)
    if after not in (before, expected):
        raise ValueError("shared approval owner changed; fresh lifecycle required")


def validate_explorer_owner_refresh(path, before, after):
    if path == "services/identity-service/src/domain/identity-kernel.ts":
        anchor = "  ): Promise<SessionRow> {\n"
        addition = """    if (lock) {
      // Session writes also take this root through the lifecycle trigger. Take
      // it first, matching authority checks and Participant lifecycle changes.
      try {
        await lockAuthorityFence(client, participantId, {
          participant: [{ id: participantId }],
        });
      } catch (error) {
        if (error instanceof AuthorityFenceError) throw new IdentityKernelError('PC-AUTH-0003');
        throw error;
      }
    }
"""
        # Only activeSession has this signature; no authentication, lifetime,
        # epoch, schema or initial-trust changes are admitted by this exception.
        expected = before.replace(anchor, anchor + addition, 1)
    elif path == "deploy/compose/local/envoy/local-gateway.yaml":
        anchor = '                        - match: { prefix: "/api/v1/ui/" }'
        addition = '''                        - match: { path_separated_prefix: "/api/v1/ui/privacy-explorer" }
                          route: { cluster: admin_web, timeout: 45s }
'''
        expected = before.replace(anchor, addition + anchor, 1)
    else:
        raise ValueError("unsupported retained Explorer owner")
    if before.count(anchor) != 1 or expected != after:
        raise ValueError("Explorer refresh changed an unreviewed product boundary")


def validate_relationship_fixture_refresh(before, after):
    before = before.split("\n#[cfg(test)]", 1)[0].strip()
    after = after.split("\n#[cfg(test)]", 1)[0].strip()
    anchor = '''        profile.method_data_classes.push(MethodDataClass {
            method: "eth_getBlockByNumber(false)".into(),
            data_class: "BLOCK_HEADER".into(),
        });'''
    addition = '''
        profile
            .method_data_classes
            .sort_by(|a, b| (&a.method, &a.data_class).cmp(&(&b.method, &b.data_class)));'''
    if anchor not in before or after not in (before, before.replace(anchor, anchor + addition, 1)):
        raise ValueError("relationship fixture refresh changed an unreviewed owner")


def refresh_source(repository, revision, source_version=2):
    # Refresh is deliberately limited to this retained state-read vertical. No
    # ABI, module or Compose input may drift outside the exact corrections below.
    # Simulation's source selection may change with affected image builds; it does not replace
    # admitted module artifacts or source configuration. Local initial-trust and
    # approval corrections are verified exactly below.
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("refresh requires a full Git source identity")
    if source_version == 1 and os.environ.get("OPENPC_REFRESH_TEST_ONLY") == "1":
        raise ValueError("legacy source fingerprint requires an affected image build")
    relevant = source_paths(source_version)
    entries = {}
    for entry in command("git", "-C", str(repository), "ls-tree", "-r", "-z", revision).split("\0"):
        if entry:
            metadata, path = entry.split("\t", 1)
            if relevant.match(path):
                entries[path] = metadata.split()[2]
    changed = set(command("git", "-C", str(repository), "diff", revision, "--name-only", "-z").split("\0"))
    changed.update(command("git", "-C", str(repository), "ls-files", "--others", "--exclude-standard", "-z").split("\0"))
    changed = {path for path in changed if source_paths().match(path)}
    allowed = ("services/runtime-agent/", "services/fact-service/", "services/multi-rpc/", "apps/admin-web/", "tests/integration/local-runtime/")
    simulation = {
        "crates/pc-policy-core/src/contract_simulation.rs",
        "crates/pc-policy-core/src/visibility_policy/simulation.rs",
        "crates/pc-policy-core/src/visibility_policy/tests.rs",
        "tests/integration/identity/postgres-oidc-binding.test.ts",
        # Static CI dispatch assertions: not a runtime fixture or image input.
        "tests/integration/ci/invocation.test.mjs",
        # The mixed runtime dispatcher preserves admitted module/business state;
        # its changed executable and transitive consumers must rebuild below.
        "services/fleet-controller/src/runtime_target_service.rs",
        "services/fleet-controller/src/runtime_target_service/source_only.rs",
        "services/fleet-controller/src/runtime_target_service/source_only/dispatch.rs",
    }
    build_owners = {".dockerignore", "services/control-api/Dockerfile",
                    "services/fact-service/Dockerfile", "services/fleet-controller/Dockerfile",
                    "services/module-registry/Dockerfile"}
    for path in build_owners & changed:
        import runpy
        validate = runpy.run_path(str(repository / "tests/integration/local-runtime/build-inputs.py"))["validate_refresh_build_inputs"]
        before = command("git", "-C", str(repository), "show", f"{revision}:{path}")
        validate(repository, path, before, (repository / path).read_text().strip())
        simulation.add(path)
    relationship_fixture = "services/fleet-controller/src/local_fixture/indexer.rs"
    if relationship_fixture in changed:
        before = command("git", "-C", str(repository), "show", f"{revision}:{relationship_fixture}")
        validate_relationship_fixture_refresh(before, (repository / relationship_fixture).read_text())
        simulation.add(relationship_fixture)
    explorer_owners = {
        "services/identity-service/src/domain/identity-kernel.ts",
        "deploy/compose/local/envoy/local-gateway.yaml",
    }
    for path in explorer_owners & changed:
        before = command("git", "-C", str(repository), "show", f"{revision}:{path}")
        validate_explorer_owner_refresh(path, before, (repository / path).read_text().strip())
        simulation.add(path)
    protected_tests = ("tests/integration/local-runtime/module-", "tests/integration/local-runtime/configuration-fixture.mjs")
    if any(path.startswith(protected_tests) for path in changed):
        raise ValueError("module or approval input changed; fresh lifecycle required")
    shared = "tests/integration/local-runtime/runtime-configuration.sh"
    if shared in changed:
        before = command("git", "-C", str(repository), "show", f"{revision}:{shared}")
        after = (repository / shared).read_text().strip()
        validate_shared_approval_refresh(before, after)
    bootstrap = "deploy/compose/local/migrate.sh"
    if bootstrap in changed:
        before = command("git", "-C", str(repository), "show", f"{revision}:{bootstrap}")
        after = (repository / bootstrap).read_text().strip()
        marker = "-- Separate initial source trust."
        end = "UPDATE control.authority_envelope\nSET action_intent_ids=array("
        # Only the explicit local initial-trust block is mutable here. Schema,
        # generated migrations, existing grants and module state stay bound.
        old_head, old_tail = before.split(marker, 1)
        new_head, new_tail = after.split(marker, 1)
        if old_head != new_head or old_tail.split(end, 1)[1] != new_tail.split(end, 1)[1]:
            raise ValueError("unrelated bootstrap change requires clean acceptance")
        changed.remove(bootstrap)
    approval = "tests/integration/local-runtime/authenticated-http.sh"
    if approval in changed:
        before = command("git", "-C", str(repository), "show", f"{revision}:{approval}")
        after = (repository / approval).read_text().strip()
        expected = before
        if '  method="${11:-POST}"' not in before:
            expected = before.replace('  local origin csrf status\n  local -a curl_retry headers', '  local origin csrf status method\n  local -a curl_retry headers', 1)
            expected = expected.replace('  approval_id="${8:-}"\n', '  approval_id="${8:-}"\n  method="${9:-POST}"\n  [[ $method == POST || $method == DELETE ]] || return 96\n', 1)
            start = expected.index('identity_mutation_request()')
            stop = expected.index('operator_assertion_step_up()', start)
            expected = expected[:start] + expected[start:stop].replace('-X POST', '-X "$method"') + expected[stop:]
            expected = expected.replace('  local staging_approval_id\n', '  local staging_approval_id method\n', 1)
            expected = expected.replace('  action_id="${10:-ACT-PARTICIPANTS_UPDATE_RESOURCE-V1}"\n', '  action_id="${10:-ACT-PARTICIPANTS_UPDATE_RESOURCE-V1}"\n  method="${11:-POST}"\n', 1)
            expected = expected.replace('403 "$staging_approval_id"', '403 "$staging_approval_id" "$method"', 1)
            expected = expected.replace('"$expected_status" "$approval_id"\n', '"$expected_status" "$approval_id" "$method"\n', 1)
        expected = expected.replace('if [ "$action_id" = ACT-PARTICIPANT_CREATE_MEMBER-V1 ]; then', 'if [[ $action_id == ACT-PARTICIPANT_CREATE_MEMBER-V1 || $method == DELETE ]]; then')
        if expected != after:
            raise ValueError("approval semantics changed; fresh lifecycle required")
    if any(path and not path.startswith(allowed) and path not in simulation for path in changed):
        raise ValueError("refresh changes an owner requiring clean acceptance")
    def image_excluded_test(path):
        if path == "tests/integration/ci/invocation.test.mjs":
            return True
        suffix = next((suffix for suffix in (".test.ts", ".test.tsx", ".test.mjs", ".spec.ts", ".spec.tsx") if path.endswith(suffix)), None)
        if not path.startswith("apps/admin-web/") or suffix is None:
            return False
        # The admitted baseline already excludes these colocated test inputs.
        # A changed Docker boundary is rejected by the owner check above.
        ignored = command("git", "-C", str(repository), "show", f"{revision}:.dockerignore").splitlines()
        return f"**/*{suffix}" in ignored

    if os.environ.get("OPENPC_REFRESH_TEST_ONLY") == "1" and any(path and not path.startswith("tests/integration/local-runtime/") and not image_excluded_test(path) for path in changed):
        raise ValueError("image reuse only permits runner/test corrections")
    return digest(json.dumps(entries, sort_keys=True))


def normalize_container_dns(containers):
    value = json.loads(json.dumps(containers))
    # A daemon restart rewrites unset DNS lists from null to empty arrays.
    # Preserve configured values, ordering and every other container field.
    for container in value.values():
        host = container["HostConfig"]
        for key in ("Dns", "DnsOptions", "DnsSearch"):
            if key in host and host[key] is None:
                host[key] = []
    return value


def validate_recreated(previous, current):
    previous = normalize_container_dns(previous)
    current = normalize_container_dns(current)
    if previous.keys() != current.keys():
        raise ValueError("refresh service set changed")
    for service, old in previous.items():
        new = current[service]
        if old["Id"] == new["Id"]:
            if old != new:
                raise ValueError(f"unchanged container drift: {service}")
            continue
        def host(value):
            value = json.loads(json.dumps(value))
            # Docker returns equivalent sets in different orders and changes
            # its default OOM flag from null to false on Compose recreation.
            for key in ("Mounts", "Binds"):
                value[key] = sorted(value.get(key) or [], key=lambda entry: json.dumps(entry, sort_keys=True))
            if value.get("OomKillDisable") is None:
                value["OomKillDisable"] = False
            return value
        if host(old["HostConfig"]) != host(new["HostConfig"]) or old["Mounts"] != new["Mounts"]:
            raise ValueError(f"refresh host/mount configuration drift: {service}")
        def config(value):
            value = json.loads(json.dumps(value))
            value.pop("Hostname", None)
            value["Env"] = sorted(value.get("Env") or [])
            for key in ("com.docker.compose.config-hash", "com.docker.compose.image", "com.docker.compose.replace"):
                value["Labels"].pop(key, None)
            return value
        if config(old["Config"]) != config(new["Config"]):
            raise ValueError(f"refresh service configuration drift: {service}")


def inspect_project(project):
    ids = command("docker", "ps", "-aq", "--no-trunc", "--filter", f"label=com.docker.compose.project={project}").split()
    if not ids:
        raise ValueError("retained containers missing")
    return json.loads(command("docker", "inspect", *ids))


def bindings(containers, project):
    result = {}
    for container in containers:
        labels = container["Config"]["Labels"]
        if labels.get("com.docker.compose.project") != project:
            raise ValueError("container ownership mismatch")
        service = labels["com.docker.compose.service"]
        if service in result:
            raise ValueError("duplicate retained service")
        result[service] = {key: container[key] for key in ("Id", "Image", "Config", "HostConfig")}
        # Docker exposes mounts as a set; inspection order changes even while
        # stopped. Preserve every value while giving that set a stable order.
        mounts = container["Mounts"]
        if len({mount["Destination"] for mount in mounts}) != len(mounts):
            raise ValueError("duplicate mount destination")
        result[service]["Mounts"] = sorted(mounts, key=lambda mount: mount["Destination"])
    return result


def read_checkpoint(root):
    path = root / "evidence/runner-resume.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("verified resume checkpoint missing; normal build/bootstrap required")
    value = json.loads(path.read_text())
    if value.get("schema") != 1 or value.get("scenario") != "typed-policy":
        raise ValueError("unsupported resume checkpoint")
    return value


def write_checkpoint(root, value):
    path = root / "evidence/runner-resume.json"
    temporary = path.with_suffix(".tmp")
    with open(temporary, "w", opener=lambda p, flags: os.open(p, flags, 0o600)) as output:
        json.dump(value, output, sort_keys=True)
    temporary.replace(path)


def validate_checkpoint(value, current):
    if value.get("sourceVersion", 1) != current.get("sourceVersion", 1):
        raise ValueError("source fingerprint upgrade requires an explicit affected refresh")
    for key in ("owner", "source", "containers", "images", "credentials", "inputs"):
        old, new = value[key], current[key]
        if key == "containers":
            old, new = normalize_container_dns(old), normalize_container_dns(new)
        if old != new:
            raise ValueError(f"resume {key} mismatch; normal affected build/bootstrap required")


def private_inputs(root):
    result = {}
    # Configuration mounts are immutable inputs. Runtime journals and DB files
    # are verified through their owners, never traversed as an unprivileged user.
    for path in sorted((root / "secrets").rglob("*")):
        if path.is_symlink():
            raise ValueError("credential symlink")
        if path.is_file():
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for directory in ("module-releases", "provider-probe-source", "fact-bridge/config"):
        for path in sorted((root / "data" / directory).rglob("*")):
            if path.is_symlink():
                raise ValueError("configuration symlink")
            if path.is_file():
                result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ("fact-bridge/worker.env", "fact-bridge/fact.env", "fact-bridge/manager-url"):
        path = root / "data" / name
        if path.is_file():
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def verify_modules(repository, root):
    result = command("node", "--import", "tsx", str(repository / "tests/integration/local-runtime/module-admission-receipts.mjs"), str(root / "secrets"), "018f0000-0000-7000-8000-000000000101", "018f0000-0000-7000-8000-000000000201", str(root / "evidence"), "enabled")
    if "phase=enabled|OPENPC_MODULE_RECEIPTS|PASS|receipts=25|" not in result:
        raise ValueError("module closure readback rejected")
    print(result)


def validate_compose(rendered, containers):
    for container in containers:
        service = container["Config"]["Labels"]["com.docker.compose.service"]
        expected = rendered["services"][service]
        actual = {mount["Destination"]: mount for mount in container["Mounts"] if mount["Type"] == "bind"}
        mounts = {}
        for volume in expected.get("volumes", []):
            if volume["type"] == "bind":
                mounts[volume["target"]] = (volume["source"], not volume.get("read_only", False))
        for section, prefix in (("secrets", "/run/secrets/"), ("configs", "/")):
            for item in expected.get(section, []):
                target = item.get("target", item["source"])
                destination = target if target.startswith("/") else prefix + target
                mounts[destination] = (rendered[section][item["source"]]["file"], False)
        if actual.keys() != mounts.keys():
            raise ValueError(f"retained Compose mount set changed: {service}")
        for destination, (source, writable) in mounts.items():
            if not Path(source).exists() or actual[destination]["Source"] != source or actual[destination]["RW"] != writable:
                raise ValueError(f"retained Compose mount changed: {service}")
            if destination in ("/app/server.mjs", "/issuer/manifest.json") and not Path(source).is_file():
                raise ValueError(f"retained provider input is not a file: {service}")
        environment = dict(entry.split("=", 1) for entry in container["Config"].get("Env", []))
        for name, value in expected.get("environment", {}).items():
            if service == "runtime-target" and name in ("OPENPC_TARGET_RUNTIME_ID", "OPENPC_TARGET_BOOTSTRAP_DIRECTORY"):
                continue  # Bound separately to the public target by the checkpoint.
            if environment.get(name) != str(value):
                raise ValueError(f"retained Compose environment changed: {service}")
        if "user" in expected and container["Config"]["User"] != expected["user"]:
            raise ValueError(f"retained Compose user changed: {service}")
        if expected.get("command") is not None and container["Config"]["Cmd"] != expected["command"]:
            raise ValueError(f"retained Compose command changed: {service}")


def current_bindings(repository, root, project, owner):
    containers = inspect_project(project)
    images = {}
    for service in ("control-worker", "policy-service", "fact-service", "identity-service", "participant-service", "control-api", "admin-web"):
        image = json.loads(command("docker", "image", "inspect", f"openpc-r1-dev/{service}:local"))[0]
        labels = image["Config"]["Labels"]
        if labels.get("io.openpc.image.owner") != "openpc-r1-local-runtime-v1" or labels.get("io.openpc.image.service") != service:
            raise ValueError("candidate image ownership mismatch")
        if not any(c["Image"] == image["Id"] and c["Config"]["Labels"]["com.docker.compose.service"] == service for c in containers):
            raise ValueError("candidate/retained image mismatch")
        images[service] = image["Id"]
    inputs = {}
    for name in ("configuration-identity-fixture.json", "configuration-target.json", "configuration-runtime-activation.json", "configuration-contract-binding-resource.json", "configuration-contract-method-resource.json", "configuration-contract-rules-resource.json", "configuration-provider.json", "configuration-indexer.json", "configuration-projection.json", "typed-policy-inputs.json", "typed-policy-browser-inputs.json", "typed-policy-browser-result.json"):
        path = root / "evidence" / name
        if path.exists():
            inputs[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(schema=1, scenario="typed-policy", owner=owner, sourceVersion=2, source=source_identity(repository), containers=bindings(containers, project), images=images, credentials=private_inputs(root), inputs=inputs)


def database_state(root, containers):
    state = {}
    for service, database, secret in (("control-pg", "openpc_control", "control_pg_password"), ("fact-pg", "openpc_facts", "fact_pg_password"), ("candidate-index-pg", "openpc_candidate_index", "candidate_index_pg_password")):
        container = next(c for c in containers if c["Config"]["Labels"]["com.docker.compose.service"] == service)
        environment = dict(os.environ, PGPASSWORD=(root / "secrets" / f"{secret}.txt").read_text().strip())
        def sql(query):
            return command("docker", "exec", "-e", "PGPASSWORD", container["Id"], "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", database, "-d", database, "-c", query, env=environment)
        migrations = json.loads(sql("select coalesce(json_agg(m order by path),'[]') from openpc_local.migration m"))
        if not migrations:
            raise ValueError("migration ledger empty")
        state[service] = dict(migrations=migrations)
        if service == "control-pg":
            for table in ("runtime_target", "policy_generation", "policy_activation_occurrence", "policy_activation_occurrence_target", "privacy_explorer_profile", "module_installation", "module_configuration_generation", "module_registration", "module_version", "contract_runtime_binding"):
                rows = sql(f"select coalesce(jsonb_agg(row_digest order by row_digest),'[]') from (select encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') row_digest from control.{table} t) fingerprints")
                state[service][table] = digest(rows)
        if service == "fact-pg":
            for table in ("canonical_generation", "canonical_fact", "fact_lineage", "source_checkpoint", "readiness_gate", "fact_invalidation"):
                rows = sql(f"select coalesce(jsonb_agg(row_digest order by row_digest),'[]') from (select encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') row_digest from facts.{table} t) fingerprints")
                state[service][table] = digest(rows)
    return state


def renew_activation(repository, root, project, owner, containers):
    previous = read_checkpoint(root)
    if previous.get("stage") != "target-created":
        raise ValueError("activation renewal requires the exact target prerequisite")
    current = current_bindings(repository, root, project, owner)
    if previous["source"] != refresh_source(repository, os.environ["OPENPC_REFRESH_FROM"], previous.get("sourceVersion", 1)):
        raise ValueError("activation prerequisite source mismatch")
    if previous["owner"] != owner or previous["images"] != current["images"]:
        raise ValueError("activation owner/image drift")
    if current["containers"].keys() - previous["containers"].keys() != {"runtime-envoy"}:
        raise ValueError("activation service set changed")
    validate_recreated(previous["containers"], {key: current["containers"][key] for key in previous["containers"]})
    activation = json.loads((root / "evidence/configuration-runtime-activation.json").read_text())
    target = str(UUID(json.loads((root / "evidence/configuration-target.json").read_text())["resourceRef"].split(":")[-1]))
    operation = str(UUID(activation["operationId"]))
    if activation["resourceRef"].split(":")[-1] != target or activation["actionIntentId"] != "ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1":
        raise ValueError("activation public result binding rejected")
    if current["inputs"] != previous["inputs"] | {"configuration-runtime-activation.json": current["inputs"]["configuration-runtime-activation.json"]}:
        raise ValueError("activation public input drift")
    configuration = root / "data/provider-probe-source/runtime-configuration.cbor"
    configuration_digest = hashlib.sha256(configuration.read_bytes()).hexdigest()
    database = next(c for c in containers if c["Config"]["Labels"]["com.docker.compose.service"] == "control-pg")
    environment = dict(os.environ, PGPASSWORD=(root / "secrets/control_pg_password.txt").read_text().strip())
    # Read the same current-input and admitted provider/projection owners used
    # by public activation. Compare the actual bytes, not an authoring fixture.
    query = f"""BEGIN;
select openpc.set_request_context('PARTICIPANT','018f0000-0000-7000-8000-000000000101','018f0000-0000-7000-8000-000000000201',uuidv7(),'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',true) as context \\gset
select coalesce(json_agg(json_build_object('generation',w.generation_digest,
 'policy',w.policy_generation_digest,'provider',p.behavior_fingerprint,'plan',plan.plan_digest)),'[]')
from control.configuration_work w
join control.runtime_target t on t.runtime_target_id=w.runtime_target_id
 and t.participant_id=w.participant_id and t.privacy_domain_id=w.privacy_domain_id
join control.runtime_configuration_generation g on g.runtime_configuration_generation_id=w.runtime_configuration_generation_id
 and g.runtime_target_id=t.runtime_target_id and g.generation_digest=w.generation_digest
 and g.policy_generation_digest=w.policy_generation_digest and g.cigl_profile_selection is null
join control.runtime_configuration_input_current c on w.configuration_digest='sha256:'||encode(c.configuration_digest,'hex')
 and c.participant_id=w.participant_id and c.privacy_domain_id=w.privacy_domain_id and c.active
join control.policy_generation policy on w.policy_generation_digest='sha256:'||encode(policy.generation_digest,'hex')
 and policy.participant_id=w.participant_id and policy.privacy_domain_id=w.privacy_domain_id and policy.active
join control.provider_profile p on p.provider_profile_id=g.provider_profile_id and p.state in ('QUALIFIED','ACTIVE')
join control.projection_plan plan on plan.projection_plan_id=g.projection_plan_id and plan.state in ('VALIDATED','RUNNING') and plan.readiness='READY'
join control.indexer_profile indexer on indexer.indexer_profile_id=plan.indexer_profile_id and indexer.state in ('QUALIFIED','ACTIVE')
where w.operation_id='{operation}' and w.runtime_target_id='{target}' and w.work_kind='RUNTIME_ACTIVATION'
 and w.state in ('PENDING','LEASED','RECONCILING') and t.state='STAGING' and t.desired_generation_digest=w.generation_digest
 and encode(c.configuration_digest,'hex')='{configuration_digest}'
 and encode(sha256(c.configuration_cbor),'hex')='{configuration_digest}'
 and not exists (select 1 from (values (p.provider_profile_id,'PROVIDER_QUALIFICATION',p.behavior_fingerprint),
   (indexer.indexer_profile_id,'INDEXER_ADMISSION',indexer.method_profile_digest),
   (plan.projection_plan_id,'PROJECTION_VALIDATION',plan.plan_digest)) expected(id,kind,digest)
  where not exists (select 1 from control.configuration_work prior
   where prior.resource_id=expected.id and prior.work_kind=expected.kind and prior.input_digest=expected.digest
    and prior.participant_id=w.participant_id and prior.privacy_domain_id=w.privacy_domain_id
    and prior.configuration_digest=w.configuration_digest and prior.state='COMPLETED'
    and prior.result_receipt is not null and prior.result_event_id is not null));
ROLLBACK;
"""
    rows = json.loads(command("docker", "exec", "-i", "-e", "PGPASSWORD", database["Id"], "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "openpc_control", "-d", "openpc_control", input=query, env=environment))
    if len(rows) != 1:
        raise ValueError("configuration bytes do not bind one admitted public activation")
    row = rows[0]
    generation = hashlib.sha256(bytes.fromhex(configuration_digest) + bytes.fromhex(row["policy"].removeprefix("sha256:")) + row["provider"].encode() + row["plan"].encode() + target.encode()).hexdigest()
    if row["generation"] != "sha256:" + generation:
        raise ValueError("configuration activation generation mismatch")
    keys = root / "secrets/runtime_analysis_target_keys.json"
    if json.loads(keys.read_text()) != {target: (root / "secrets/runtime_agent_projection_public_key.txt").read_text().strip()}:
        raise ValueError("public target projection trust mismatch")
    ca = root / "secrets/runtime_ads_ca.pem"
    client = root / "data/runtime/tls/ads-client.pem"
    server = root / "secrets/runtime_ads_server_cert.pem"
    serial = root / "secrets/runtime_ads_ca.srl"
    command("openssl", "verify", "-CAfile", str(ca), "-purpose", "sslclient", str(client))
    command("openssl", "verify", "-CAfile", str(ca), "-verify_hostname", "control-worker", str(server))
    client_serial = int(command("openssl", "x509", "-in", str(client), "-noout", "-serial").split("=")[1], 16)
    server_serial = int(command("openssl", "x509", "-in", str(server), "-noout", "-serial").split("=")[1], 16)
    if int(serial.read_text().strip(), 16) != client_serial or client_serial != server_serial + 1:
        raise ValueError("ADS serial does not bind the retained certificate issuance")
    san = command("openssl", "x509", "-in", str(client), "-noout", "-ext", "subjectAltName")
    if san.splitlines()[-1].strip() != "URI:spiffe://openpc.local/runtime-target/" + target:
        raise ValueError("ADS certificate does not bind the public target")
    if command("openssl", "x509", "-in", str(client), "-pubkey", "-noout") != command("openssl", "pkey", "-in", str(root / "data/runtime/tls/ads-client.key"), "-pubout"):
        raise ValueError("ADS retained private key mismatch")
    if (root / "data/runtime/tls/ads-ca.pem").read_bytes() != ca.read_bytes():
        raise ValueError("ADS mounted CA mismatch")
    envoy = json.loads((root / "data/runtime/envoy.json").read_text())
    ads = envoy["static_resources"]["clusters"]
    if envoy["node"]["id"] != target or len(ads) != 1 or ads[0]["name"] != "ads":
        raise ValueError("ADS bootstrap target mismatch")
    transport = ads[0]["transport_socket"]["typed_config"]
    tls = transport["common_tls_context"]
    if transport["sni"] != "control-worker" or tls["tls_certificates"] != [{"certificate_chain": {"filename": "/runtime/tls/ads-client.pem"}, "private_key": {"filename": "/runtime/tls/ads-client.key"}}] or tls["validation_context"]["trusted_ca"] != {"filename": "/runtime/tls/ads-ca.pem"}:
        raise ValueError("ADS bootstrap custody mismatch")
    # Only proven owner outputs may replace the prior commitments. Every other
    # changed, added or removed input remains a hard failure.
    expected = dict(previous["credentials"])
    for path in (keys, configuration, serial):
        expected[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    if expected != current["credentials"]:
        raise ValueError("unrecognized retained input change")
    state = database_state(root, containers)
    for service, tables in previous["state"].items():
        for table, value in tables.items():
            if (service, table) != ("control-pg", "runtime_target") and state[service][table] != value:
                raise ValueError("retained module/database baseline changed")
    verify_modules(repository, root)
    current.update(state=state, stage="runtime-activation")
    write_checkpoint(root, current)
    print("OPENPC_ACTIVATION_CHECKPOINT|PASS|public-target-key|admitted-configuration-generation|ads-certificate-serial|unchanged-baseline")


def main():
    mode, repository_arg, root_arg, project, owner = sys.argv[1:]
    repository, root = Path(repository_arg), Path(root_arg)
    if mode == "source":
        print(source_identity(repository))
        return
    containers = inspect_project(project)
    if mode == "compose":
        validate_compose(json.load(sys.stdin), containers)
        print("OPENPC_RESUME_COMPOSE|PASS|environment|mounts|provider-files|entrypoints")
        return
    if mode == "renew-activation":
        renew_activation(repository, root, project, owner, containers)
        return
    if mode == "verify":
        if any(c["State"]["Running"] for c in containers):
            raise ValueError("retained environment is in use")
        value = read_checkpoint(root)
        current = current_bindings(repository, root, project, owner)
        revision = os.environ.get("OPENPC_REFRESH_FROM", "")
        if revision:
            source_version = value.get("sourceVersion", 1)
            current["source"] = refresh_source(repository, revision, source_version)
            current["sourceVersion"] = source_version
        validate_checkpoint(value, current)
        required = {"configuration-identity-fixture.json", "configuration-target.json", "configuration-contract-binding-resource.json"}
        if value.get("stage") in ("target-created", "runtime-activation", "read-method"):
            required.update(("configuration-contract-method-resource.json", "configuration-contract-rules-resource.json", "configuration-provider.json", "configuration-indexer.json", "configuration-projection.json"))
            if value["stage"] == "runtime-activation":
                required.add("configuration-runtime-activation.json")
        elif value.get("stage") != "visibility":
            required.update(("typed-policy-inputs.json", "typed-policy-browser-inputs.json", "typed-policy-browser-result.json"))
        if not required.issubset(value["inputs"]):
            raise ValueError("typed policy checkpoint incomplete")
        active = command("docker", "ps", "--format", "{{.Names}}|{{.Labels}}")
        if "openpc-local-e2e-" in active or "buildx_buildkit_openpc-r1-local-v1-node" in active:
            raise ValueError("another runtime or dedicated builder is active")
        for name in ("identity_mtls_rotated_cert.pem", "identity_mtls_server_cert.pem", "identity_mtls_ca.pem"):
            command("openssl", "x509", "-checkend", "900", "-noout", "-in", str(root / "secrets" / name))
        print("OPENPC_RESUME_PREFLIGHT|PASS|ownership|source|images|configuration|credentials-ttl")
        return
    if mode == "recreated":
        previous = read_checkpoint(root)
        current = current_bindings(repository, root, project, owner)
        validate_recreated(previous["containers"], current["containers"])
        for key in ("owner", "credentials", "inputs"):
            if previous[key] != current[key]:
                raise ValueError(f"refresh {key} drift")
        print("OPENPC_REFRESH|PASS|configuration|mounts|credentials|owned-images")
        return
    if mode == "state":
        if read_checkpoint(root)["state"] != database_state(root, containers):
            raise ValueError("retained migration/state tuple mismatch")
        if read_checkpoint(root).get("stage") in ("target-created", "runtime-activation", "read-method", "visibility"):
            verify_modules(repository, root)
        print("OPENPC_RESUME_STATE|PASS|migrations|target-generation|policy-profile-fact-bindings")
        return
    if mode not in ("record", "record-prerequisites"):
        raise ValueError("unsupported provenance operation")
    value = current_bindings(repository, root, project, owner)
    if value["source"] != os.environ["OPENPC_RUN_SOURCE_IDENTITY"]:
        raise ValueError("source changed during build/journey")
    value["state"] = database_state(root, containers)
    if mode == "record-prerequisites" or os.environ.get("OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY") == "1":
        verify_modules(repository, root)
        value["stage"] = "target-created" if mode == "record-prerequisites" else os.environ.get("OPENPC_RESUME_STAGE", "visibility")
        if value["stage"] == "target-created" and (root / "evidence/configuration-runtime-activation.json").exists():
            raise ValueError("target prerequisite already advanced")
    write_checkpoint(root, value)
    print("OPENPC_RESUME_CHECKPOINT|PASS|scenario=typed-policy")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        # Do not print Docker configuration, credential bytes or query output.
        print("OPENPC_RESUME_PREFLIGHT|FAIL|retained provenance/state unavailable or changed", file=sys.stderr)
        raise SystemExit(96)
