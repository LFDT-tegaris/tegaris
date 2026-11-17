"""Joined PDS owner regression using disposable PostgreSQL 18 and external mTLS.

Run under run-bounded.sh with the database profile and 40 GiB peak disk. This is downstream
owner acceptance, not the governed publication or Envoy target journey.
"""
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import shutil
import ssl
import sys
import subprocess
import tempfile
import threading
import time

REPOSITORY = Path(__file__).resolve().parents[3]
IMAGE = "docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7"


def run(*args, data=None, env=None, visible=False, cwd=REPOSITORY):
    result = subprocess.run(args, input=data, text=True, capture_output=not visible,
                            cwd=cwd, env=env, check=False)
    if result.returncode:
        if result.stderr:
            print(result.stderr, flush=True)
        raise RuntimeError(f"{args[0]} failed with status {result.returncode}")
    return result.stdout


def certificates(root):
    def openssl(*args):
        run("openssl", *args, cwd=root)
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=Joined test CA",
            "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE")
    for name, san, eku in [("server", "DNS:provider.openpc.test", "serverAuth"),
                           ("client", "URI:spiffe://openpc.local/broker/joined", "clientAuth")]:
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={name}")
        (root / f"{name}.ext").write_text(
            f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            f"extendedKeyUsage={eku}\nsubjectAltName={san}\n")
        openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-out", f"{name}.pem", "-days", "1", "-extfile", f"{name}.ext")


def provider(root, submission=False):
    expected_client = ssl.PEM_cert_to_DER_cert((root / "client.pem").read_text())

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            if self.path != "/rpc" or self.connection.getpeercert(binary_form=True) != expected_client:
                self.send_error(403)
                return
            length = int(self.headers.get("content-length", "0"))
            if length < 1 or length > 4096:
                self.send_error(413)
                return
            request = json.loads(self.rfile.read(length))
            contacts = root / "provider-contacts"
            contacts.write_text(str(int(contacts.read_text()) + 1 if contacts.exists() else 1))
            preflight_block = int((root / "preflight-block").read_text()) if (root / "preflight-block").exists() else 16
            observation_mode = (root / "observation-mode").read_text() if (root / "observation-mode").exists() else "pending"
            cigl_mode = (root / "cigl-mode").read_text() if (root / "cigl-mode").exists() else "ok"
            known_hashes = []
            if submission and (root / "submissions.json").exists():
                expected = json.loads((root / "expected-submissions.json").read_text())
                known_hashes = [expected[raw] for raw in json.loads((root / "submissions.json").read_text())]
            if request["method"] == "eth_chainId":
                result = "0x1" if submission else "0x7a69"
            elif request["method"] == "eth_getBlockByNumber" and submission:
                import hashlib
                if request["params"] == ["0x0", False]:
                    result = {"number": "0x0", "hash": "0x" + hashlib.sha256(b"local genesis").hexdigest()}
                elif request["params"] == ["latest", False]:
                    result = {"number": hex(preflight_block), "hash": "0x" + hashlib.sha256(f"block-{preflight_block}".encode()).hexdigest(),
                              "stateRoot": "0x" + hashlib.sha256(f"state-{preflight_block}".encode()).hexdigest(),
                              "gasLimit": "0x1000000", "baseFeePerGas": "0x1"}
                elif request["params"] == ["safe", False]:
                    result = None
                elif request["params"] == ["finalized", False]:
                    result = ({"number": "0x14", "hash": "0x" + hashlib.sha256(b"block-20").hexdigest(),
                               "transactions": known_hashes} if observation_mode == "finalized" else None)
                elif request["params"] in (["0x11", False], ["0x12", False], ["0x13", False], ["0x14", False]):
                    number = int(request["params"][0], 16)
                    label = "orphaned-18" if number == 18 and observation_mode == "reorg" else f"block-{number}"
                    result = {"number": request["params"][0], "hash": "0x" + hashlib.sha256(label.encode()).hexdigest(),
                              "transactions": known_hashes}
                else:
                    self.send_error(400)
                    return
            elif request["method"] in ("eth_getTransactionByHash", "eth_getTransactionReceipt") and submission:
                import hashlib
                if len(request["params"]) != 1:
                    self.send_error(400)
                    return
                tx_hash = request["params"][0]
                transactions = json.loads((root / "observation-transactions.json").read_text())
                if tx_hash not in known_hashes:
                    result = None
                elif request["method"] == "eth_getTransactionByHash":
                    result = {**transactions[tx_hash], "hash": tx_hash, "chainId": "0x1", "blockHash": None, "blockNumber": None}
                elif observation_mode in ("pending", "reorg"):
                    result = None
                else:
                    reverted = observation_mode in ("reverted", "finalized")
                    number = 19 if reverted else 18
                    result = {"transactionHash": tx_hash, "from": transactions[tx_hash]["from"], "to": transactions[tx_hash]["to"],
                              "blockNumber": hex(number), "blockHash": "0x" + hashlib.sha256(f"block-{number}".encode()).hexdigest(),
                              "transactionIndex": hex(known_hashes.index(tx_hash)), "status": "0x0" if reverted else "0x1", "logs": []}
            elif request["method"] in ("eth_getCode", "eth_getTransactionCount", "eth_getBalance") and submission:
                import hashlib
                address, anchor = request["params"]
                if anchor != {"blockHash": "0x" + hashlib.sha256(f"block-{preflight_block}".encode()).hexdigest(), "requireCanonical": True}:
                    self.send_error(400)
                    return
                if request["method"] == "eth_getCode":
                    result = "0x60006000f3" if address == "0x" + "01" * 20 else "0x"
                    if address in ("0x" + "02" * 20, "0x" + "03" * 20):
                        result = "0x6002" if cigl_mode == "code-drift" else "0x6001"
                elif request["method"] == "eth_getTransactionCount":
                    # Accepted submissions remain pending at this block; the
                    # next nonce may queue without fabricating chain execution.
                    result = "0x9"
                else:
                    result = "0x" + "f" * 64
            elif request["method"] == "debug_traceCall" and submission:
                import hashlib
                call, anchor, options = request["params"]
                if (anchor != {"blockHash": "0x" + hashlib.sha256(f"block-{preflight_block}".encode()).hexdigest(), "requireCanonical": True}
                        or call["to"] != "0x" + "01" * 20
                        or call["data"] != "0x70a08231" + "00" * 12 + "02" * 20
                        or "stateOverrides" in options):
                    self.send_error(400)
                    return
                target = "03" if cigl_mode == "shared-deny" else "04" if cigl_mode == "unreviewed" else "02"
                if options.get("tracer") == "callTracer":
                    result = {"type": "CALL", "from": call["from"], "to": call["to"], "input": call["data"],
                              "value": call["value"], "gas": call["gas"], "gasUsed": "0x1000", "calls": [
                                  {"type": "STATICCALL", "from": call["to"], "to": "0x" + target * 20,
                                   "input": "0x70a08231" + "00" * 12 + ("03" if cigl_mode == "argument" else "02") * 20,
                                   "gas": "0x3e8", "gasUsed": "0x1"}]}
                else:
                    result = {"failed": False, "gas": 4096, "returnValue": "", "structLogs": [
                        {"pc": 0, "op": "STATICCALL", "gas": 10000, "gasCost": 100, "depth": 1},
                        {"pc": 0, "op": "STOP", "gas": 999, "gasCost": 0, "depth": 2},
                        {"pc": 1, "op": "STOP", "gas": 9000, "gasCost": 0, "depth": 1}]}
            elif request["method"] == "eth_sendRawTransaction" and submission:
                # Table-driven external faults; internal authority and journal remain real.
                expected = json.loads((root / "expected-submissions.json").read_text())
                if len(request["params"]) != 1 or request["params"][0] not in expected:
                    self.send_error(400)
                    return
                raw = request["params"][0]
                path = root / "submissions.json"
                contacts = json.loads(path.read_text()) if path.exists() else []
                contacts.append(raw)
                path.write_text(json.dumps(contacts))
                result = expected[raw]
                if (root / "lose-submission-response").exists():
                    self.close_connection = True
                    return
            elif request["method"] in ("eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getLogs") and not submission:
                import hashlib
                block_hash = "0x" + hashlib.sha256(b"block-16").hexdigest()
                tx_hash = "0x" + "44" * 32
                topic = (root / "visibility-event-topic").read_text()
                mode = (root / "visibility-mode").read_text() if (root / "visibility-mode").exists() else "ok"
                log = {"address": "0x" + "01" * 20, "blockHash": block_hash, "blockNumber": "0x10",
                       "transactionHash": tx_hash, "transactionIndex": "0x0", "logIndex": "0x0",
                       "removed": False, "topics": [topic], "data": "0x" + "00" * 31 + "2a"}
                if mode == "hidden-log":
                    log["topics"] = ["0x" + "ff" * 32]
                elif mode == "removed-log":
                    log["removed"] = True
                if request["method"] == "eth_getLogs":
                    if request["params"] != [{"address": "0x" + "01" * 20, "blockHash": block_hash, "topics": [topic]}]:
                        self.send_error(400)
                        return
                    result = [log]
                else:
                    if request["params"] != [tx_hash]:
                        self.send_error(400)
                        return
                    common = {"blockHash": block_hash, "blockNumber": "0x10", "transactionIndex": "0x0",
                              "from": "0x" + "02" * 20, "to": "0x" + "01" * 20}
                    if request["method"] == "eth_getTransactionByHash":
                        result = {**common, "hash": tx_hash, "gas": "0x5208", "input": "0x", "nonce": "0x1", "value": "0x0"}
                        if mode == "wrong-hash":
                            result["hash"] = "0x" + "55" * 32
                    else:
                        result = {**common, "transactionHash": tx_hash, "cumulativeGasUsed": "0x5208",
                                  "gasUsed": "0x5208", "contractAddress": None, "logs": [log],
                                  "logsBloom": "0x" + "00" * 256, "status": "0x1"}
            elif request["method"] == "eth_call":
                call, anchor = request["params"]
                if call != {"to": "0x" + "01" * 20, "data": "0x70a08231" + "00" * 12 + "02" * 20}:
                    self.send_error(400)
                    return
                import hashlib
                if anchor != {"blockHash": "0x" + hashlib.sha256(b"block-16").hexdigest(), "requireCanonical": True}:
                    self.send_error(400)
                    return
                if (root / "hold").exists():
                    (root / "contact").write_text("contact")
                    deadline = time.monotonic() + 10
                    while not (root / "release").exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    if not (root / "release").exists():
                        self.send_error(504)
                        return
                result = "0x" + "00" * 31 + "2a"
            else:
                self.send_error(400)
                return
            body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(root / "ca.pem")
    context.load_cert_chain(root / "server.pem", root / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    if sys.argv[1:] not in ([], ["--submission"], ["--cigl-analysis"], ["--cigl-revocation"], ["--reservations"], ["--spool-capacity"]):
        raise SystemExit("usage: run-decision-owner.py [--submission|--cigl-analysis|--cigl-revocation|--reservations|--spool-capacity]")
    analysis_only = sys.argv[1:] == ["--cigl-analysis"]
    revocation_only = sys.argv[1:] == ["--cigl-revocation"]
    submission = analysis_only or revocation_only or sys.argv[1:] == ["--submission"]
    reservations = sys.argv[1:] == ["--reservations"]
    spool_capacity = sys.argv[1:] == ["--spool-capacity"]
    run("bash", str(REPOSITORY / "scripts/maintenance/run-bounded.sh"),
        "--profile", "database", "--reuse", "--peak-disk-gib", "40", "--", "true")
    scratch = Path(os.environ.get("OPENPC_DECISION_OWNER_TMP_ROOT", REPOSITORY.parent / "Agents/tmp"))
    scratch.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="joined-decision-owner-", dir=scratch))
    name = f"openpc-joined-decision-{os.getpid()}"
    password, capability = secrets.token_hex(24), secrets.token_hex(32)
    for key in ["control_pg_password", "identity_runtime_db_password", "participant_runtime_db_password",
                "policy_runtime_db_password", "control_api_runtime_db_password", "control_worker_runtime_db_password"]:
        (root / key).write_text(password)
        (root / key).chmod(0o600)
    created = passed = False
    server = None
    analysis_api = None
    migration_root = REPOSITORY / "migrations"
    deferred_migrations = []
    if reservations:
        # Populated custody upgrade component, not a seeded deployment journey.
        migration_root = root / "migrations"
        shutil.copytree(REPOSITORY / "migrations", migration_root)
        # Preserve migration order: later security tails assume predecessor
        # schemas and must not run before the populated upgrade under test.
        for deferred_path in sorted((migration_root / "postgres/control-api").glob("*.sql")):
            if int(deferred_path.name.split("_", 1)[0]) >= 17:
                deferred_migrations.append((deferred_path, deferred_path.read_text()))
                deferred_path.unlink()

    def sql(database, statement, *, transaction=False):
        return run("docker", "exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                   "-U", "postgres", "-d", database,
                   *(["--single-transaction", "-f", "-"] if transaction else []), data=statement)

    try:
        run("docker", "run", "-d", "--name", name, "--label", "io.openpc.owner=openpc-r1",
            "--label", "io.openpc.test=joined-decision-owner", "--memory", "1g", "--cpus", "1",
            "--pids-limit", "128", "-p", "127.0.0.1::5432", "-e", f"POSTGRES_PASSWORD={password}",
            "-e", "POSTGRES_DB=openpc_control", "-v", f"{migration_root}:/migrations:ro",
            "-v", f"{REPOSITORY}/deploy/compose/local/migrate.sh:/openpc-migrate.sh:ro",
            "-v", f"{root}:/run/secrets:ro", IMAGE)
        created = True
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                probe = subprocess.run(
                    ["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "openpc_control"],
                    text=True,
                    capture_output=True,
                    timeout=5,
                )
            except subprocess.TimeoutExpired:
                (root / "readiness.log").write_text("pg_isready timed out\n")
                time.sleep(0.5)
                continue
            (root / "readiness.log").write_text(probe.stdout + probe.stderr)
            if probe.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("PostgreSQL startup deadline")
        run("docker", "exec", "-e", "PGHOST=127.0.0.1", "-e", "PGUSER=postgres", "-e", "PGDATABASE=openpc_control",
            name, "sh", "/openpc-migrate.sh", "control-schema" if reservations else "control")
        if reservations:
            # The predecessor database is a controlled bootstrap fixture. It
            # asserts migration retention/backfill only, not upstream authority.
            sql("openpc_control", """
            BEGIN;
            SET LOCAL session_replication_role=replica;
            INSERT INTO control.deployment_intent(deployment_intent_id,participant_id,privacy_domain_id,
              actor_principal_id,deployment_policy_id,runtime_target_id,wallet_binding_id,preparation_bytes,
              publication_bytes,preparation_digest,intent_digest,creation_operation_id,creation_authority_digest,expires_at)
            VALUES('018f0000-0000-7000-8000-000000007001','018f0000-0000-7000-8000-000000007002',
              '018f0000-0000-7000-8000-000000007003','018f0000-0000-7000-8000-000000007004',
              uuidv7(),uuidv7(),uuidv7(),convert_to('{"intent":{"nonce":"9","sender":"0x7777777777777777777777777777777777777777"}}','UTF8'),
              convert_to('{}','UTF8'),'sha256:'||repeat('7',64),'sha256:'||repeat('7',64),uuidv7(),
              'sha256:'||repeat('7',64),clock_timestamp()+interval '2 minutes');
            INSERT INTO control.deployment_address_reservation(attempt_id,command_id,participant_id,privacy_domain_id,
              target_runtime_id,chain_id,genesis_digest,contract_address,sender_address,creator_address,mechanism,
              artifact_digest,init_code_hash,intent_digest,profile_digest,generation_digest,transaction_hash,
              prepared_record_digest,expires_at,state,created_at,handoff_at)
            SELECT uuidv7(),uuidv7(),'018f0000-0000-7000-8000-000000007002','018f0000-0000-7000-8000-000000007003',
              'target:legacy','31337','sha256:'||repeat('7',64),'0x'||repeat(marker,40),'0x'||repeat(marker,40),
              '0x'||repeat(marker,40),'TRANSACTION_CREATE','sha256:'||repeat('7',64),'0x'||repeat('7',64),
              'sha256:'||repeat(marker,64),'sha256:'||repeat('7',64),'sha256:'||repeat('7',64),'0x'||repeat(marker,64),
              'sha256:'||repeat(marker,64),clock_timestamp()+interval '1 minute','HANDOFF',
              clock_timestamp()-interval '1 second',date_trunc('milliseconds',clock_timestamp())
            FROM (VALUES('7'),('8')) markers(marker);
            COMMIT;
            """)
            for deferred_path, deferred_migration in deferred_migrations:
                deferred_path.write_text(deferred_migration)
            run("docker", "exec", "-e", "PGHOST=127.0.0.1", "-e", "PGUSER=postgres", "-e", "PGDATABASE=openpc_control",
                name, "sh", "/openpc-migrate.sh", "control")
            sql("openpc_control", """
            DO $$ BEGIN
             IF (SELECT count(*) FROM control.deployment_address_reservation
              WHERE participant_id='018f0000-0000-7000-8000-000000007002' AND state='HANDOFF')<>2
              OR NOT EXISTS(SELECT 1 FROM control.deployment_address_reservation WHERE sender_address='0x'||repeat('7',40) AND sender_nonce='9')
              OR NOT EXISTS(SELECT 1 FROM control.deployment_address_reservation WHERE sender_address='0x'||repeat('8',40) AND sender_nonce IS NULL)
              OR (SELECT count(*) FROM control.deployment_address_claim WHERE participant_id='018f0000-0000-7000-8000-000000007002' AND active)<>2
             THEN RAISE EXCEPTION 'legacy custody not preserved'; END IF;
            END $$;
            """)
        port = run("docker", "port", name, "5432/tcp").strip().rsplit(":", 1)[1]
        env = dict(os.environ)
        def url(user, database):
            return f"postgresql://{user}:{password}@127.0.0.1:{port}/{database}"
        if reservations:
            env.update(OPENPC_DEPLOYMENT_RESERVATION_DATABASE_URL=url("openpc_local_control_worker", "openpc_control"),
                       OPENPC_DEPLOYMENT_API_DATABASE_URL=url("openpc_configuration_runtime", "openpc_control"),
                       OPENPC_REQUIRE_DEPLOYMENT_RESERVATIONS="1")
            run("pnpm", "--filter", "@openpc/control-api", "exec", "vitest", "run", "--maxWorkers=2",
                "--config", "vitest.config.ts", "src/configuration/deployment/reservations.test.ts", env=env, visible=True)
            run("cargo", "test", "-p", "openpc-fleet-controller", "--lib", "--locked", "--offline",
                "deployment_worker::store::tests::postgres_worker_handoff_requires_current_public_module_authority",
                "--", "--ignored", "--exact", env=env, visible=True)
            passed = True
            return
        sql("openpc_control", f"CREATE ROLE joined_identity LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION INHERIT NOBYPASSRLS; GRANT openpc_control_runtime,openpc_control_platform_runtime TO joined_identity; CREATE DATABASE openpc_facts;")
        for migration in sorted((REPOSITORY / "migrations/postgres/facts").glob("[0-9][0-9][0-9][0-9]_*.sql")):
            sql("openpc_facts", migration.read_text(), transaction=True)
        # Bootstrap only the mutation verifier key and least-privilege roles.
        # Fact admission, finalization, shard readiness and reorg use FactStore.
        sql("openpc_facts", f"""
            CREATE ROLE joined_fact_provisioner NOLOGIN;
            GRANT USAGE ON SCHEMA facts TO joined_fact_provisioner;
            GRANT INSERT ON facts.mutation_capability_secret TO joined_fact_provisioner;
            CREATE POLICY joined_key_bootstrap ON facts.mutation_capability_secret FOR INSERT TO joined_fact_provisioner WITH CHECK (secret_version=1 AND octet_length(verifier_secret)=32);
            SET ROLE joined_fact_provisioner;
            INSERT INTO facts.mutation_capability_secret VALUES (1,decode('{capability}','hex'));
            RESET ROLE;
            CREATE ROLE joined_fact_writer LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
            GRANT openpc_fact_bridge_writer TO joined_fact_writer;
            CREATE ROLE joined_fact_reader LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
            GRANT openpc_policy_fact_reader TO joined_fact_reader;
        """)
        env.update(OPENPC_ASTRA05_ADMIN_DATABASE_URL=url("postgres", "openpc_control"),
                   OPENPC_ASTRA05_RUNTIME_DATABASE_URL=url("joined_identity", "openpc_control"),
                   OPENPC_ASTRA05_FACT_DATABASE_URL=url("joined_fact_writer", "openpc_facts"),
                   OPENPC_POLICY_FACT_READER_DATABASE_URL=url("joined_fact_reader", "openpc_facts"),
                   OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX=capability,
                   OPENPC_ASTRA05_PUBLICATION_FIXTURE=str(root / "publication.json"),
                   OPENPC_ASTRA05_DECISION_OWNER_ROOT=str(root))
        certificates(root)
        server = provider(root, submission)
        if submission:
            env["OPENPC_JOINED_SUBMISSION"] = "1"
            env["OPENPC_ASTRA07_WALLET_PUBLICATION_FIXTURE"] = str(root / "wallet-publication.json")
        env["OPENPC_ASTRA05_PROVIDER_PORT"] = str(server.server_port)
        # Build before issuing short-lived identity assertions.
        test = ("postgres_tls_joined_capacity_owner" if spool_capacity else
                "postgres_tls_cigl_generation_revocation" if revocation_only else
                "postgres_tls_initial_cigl_analysis" if analysis_only else
                "postgres_tls_submission_owner" if submission else "postgres_tls_joined_local_decision_owner")
        full_test = ("identity_publication_tests::decision_owner::capacity::" if spool_capacity else
                    "identity_publication_tests::decision_owner::submission::" if submission
                     else "identity_publication_tests::decision_owner::") + test
        publication_test = "postgres-wallet-binding.test.ts" if submission else "postgres-runtime-snapshot.test.ts"
        if submission:
            env.update(OPENPC_I02_ADMIN_DATABASE_URL=env["OPENPC_ASTRA05_ADMIN_DATABASE_URL"],
                       OPENPC_I02_RUNTIME_DATABASE_URL=url("openpc_identity_runtime", "openpc_control"),
                       OPENPC_I02_PLATFORM_RUNTIME_DATABASE_URL=env["OPENPC_ASTRA05_RUNTIME_DATABASE_URL"])
        run("cargo", "test", "-p", "openpc-runtime-agent", test,
            "--locked", "--offline", "--no-run", env=env, visible=True)
        if analysis_only:
            env["OPENPC_CIGL_COMPILATION_DATABASE_URL"] = url("openpc_local_control_worker", "openpc_control")
            run("cargo", "test", "-p", "openpc-fleet-controller", "--lib", "postgres_review_compiles_exact_sources_and_complete_shared_grants",
                "--locked", "--offline", "--no-run", env=env, visible=True)
            run("cargo", "test", "-p", "openpc-fleet-controller", "--bin", "local_runtime_worker",
                "postgres_runtime_result_fences_precede_target_mutations", "--locked", "--offline", "--no-run", env=env, visible=True)
            run("cargo", "build", "-p", "openpc-policy-compiler", "--bin", "openpc-policy-evaluator",
                "--locked", "--offline", env=env, visible=True)
        run("pnpm", "exec", "vitest", "run", "--config", "tests/integration/identity/vitest.config.ts",
            "tests/integration/identity/" + publication_test, env=env, visible=True)
        if analysis_only:
            run("cargo", "test", "-p", "openpc-fleet-controller", "--bin", "local_runtime_worker",
                "postgres_runtime_result_fences_precede_target_mutations", "--locked", "--offline",
                "--", "--ignored", env=env, visible=True)
        publication = Path(env["OPENPC_ASTRA07_WALLET_PUBLICATION_FIXTURE"] if submission
                           else env["OPENPC_ASTRA05_PUBLICATION_FIXTURE"])
        if not publication.is_file() or not publication.stat().st_size:
            raise RuntimeError("publication prerequisite missing; target acceptance BLOCKED")
        if analysis_only:
            # One fixture coordinates the real public API with the live runtime
            # through bounded scratch exchange. Neither may manufacture the
            # other's analysis/approval result. Build peaks completed above.
            env["OPENPC_CIGL_PUBLIC_ANALYSIS"] = "1"
            analysis_api = subprocess.Popen(["pnpm", "exec", "vitest", "run", "--config",
                "tests/integration/identity/vitest.config.ts", "tests/integration/identity/postgres-cigl-analysis.test.ts"],
                cwd=REPOSITORY, env=env, start_new_session=True)
        run("timeout", "--signal=TERM", "--kill-after=5s", "120s",
            "cargo", "test", "-p", "openpc-runtime-agent", test,
            "--locked", "--offline", "--", "--ignored", "--exact", full_test, env=env, visible=True)
        if analysis_only:
            run("cargo", "test", "-p", "openpc-fleet-controller", "--lib",
                "cigl_publication::reviewed_profile::tests::postgres_review_compiles_exact_sources_and_complete_shared_grants",
                "--locked", "--offline", "--", "--ignored", "--exact", env=env, visible=True)
        if analysis_api and analysis_api.wait(timeout=60) != 0:
            raise RuntimeError("public analysis acceptance failed")
        if analysis_only:
            run("cargo", "test", "-p", "openpc-fleet-controller", "--bin", "local_runtime_worker",
                "postgres_lost_activation_observation_uses_original_custody", "--locked", "--offline",
                "--", "--ignored", env=env, visible=True)
        passed = True
    finally:
        # A failed public prerequisite has already written its failure marker.
        # Let Vitest flush that primary failure before stopping its blocked
        # dependent; otherwise the aggregate retains only Fleet's BLOCKED text.
        if analysis_api and analysis_api.poll() is None and (root / "analysis-api-failed").exists():
            try:
                analysis_api.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if analysis_api and analysis_api.poll() is None:
            os.killpg(analysis_api.pid, signal.SIGTERM)
            try:
                analysis_api.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(analysis_api.pid, signal.SIGKILL)
                analysis_api.wait(timeout=5)
        if server:
            server.shutdown()
            server.server_close()
        if created:
            if not passed:
                result = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
                (root / "postgres.log").write_text(result.stdout + result.stderr)
            run("docker", "rm", "-fv", name)
        if passed:
            shutil.rmtree(root)
        else:
            print(f"Retained joined-owner failure material: {root}", flush=True)


if __name__ == "__main__":
    main()
