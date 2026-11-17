//! A database-owner regression. The initialized module/provider rows establish
//! the segment's starting state, not public admission or a certified route.
use super::*;
use sqlx::postgres::PgPoolOptions;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const PARTICIPANT: &str = "018f0000-0000-7000-8000-000000000801";
const PRIVACY: &str = "018f0000-0000-7000-8000-000000000802";
const FOREIGN_PRIVACY: &str = "018f0000-0000-7000-8000-000000000899";

struct Database {
    container: String,
    directory: PathBuf,
    admin: PgPool,
    worker: PgPool,
}
impl Drop for Database {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Ok(logs) = Command::new("docker")
                .args(["logs", &self.container])
                .output()
            {
                let mut bytes = logs.stdout;
                bytes.extend(logs.stderr);
                let _ = fs::write(self.directory.join("postgres.log"), bytes);
            }
        } else {
            fs::remove_dir_all(&self.directory).expect("owned probe test cleanup");
        }
        let removed = Command::new("docker")
            .args(["rm", "-f", &self.container])
            .output()
            .expect("owned PostgreSQL cleanup");
        assert!(removed.status.success(), "owned PostgreSQL cleanup failed");
    }
}
impl Database {
    async fn start() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let container = format!("openpc-provider-lease-{}-{nonce}", std::process::id());
        let password = format!("local-probe-{nonce}");
        let directory = env::var_os("OPENPC_TEST_TMP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(&container);
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let secrets = directory.join("secrets");
        fs::create_dir(&secrets).unwrap();
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
        for name in [
            "control_pg_password",
            "identity_runtime_db_password",
            "participant_runtime_db_password",
            "policy_runtime_db_password",
            "control_api_runtime_db_password",
            "control_worker_runtime_db_password",
        ] {
            let path = secrets.join(name);
            fs::write(&path, &password).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let started = Command::new("docker").args([
            "run", "--detach", "--name", &container,
            "--label", "io.openpc.test=provider-probe-lease",
            "--memory", "768m", "--memory-swap", "768m", "--cpus", "1", "--pids-limit", "256",
            "--publish", "127.0.0.1::5432",
            "--volume", &format!("{}:/migrations/postgres:ro", root.join("migrations/postgres").display()),
            "--volume", &format!("{}:/local/migrate.sh:ro", root.join("deploy/compose/local/migrate.sh").display()),
            "--volume", &format!("{}:/run/secrets:ro", secrets.display()),
            "--env", &format!("POSTGRES_PASSWORD={password}"), "--env", "POSTGRES_DB=openpc_control",
            "docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7",
        ]).output().unwrap();
        assert!(started.status.success(), "owned PostgreSQL start failed");
        let port = Command::new("docker")
            .args(["port", &container, "5432/tcp"])
            .output()
            .unwrap();
        assert!(port.status.success());
        let port = String::from_utf8(port.stdout).unwrap();
        let port: u16 = port
            .trim()
            .strip_prefix("127.0.0.1:")
            .unwrap()
            .parse()
            .unwrap();
        let url = format!("postgresql://postgres:{password}@127.0.0.1:{port}/openpc_control");
        let admin = PgPoolOptions::new()
            .max_connections(3)
            .connect_lazy(&url)
            .unwrap();
        // Actual installed LOGIN identity; SET ROLE on the administrator cannot
        // satisfy independent source-installation authentication.
        let worker = PgPoolOptions::new().max_connections(3)
            .connect_lazy(&format!("postgresql://openpc_local_control_worker:{password}@127.0.0.1:{port}/openpc_control"))
            .unwrap();
        let db = Self {
            container,
            directory,
            admin,
            worker,
        };
        let ready_until = Instant::now() + Duration::from_secs(30);
        loop {
            if sqlx::query("select 1").execute(&db.admin).await.is_ok() {
                break;
            }
            assert!(
                Instant::now() < ready_until,
                "owned PostgreSQL readiness failed"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // Exercise the supported fresh installer, including generated-lane
        // ordering and legacy host enrollment. This is not a predecessor upgrade.
        let migrated = Command::new("docker")
            .args([
                "exec",
                "-e",
                "PGHOST=127.0.0.1",
                "-e",
                "PGUSER=postgres",
                "-e",
                "PGDATABASE=openpc_control",
                &db.container,
                "sh",
                "/local/migrate.sh",
                "control",
            ])
            .output()
            .unwrap();
        let mut migration_log = migrated.stdout;
        migration_log.extend(migrated.stderr);
        fs::write(db.directory.join("migration.log"), migration_log).unwrap();
        assert!(
            migrated.status.success(),
            "supported provider fixture migration failed"
        );
        let installed: bool = sqlx::query_scalar("select session_user='openpc_local_control_worker' and current_user=session_user and r.rolcanlogin and not r.rolsuper and not r.rolbypassrls and not r.rolcreaterole and not r.rolcreatedb and not r.rolreplication and pg_has_role(session_user,'openpc_control_worker','USAGE') and exists(select 1 from pg_auth_members m join pg_roles p on p.oid=m.roleid where m.member=r.oid and p.rolname='openpc_runtime_source_legacy' and not m.admin_option and not m.inherit_option and not m.set_option and shobj_description(p.oid,'pg_authid')='openpc:runtime-artifact-source:legacy-unproven:v1') from pg_roles r where r.rolname=session_user")
            .fetch_one(&db.worker).await.unwrap();
        assert!(
            installed,
            "the actual fresh installed login must own this segment"
        );
        let mut setup = db.admin.begin().await.unwrap();
        context(&mut setup, PARTICIPANT, PRIVACY).await.unwrap();
        candidate_fences(&mut setup, false).await.unwrap();
        sqlx::raw_sql(r#"
            insert into control.module_registration(module_id,display_name,owner)
                values('pc.config.assets','Probe segment configuration','LS-MODULE-REGISTRY');
            insert into control.module_version(module_version_id,module_id,semantic_version,
                manifest_cbor,manifest_digest,cose_sign1,sbom_digest,provenance_digest,build_receipt_digest)
                values('018f0000-0000-7000-8000-000000000803','pc.config.assets','1.0.0',
                '\xa0',decode(repeat('11',32),'hex'),'\xa0',decode(repeat('12',32),'hex'),
                decode(repeat('13',32),'hex'),decode(repeat('14',32),'hex'));
            insert into control.module_installation(module_installation_id,participant_id,privacy_domain_id,
                module_version_id,state,authority_epoch,delegation_epoch,desired_manifest_digest,idempotency_key,lifecycle_operation_id)
                values('018f0000-0000-7000-8000-000000000804','018f0000-0000-7000-8000-000000000801',
                '018f0000-0000-7000-8000-000000000802','018f0000-0000-7000-8000-000000000803',
                'ENABLED',1,1,decode(repeat('11',32),'hex'),'probe-segment-bootstrap','018f0000-0000-7000-8000-000000000806');
            insert into control.module_configuration_generation(participant_id,privacy_domain_id,
                module_installation_id,generation,configuration_cbor,configuration_digest,active)
                values('018f0000-0000-7000-8000-000000000801','018f0000-0000-7000-8000-000000000802',
                '018f0000-0000-7000-8000-000000000804',1,'\xa0',decode(repeat('15',32),'hex'),true);
            insert into control.provider_profile(provider_profile_id,participant_id,privacy_domain_id,chain_id,
                endpoint_secret_ref,behavior_fingerprint,policy_generation_digest)
                values('018f0000-0000-7000-8000-000000000807','018f0000-0000-7000-8000-000000000801','018f0000-0000-7000-8000-000000000802','31337',
                'urn:openpc:secret:018f0000-0000-7000-8000-000000000805',
                'sha256:'||repeat('16',32),'sha256:'||repeat('17',32));
        "#).execute(&mut *setup).await.unwrap();
        let fixture = crate::local_fixture::build_local_configuration_fixture(
            Some("018f0000-0000-7000-8000-000000000807"),
            None,
            None,
            Some("workload"),
        )
        .unwrap();
        let bytes = fixture
            .configuration_cbor_hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        let mut configuration = pc_policy_core::invocation::decode_active_invocation_configuration(
            &bytes,
            &Digest::of(&bytes),
        )
        .unwrap();
        for asset in &mut configuration.assets {
            asset.tenant_id = PARTICIPANT.into();
            asset.privacy_domain_id = PRIVACY.into();
        }
        let bytes =
            pc_policy_core::invocation::encode_active_invocation_configuration(&configuration)
                .unwrap();
        sqlx::query("update control.provider_profile set behavior_fingerprint=$1")
            .bind(fixture.provider_artifact_digest)
            .execute(&mut *setup)
            .await
            .unwrap();
        setup.commit().await.unwrap();
        let path = db.directory.join("runtime-configuration.cbor");
        fs::write(&path, bytes).unwrap();
        crate::runtime_configuration_input::RuntimeConfigurationInputSource::new(path)
            .unwrap()
            .refresh(&db.worker, PARTICIPANT, PRIVACY)
            .await
            .unwrap();
        db
    }
}

async fn source_custody_fence(pool: &PgPool) -> Transaction<'static, Postgres> {
    let mut tx = pool.begin().await.unwrap();
    context(&mut tx, PARTICIPANT, PRIVACY).await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',true)")
        .bind(PARTICIPANT).bind(PRIVACY).execute(&mut *tx).await.unwrap();
    sqlx::query("select openpc.lock_runtime_artifact_source_custody()")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx
}

async fn observation_state(pool: &PgPool) -> (String, String, String, bool) {
    sqlx::query_as("select state,lease_token::text,lease_until::text,observation is null from control.provider_probe_observation")
        .fetch_one(pool).await.unwrap()
}

#[tokio::test]
#[ignore = "requires the owned PostgreSQL 18.6 container; explicitly executed by CI"]
async fn postgres_runtime_inputs_are_scoped_immutable_and_bound_to_public_digests() {
    let db = Database::start().await;
    let source = crate::runtime_configuration_input::RuntimeConfigurationInputSource::new(
        db.directory.join("runtime-configuration.cbor"),
    )
    .unwrap();
    // A repeat of the exact source reuses its immutable row.
    source
        .refresh(&db.worker, PARTICIPANT, PRIVACY)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("select count(*) from control.runtime_configuration_input")
        .fetch_one(&db.admin)
        .await
        .unwrap();
    assert_eq!(count, 1);
    for (participant, privacy, expected) in [
        (PARTICIPANT, PRIVACY, 1_i64),
        (PARTICIPANT, FOREIGN_PRIVACY, 0),
        (FOREIGN_PRIVACY, PRIVACY, 0),
    ] {
        let mut tx = db.worker.begin().await.unwrap();
        context(&mut tx, participant, privacy).await.unwrap();
        let count: i64 =
            sqlx::query_scalar("select count(*) from control.runtime_configuration_input_current")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(count, expected);
        tx.rollback().await.unwrap();
    }
    for statement in [
        "update control.runtime_configuration_input set configuration_cbor='\\xa0'::bytea",
        "delete from control.runtime_configuration_input",
        "insert into control.runtime_configuration_input (participant_id,privacy_domain_id,module_installation_id,module_configuration_generation_id,configuration_cbor,configuration_digest,resource_bindings,selected) select participant_id,privacy_domain_id,module_installation_id,uuidv7(),configuration_cbor,configuration_digest,resource_bindings,true from control.runtime_configuration_input",
    ] {
        let mut tx = db.worker.begin().await.unwrap();
        context(&mut tx, PARTICIPANT, PRIVACY).await.unwrap();
        assert!(
            sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
                .execute(&mut *tx)
                .await
                .is_err()
        );
        tx.rollback().await.unwrap();
    }
    // A changed public reference invalidates old input data immediately. Merely
    // redelivering those same bytes cannot revive it or produce an observation.
    let mut changed = db.admin.begin().await.unwrap();
    context(&mut changed, PARTICIPANT, PRIVACY).await.unwrap();
    candidate_fences(&mut changed, false).await.unwrap();
    sqlx::query(
        "update control.provider_profile set behavior_fingerprint='sha256:'||repeat('99',32)",
    )
    .execute(&mut *changed)
    .await
    .unwrap();
    changed.commit().await.unwrap();
    source
        .refresh(&db.worker, PARTICIPANT, PRIVACY)
        .await
        .unwrap();
    let mut tx = db.worker.begin().await.unwrap();
    context(&mut tx, PARTICIPANT, PRIVACY).await.unwrap();
    let count: i64 =
        sqlx::query_scalar("select count(*) from control.runtime_configuration_input_current")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(count, 0);
    tx.rollback().await.unwrap();
    let count: i64 = sqlx::query_scalar("select count(*) from control.provider_probe_observation")
        .fetch_one(&db.admin)
        .await
        .unwrap();
    assert_eq!(count, 0);
    db.worker.close().await;
    db.admin.close().await;
}

#[tokio::test]
#[ignore = "requires the owned PostgreSQL 18.6 container; explicitly executed by CI"]
async fn postgres_claim_renewal_cancellation_and_lost_owner_publication() {
    let db = Database::start().await;
    let worker = ProviderProbeWorker {
        source_directory: db.directory.clone(),
        connections: ConnectionRegistry::open(
            &db.directory.join("connections"),
            "probe-lease-test",
            4,
        )
        .unwrap(),
    };
    let source = source_custody_fence(&db.worker).await;
    assert!(
        timeout(
            Duration::from_secs(1),
            worker.claim(&db.worker, PARTICIPANT, PRIVACY)
        )
        .await
        .unwrap()
        .unwrap()
        .is_none(),
        "unclaimed lifecycle contention must defer without a lease"
    );
    let count: i64 = sqlx::query_scalar("select count(*) from control.provider_probe_observation")
        .fetch_one(&db.admin)
        .await
        .unwrap();
    assert_eq!(count, 0);
    source.rollback().await.unwrap();
    assert!(
        worker
            .claim(&db.worker, PARTICIPANT, FOREIGN_PRIVACY)
            .await
            .unwrap()
            .is_none()
    );
    let first = worker
        .claim(&db.worker, PARTICIPANT, PRIVACY)
        .await
        .unwrap()
        .unwrap();
    // A source-first renewal waits at the lifecycle boundary with the original
    // authority still live, then rereads the actual candidate after release.
    {
        let source = source_custody_fence(&db.worker).await;
        let renewal = worker.renew(&db.worker, PARTICIPANT, PRIVACY, &first);
        tokio::pin!(renewal);
        assert!(
            timeout(Duration::from_millis(150), &mut renewal)
                .await
                .is_err()
        );
        source.rollback().await.unwrap();
        timeout(Duration::from_secs(1), &mut renewal)
            .await
            .unwrap()
            .unwrap();
    }

    // Provider-first admission retains each canonical fence through its real
    // current-input read. The source SQL owner must fail closed until commit.
    let mut provider = db.worker.begin().await.unwrap();
    context(&mut provider, PARTICIPANT, PRIVACY).await.unwrap();
    assert!(candidate_fences(&mut provider, false).await.unwrap());
    assert!(
        worker
            .current_candidate(&mut provider, &first)
            .await
            .unwrap()
    );
    for key in [
        format!("evidence-lifecycle:{PARTICIPANT}"),
        "module-release-catalog".into(),
        format!("module-admission:{PARTICIPANT}:{PRIVACY}"),
        format!("openpc-policy-generations:{PARTICIPANT}:{PRIVACY}"),
    ] {
        let mut contender = db.admin.begin().await.unwrap();
        let available: bool =
            sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended($1,0))")
                .bind(key)
                .fetch_one(&mut *contender)
                .await
                .unwrap();
        assert!(!available);
        contender.rollback().await.unwrap();
    }
    let mut blocked_source = db.worker.begin().await.unwrap();
    context(&mut blocked_source, PARTICIPANT, PRIVACY)
        .await
        .unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',true)")
        .bind(PARTICIPANT).bind(PRIVACY).execute(&mut *blocked_source).await.unwrap();
    let error = sqlx::query("select openpc.lock_runtime_artifact_source_custody()")
        .execute(&mut *blocked_source)
        .await
        .unwrap_err();
    assert_eq!(error.as_database_error().unwrap().message(), "PC-DATA-6007");
    blocked_source.rollback().await.unwrap();
    provider.commit().await.unwrap();
    source_custody_fence(&db.worker)
        .await
        .rollback()
        .await
        .unwrap();

    // Bounded admission failure cannot renew the lease or publish any result.
    let before = observation_state(&db.admin).await;
    let source = source_custody_fence(&db.worker).await;
    let started = Instant::now();
    assert!(
        worker
            .renew(&db.worker, PARTICIPANT, PRIVACY, &first)
            .await
            .is_err()
    );
    assert!(started.elapsed() < RENEW_TIMEOUT);
    assert!(
        worker
            .publish(
                &db.worker,
                PARTICIPANT,
                PRIVACY,
                &first,
                Err("external result unavailable".into())
            )
            .await
            .is_err()
    );
    assert_eq!(observation_state(&db.admin).await, before);
    source.rollback().await.unwrap();
    worker
        .renew(&db.worker, PARTICIPANT, PRIVACY, &first)
        .await
        .unwrap();
    println!(
        "OPENPC_PROVIDER_ADMISSION|PASS|source-first|provider-first|bounded-timeout|original-lease"
    );
    let remaining: f64 = sqlx::query_scalar("select extract(epoch from lease_until-clock_timestamp())::double precision from control.provider_probe_observation")
        .fetch_one(&db.admin).await.unwrap();
    assert!(remaining > 0.0 && remaining <= f64::from(CLAIM_SECONDS));
    worker
        .renew(&db.worker, PARTICIPANT, PRIVACY, &first)
        .await
        .unwrap();
    assert!(
        worker
            .claim(&db.worker, PARTICIPANT, PRIVACY)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        worker
            .renew(&db.worker, PARTICIPANT, FOREIGN_PRIVACY, &first)
            .await
            .is_err()
    );

    // Time is advanced at the durable lease row solely for the crash-race
    // regression. The production claim still uses the real database clock/CAS.
    let mut expired = db.admin.begin().await.unwrap();
    context(&mut expired, PARTICIPANT, PRIVACY).await.unwrap();
    candidate_fences(&mut expired, false).await.unwrap();
    sqlx::query("update control.provider_probe_observation set lease_until=clock_timestamp()-interval '1 second'")
        .execute(&mut *expired).await.unwrap();
    expired.commit().await.unwrap();
    let successor = worker
        .claim(&db.worker, PARTICIPANT, PRIVACY)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.observation_id, successor.observation_id);
    assert_ne!(first.lease_token, successor.lease_token);
    assert!(
        worker
            .renew(&db.worker, PARTICIPANT, PRIVACY, &first)
            .await
            .is_err()
    );
    worker
        .publish(
            &db.worker,
            PARTICIPANT,
            PRIVACY,
            &first,
            Err("stale worker".into()),
        )
        .await
        .unwrap();
    let state: String = sqlx::query_scalar("select state from control.provider_probe_observation")
        .fetch_one(&db.admin)
        .await
        .unwrap();
    assert_eq!(state, "RUNNING");

    // Only the external provider future is inert. The cancellation decision,
    // lease renewal and configuration read use the real restricted DB owner.
    let cancel = worker.while_current(
        &db.worker,
        PARTICIPANT,
        PRIVACY,
        &successor,
        std::future::pending::<Result<(), String>>(),
    );
    let change = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut tx = db.worker.begin().await.unwrap();
        context(&mut tx, PARTICIPANT, PRIVACY).await.unwrap();
        candidate_fences(&mut tx, false).await.unwrap();
        sqlx::query("update control.runtime_configuration_input set selected=false")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(12), async {
        tokio::join!(cancel, change)
    })
    .await
    .unwrap();
    assert!(result.is_err());
    let polled = AtomicBool::new(false);
    assert!(
        worker
            .while_current(&db.worker, PARTICIPANT, PRIVACY, &successor, async {
                polled.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
            .is_err()
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "changed candidate must prevent the first provider exchange"
    );
    worker
        .publish(
            &db.worker,
            PARTICIPANT,
            PRIVACY,
            &successor,
            result.map(|()| unreachable!()),
        )
        .await
        .unwrap();
    let row = sqlx::query("select o.state,p.state provider_state,o.observation from control.provider_probe_observation o join control.provider_profile p using(provider_profile_id)")
        .fetch_one(&db.admin).await.unwrap();
    assert_eq!(row.get::<String, _>("state"), "FAILED");
    assert_eq!(row.get::<String, _>("provider_state"), "REGISTERED");
    assert!(
        row.get::<Option<serde_json::Value>, _>("observation")
            .is_none()
    );
    drop(worker);
    db.worker.close().await;
    db.admin.close().await;
}
