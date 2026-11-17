use super::*;
use sqlx::PgPool;
use std::fs;

#[path = "postgres_tests/materialization.rs"]
mod materialization;
#[path = "postgres_tests/recovery.rs"]
mod recovery;

#[tokio::test]
#[ignore = "requires the existing isolated identity PostgreSQL runner"]
async fn postgres_source_custody_installation_requires_actual_keys_and_retained_journal() {
    let admin = PgPool::connect(&std::env::var("OPENPC_I02_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let worker =
        PgPool::connect(&std::env::var("OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL").unwrap())
            .await
            .unwrap();
    let password = uuid::Uuid::now_v7().simple().to_string();
    let database_backup = recovery::ControlBackup::capture();
    let directory = tests::Directory::new();
    let source_file = directory.0.join("input.cbor");
    let journal = directory.0.join("journal");
    let root = directory.0.join("retained-root");
    let root_binding =
        SourceRootBinding::for_directories(uuid::Uuid::now_v7().to_string(), &journal, &root)
            .unwrap();
    let signing_file = directory.0.join("signing.key");
    let commit_file = directory.0.join("commit.key");
    let configuration_file = directory.0.join("source.json");
    let password_file = directory.0.join("database-password");
    let installation = SourceCustodyInstallation {
        participant_id: uuid::Uuid::now_v7().to_string(),
        privacy_domain_id: uuid::Uuid::now_v7().to_string(),
        source_owner_id: uuid::Uuid::now_v7().to_string(),
        source_file_binding: SourceCustodyInstallation::file_binding(&source_file).unwrap(),
    };
    let role = super::installation::rooted_login(
        &installation.participant_id,
        &installation.privacy_domain_id,
    )
    .unwrap();
    fs::write(&signing_file, [7; 32]).unwrap();
    fs::write(&commit_file, [8; 32]).unwrap();
    fs::write(&password_file, &password).unwrap();
    let configuration_input = directory.0.join("configuration-input.json");
    fs::write(
        &configuration_input,
        serde_json::to_vec(&serde_json::json!({
            "participant_id": installation.participant_id,"privacy_domain_id":installation.privacy_domain_id,
            "source_owner_id": installation.source_owner_id,"generation_id":root_binding.generation_id,
            "source_file": source_file, "journal_directory": journal,
            "signing_key_file": signing_file, "commit_key_file": commit_file,
            "retained_root_directory": root,
            "database_password_file": password_file,
            "fresh_scope": {"participant_display_name":"Native source initial trust","privacy_domain_name":"Source","residency_profile":"LOCAL_DEVELOPMENT"},
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &configuration_file,
        serde_json::to_vec(
            &RuntimeArtifactSourceWorker::render_configuration(&configuration_input).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let initialize = || {
        RuntimeArtifactSourceWorker::initialize(
            &worker,
            &configuration_file,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file),
        )
    };
    let open = || {
        RuntimeArtifactSourceWorker::open(
            &configuration_file,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file),
        )
    };
    // Scope and installed public trust are the only bootstrap rows. No approval,
    // disposition, native result or target transition is fabricated.
    assert!(initialize().await.is_err());
    assert!(!journal.join(format!("{JOURNAL}.json")).exists());
    assert!(
        RuntimeArtifactSourceWorker::install(
            &worker,
            &configuration_file,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file)
        )
        .await
        .is_err()
    );
    assert!(!journal.join(format!("{JOURNAL}.json")).exists());
    RuntimeArtifactSourceWorker::install(
        &admin,
        &configuration_file,
        &installation.participant_id,
        &installation.privacy_domain_id,
        Some(&source_file),
    )
    .await
    .unwrap();
    // The installer creates a new dedicated least-privilege login. The shared
    // legacy worker is neither promoted nor given the rooted scope's trust.
    database_backup.reject_unknown_worker_bridges();
    let unknown_keys: i64 = sqlx::query_scalar("select (select count(*) from control.fleet_fact_admission_key where database_role='openpc_unknown_source_worker')+(select count(*) from control.runtime_target_disposition_key where database_role='openpc_unknown_source_worker')")
        .fetch_one(&admin).await.unwrap();
    assert_eq!(unknown_keys, 0);
    database_backup.install_worker_bridges(&role);
    let bridge_keys_distinct: bool = sqlx::query_scalar("select octet_length(f.verifier_secret)=32 and octet_length(t.verifier_secret)=32 and f.verifier_secret<>t.verifier_secret from control.fleet_fact_admission_key f join control.runtime_target_disposition_key t using(database_role) where f.database_role=$1")
        .bind(&role).fetch_one(&admin).await.unwrap();
    assert!(bridge_keys_distinct);
    let source_scope_preserved: bool = sqlx::query_scalar("select p.root_privacy_domain_id=d.privacy_domain_id and d.residency_profile='LOCAL_DEVELOPMENT' and d.placement_profile='PARTICIPANT_LOCAL' and s.source_owner_id=$3::text::uuid from control.participant p join control.privacy_domain d on d.participant_id=p.participant_id join control.runtime_artifact_source s on s.participant_id=p.participant_id and s.privacy_domain_id=d.privacy_domain_id where p.participant_id=$1::text::uuid and d.privacy_domain_id=$2::text::uuid")
        .bind(&installation.participant_id).bind(&installation.privacy_domain_id).bind(&installation.source_owner_id).fetch_one(&admin).await.unwrap();
    assert!(source_scope_preserved);
    let legacy_worker = worker;
    let options: sqlx::postgres::PgConnectOptions = std::env::var("OPENPC_I02_ADMIN_DATABASE_URL")
        .unwrap()
        .parse()
        .unwrap();
    let worker = PgPool::connect_with(options.username(&role).password(&password))
        .await
        .unwrap();
    let initialize = || {
        RuntimeArtifactSourceWorker::initialize(
            &worker,
            &configuration_file,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file),
        )
    };
    assert!(
        RuntimeArtifactSourceWorker::require_uninstalled(
            &legacy_worker,
            &installation.participant_id,
            &installation.privacy_domain_id,
        )
        .await
        .is_err()
    );
    let original = fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap();
    assert!(initialize().await.is_err());
    for pool in [&worker, &legacy_worker] {
        assert!(
            RuntimeArtifactSourceWorker::start_configured(
                pool,
                None,
                &installation.participant_id,
                &installation.privacy_domain_id,
                Some(&source_file),
            )
            .await
            .is_err()
        );
    }
    // Exact startup reasons come from the failing owner, not generic exit1.
    let start = |path, pool| {
        RuntimeArtifactSourceWorker::start_configured(
            pool,
            path,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file),
        )
    };
    assert_eq!(
        start(Some(directory.0.join("absent.json")), &worker)
            .await
            .err(),
        Some(SourceStartupError::ConfigurationMissing)
    );
    assert_eq!(
        start(Some(configuration_file.clone()), &legacy_worker)
            .await
            .err(),
        Some(SourceStartupError::ProtectedScopeLogin)
    );
    let substituted = directory.0.join("substituted.json");
    let mut changed: serde_json::Value =
        serde_json::from_slice(&fs::read(&configuration_file).unwrap()).unwrap();
    changed["retained_root"]["binding"]["generation_id"] =
        serde_json::json!(uuid::Uuid::now_v7().to_string());
    fs::write(&substituted, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert_eq!(
        start(Some(substituted), &worker).await.err(),
        Some(SourceStartupError::RootBindingMismatch)
    );
    let root_file = root.join("runtime-artifact-source-root.json");
    let retained_original = fs::read(&root_file).unwrap();
    fs::rename(&root_file, root.join("original-root")).unwrap();
    assert_eq!(
        start(Some(configuration_file.clone()), &worker).await.err(),
        Some(SourceStartupError::RootMissing)
    );
    fs::rename(root.join("original-root"), &root_file).unwrap();
    // ELOOP is real filesystem unavailability, not the missing-config attack.
    let io_path = directory.0.join("io-loop.json");
    std::os::unix::fs::symlink(&io_path, &io_path).unwrap();
    assert_eq!(
        start(Some(io_path), &worker).await.err(),
        Some(SourceStartupError::ConfigurationUnavailable)
    );
    let unreachable = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unavailable:unavailable@127.0.0.1:1/unavailable")
        .unwrap();
    unreachable.close().await;
    assert_eq!(
        start(Some(configuration_file.clone()), &unreachable)
            .await
            .err(),
        Some(SourceStartupError::ControlUnavailable)
    );
    assert_eq!(fs::read(&root_file).unwrap(), retained_original);
    assert_eq!(
        fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
        original
    );
    let mut installed = RuntimeArtifactSourceWorker::start_configured(
        &worker,
        Some(configuration_file.clone()),
        &installation.participant_id,
        &installation.privacy_domain_id,
        Some(&source_file),
    )
    .await
    .unwrap();
    assert_cluster_binding_guards(&admin, &worker, &legacy_worker, &mut installed).await;
    assert_eq!(
        fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
        original
    );
    // The installed SQL owner must preserve exact lifecycle contention through
    // native reconciliation, startup and guarded input refresh. No business
    // disposition is seeded and no failed attempt may burn a signing permit.
    let mut holder = admin.begin().await.unwrap();
    sqlx::query("select pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!(
            "evidence-lifecycle:{}",
            installation.participant_id
        ))
        .execute(&mut *holder)
        .await
        .unwrap();
    assert_eq!(installed.tick(&worker).await, Err(SourceCustodyError::Busy));
    assert_eq!(
        installed
            .source_allowed(
                &worker,
                &installation.participant_id,
                &installation.privacy_domain_id,
                &source_file,
                &Digest::of(b"unused"),
            )
            .await,
        Err(SourceCustodyError::Busy)
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(25),
            installed.wait_until_ready(&worker),
        )
        .await
        .is_err()
    );
    fs::write(&source_file, b"not a valid configuration").unwrap();
    crate::runtime_configuration_input::RuntimeConfigurationInputSource::new(source_file.clone())
        .unwrap()
        .refresh_guarded(
            &worker,
            &installation.participant_id,
            &installation.privacy_domain_id,
            &installed,
        )
        .await
        .unwrap(); // Deferred before parsing or inserting any source bytes.
    let inputs: i64 = sqlx::query_scalar("select count(*) from control.runtime_configuration_input where participant_id=$1::text::uuid")
        .bind(&installation.participant_id).fetch_one(&admin).await.unwrap();
    assert_eq!(inputs, 0);
    assert_eq!(
        fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
        original
    );
    holder.rollback().await.unwrap();
    installed.wait_until_ready(&worker).await.unwrap();
    // A generic serialization failure, lookalike message or transport failure
    // is never silently deferred. Exercise real PostgreSQL error decoding.
    for (statement, expected) in [
        (
            "do $$ begin raise exception using errcode='P0001',message='PC-DATA-6007'; end $$",
            SourceCustodyError::Busy,
        ),
        (
            "do $$ begin raise exception using errcode='40001',message='PC-DATA-6007'; end $$",
            SourceCustodyError::Busy,
        ),
        (
            "do $$ begin raise exception using errcode='40001',message='other'; end $$",
            RuntimeError::RuntimeUnavailable.into(),
        ),
        (
            "do $$ begin raise exception using errcode='P0001',message='PC-DATA-6007 extra'; end $$",
            RuntimeError::RuntimeUnavailable.into(),
        ),
        (
            "do $$ begin raise exception using errcode='40P01',message='PC-DATA-6007'; end $$",
            RuntimeError::RuntimeUnavailable.into(),
        ),
    ] {
        let error = sqlx::query(statement).execute(&admin).await.unwrap_err();
        assert_eq!(super::control::database_error(error), expected);
    }
    assert_eq!(
        super::control::database_error(sqlx::Error::PoolClosed),
        RuntimeError::RuntimeUnavailable.into()
    );
    assert!(open().is_err()); // Lifetime ownership, including an empty journal.
    assert!(
        RuntimeArtifactSourceWorker::require_uninstalled(
            &worker,
            &installation.participant_id,
            &installation.privacy_domain_id
        )
        .await
        .is_err()
    );
    assert!(
        installed
            .source_allowed(
                &worker,
                &installation.participant_id,
                &installation.privacy_domain_id,
                &directory.0.join("substituted.cbor"),
                &Digest::of(b"unused")
            )
            .await
            .is_err()
    );
    assert!(
        installed
            .source_allowed(
                &worker,
                &installation.participant_id,
                &installation.privacy_domain_id,
                &source_file,
                &Digest::of(b"unused")
            )
            .await
            .unwrap()
    );
    let observed = SourceConsumerUse {
        configuration_digest: Digest::of(b"original native artifact"),
        consumer_id: "native-postgres-consumer".into(),
        boundary: Some(SourceConsumerBoundary::RuntimeTargetEffect),
        target_id: Some(uuid::Uuid::now_v7().to_string()),
        original_id: uuid::Uuid::now_v7().to_string(),
    };
    let mut missing_boundary = observed.clone();
    missing_boundary.boundary = None;
    let mut tx = super::control::context(
        &worker,
        &installation.participant_id,
        &installation.privacy_domain_id,
    )
    .await
    .unwrap();
    assert!(
        installed
            .record_consumer_use(&mut tx, missing_boundary)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
        original
    );
    let mut tx = super::control::context(
        &worker,
        &installation.participant_id,
        &installation.privacy_domain_id,
    )
    .await
    .unwrap();
    installed
        .record_consumer_use(&mut tx, observed.clone())
        .await
        .unwrap();
    let used = fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap();
    assert_ne!(used, original);
    // A caller rollback cannot erase a pre-effect record or classify it unused.
    tx.rollback().await.unwrap();
    assert_eq!(
        fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
        used
    );
    let clone = installed.clone();
    let mut tx = super::control::context(
        &worker,
        &installation.participant_id,
        &installation.privacy_domain_id,
    )
    .await
    .unwrap();
    clone
        .record_consumer_use(&mut tx, observed.clone())
        .await
        .unwrap();
    // Exact replay uses the already signed original and one journal owner.
    assert_eq!(
        fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
        used
    );
    let mut competing = worker.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',true)")
        .bind(&installation.participant_id).bind(&installation.privacy_domain_id).execute(&mut *competing).await.unwrap();
    assert_eq!(
        clone
            .record_consumer_use(&mut competing, observed.clone())
            .await,
        Err(SourceCustodyError::Busy)
    );
    competing.rollback().await.unwrap();
    tx.rollback().await.unwrap();
    let mut missing = clone.clone();
    missing.custody = None;
    let mut tx = super::control::context(
        &worker,
        &installation.participant_id,
        &installation.privacy_domain_id,
    )
    .await
    .unwrap();
    assert!(
        missing
            .record_consumer_use(&mut tx, observed.clone())
            .await
            .is_err()
    );
    assert!(clone.require_legacy_consumer(&mut tx).await.is_err());
    tx.rollback().await.unwrap();
    let mut foreign = clone.clone();
    foreign.privacy = uuid::Uuid::now_v7().to_string();
    let mut tx = super::control::context(
        &worker,
        &installation.participant_id,
        &installation.privacy_domain_id,
    )
    .await
    .unwrap();
    assert!(
        foreign
            .record_consumer_restriction(&mut tx, observed.clone())
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
        used
    );
    drop(missing);
    drop(foreign);
    drop(clone);
    let pending = super::history::ImportIdentity {
        input_id: uuid::Uuid::now_v7().to_string(),
        module_installation_id: uuid::Uuid::now_v7().to_string(),
        module_configuration_generation_id: uuid::Uuid::now_v7().to_string(),
        configuration_digest: Digest::of(b"uncertain original source publication"),
    };
    let mut import_tx = worker.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true)")
        .bind(&installation.participant_id).bind(&installation.privacy_domain_id).execute(&mut *import_tx).await.unwrap();
    installed
        .bind_import(&mut import_tx, pending.clone(), true)
        .await
        .unwrap();
    // Exercise the actual SQL import verifier against native-produced custody.
    // This validates admission only; it does not seed a module/input or claim
    // the still-required public module/import/lost-COMMIT journey.
    let input = serde_json::json!({"participant_id":installation.participant_id,
        "privacy_domain_id":installation.privacy_domain_id,"runtime_configuration_input_id":pending.input_id,
        "module_installation_id":pending.module_installation_id,"module_configuration_generation_id":pending.module_configuration_generation_id,
        "configuration_digest":format!("\\x{}",pending.configuration_digest.as_str()),
        "configuration_cbor":format!("\\x{}", b"uncertain original source publication".iter().map(|byte|format!("{byte:02x}")).collect::<String>())});
    sqlx::query("select openpc.assert_runtime_artifact_source_import(jsonb_populate_record(null::control.runtime_configuration_input,$1::jsonb))")
        .bind(&input).execute(&mut *import_tx).await.unwrap();
    let wire: String =
        sqlx::query_scalar("select current_setting('openpc.runtime_source_import_wire')")
            .fetch_one(&mut *import_tx)
            .await
            .unwrap();
    let nonce: String =
        sqlx::query_scalar("select current_setting('openpc.runtime_source_import_nonce')")
            .fetch_one(&mut *import_tx)
            .await
            .unwrap();
    let mac: String =
        sqlx::query_scalar("select current_setting('openpc.runtime_source_import_mac')")
            .fetch_one(&mut *import_tx)
            .await
            .unwrap();
    let mut swapped = input.clone();
    swapped["runtime_configuration_input_id"] = serde_json::json!(uuid::Uuid::now_v7().to_string());
    assert!(sqlx::query("select openpc.assert_runtime_artifact_source_import(jsonb_populate_record(null::control.runtime_configuration_input,$1::jsonb))")
        .bind(swapped).execute(&mut *import_tx).await.is_err());
    import_tx.rollback().await.unwrap();
    let mut replay = worker.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true),set_config('openpc.runtime_source_import_wire',$3,true),set_config('openpc.runtime_source_import_nonce',$4,true),set_config('openpc.runtime_source_import_mac',$5,true)")
        .bind(&installation.participant_id).bind(&installation.privacy_domain_id).bind(wire).bind(nonce).bind(mac).execute(&mut *replay).await.unwrap();
    assert!(sqlx::query("select openpc.assert_runtime_artifact_source_import(jsonb_populate_record(null::control.runtime_configuration_input,$1::jsonb))")
        .bind(&input).execute(&mut *replay).await.is_err());
    replay.rollback().await.unwrap();
    let mut bypass = worker.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true)")
        .bind(&installation.participant_id).bind(&installation.privacy_domain_id).execute(&mut *bypass).await.unwrap();
    let rejected = sqlx::query("insert into control.runtime_configuration_input select (jsonb_populate_record(null::control.runtime_configuration_input,$1::jsonb)).*")
        .bind(&input).execute(&mut *bypass).await.unwrap_err();
    assert_eq!(
        rejected.as_database_error().unwrap().message(),
        "PC-AUTH-0005"
    );
    bypass.rollback().await.unwrap();
    let used = fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap();
    // Actual SQL absence does not mark the original committed, erase its
    // pending identity or authorize replay under a new input UUID.
    installed.tick(&worker).await.unwrap();
    assert_eq!(
        fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
        used
    );
    let mut replacement = pending;
    replacement.input_id = uuid::Uuid::now_v7().to_string();
    assert!(installed.record_import_pending(replacement).await.is_err());
    drop(installed);
    let backup = tests::Directory::new();
    let stale_backup = tests::Directory::new();
    fs::write(backup.0.join(format!("{JOURNAL}.json")), &used).unwrap();
    fs::write(stale_backup.0.join(format!("{JOURNAL}.json")), &original).unwrap();
    let root_original = fs::read(root.join("runtime-artifact-source-root.json")).unwrap();
    fs::rename(&root, directory.0.join("retained-root-original")).unwrap();
    fs::rename(&journal, directory.0.join("journal-original")).unwrap();
    assert!(initialize().await.is_err());
    assert!(
        RuntimeArtifactSourceWorker::install(
            &admin,
            &configuration_file,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file)
        )
        .await
        .is_err()
    );
    assert!(!root.exists());
    assert!(!journal.exists());
    fs::rename(directory.0.join("retained-root-original"), &root).unwrap();
    fs::rename(directory.0.join("journal-original"), &journal).unwrap();
    // The supported restore owner cannot import an old source prefix, include
    // the independent root in its destination, or restore a legacy journal.
    assert!(
        RuntimeArtifactSourceWorker::restore(
            &worker,
            &configuration_file,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file),
            &stale_backup.0
        )
        .await
        .is_err()
    );
    assert!(
        RuntimeArtifactSourceWorker::restore(
            &worker,
            &configuration_file,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file),
            &directory.0
        )
        .await
        .is_err()
    );
    fs::rename(
        journal.join(format!("{JOURNAL}.json")),
        journal.join("original-custody"),
    )
    .unwrap();
    assert!(open().is_err()); // Startup never recreates missing host custody.
    RuntimeArtifactSourceWorker::restore(
        &worker,
        &configuration_file,
        &installation.participant_id,
        &installation.privacy_domain_id,
        Some(&source_file),
        &backup.0,
    )
    .await
    .unwrap();
    assert_eq!(
        fs::read(root.join("runtime-artifact-source-root.json")).unwrap(),
        root_original
    );
    assert_eq!(fs::read(journal.join("original-custody")).unwrap(), used);
    let mut restarted = open().unwrap();
    restarted.tick(&worker).await.unwrap();
    assert_eq!(
        fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
        used
    );
    drop(restarted);
    let marker: String = sqlx::query_scalar("select r.rolname::text from pg_auth_members m join pg_roles r on r.oid=m.roleid where m.member=(select oid from pg_roles where rolname=$1) and left(r.rolname,16)='openpc_rs_scope_'")
        .bind(&role).fetch_one(&admin).await.unwrap();
    role_statement(&admin, "REVOKE %I FROM %I", &marker, &role)
        .await
        .unwrap();
    fs::rename(
        journal.join(format!("{JOURNAL}.json")),
        journal.join("marker-loss-original"),
    )
    .unwrap();
    assert!(
        RuntimeArtifactSourceWorker::restore(
            &worker,
            &configuration_file,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file),
            &backup.0,
        )
        .await
        .is_err()
    );
    assert!(!journal.join(format!("{JOURNAL}.json")).exists());
    fs::rename(
        journal.join("marker-loss-original"),
        journal.join(format!("{JOURNAL}.json")),
    )
    .unwrap();
    // Even missing membership cannot make an installed scope legacy while its
    // independent dedicated login survives. Startup and reinstallation deny.
    for pool in [&worker, &legacy_worker] {
        assert!(
            RuntimeArtifactSourceWorker::start_configured(
                pool,
                None,
                &installation.participant_id,
                &installation.privacy_domain_id,
                Some(&source_file),
            )
            .await
            .is_err()
        );
    }
    assert!(
        RuntimeArtifactSourceWorker::install(
            &admin,
            &configuration_file,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file),
        )
        .await
        .is_err()
    );
    assert_eq!(
        fs::read(root.join("runtime-artifact-source-root.json")).unwrap(),
        root_original
    );
    assert_eq!(
        fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
        used
    );
    role_statement(
        &admin,
        "GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET FALSE",
        &marker,
        &role,
    )
    .await
    .unwrap();
    // An interrupted initial native genesis may not publish even the new
    // Participant/privacy/source trust. Preserve the failed local bytes.
    let failed = tests::Directory::new();
    let failed_journal = failed.0.join("journal");
    fs::create_dir(&failed_journal).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&failed_journal, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        failed_journal.join(format!("{JOURNAL}.next")),
        b"interrupted genesis",
    )
    .unwrap();
    let failed_participant = uuid::Uuid::now_v7().to_string();
    let mut failed_configuration: serde_json::Value =
        serde_json::from_slice(&fs::read(&configuration_file).unwrap()).unwrap();
    failed_configuration["installation"]["participant_id"] = serde_json::json!(failed_participant);
    failed_configuration["installation"]["privacy_domain_id"] =
        serde_json::json!(uuid::Uuid::now_v7().to_string());
    failed_configuration["installation"]["source_owner_id"] =
        serde_json::json!(uuid::Uuid::now_v7().to_string());
    failed_configuration["database_role"] = serde_json::json!(
        super::installation::rooted_login(
            &failed_participant,
            failed_configuration["installation"]["privacy_domain_id"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    );
    failed_configuration["journal_directory"] = serde_json::json!(failed_journal);
    failed_configuration["retained_root"] = serde_json::json!({"directory":failed.0.join("root"),
        "binding":SourceRootBinding::for_directories(uuid::Uuid::now_v7().to_string(), &failed_journal, &failed.0.join("root")).unwrap()});
    let failed_config_file = failed.0.join("source.json");
    fs::write(
        &failed_config_file,
        serde_json::to_vec(&failed_configuration).unwrap(),
    )
    .unwrap();
    assert!(
        RuntimeArtifactSourceWorker::install(
            &admin,
            &failed_config_file,
            &failed_participant,
            failed_configuration["installation"]["privacy_domain_id"]
                .as_str()
                .unwrap(),
            Some(&source_file)
        )
        .await
        .is_err()
    );
    let count: i64 = sqlx::query_scalar(
        "select count(*) from control.participant where participant_id=$1::text::uuid",
    )
    .bind(failed_participant)
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(count, 0);
    let count: i64 = sqlx::query_scalar("select count(*) from pg_roles where rolname=$1")
        .bind(failed_configuration["database_role"].as_str().unwrap())
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(count, 0); // Failed native genesis cannot leave installed host trust.
    assert_eq!(
        fs::read(failed_journal.join(format!("{JOURNAL}.next"))).unwrap(),
        b"interrupted genesis"
    );
    assert!(!failed.0.join("root").exists());
    worker.close().await;
    legacy_worker.close().await;
    admin.close().await;
    // The actual per-database restore excludes cluster roles, host configuration
    // and the retained root. This is a native-custody component check, not a
    // public business-effect/physical-retirement or whole-cluster qualification.
    database_backup.restore();
    let admin = PgPool::connect(&std::env::var("OPENPC_I02_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let options: sqlx::postgres::PgConnectOptions = std::env::var("OPENPC_I02_ADMIN_DATABASE_URL")
        .unwrap()
        .parse()
        .unwrap();
    let worker = PgPool::connect_with(options.username(&role).password(&password))
        .await
        .unwrap();
    let legacy_worker =
        PgPool::connect(&std::env::var("OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL").unwrap())
            .await
            .unwrap();
    let count: i64 = sqlx::query_scalar(
        "select count(*) from control.runtime_artifact_source where source_owner_id=$1::text::uuid",
    )
    .bind(&installation.source_owner_id)
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(count, 0); // Older Control really lacks this installed source.
    let mut tx = worker.begin().await.unwrap();
    assert!(matches!(
        super::installation::authenticate(
            &mut tx,
            &installation.participant_id,
            &installation.privacy_domain_id
        )
        .await
        .unwrap(),
        super::installation::Mode::Rooted(_)
    ));
    tx.rollback().await.unwrap();
    for pool in [&worker, &legacy_worker] {
        for config in [None, Some(configuration_file.clone())] {
            assert!(
                RuntimeArtifactSourceWorker::start_configured(
                    pool,
                    config,
                    &installation.participant_id,
                    &installation.privacy_domain_id,
                    Some(&source_file)
                )
                .await
                .is_err()
            );
        }
    }
    assert!(
        RuntimeArtifactSourceWorker::install(
            &admin,
            &configuration_file,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file)
        )
        .await
        .is_err()
    );
    assert_eq!(
        fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
        used
    );
    // Replay an actual older native backup into the same installed directory.
    // Preserve the current original separately; never restore the retained root.
    fs::write(journal.join(format!("{JOURNAL}.json")), &original).unwrap();
    assert!(open().is_err());
    for pool in [&worker, &legacy_worker] {
        assert!(
            RuntimeArtifactSourceWorker::start_configured(
                pool,
                Some(configuration_file.clone()),
                &installation.participant_id,
                &installation.privacy_domain_id,
                Some(&source_file)
            )
            .await
            .is_err()
        );
    }
    assert!(
        RuntimeArtifactSourceWorker::restore(
            &worker,
            &configuration_file,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file),
            &stale_backup.0
        )
        .await
        .is_err()
    );
    assert_eq!(fs::read(journal.join("original-custody")).unwrap(), used);
    assert_eq!(
        fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
        original
    );
    assert_eq!(
        fs::read(root.join("runtime-artifact-source-root.json")).unwrap(),
        root_original
    );
    role_statement(&admin, "DROP ROLE %I", &marker, "")
        .await
        .unwrap();
    for pool in [&worker, &legacy_worker] {
        let mut tx = pool.begin().await.unwrap();
        assert!(
            super::installation::authenticate(
                &mut tx,
                &installation.participant_id,
                &installation.privacy_domain_id
            )
            .await
            .is_err()
        );
        tx.rollback().await.unwrap();
    }
    role_statement(
        &admin,
        "REVOKE openpc_runtime_source_legacy FROM %I",
        "openpc_local_control_worker",
        "",
    )
    .await
    .unwrap();
    database_backup.reapply_bootstrap();
    let mut tx = legacy_worker.begin().await.unwrap();
    assert!(
        super::installation::authenticate(
            &mut tx,
            &uuid::Uuid::now_v7().to_string(),
            &uuid::Uuid::now_v7().to_string()
        )
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
    println!(
        "OPENPC_RUNTIME_SOURCE_RECOVERY|control=OLDER_RESTORED|native=OLDER_RESTORED|globals=PRESERVED|retained_root=UNCHANGED|legacy_downgrade=DENIED|migration_reenrollment=DENIED|scope=COMPONENT_ONLY"
    );
    worker.close().await;
    legacy_worker.close().await;
    admin.close().await;
}

async fn role_statement(
    pool: &PgPool,
    template: &'static str,
    first: &str,
    second: &str,
) -> Result<(), sqlx::Error> {
    let statement: String = sqlx::query_scalar("select format($1,$2::text,$3::text)")
        .bind(template)
        .bind(first)
        .bind(second)
        .fetch_one(pool)
        .await?;
    // Every template is fixed in this test; PostgreSQL quotes every dynamic
    // identifier/literal with %I/%L before the resulting statement is executed.
    sqlx::query(sqlx::AssertSqlSafe(statement))
        .execute(pool)
        .await?;
    Ok(())
}

async fn assert_cluster_binding_guards(
    admin: &PgPool,
    worker: &PgPool,
    legacy: &PgPool,
    installed: &mut RuntimeArtifactSourceWorker,
) {
    let role: String = sqlx::query_scalar("select session_user::text")
        .fetch_one(worker)
        .await
        .unwrap();
    let marker: String = sqlx::query_scalar("select r.rolname::text from pg_auth_members m join pg_roles r on r.oid=m.roleid where m.member=(select oid from pg_roles where rolname=$1) and left(r.rolname,16)='openpc_rs_scope_'")
        .bind(&role).fetch_one(admin).await.unwrap();
    let profile: String = sqlx::query_scalar(
        "select shobj_description(oid,'pg_authid') from pg_roles where rolname=$1",
    )
    .bind(&marker)
    .fetch_one(admin)
    .await
    .unwrap();
    let mut legacy_tx = legacy.begin().await.unwrap();
    assert_eq!(
        super::installation::authenticate(
            &mut legacy_tx,
            &uuid::Uuid::now_v7().to_string(),
            &uuid::Uuid::now_v7().to_string()
        )
        .await
        .unwrap(),
        super::installation::Mode::LegacyUnproven,
    ); // Positive legacy identity remains explicitly UNPROVEN in another scope.
    legacy_tx.rollback().await.unwrap();
    // A separately bootstrapped legacy scope can still start through the real
    // worker entry owner; it receives no root or native non-use proof.
    let legacy_participant = uuid::Uuid::now_v7().to_string();
    let legacy_privacy = uuid::Uuid::now_v7().to_string();
    let mut initial = admin.begin().await.unwrap();
    sqlx::query("insert into control.participant(participant_id,display_name,state,authority_epoch) values($1::text::uuid,'Legacy initial trust','ACTIVE',1)")
        .bind(&legacy_participant).execute(&mut *initial).await.unwrap();
    sqlx::query("insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1::text::uuid,$2::text::uuid,'Legacy','PARTICIPANT_LOCAL','LOCAL','ACTIVE')")
        .bind(&legacy_privacy).bind(&legacy_participant).execute(&mut *initial).await.unwrap();
    sqlx::query("update control.participant set root_privacy_domain_id=$2::text::uuid where participant_id=$1::text::uuid")
        .bind(&legacy_participant).bind(&legacy_privacy).execute(&mut *initial).await.unwrap();
    initial.commit().await.unwrap();
    let mut legacy_scope = RuntimeArtifactSourceWorker::start_configured(
        legacy,
        None,
        &legacy_participant,
        &legacy_privacy,
        None,
    )
    .await
    .unwrap();
    assert!(legacy_scope.custody.is_none());
    legacy_scope.tick(legacy).await.unwrap();
    // The installed login cannot create temporary relations. Simulate privileged
    // configuration drift only in this disposable fixture, then verify fake
    // catalogs cannot conceal either the extra privilege or revoked membership.
    let denied =
        sqlx::query("create temporary table pg_roles as select * from pg_catalog.pg_roles")
            .execute(worker)
            .await
            .unwrap_err();
    assert_eq!(
        denied.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );
    role_statement(
        admin,
        "GRANT TEMPORARY ON DATABASE openpc_control TO %I",
        &role,
        "",
    )
    .await
    .unwrap();
    let mut poisoned = worker.begin().await.unwrap();
    for statement in [
        "create temporary table pg_roles as select * from pg_catalog.pg_roles",
        "create temporary table pg_auth_members as select * from pg_catalog.pg_auth_members",
        "create temporary table pg_shdepend as select * from pg_catalog.pg_shdepend where refobjid<>(select oid from pg_catalog.pg_roles where rolname=session_user)",
    ] {
        sqlx::query(statement)
            .execute(&mut *poisoned)
            .await
            .unwrap();
    }
    role_statement(admin, "REVOKE %I FROM %I", &marker, &role)
        .await
        .unwrap();
    assert!(
        super::installation::authenticate(
            &mut poisoned,
            &installed.participant,
            &installed.privacy
        )
        .await
        .is_err()
    );
    poisoned.rollback().await.unwrap();
    role_statement(
        admin,
        "REVOKE TEMPORARY ON DATABASE openpc_control FROM %I",
        &role,
        "",
    )
    .await
    .unwrap();
    role_statement(
        admin,
        "GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET FALSE",
        &marker,
        &role,
    )
    .await
    .unwrap();
    installed.tick(worker).await.unwrap();
    for (template, first, second) in [
        ("CREATE ROLE %I NOLOGIN", "openpc_rs_forbidden_create", ""),
        ("ALTER ROLE %I CREATEROLE", role.as_str(), ""),
        ("COMMENT ON ROLE %I IS %L", marker.as_str(), "replacement"),
        (
            "GRANT %I TO %I",
            marker.as_str(),
            "openpc_local_control_worker",
        ),
        ("SET ROLE %I", marker.as_str(), ""),
    ] {
        let error = role_statement(worker, template, first, second)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("42501")
        );
    }
    // Checks run on an already-started owner, before any native mutation.
    for (change, restore, first, second) in [
        (
            "COMMENT ON ROLE %I IS %L",
            "COMMENT ON ROLE %I IS %L",
            marker.as_str(),
            "invalid",
        ),
        (
            "GRANT %I TO %I WITH SET TRUE",
            "GRANT %I TO %I WITH SET FALSE",
            marker.as_str(),
            role.as_str(),
        ),
        (
            "GRANT %I TO %I WITH INHERIT TRUE",
            "GRANT %I TO %I WITH INHERIT FALSE",
            marker.as_str(),
            role.as_str(),
        ),
        (
            "GRANT %I TO %I WITH ADMIN TRUE",
            "GRANT %I TO %I WITH ADMIN FALSE",
            marker.as_str(),
            role.as_str(),
        ),
        (
            "GRANT openpc_runtime_source_legacy TO %I WITH ADMIN FALSE, INHERIT FALSE, SET FALSE",
            "REVOKE openpc_runtime_source_legacy FROM %I",
            role.as_str(),
            "",
        ),
        (
            "GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET FALSE",
            "REVOKE %I FROM %I",
            marker.as_str(),
            "openpc_local_control_worker",
        ),
        (
            "GRANT openpc_control_worker TO %I",
            "REVOKE openpc_control_worker FROM %I",
            marker.as_str(),
            "",
        ),
        (
            "GRANT pg_write_server_files TO %I",
            "REVOKE pg_write_server_files FROM %I",
            role.as_str(),
            "",
        ),
        (
            "GRANT SELECT ON control.participant TO %I",
            "REVOKE SELECT ON control.participant FROM %I",
            marker.as_str(),
            "",
        ),
        (
            "GRANT SELECT ON control.participant TO %I",
            "REVOKE SELECT ON control.participant FROM %I",
            role.as_str(),
            "",
        ),
    ] {
        role_statement(admin, change, first, second).await.unwrap();
        assert!(installed.tick(worker).await.is_err(), "accepted {change}");
        role_statement(
            admin,
            restore,
            first,
            if second == "invalid" {
                &profile
            } else {
                second
            },
        )
        .await
        .unwrap();
        installed.tick(worker).await.unwrap();
    }
}
#[test]
#[ignore = "requires the existing isolated identity PostgreSQL runner"]
fn postgres_source_denial_wire_matches_control_consumer() {
    super::disposition::tests::control_wire(true);
}
