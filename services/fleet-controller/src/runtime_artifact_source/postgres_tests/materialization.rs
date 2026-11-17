//! Real SQL/native component boundary. Initial module reference rows are a
//! fixture; this is not governed qualification, disposition or journey acceptance.
use super::super::*;
use sqlx::{PgPool, Postgres, Transaction};
use std::fs;

fn id() -> String {
    uuid::Uuid::now_v7().to_string()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn begin(
    pool: &PgPool,
    installation: &SourceCustodyInstallation,
) -> Transaction<'static, Postgres> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true)")
        .bind(&installation.participant_id).bind(&installation.privacy_domain_id).execute(&mut *tx).await.unwrap();
    tx
}

async fn bind(
    tx: &mut Transaction<'_, Postgres>,
    input: &ImportIdentity,
    message: &materialization::Message,
) {
    sqlx::query("select set_config('openpc.runtime_source_read_permits',jsonb_build_object($1::text,jsonb_build_object('wire',$2::text,'mac',$3::text))::text,true)")
        .bind(&input.input_id).bind(hex(&message.wire)).bind(hex(&message.mac)).execute(&mut **tx).await.unwrap();
}

async fn payload(
    tx: &mut Transaction<'_, Postgres>,
    input: &ImportIdentity,
) -> Result<Vec<u8>, sqlx::Error> {
    sqlx::query_scalar("select openpc.runtime_artifact_input_payload($1::text::uuid)")
        .bind(&input.input_id)
        .fetch_one(&mut **tx)
        .await
}

async fn import(
    owner: &mut RuntimeArtifactSourceWorker,
    pool: &PgPool,
    installation: &SourceCustodyInstallation,
    input: &ImportIdentity,
    bytes: &[u8],
) {
    let mut tx = begin(pool, installation).await;
    owner
        .bind_import(&mut tx, input.clone(), true)
        .await
        .unwrap();
    sqlx::query("insert into control.runtime_configuration_input(runtime_configuration_input_id,participant_id,privacy_domain_id,module_installation_id,module_configuration_generation_id,configuration_cbor,configuration_digest,resource_bindings,selected) values($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6,sha256($6),$7,false)")
        .bind(&input.input_id).bind(&installation.participant_id).bind(&installation.privacy_domain_id).bind(&input.module_installation_id).bind(&input.module_configuration_generation_id).bind(bytes)
        .bind(serde_json::json!([{"kind":"ProviderProfile","id":id(),"digest":format!("sha256:{}",input.configuration_digest.as_str()),"chainId":"1"}])).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    owner.record_import_committed(input.clone()).await.unwrap();
}

async fn node_archive(input: serde_json::Value) {
    let project = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("timeout")
            .current_dir(project)
            .args([
                "--kill-after=2s",
                "30s",
                "node",
                "--import",
                "tsx",
                "tests/integration/identity/runtime-artifact-materialization-client.mjs",
            ])
            .env("OPENPC_RUNTIME_SOURCE_READ_TEST", input.to_string())
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "actual archive client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn reject_archive_repackaging(
    owner: &RuntimeArtifactSourceWorker,
    pool: &PgPool,
    installation: &SourceCustodyInstallation,
    input: &ImportIdentity,
) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)")
        .bind(&installation.participant_id).bind(&installation.privacy_domain_id).execute(&mut *tx).await.unwrap();
    let challenge: serde_json::Value = sqlx::query_scalar(
        "select openpc.runtime_artifact_archive_challenge($1::text::uuid,'runtime-native-archive')",
    )
    .bind(&input.input_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let mut native = owner.custody.as_ref().unwrap().lock().await;
    assert_eq!(
        native
            .materialize(serde_json::from_value(challenge).unwrap(), &[8; 32])
            .err(),
        Some(RuntimeError::Denied)
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the existing isolated identity PostgreSQL runner"]
async fn postgres_source_materialization_precedes_bytes_and_survives_failed_publication() {
    let admin_url = std::env::var("OPENPC_I02_ADMIN_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&admin_url).await.unwrap();
    let directory = tests::Directory::new();
    let source_file = directory.0.join("source.cbor");
    let journal = directory.0.join("journal");
    let retained = directory.0.join("retained");
    let configuration = directory.0.join("source.json");
    let render_input = directory.0.join("render-input.json");
    let password = uuid::Uuid::now_v7().simple().to_string();
    let installation = SourceCustodyInstallation {
        participant_id: id(),
        privacy_domain_id: id(),
        source_owner_id: id(),
        source_file_binding: SourceCustodyInstallation::file_binding(&source_file).unwrap(),
    };
    let database: serde_json::Value =
        sqlx::query_scalar("select openpc.runtime_artifact_database_identity()")
            .fetch_one(&admin)
            .await
            .unwrap();
    fs::write(directory.0.join("signing.key"), [7; 32]).unwrap();
    fs::write(directory.0.join("commit.key"), [8; 32]).unwrap();
    fs::write(directory.0.join("password"), &password).unwrap();
    let archive_password = uuid::Uuid::now_v7().simple().to_string();
    fs::write(directory.0.join("archive.password"), &archive_password).unwrap();
    fs::write(directory.0.join("archive.key"), [11; 32]).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            directory.0.join("archive.key"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    fs::write(&render_input,serde_json::to_vec(&serde_json::json!({
        "participant_id":installation.participant_id,"privacy_domain_id":installation.privacy_domain_id,
        "source_owner_id":installation.source_owner_id,"generation_id":id(),"source_file":source_file,
        "journal_directory":journal,"retained_root_directory":retained,"signing_key_file":directory.0.join("signing.key"),
        "commit_key_file":directory.0.join("commit.key"),"database_password_file":directory.0.join("password"),
        "fresh_scope":{"participant_display_name":"Materialization component","privacy_domain_name":"Materialization"},
        "materialization_database":database,
        "archive_custody":{"stream_id":"runtime-native-archive","database_password_file":directory.0.join("archive.password"),"keys":{"archive-key":directory.0.join("archive.key")}},
    })).unwrap()).unwrap();
    let rendered = RuntimeArtifactSourceWorker::render_configuration(&render_input).unwrap();
    fs::write(&configuration, serde_json::to_vec(&rendered).unwrap()).unwrap();
    RuntimeArtifactSourceWorker::install(
        &admin,
        &configuration,
        &installation.participant_id,
        &installation.privacy_domain_id,
        Some(&source_file),
    )
    .await
    .unwrap();
    let role = installation::rooted_login(
        &installation.participant_id,
        &installation.privacy_domain_id,
    )
    .unwrap();
    let options: sqlx::postgres::PgConnectOptions = admin_url.parse().unwrap();
    let worker = PgPool::connect_with(options.username(&role).password(&password))
        .await
        .unwrap();
    let mut owner = RuntimeArtifactSourceWorker::start_configured(
        &worker,
        Some(configuration.clone()),
        &installation.participant_id,
        &installation.privacy_domain_id,
        Some(&source_file),
    )
    .await
    .unwrap();

    let server = owner.start_materialization().await.unwrap().unwrap();

    // Initial immutable module references only. The actual runtime-input INSERT
    // still uses the dedicated nonsuperuser, native pending original and MAC.
    let module = id();
    let bytes = b"exact materialization fixture payload";
    let input = ImportIdentity {
        input_id: id(),
        module_installation_id: id(),
        module_configuration_generation_id: id(),
        configuration_digest: Digest::of(bytes),
    };
    let mut setup = admin.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true)")
        .bind(&installation.participant_id).bind(&installation.privacy_domain_id).execute(&mut *setup).await.unwrap();
    sqlx::query("insert into control.module_registration(module_id,display_name,owner) values('pc.materialization.fixture','Materialization component','test')")
        .execute(&mut *setup).await.unwrap();
    sqlx::query("insert into control.module_version(module_version_id,module_id,semantic_version,manifest_cbor,manifest_digest,cose_sign1,sbom_digest,provenance_digest,build_receipt_digest) values($1::text::uuid,'pc.materialization.fixture','1.0.0',$2,sha256($2),$2,sha256($2),sha256($2),sha256($2))")
        .bind(&module).bind(bytes.as_slice()).execute(&mut *setup).await.unwrap();
    sqlx::query("insert into control.module_installation(module_installation_id,participant_id,privacy_domain_id,module_version_id,state,authority_epoch,delegation_epoch,desired_manifest_digest,lifecycle_operation_id,idempotency_key) values($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,'ENABLED',1,1,sha256($5),uuidv7(),'materialization-component')")
        .bind(&input.module_installation_id).bind(&installation.participant_id).bind(&installation.privacy_domain_id).bind(&module).bind(bytes.as_slice()).execute(&mut *setup).await.unwrap();
    sqlx::query("insert into control.module_configuration_generation(generation_id,participant_id,privacy_domain_id,module_installation_id,generation,configuration_cbor,configuration_digest,active) values($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,1,$5,sha256($5),true)")
        .bind(&input.module_configuration_generation_id).bind(&installation.participant_id).bind(&installation.privacy_domain_id).bind(&input.module_installation_id).bind(b"module reference only".as_slice()).execute(&mut *setup).await.unwrap();
    setup.commit().await.unwrap();
    import(&mut owner, &worker, &installation, &input, bytes).await;
    let other_bytes = b"separate original, never selected or materialized";
    let other = ImportIdentity {
        input_id: id(),
        configuration_digest: Digest::of(other_bytes),
        ..input.clone()
    };
    import(&mut owner, &worker, &installation, &other, other_bytes).await;

    // A NOLOGIN role is dormant until a product login can SET it. Enrollment
    // and every release reject that indirect raw-column escape as well.
    sqlx::query("create role openpc_materialization_raw_reader nologin")
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("grant select(configuration_cbor) on control.runtime_configuration_input to openpc_materialization_raw_reader")
        .execute(&admin).await.unwrap();
    sqlx::query("grant openpc_materialization_raw_reader to openpc_control_worker with inherit false, set true")
        .execute(&admin).await.unwrap();
    let mut indirect = begin(&worker, &installation).await;
    let rejected = sqlx::query("select openpc.assert_runtime_artifact_materialization_boundary()")
        .execute(&mut *indirect)
        .await
        .unwrap_err();
    assert_eq!(
        rejected.as_database_error().unwrap().message(),
        "RUNTIME-ARTIFACT-SOURCE-READ-GRANT-UNAVAILABLE"
    );
    indirect.rollback().await.unwrap();
    sqlx::query("revoke openpc_materialization_raw_reader from openpc_control_worker")
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("revoke select(configuration_cbor) on control.runtime_configuration_input from openpc_materialization_raw_reader")
        .execute(&admin).await.unwrap();
    sqlx::query("drop role openpc_materialization_raw_reader")
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("create role openpc_materialization_elevated_reader login")
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("grant openpc_control_reader,openpc_control_owner to openpc_materialization_elevated_reader")
        .execute(&admin).await.unwrap();
    let mut elevated = begin(&worker, &installation).await;
    let rejected = sqlx::query("select openpc.assert_runtime_artifact_materialization_boundary()")
        .execute(&mut *elevated)
        .await
        .unwrap_err();
    assert_eq!(
        rejected.as_database_error().unwrap().message(),
        "RUNTIME-ARTIFACT-SOURCE-READ-ROLE-UNAVAILABLE"
    );
    elevated.rollback().await.unwrap();
    sqlx::query("drop role openpc_materialization_elevated_reader")
        .execute(&admin)
        .await
        .unwrap();

    sqlx::query("create view control.materialization_raw_view with (security_invoker=true) as select configuration_cbor from control.runtime_configuration_input")
        .execute(&admin).await.unwrap();
    sqlx::query("grant select on control.materialization_raw_view to openpc_control_worker")
        .execute(&admin)
        .await
        .unwrap();
    let mut view = begin(&worker, &installation).await;
    let rejected = sqlx::query("select * from control.materialization_raw_view")
        .execute(&mut *view)
        .await
        .unwrap_err();
    assert_eq!(
        rejected.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );
    view.rollback().await.unwrap();
    let mut view = begin(&worker, &installation).await;
    let rejected = sqlx::query("select openpc.assert_runtime_artifact_materialization_boundary()")
        .execute(&mut *view)
        .await
        .unwrap_err();
    assert_eq!(
        rejected.as_database_error().unwrap().message(),
        "RUNTIME-ARTIFACT-SOURCE-READ-PROJECTION-UNAVAILABLE"
    );
    view.rollback().await.unwrap();
    sqlx::query("drop view control.materialization_raw_view")
        .execute(&admin)
        .await
        .unwrap();

    let before_node = fs::read(journal.join("runtime-artifact-source.json")).unwrap();
    let project = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let node_input = serde_json::json!({
        "role": role, "password": password, "participant": installation.participant_id,
        "privacy": installation.privacy_domain_id, "input": input.input_id,
        "digest": input.configuration_digest.as_str(),
    })
    .to_string();
    // Keep the single-thread async runtime available to serve the actual IPC.
    // The existing host timeout bounds this one client without changing Tokio
    // production features or leaving an unbounded child on test failure.
    let node = tokio::task::spawn_blocking(move || {
        std::process::Command::new("timeout")
            .current_dir(&project)
            .args([
                "--kill-after=2s",
                "15s",
                "node",
                "--import",
                "tsx",
                "tests/integration/identity/runtime-artifact-materialization-client.mjs",
            ])
            .env("OPENPC_RUNTIME_SOURCE_READ_TEST", node_input)
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        node.status.success(),
        "actual Node materialization client failed"
    );
    let after_node = fs::read(journal.join("runtime-artifact-source.json")).unwrap();
    assert_ne!(after_node, before_node);

    for query in [
        "select configuration_cbor from control.runtime_configuration_input",
        "select row_to_json(input) from control.runtime_configuration_input input",
        "copy control.runtime_configuration_input to stdout",
    ] {
        let mut tx = begin(&worker, &installation).await;
        let error = sqlx::query(sqlx::AssertSqlSafe(query))
            .execute(&mut *tx)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("42501")
        );
        tx.rollback().await.unwrap();
    }
    let mut missing = begin(&worker, &installation).await;
    assert!(payload(&mut missing, &input).await.is_err());
    missing.rollback().await.unwrap();
    let mut tx = begin(&worker, &installation).await;
    let request: serde_json::Value = sqlx::query_scalar(
        "select openpc.runtime_artifact_materialization_challenge($1::text::uuid)",
    )
    .bind(&input.input_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let reflected: materialization::Message = serde_json::from_value(request.clone()).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&reflected.wire).unwrap();
    assert!(
        document["materialization"]["backend_id"]
            .as_str()
            .is_some_and(|value| value.contains(':'))
    );
    sqlx::query("savepoint reflection")
        .execute(&mut *tx)
        .await
        .unwrap();
    bind(&mut tx, &input, &reflected).await;
    assert!(payload(&mut tx, &input).await.is_err());
    sqlx::query("rollback to savepoint reflection")
        .execute(&mut *tx)
        .await
        .unwrap();
    // The actual native owner writes its original before the database can
    // release bytes. No simulated permit or seeded source-result row is used.
    let response = owner
        .custody
        .as_ref()
        .unwrap()
        .lock()
        .await
        .materialize(serde_json::from_value(request).unwrap(), &[8; 32])
        .unwrap();
    bind(&mut tx, &input, &response).await;
    assert_eq!(payload(&mut tx, &input).await.unwrap(), bytes);
    sqlx::query("savepoint other_input")
        .execute(&mut *tx)
        .await
        .unwrap();
    bind(&mut tx, &other, &response).await;
    assert!(payload(&mut tx, &other).await.is_err());
    sqlx::query("rollback to savepoint other_input")
        .execute(&mut *tx)
        .await
        .unwrap();
    // Exercise the actual shared Fleet/Fact client and bounded native socket,
    // including its independent fresh transaction-bound challenge.
    openpc_indexer_adapter::control_materialization::authorize_input(&mut tx, &input.input_id)
        .await
        .unwrap();
    assert_eq!(payload(&mut tx, &input).await.unwrap(), bytes);
    assert!(server.healthy());
    let original = fs::read(journal.join("runtime-artifact-source.json")).unwrap();
    assert_eq!(
        original, after_node,
        "fresh generic reads do not grow permanent-use history"
    );
    // A competing reader cannot reverse-wait behind this lifecycle owner.
    let mut concurrent = begin(&worker, &installation).await;
    let conflict =
        sqlx::query("select openpc.runtime_artifact_materialization_challenge($1::text::uuid)")
            .bind(&input.input_id)
            .execute(&mut *concurrent)
            .await
            .unwrap_err();
    assert_eq!(
        conflict.as_database_error().unwrap().message(),
        "PC-DATA-6007"
    );
    concurrent.rollback().await.unwrap();
    // Rejected real probe publication rolls SQL back after bytes escaped.
    assert!(sqlx::query("insert into control.provider_probe_observation(participant_id,privacy_domain_id,provider_profile_id,source_revision,input_digest,configuration_digest,lease_token,lease_until) values($1::text::uuid,$2::text::uuid,uuidv7(),1,$3,$3,uuidv7(),clock_timestamp()+interval '30 seconds')")
        .bind(&installation.participant_id).bind(&installation.privacy_domain_id).bind(format!("sha256:{}",input.configuration_digest.as_str())).execute(&mut *tx).await.is_err());
    tx.rollback().await.unwrap();
    let mut replay = begin(&worker, &installation).await;
    bind(&mut replay, &input, &response).await;
    assert!(payload(&mut replay, &input).await.is_err());
    replay.rollback().await.unwrap();
    assert_eq!(
        fs::read(journal.join("runtime-artifact-source.json")).unwrap(),
        original
    );
    let admission = SourceDispositionAdmission {
        installation: installation.clone(),
        disposition_id: id(),
        operation_id: id(),
        input_id: input.input_id.clone(),
        configuration_digest: input.configuration_digest.clone(),
        admission_receipt_digest: Digest::of(b"no real governance admission"),
        selection_digest: Digest::of(b"component selection"),
    };
    assert_eq!(
        owner
            .custody
            .as_ref()
            .unwrap()
            .lock()
            .await
            .begin_governed(admission.clone())
            .err(),
        Some(RuntimeError::Denied)
    );
    owner.tick(&worker).await.unwrap();
    drop(server);
    drop(owner);
    let restarted = RuntimeArtifactSourceWorker::start_configured(
        &worker,
        Some(configuration.clone()),
        &installation.participant_id,
        &installation.privacy_domain_id,
        Some(&source_file),
    )
    .await
    .unwrap();
    let server = restarted.start_materialization().await.unwrap().unwrap();
    let mut fresh = begin(&worker, &installation).await;
    openpc_indexer_adapter::control_materialization::authorize_input(&mut fresh, &input.input_id)
        .await
        .unwrap();
    assert_eq!(payload(&mut fresh, &input).await.unwrap(), bytes);
    fresh.rollback().await.unwrap();
    assert_eq!(
        restarted
            .custody
            .as_ref()
            .unwrap()
            .lock()
            .await
            .begin_governed(admission)
            .err(),
        Some(RuntimeError::Denied)
    );
    assert_eq!(
        fs::read(journal.join("runtime-artifact-source.json")).unwrap(),
        original
    );
    drop(server);
    let mut restarted = restarted;
    let archived_bytes = vec![0x93; 400_001];
    let archived = ImportIdentity {
        input_id: id(),
        configuration_digest: Digest::of(&archived_bytes),
        ..input.clone()
    };
    import(
        &mut restarted,
        &worker,
        &installation,
        &archived,
        &archived_bytes,
    )
    .await;
    let server = restarted.start_materialization().await.unwrap().unwrap();
    let archive_role = archive::login(&installation).unwrap();
    let archive_options: sqlx::postgres::PgConnectOptions = admin_url.parse().unwrap();
    let archive_pool = PgPool::connect_with(
        archive_options
            .username(&archive_role)
            .password(&archive_password),
    )
    .await
    .unwrap();
    for (pool, stream, privacy) in [
        (
            &worker,
            "runtime-native-archive",
            installation.privacy_domain_id.clone(),
        ),
        (
            &archive_pool,
            "wrong-stream",
            installation.privacy_domain_id.clone(),
        ),
        (&archive_pool, "runtime-native-archive", id()),
    ] {
        let mut denied = pool.begin().await.unwrap();
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)")
            .bind(&installation.participant_id).bind(privacy).execute(&mut *denied).await.unwrap();
        assert!(
            sqlx::query("select openpc.runtime_artifact_archive_challenge($1::text::uuid,$2)")
                .bind(&archived.input_id)
                .bind(stream)
                .execute(&mut *denied)
                .await
                .is_err()
        );
        denied.rollback().await.unwrap();
    }
    let archive_request = |identity: &ImportIdentity| {
        serde_json::json!({"role":archive_role,"password":archive_password,
        "participant":installation.participant_id,"privacy":installation.privacy_domain_id,"input":identity.input_id,
        "digest":identity.configuration_digest.as_str(),"key_file":directory.0.join("archive.key"),"archive":true})
    };
    let stale_backup = tests::Directory::new();
    fs::copy(
        journal.join("runtime-artifact-source.json"),
        stale_backup.0.join("runtime-artifact-source.json"),
    )
    .unwrap();
    let mut archive_input = archive_request(&archived);
    archive_input["lost_commit"] = serde_json::json!(true);
    node_archive(archive_input).await;
    {
        let native = restarted.custody.as_ref().unwrap().lock().await;
        let archives = native
            .checked_state()
            .unwrap()
            .history
            .as_ref()
            .unwrap()
            .archives(&native.history_signer)
            .unwrap();
        assert_eq!(archives.len(), 1);
        assert!(archives[0].2.is_none());
    }
    // A committed SQL row is not a custody proof: original-byte substitution
    // and a missing part must fail before any native completion is journalled.
    let pending_journal = fs::read(journal.join("runtime-artifact-source.json")).unwrap();
    let original_pending: Vec<u8> = sqlx::query_scalar("select source_pending_original from control.evidence_runtime_artifact_archive where runtime_configuration_input_id=$1::text::uuid")
        .bind(&archived.input_id).fetch_one(&admin).await.unwrap();
    for restore in [false, true] {
        let mut tx = admin.begin().await.unwrap();
        sqlx::query("set local session_replication_role='replica'")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("update control.evidence_runtime_artifact_archive set source_pending_original=$2 where runtime_configuration_input_id=$1::text::uuid")
            .bind(&archived.input_id).bind(if restore {original_pending.clone()} else {b"substituted original".to_vec()}).execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        if !restore {
            assert_eq!(
                restarted.tick(&worker).await.err(),
                Some(SourceCustodyError::Runtime(
                    RuntimeError::InvalidAuthorization
                ))
            );
        }
        assert_eq!(
            pending_journal,
            fs::read(journal.join("runtime-artifact-source.json")).unwrap()
        );
    }
    let mut tx = admin.begin().await.unwrap();
    sqlx::query("set local session_replication_role='replica'")
        .execute(&mut *tx)
        .await
        .unwrap();
    let part:serde_json::Value=sqlx::query_scalar("delete from control.evidence_runtime_artifact_archive_part p where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and stream_id='runtime-native-archive' and ordinal=(select max(ordinal) from control.evidence_runtime_artifact_archive_part where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and stream_id='runtime-native-archive') returning to_jsonb(p)")
        .bind(&installation.participant_id).bind(&installation.privacy_domain_id).fetch_one(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        restarted.tick(&worker).await.err(),
        Some(SourceCustodyError::Runtime(
            RuntimeError::InvalidAuthorization
        ))
    );
    assert_eq!(
        pending_journal,
        fs::read(journal.join("runtime-artifact-source.json")).unwrap()
    );
    let mut tx = admin.begin().await.unwrap();
    sqlx::query("set local session_replication_role='replica'")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("insert into control.evidence_runtime_artifact_archive_part select * from jsonb_populate_record(null::control.evidence_runtime_artifact_archive_part,$1)").bind(part).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    restarted.tick(&worker).await.unwrap();
    {
        let native = restarted.custody.as_ref().unwrap().lock().await;
        let archives = native
            .checked_state()
            .unwrap()
            .history
            .as_ref()
            .unwrap()
            .archives(&native.history_signer)
            .unwrap();
        assert_eq!(archives.len(), 1);
        assert!(archives[0].2.is_some());
    }
    let after = fs::read(journal.join("runtime-artifact-source.json")).unwrap();
    restarted.tick(&worker).await.unwrap();
    assert_eq!(
        after,
        fs::read(journal.join("runtime-artifact-source.json")).unwrap()
    );
    let mut inspection = begin(&worker, &installation).await;
    let original_payload: (String,Vec<u8>)=sqlx::query_as("select segment_id::text,encrypted_segment from control.evidence_segment_payload where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and stream_id='runtime-native-archive' order by segment_id limit 1")
        .bind(&installation.participant_id).bind(&installation.privacy_domain_id).fetch_one(&mut *inspection).await.unwrap();
    inspection.rollback().await.unwrap();
    for restore in [false, true] {
        let mut fault = admin.begin().await.unwrap();
        sqlx::query("set local session_replication_role='replica'")
            .execute(&mut *fault)
            .await
            .unwrap();
        let bytes = if restore {
            original_payload.1.clone()
        } else {
            original_payload.1[..original_payload.1.len() - 1].to_vec()
        };
        sqlx::query("update control.evidence_segment_payload set encrypted_segment=$2 where segment_id=$1::text::uuid").bind(&original_payload.0).bind(bytes).execute(&mut *fault).await.unwrap();
        fault.commit().await.unwrap();
        if restore {
            restarted.tick(&worker).await.unwrap();
        } else {
            assert_eq!(
                restarted.tick(&worker).await.err(),
                Some(SourceCustodyError::Runtime(
                    RuntimeError::InvalidAuthorization
                ))
            );
        }
        assert_eq!(
            after,
            fs::read(journal.join("runtime-artifact-source.json")).unwrap()
        );
    }
    // Simulate an older Control restore that lost the complete archive while
    // retaining the original current host history. Startup/tick cannot revive it.
    let mut tx = admin.begin().await.unwrap();
    sqlx::query("set local session_replication_role='replica'")
        .execute(&mut *tx)
        .await
        .unwrap();
    let archive_row:serde_json::Value=sqlx::query_scalar("delete from control.evidence_runtime_artifact_archive a where runtime_configuration_input_id=$1::text::uuid returning to_jsonb(a)").bind(&archived.input_id).fetch_one(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        restarted.tick(&worker).await.err(),
        Some(SourceCustodyError::Runtime(
            RuntimeError::InvalidAuthorization
        ))
    );
    assert_eq!(
        after,
        fs::read(journal.join("runtime-artifact-source.json")).unwrap()
    );
    let mut tx = admin.begin().await.unwrap();
    sqlx::query("set local session_replication_role='replica'")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("insert into control.evidence_runtime_artifact_archive select * from jsonb_populate_record(null::control.evidence_runtime_artifact_archive,$1)").bind(archive_row).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    drop(server);
    drop(restarted);
    let root_original = fs::read(retained.join("runtime-artifact-source-root.json")).unwrap();
    assert_eq!(
        RuntimeArtifactSourceWorker::restore(
            &worker,
            &configuration,
            &installation.participant_id,
            &installation.privacy_domain_id,
            Some(&source_file),
            &stale_backup.0
        )
        .await
        .err(),
        Some(SourceCustodyError::Runtime(
            RuntimeError::InvalidAuthorization
        ))
    );
    assert_eq!(
        after,
        fs::read(journal.join("runtime-artifact-source.json")).unwrap()
    );
    assert_eq!(
        root_original,
        fs::read(retained.join("runtime-artifact-source-root.json")).unwrap()
    );
    let mut reopened = RuntimeArtifactSourceWorker::start_configured(
        &worker,
        Some(configuration.clone()),
        &installation.participant_id,
        &installation.privacy_domain_id,
        Some(&source_file),
    )
    .await
    .unwrap();
    assert_eq!(
        after,
        fs::read(journal.join("runtime-artifact-source.json")).unwrap()
    );
    let partial_bytes = vec![0x94; 400_001];
    let partial = ImportIdentity {
        input_id: id(),
        configuration_digest: Digest::of(&partial_bytes),
        ..input.clone()
    };
    import(
        &mut reopened,
        &worker,
        &installation,
        &partial,
        &partial_bytes,
    )
    .await;
    let server = reopened.start_materialization().await.unwrap().unwrap();
    let count_sql = "select count(*) from control.evidence_catalogue where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and stream_id='runtime-native-archive'";
    let before_count: i64 = sqlx::query_scalar(count_sql)
        .bind(&installation.participant_id)
        .bind(&installation.privacy_domain_id)
        .fetch_one(&admin)
        .await
        .unwrap();
    let mut partial_request = archive_request(&partial);
    partial_request["partial_rollback"] = serde_json::json!(true);
    node_archive(partial_request).await;
    let count: i64 = sqlx::query_scalar(count_sql)
        .bind(&installation.participant_id)
        .bind(&installation.privacy_domain_id)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(count, before_count);
    let archive_count:i64=sqlx::query_scalar("select count(*) from control.evidence_runtime_artifact_archive where runtime_configuration_input_id=$1::text::uuid").bind(&partial.input_id).fetch_one(&admin).await.unwrap();
    assert_eq!(archive_count, 0);
    let uncertain = fs::read(journal.join("runtime-artifact-source.json")).unwrap();
    reopened.tick(&worker).await.unwrap();
    reject_archive_repackaging(&reopened, &archive_pool, &installation, &partial).await;
    assert_eq!(
        uncertain,
        fs::read(journal.join("runtime-artifact-source.json")).unwrap()
    );
    drop(server);
    let lost_bytes = b"independent lost IPC archive attempt";
    let lost = ImportIdentity {
        input_id: id(),
        configuration_digest: Digest::of(lost_bytes),
        ..input.clone()
    };
    import(&mut reopened, &worker, &installation, &lost, lost_bytes).await;
    let server = reopened.start_materialization().await.unwrap().unwrap();
    let mut lost_tx = archive_pool.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)")
        .bind(&installation.participant_id).bind(&installation.privacy_domain_id).execute(&mut *lost_tx).await.unwrap();
    let challenge: serde_json::Value = sqlx::query_scalar(
        "select openpc.runtime_artifact_archive_challenge($1::text::uuid,'runtime-native-archive')",
    )
    .bind(&lost.input_id)
    .fetch_one(&mut *lost_tx)
    .await
    .unwrap();
    let message: materialization::Message = serde_json::from_value(challenge).unwrap();
    {
        use std::os::fd::AsRawFd;
        use tokio::io::AsyncWriteExt;
        let native = reopened.custody.as_ref().unwrap().lock().await;
        let generation = &native
            .checked_state()
            .unwrap()
            .retained_root
            .as_ref()
            .unwrap()
            .generation_id;
        let directory = fs::File::open(
            std::path::PathBuf::from(
                std::env::var_os("OPENPC_RUNTIME_ARTIFACT_SOURCE_SOCKET_DIRECTORY").unwrap(),
            )
            .join(generation),
        )
        .unwrap();
        let mut stream = tokio::net::UnixStream::connect(format!(
            "/proc/self/fd/{}/read.sock",
            directory.as_raw_fd()
        ))
        .await
        .unwrap();
        drop(native);
        let bytes = canonical_bytes(&message).unwrap();
        stream.write_u32(bytes.len() as u32).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        drop(stream); // Actual IPC peer disappears before receiving any response.
    }
    let mut observed = false;
    for _ in 0..100 {
        {
            let native = reopened.custody.as_ref().unwrap().lock().await;
            observed = native
                .checked_state()
                .unwrap()
                .history
                .as_ref()
                .unwrap()
                .archives(&native.history_signer)
                .unwrap()
                .iter()
                .any(|(pending, _, complete)| {
                    pending.materialization.input == lost && complete.is_none()
                });
        }
        if observed {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(observed, "lost IPC must retain its native pending original");
    lost_tx.rollback().await.unwrap();
    let uncertain = fs::read(journal.join("runtime-artifact-source.json")).unwrap();
    reopened.tick(&worker).await.unwrap();
    assert_eq!(
        uncertain,
        fs::read(journal.join("runtime-artifact-source.json")).unwrap()
    );
    drop(server);
    drop(reopened);
    let mut reopened = RuntimeArtifactSourceWorker::start_configured(
        &worker,
        Some(configuration),
        &installation.participant_id,
        &installation.privacy_domain_id,
        Some(&source_file),
    )
    .await
    .unwrap();
    reopened.tick(&worker).await.unwrap();
    reject_archive_repackaging(&reopened, &archive_pool, &installation, &lost).await;
    reject_archive_repackaging(&reopened, &archive_pool, &installation, &partial).await;
    assert_eq!(
        uncertain,
        fs::read(journal.join("runtime-artifact-source.json")).unwrap()
    );
    drop(reopened);
    archive_pool.close().await;
    worker.close().await;
    admin.close().await;
}
