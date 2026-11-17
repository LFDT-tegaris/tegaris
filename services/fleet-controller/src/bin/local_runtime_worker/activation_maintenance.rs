//! Explicit host-operator settlement of one already signed initial activation.
//! This module starts no runtime plane and has no transport or signing calls.
use super::*;
use openpc_fleet_controller::target_disposition::{
    HistoricalActivationCandidate, HistoricalCompletionClaim, OriginalTargetActivation,
    TargetDispositionStore,
};
use serde::{Deserialize, Serialize};
use std::{io::Read, os::unix::fs::MetadataExt};

#[cfg(test)]
#[path = "activation_maintenance_tests.rs"]
mod database_tests;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Intent {
    pub(super) schema_version: String,
    pub(super) vm_boot_id: String,
    pub(super) installation_id: String,
    pub(super) source_revision: String,
    pub(super) controller_image_id: String,
    pub(super) executable_digest: String,
    pub(super) database_installation_id: String,
    pub(super) database_server_address: String,
    pub(super) database_oid: String,
    pub(super) database_name: String,
    pub(super) database_role: String,
    pub(super) worker_role: String,
    pub(super) worker_id: String,
    pub(super) participant_id: String,
    pub(super) privacy_domain_id: String,
    pub(super) runtime_target_id: String,
    pub(super) work_id: String,
    pub(super) operation_id: String,
    pub(super) execution_attempt_id: String,
    pub(super) occurrence_id: String,
    pub(super) generation_id: String,
    pub(super) generation_digest: String,
    pub(super) configuration_digest: String,
    pub(super) xds_version_digest: String,
    pub(super) capsule_digest: String,
    pub(super) receipt_digest: String,
    pub(super) delivery_digest: String,
    pub(super) acknowledgement_digest: String,
    pub(super) disposition_revision: i64,
    pub(super) original_state_digest: String,
    pub(super) claim_count: i64,
    pub(super) reason: String,
    pub(super) correlation: String,
}

/// Remaining legacy modes are checked before Config, database or background
/// initialization. A misspelled maintenance command must never start a worker.
pub(super) fn require_remaining_arguments(arguments: &[String]) -> WorkerResult<()> {
    let valid = match arguments.get(1).map(String::as_str) {
        None => arguments.len() == 1,
        Some("healthcheck" | "source-custody-initialize" | "fact-admission-once") => {
            arguments.len() == 2
        }
        Some("source-custody-restore") => arguments.len() == 3,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err("worker command arguments rejected".into())
    }
}

fn rejected() -> String {
    "original activation maintenance intent rejected".into()
}

pub(super) fn private_file(path: &Path) -> WorkerResult<Vec<u8>> {
    if !path.is_absolute() {
        return Err(rejected());
    }
    let before = fs::symlink_metadata(path).map_err(|_| rejected())?;
    if !before.is_file() || before.mode() & 0o077 != 0 || before.len() > 16_384 {
        return Err(rejected());
    }
    let file = fs::File::open(path).map_err(|_| rejected())?;
    let opened = file.metadata().map_err(|_| rejected())?;
    // Opening a substituted link or file cannot replace the sealed input.
    if (before.dev(), before.ino(), before.uid()) != (opened.dev(), opened.ino(), opened.uid()) {
        return Err(rejected());
    }
    let mut bytes = Vec::new();
    file.take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| rejected())?;
    if bytes.len() > 16_384 || bytes.len() as u64 != opened.len() {
        return Err(rejected());
    }
    Ok(bytes)
}

fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read_only_seal_mount(mounts: &str) -> bool {
    let seal = Path::new("/run/openpc-maintenance/installation.json");
    let mut covering = Vec::new();
    for line in mounts.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() > 5 && seal.starts_with(Path::new(fields[4])) {
            covering.push((fields[4], fields[5]));
        }
    }
    let Some(depth) = covering.iter().map(|(path, _)| path.len()).max() else {
        return false;
    };
    let effective: Vec<_> = covering
        .into_iter()
        .filter(|(path, _)| path.len() == depth)
        .collect();
    effective.len() == 1
        && effective[0].0 == "/run/openpc-maintenance"
        && effective[0].1.split(',').any(|option| option == "ro")
}

impl Intent {
    pub(super) fn validate(&self) -> WorkerResult<()> {
        if self.schema_version != "1"
            || !uuid(&self.vm_boot_id)
            || !hex(&self.source_revision, 40)
            || self.claim_count < 1
            || self.disposition_revision < 1
            || self.worker_role != "openpc_control_worker"
            || self.database_role.len() > 63
            || !hex(&self.database_installation_id, 64)
            || self
                .database_server_address
                .parse::<std::net::IpAddr>()
                .is_err()
            || self.database_oid.parse::<u32>().is_err()
            || self.reason.trim().is_empty()
            || self.reason.len() > 512
            || self.reason.chars().any(char::is_control)
            || [
                &self.database_role,
                &self.installation_id,
                &self.database_name,
                &self.worker_id,
                &self.correlation,
            ]
            .iter()
            .any(|v| v.is_empty() || v.len() > 192 || !v.bytes().all(|b| b.is_ascii_graphic()))
            || [
                &self.participant_id,
                &self.privacy_domain_id,
                &self.runtime_target_id,
                &self.work_id,
                &self.operation_id,
                &self.execution_attempt_id,
                &self.occurrence_id,
                &self.generation_id,
            ]
            .iter()
            .any(|v| !uuid(v))
            || [
                &self.controller_image_id,
                &self.executable_digest,
                &self.generation_digest,
                &self.configuration_digest,
                &self.xds_version_digest,
                &self.capsule_digest,
                &self.receipt_digest,
                &self.delivery_digest,
                &self.acknowledgement_digest,
                &self.original_state_digest,
            ]
            .iter()
            .any(|v| !v.strip_prefix("sha256:").is_some_and(|s| hex(s, 64)))
        {
            return Err(rejected());
        }
        Ok(())
    }

    fn matches_environment(&self, config: &Config) -> WorkerResult<()> {
        self.matches_seal(config, false)
    }

    pub(super) fn matches_denial_environment(&self, config: &Config) -> WorkerResult<()> {
        self.matches_seal(config, true)
    }

    fn matches_seal(&self, config: &Config, denial: bool) -> WorkerResult<()> {
        if self.participant_id != config.participant_id
            || self.privacy_domain_id != config.privacy_domain_id
            || self.worker_id != config.worker_id
            || self.database_role != config.user
            || self.database_name != config.database
            || fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| rejected())?
                .trim()
                != self.vm_boot_id
            || format!(
                "sha256:{}",
                Digest::of(&fs::read("/proc/self/exe").map_err(|_| rejected())?).as_str()
            ) != self.executable_digest
        {
            return Err(rejected());
        }
        // The host installs this separate immutable deployment seal only after
        // inspecting the exact image/source. Caller input cannot choose them.
        let seal_path = Path::new("/run/openpc-maintenance/installation.json");
        for path in [
            Path::new("/run"),
            Path::new("/run/openpc-maintenance"),
            seal_path,
        ] {
            let metadata = fs::symlink_metadata(path).map_err(|_| rejected())?;
            if metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(rejected());
            }
        }
        let metadata = fs::symlink_metadata(seal_path).map_err(|_| rejected())?;
        if metadata.mode() & 0o777 != if denial { 0o444 } else { 0o400 } {
            return Err(rejected());
        }
        let seal = if denial {
            // This separate seal contains public installation metadata only.
            // Its root ownership, exact mode and effective read-only mount
            // permit the journal's normal non-root owner to read it.
            let file = fs::File::open(seal_path).map_err(|_| rejected())?;
            let opened = file.metadata().map_err(|_| rejected())?;
            if !opened.is_file()
                || opened.uid() != 0
                || opened.len() > 16_384
                || (opened.dev(), opened.ino()) != (metadata.dev(), metadata.ino())
            {
                return Err(rejected());
            }
            let mut bytes = Vec::new();
            file.take(16_385)
                .read_to_end(&mut bytes)
                .map_err(|_| rejected())?;
            if bytes.len() as u64 != opened.len() {
                return Err(rejected());
            }
            bytes
        } else {
            private_file(seal_path)?
        };
        let mounts = fs::read_to_string("/proc/self/mountinfo").map_err(|_| rejected())?;
        if !read_only_seal_mount(&mounts) {
            return Err(rejected());
        }
        let seal: Value = serde_json::from_slice(&seal).map_err(|_| rejected())?;
        if seal
            != serde_json::json!({
                "schemaVersion":"1", "installationId":self.installation_id,
                "vmBootId":self.vm_boot_id, "sourceRevision":self.source_revision,
                "controllerImageId":self.controller_image_id, "executableDigest":self.executable_digest,
                "databaseName":self.database_name,"databaseRole":self.database_role,"workerRole":self.worker_role,
                "databaseInstallationId":self.database_installation_id,
                "databaseServerAddress":self.database_server_address,"databaseOid":self.database_oid,
                "workerId":self.worker_id, "participantId":self.participant_id,
                "privacyDomainId":self.privacy_domain_id
            })
        {
            return Err(rejected());
        }
        Ok(())
    }
}

/// The explicit digest seals exact bytes, including the operator reason. No
/// database connection or worker configuration is initialized for bad input.
pub(super) async fn run(path: &Path, expected: &str) -> WorkerResult<()> {
    let bytes = private_file(path)?;
    if expected != format!("sha256:{}", Digest::of(&bytes).as_str()) {
        return Err(rejected());
    }
    let intent: Intent = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
    intent.validate()?;
    let config = Config::read()?;
    intent.matches_environment(&config)?;
    tokio::time::timeout(
        Duration::from_secs(45),
        execute(&config, &intent, &bytes, expected),
    )
    .await
    .map_err(|_| "maintenance deadline exceeded; reconcile original record before retry")?
}

async fn execute(config: &Config, intent: &Intent, bytes: &[u8], digest: &str) -> WorkerResult<()> {
    let pool = config.connect().await?;
    let mut tx = result_roots_with_deadlines(&pool, config, "RUNTIME_ACTIVATION", true).await?;
    let result = settle_in(&mut tx, config, &pool, intent, bytes, digest).await;
    match result {
        Ok(replay) => {
            if replay {
                tx.rollback().await.map_err(
                    |_| "maintenance replay rollback unconfirmed; reconcile original record",
                )?;
            } else {
                tx.commit()
                    .await
                    .map_err(|_| "maintenance commit unconfirmed; reconcile original record")?;
            }
            println!(
                "{}",
                serde_json::json!({"event":"original_activation_maintenance_completed", "replay":replay})
            );
            Ok(())
        }
        Err(error) => {
            let diagnostic_failed = record_result_failure("maintenance_failed", &error);
            if tx.rollback().await.is_err() {
                return Err(format!(
                    "maintenance rollback unconfirmed: {}",
                    serde_json::json!({
                        "primary":error,"diagnosticFailed":diagnostic_failed
                    })
                ));
            }
            Err(error)
        }
    }
}

async fn settle_in(
    tx: &mut Transaction<'_, Postgres>,
    config: &Config,
    pool: &PgPool,
    intent: &Intent,
    bytes: &[u8],
    digest: &str,
) -> WorkerResult<bool> {
    let owner: bool = sqlx::query_scalar(
        "select pg_try_advisory_xact_lock(hashtextextended('original-activation-maintenance',0))",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| "maintenance owner unavailable")?;
    if !owner {
        return Err("maintenance owner busy".into());
    }
    let role: String = sqlx::query_scalar("select current_user::text")
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| "maintenance role unavailable")?;
    if role != intent.database_role {
        return Err(rejected());
    }
    let worker_identity: bool = sqlx::query_scalar(r#"select current_user::text=$1 and session_user::text=$1
        and $2::text='openpc_control_worker' and pg_has_role(current_user,$2::text::name,'USAGE')
        and current_setting('role')='none' and current_setting('row_security')='on'
        and current_setting('session_replication_role')='origin'
        and not pg_has_role(current_user,'openpc_control_owner','USAGE')
        and not has_schema_privilege(current_user,'control','CREATE')
        and not exists(select 1 from pg_roles where rolname in(current_user,session_user) and (rolsuper or rolbypassrls))"#)
        .bind(&intent.database_role).bind(&intent.worker_role)
        .fetch_one(&mut **tx).await.map_err(|_| "maintenance worker identity unavailable")?;
    if !worker_identity {
        return Err(rejected());
    }

    let database_matches: bool = sqlx::query_scalar("select current_database()=$1 and host(inet_server_addr())=$2 and (select oid::text from pg_database where datname=current_database())=$3")
        .bind(&intent.database_name).bind(&intent.database_server_address).bind(&intent.database_oid)
        .fetch_one(&mut **tx).await.map_err(|_| "maintenance database identity unavailable")?;
    if !database_matches {
        return Err(rejected());
    }
    let replay = sqlx::query(r#"select a.intent_digest=$2 and a.intent_bytes=$3
        and a.intent=$4 and a.provenance='HOST_OPERATOR_V1'
        and a.participant_id=$5::text::uuid and a.privacy_domain_id=$6::text::uuid
        and a.operation_id=$7::text::uuid and a.execution_attempt_id=$8::text::uuid
        and a.claim_count=$9 and w.state='COMPLETED' and w.result_event_id=a.result_event_id
        and w.result_receipt_digest=$10 and w.execution_attempt_id=a.execution_attempt_id
        and w.operation_id=a.operation_id and w.attempt_count=a.claim_count
        and w.runtime_target_id=$11::text::uuid and w.runtime_configuration_generation_id=$12::text::uuid
        and w.generation_digest=$13 and w.configuration_digest=$14 and w.xds_version_digest=$15
        and w.predecessor_digest is null and w.lease_owner is null and w.lease_until is null
        and o.capsule_digest=$16 and o.activation_receipt_digest=$10
        and o.activation_receipt=w.result_receipt
        and d.revision=$17 and 'sha256:'||encode(sha256(d.signed_delivery),'hex')=$18
        and 'sha256:'||encode(sha256(k.signed_acknowledgement),'hex')=$19
        and admission.binding->>'action'='ConfirmActivation'
        and admission.binding->'source'->>'original_work_id'=w.configuration_work_id::text
        and admission.activation_proof->>'occurrenceId'=$20
        and c.activation_occurrence_id=$20::text::uuid and c.phase='FORWARD' and c.state='ACTIVE_MATCHED'
        and c.activation_receipt_digest=$10 and c.observed_generation_digest=$16
        and e.participant_id=a.participant_id and e.privacy_domain_id=a.privacy_domain_id
        and e.aggregate_type='runtime-targets' and e.aggregate_id=w.resource_id
        and e.event_type='runtime-target.activated.v1'
        and e.payload_digest=decode(substring($10 from 8),'hex') as valid,
        e.payload_cbor,o.activation_receipt
        from control.runtime_activation_maintenance a join control.configuration_work w using(configuration_work_id,participant_id,privacy_domain_id,operation_id,execution_attempt_id,result_event_id)
        join control.runtime_activation_observation o using(configuration_work_id,participant_id,privacy_domain_id,operation_id,execution_attempt_id,runtime_target_id,runtime_configuration_generation_id,generation_digest,xds_version_digest)
        join control.runtime_target_disposition_admission admission on admission.participant_id=w.participant_id
          and admission.privacy_domain_id=w.privacy_domain_id and admission.runtime_target_id=w.runtime_target_id
          and admission.revision=$17
        join control.runtime_target_disposition_delivery d on d.participant_id=admission.participant_id
          and d.privacy_domain_id=admission.privacy_domain_id and d.runtime_target_id=admission.runtime_target_id and d.revision=admission.revision
        join control.runtime_target_disposition_acknowledgement k on k.participant_id=d.participant_id
          and k.privacy_domain_id=d.privacy_domain_id and k.runtime_target_id=d.runtime_target_id and k.delivery_digest=d.delivery_digest
        join control.policy_activation_occurrence_target c on c.participant_id=w.participant_id
          and c.privacy_domain_id=w.privacy_domain_id and c.configuration_work_id=w.configuration_work_id
        join control.outbox_event e on e.event_id=a.result_event_id and e.participant_id=a.participant_id
        where a.configuration_work_id=$1::text::uuid"#)
        .bind(&intent.work_id).bind(digest).bind(bytes).bind(serde_json::to_value(intent).map_err(|_| rejected())?)
        .bind(&intent.participant_id).bind(&intent.privacy_domain_id).bind(&intent.operation_id)
        .bind(&intent.execution_attempt_id).bind(intent.claim_count).bind(&intent.receipt_digest)
        .bind(&intent.runtime_target_id).bind(&intent.generation_id).bind(&intent.generation_digest)
        .bind(&intent.configuration_digest).bind(&intent.xds_version_digest).bind(&intent.capsule_digest)
        .bind(intent.disposition_revision).bind(&intent.delivery_digest).bind(&intent.acknowledgement_digest).bind(&intent.occurrence_id)
        .fetch_optional(&mut **tx).await.map_err(|_| "maintenance replay unavailable")?;
    if let Some(row) = replay {
        let valid: bool = row.try_get("valid").map_err(|_| rejected())?;
        let receipt: Value = row.try_get("activation_receipt").map_err(|_| rejected())?;
        let payload: Vec<u8> = row.try_get("payload_cbor").map_err(|_| rejected())?;
        return if valid && canonical_bytes(&receipt).map_err(|_| rejected())? == payload {
            Ok(true)
        } else {
            Err(rejected())
        };
    }
    let work = original_work(tx, intent).await?;
    let retained = original_journal(config, &intent.runtime_target_id)
        .map_err(|_| "maintenance original journal unavailable")?;
    let peer = runtime_tls::target_identity_from_pem(
        &fs::read(required("CONTROL_WORKER_TARGET_CLIENT_CERT_FILE")?).map_err(|_| rejected())?,
    )
    .map_err(|_| rejected())?;
    if peer.target_id != intent.runtime_target_id {
        return Err(rejected());
    }
    let receipt_key =
        PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, config.agent_key)
            .map_err(|_| rejected())?
            .verifier()
            .sec1_bytes();
    let runtime_key = RuntimeWireSigner::from_secret_bytes(config.agent_key)
        .map_err(|_| rejected())?
        .verifier()
        .public_key_bytes();
    let store = TargetDispositionStore::from_host_installation(
        pool.clone(),
        config.participant_id.clone(),
        config.privacy_domain_id.clone(),
        config.fleet_key,
        read_key(&required("CONTROL_WORKER_TARGET_DISPOSITION_KEY_FILE")?)?,
        BTreeMap::new(),
    )?
    .with_identity_runtime_trust(&config.identity_runtime_public_key)?;
    store.register_host_target_key(&peer.target_id, &receipt_key)?;
    store.register_host_runtime_target_key(&peer.target_id, &runtime_key)?;
    let generation = parse_digest(intent.generation_digest.clone())?;
    let configuration = parse_digest(intent.configuration_digest.clone())?;
    let xds = parse_digest(intent.xds_version_digest.clone())?;
    let capsule = parse_digest(intent.capsule_digest.clone())?;
    let receipt = parse_digest(intent.receipt_digest.clone())?;
    let verified = store
        .verify_original_activation_completion_in(
            tx,
            OriginalTargetActivation {
                peer: &peer,
                capsule: &retained.capsule,
                signed_token: &retained.activation_token,
                signed_receipt: &retained.activation_receipt,
                artifacts: &retained.artifacts,
            },
            HistoricalActivationCandidate {
                work_id: &intent.work_id,
                operation_id: &intent.operation_id,
                execution_attempt_id: &intent.execution_attempt_id,
                occurrence_id: &intent.occurrence_id,
                generation_id: &intent.generation_id,
                generation_digest: &generation,
                configuration_digest: &configuration,
                xds_version_digest: &xds,
                capsule_digest: &capsule,
                receipt_digest: &receipt,
                claim: HistoricalCompletionClaim::Parked {
                    count: intent.claim_count,
                },
            },
        )
        .await?;
    // The historical verifier now owns canonical Identity/generation/target/work
    // locks. Compare the sealed original state before claiming. Full row/revision
    // bindings include same-bytes ABA and other generations of the policy scope.
    if original_state_digest_in(tx, intent).await? != intent.original_state_digest {
        return Err("maintenance original state changed".into());
    }
    // Check exact immutable wire bytes before claiming, never before the fences.
    let wire: bool = sqlx::query_scalar(r#"select
        d.revision=$4 and 'sha256:'||encode(sha256(d.signed_delivery),'hex')=$2
        and 'sha256:'||encode(sha256(k.signed_acknowledgement),'hex')=$3
        from control.runtime_target_disposition_delivery d
        join control.runtime_target_disposition_acknowledgement k using(participant_id,privacy_domain_id,runtime_target_id,delivery_digest)
        where d.runtime_target_id=$1::text::uuid
        order by d.revision desc limit 1"#)
        .bind(&intent.runtime_target_id).bind(&intent.delivery_digest).bind(&intent.acknowledgement_digest).bind(intent.disposition_revision)
        .fetch_one(&mut **tx).await.map_err(|_| "maintenance wire evidence unavailable")?;
    if !wire {
        return Err(rejected());
    }
    set_context(tx, config).await?;
    let claimed = sqlx::query(
        r#"update control.configuration_work set state='LEASED',lease_owner=$2,
        lease_until=clock_timestamp()+interval '30 seconds'
        where configuration_work_id=$1::text::uuid and state='RECONCILING'
        and reconcile_after='infinity'::timestamptz and lease_owner is null and lease_until is null
        and result_event_id is null and completed_at is null and predecessor_digest is null
        and execution_attempt_id=$3::text::uuid and attempt_count=$4"#,
    )
    .bind(&intent.work_id)
    .bind(&config.worker_id)
    .bind(&intent.execution_attempt_id)
    .bind(intent.claim_count)
    .execute(&mut **tx)
    .await
    .map_err(|_| "maintenance original claim unavailable")?
    .rows_affected();
    if claimed != 1 {
        return Err(rejected());
    }
    let ns = verified.observed_at_ns();
    complete_in(
        tx,
        &work,
        config,
        ResolvedCompletion {
            capsule_value: Some(verified.capsule_digest().clone()),
            receipt: verified.receipt().clone(),
            digest_value: verified.receipt_digest().clone(),
            observed_at: Some(format!(
                "{}.{:06} seconds",
                ns / 1_000_000_000,
                (ns % 1_000_000_000) / 1_000
            )),
            historical: true,
        },
    )
    .await?;
    sqlx::query(r#"insert into control.runtime_activation_maintenance
        (configuration_work_id,participant_id,privacy_domain_id,operation_id,execution_attempt_id,result_event_id,
        claim_count,intent_digest,intent_bytes,intent,provenance)
        select configuration_work_id,participant_id,privacy_domain_id,operation_id,execution_attempt_id,result_event_id,
        attempt_count,$2,$3,$4,'HOST_OPERATOR_V1' from control.configuration_work
        where configuration_work_id=$1::text::uuid"#)
        .bind(&intent.work_id).bind(digest).bind(bytes).bind(serde_json::to_value(intent).map_err(|_| rejected())?)
        .execute(&mut **tx).await.map_err(|_| "maintenance audit write rejected")?;
    Ok(false)
}

fn original_journal(
    config: &Config,
    target: &str,
) -> pc_runtime_types::RuntimeResult<retained_target::RetainedTarget> {
    // Native tests on the host read the SAME installed journal through its
    // original bind source. Release builds accept no journal path override.
    #[cfg(test)]
    if let Some(path) = env::var_os("OPENPC_MAINTENANCE_TEST_JOURNAL_ROOT") {
        return retained_target::read_installed_from(config, target, Path::new(&path));
    }
    retained_target::read_installed(config, target)
}

async fn original_work(
    tx: &mut Transaction<'_, Postgres>,
    intent: &Intent,
) -> WorkerResult<ClaimedWork> {
    let row = sqlx::query(r#"select resource_id::text,input_digest from control.configuration_work
        where configuration_work_id=$1::text::uuid and participant_id=$2::text::uuid
        and privacy_domain_id=$3::text::uuid and operation_id=$4::text::uuid
        and execution_attempt_id=$5::text::uuid and runtime_target_id=$6::text::uuid
        and runtime_configuration_generation_id=$7::text::uuid and generation_digest=$8
        and configuration_digest=$9 and xds_version_digest=$10 and attempt_count=$11
        and work_kind='RUNTIME_ACTIVATION' and state='RECONCILING' and reconcile_after='infinity'::timestamptz
        and lease_owner is null and lease_until is null and result_event_id is null and completed_at is null
        and execution_started_at is not null and predecessor_digest is null"#)
        .bind(&intent.work_id).bind(&intent.participant_id).bind(&intent.privacy_domain_id)
        .bind(&intent.operation_id).bind(&intent.execution_attempt_id).bind(&intent.runtime_target_id)
        .bind(&intent.generation_id).bind(&intent.generation_digest).bind(&intent.configuration_digest)
        .bind(&intent.xds_version_digest).bind(intent.claim_count)
        .fetch_one(&mut **tx).await.map_err(|_| "maintenance original parked work unavailable")?;
    Ok(ClaimedWork {
        work_id: intent.work_id.clone(),
        occurrence_id: Some(intent.occurrence_id.clone()),
        operation_id: intent.operation_id.clone(),
        work_kind: "RUNTIME_ACTIVATION".into(),
        resource_id: row.try_get("resource_id").map_err(|_| rejected())?,
        input_digest: row.try_get("input_digest").map_err(|_| rejected())?,
        participant_id: intent.participant_id.clone(),
        privacy_domain_id: intent.privacy_domain_id.clone(),
        configuration_cbor: Vec::new(),
        configuration_digest: parse_digest(intent.configuration_digest.clone())?,
        policy: None,
        related_profile_receipt: None,
        provider_receipt: None,
        projection_receipt: None,
        contract_policy_assets: Vec::new(),
        generation_id: Some(intent.generation_id.clone()),
        target_id: Some(intent.runtime_target_id.clone()),
        generation_digest: Some(parse_digest(intent.generation_digest.clone())?),
        predecessor_digest: None,
        xds_version_digest: Some(parse_digest(intent.xds_version_digest.clone())?),
        active_generation_digest: None,
        active_xds_version_digest: None,
        journal_sequence: 0,
        attempt_count: intent.claim_count,
        execution_attempt_id: Some(intent.execution_attempt_id.clone()),
        reconcile_only: true,
    })
}

// Hash only the exact original dependency closure. This runs after the existing
// verifier holds its canonical fences, before any maintenance write. No caller
// supplies row content or a readiness assertion.
const ORIGINAL_STATE_SQL: &str = r#"select 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(
 jsonb_build_object('work',to_jsonb(w),'target',to_jsonb(rt),'runtimeGeneration',to_jsonb(rg),
 'occurrence',to_jsonb(occ),'policyActivation',to_jsonb(pa),'policyGeneration',to_jsonb(pg),'bundle',to_jsonb(bundle),
 'cohort',(select jsonb_agg(to_jsonb(c) order by c.runtime_target_id,c.phase)
   from control.policy_activation_occurrence_target c where c.participant_id=w.participant_id
   and c.privacy_domain_id=w.privacy_domain_id and c.activation_occurrence_id=occ.activation_occurrence_id),
 'scopeGenerations',(select jsonb_agg(to_jsonb(g) order by g.policy_generation_id)
   from control.policy_generation g where g.participant_id=pg.participant_id
   and g.privacy_domain_id=pg.privacy_domain_id and g.scope_digest=pg.scope_digest),
 'scopeActivations',(select jsonb_agg(to_jsonb(a) order by a.policy_activation_id)
   from control.policy_activation a join control.policy_generation g using(participant_id,privacy_domain_id,policy_generation_id)
   where g.participant_id=pg.participant_id and g.privacy_domain_id=pg.privacy_domain_id and g.scope_digest=pg.scope_digest)
 )), 'UTF8')),'hex')
 from control.configuration_work w
 join control.runtime_target rt using(participant_id,privacy_domain_id,runtime_target_id)
 join control.runtime_configuration_generation rg on rg.runtime_configuration_generation_id=w.runtime_configuration_generation_id
   and rg.participant_id=w.participant_id and rg.privacy_domain_id=w.privacy_domain_id
 join control.policy_activation_occurrence occ on occ.participant_id=w.participant_id
   and occ.privacy_domain_id=w.privacy_domain_id and occ.activation_occurrence_id=$2::text::uuid
 join control.policy_activation pa on pa.participant_id=occ.participant_id
   and pa.privacy_domain_id=occ.privacy_domain_id and pa.policy_activation_id=occ.activation_occurrence_id
 join control.policy_generation pg on pg.participant_id=occ.participant_id
   and pg.privacy_domain_id=occ.privacy_domain_id and pg.policy_generation_id=occ.policy_generation_id
 join control.policy_release_bundle bundle on bundle.participant_id=occ.participant_id
   and bundle.privacy_domain_id=occ.privacy_domain_id and bundle.release_bundle_id=occ.release_bundle_id
 where w.configuration_work_id=$1::text::uuid"#;

async fn original_state_digest_in(
    tx: &mut Transaction<'_, Postgres>,
    intent: &Intent,
) -> WorkerResult<String> {
    sqlx::query_scalar(ORIGINAL_STATE_SQL)
        .bind(&intent.work_id)
        .bind(&intent.occurrence_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| "maintenance original state unavailable".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn intent_value() -> Value {
        let id = "018f0000-0000-7000-8000-000000000101";
        let sha = format!("sha256:{}", "a".repeat(64));
        serde_json::json!({
            "schemaVersion":"1", "vmBootId":id, "installationId":"installed-preview",
            "sourceRevision":"a".repeat(40),"controllerImageId":sha,"executableDigest":sha,
            "databaseInstallationId":"a".repeat(64),"databaseServerAddress":"127.0.0.1","databaseOid":"16384",
            "databaseName":"openpc_control","databaseRole":"installed_worker_login","workerRole":"openpc_control_worker", "workerId":"worker",
            "participantId":id,"privacyDomainId":id,"runtimeTargetId":id,"workId":id,
            "operationId":id,"executionAttemptId":id,"occurrenceId":id,"generationId":id,
            "generationDigest":sha,"configurationDigest":sha,"xdsVersionDigest":sha,
            "capsuleDigest":sha,"receiptDigest":sha,"deliveryDigest":sha,"acknowledgementDigest":sha,
            "dispositionRevision":1,"originalStateDigest":sha,"claimCount":1,"reason":"Settle original signed observation","correlation":"review-1"
        })
    }

    #[test]
    fn sealed_intent_rejects_unknown_duplicate_and_missing_fields() {
        let good = intent_value();
        serde_json::from_value::<Intent>(good.clone())
            .unwrap()
            .validate()
            .unwrap();
        let mut bad = good.clone();
        bad["renewPermission"] = Value::Bool(true);
        assert!(serde_json::from_value::<Intent>(bad).is_err());
        let mut bad = good.clone();
        bad.as_object_mut().unwrap().remove("acknowledgementDigest");
        assert!(serde_json::from_value::<Intent>(bad).is_err());
        let duplicate = format!("{{\"workId\":\"foreign\",{}", &good.to_string()[1..]);
        assert!(serde_json::from_str::<Intent>(&duplicate).is_err());
    }

    #[test]
    fn intent_cannot_select_other_role_omit_proof_or_smuggle_control_characters() {
        for (key, value) in [
            ("workerRole", serde_json::json!("openpc_control_runtime")),
            ("claimCount", serde_json::json!(0)),
            ("acknowledgementDigest", serde_json::json!("sha256:missing")),
            ("reason", serde_json::json!("approve\nrenew")),
            ("reason", serde_json::json!(" ")),
            ("correlation", serde_json::json!("two words")),
            ("workId", serde_json::json!("foreign")),
            ("sourceRevision", serde_json::json!("unreviewed")),
        ] {
            let mut value_set = intent_value();
            value_set[key] = value;
            assert!(
                serde_json::from_value::<Intent>(value_set)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn unknown_maintenance_commands_cannot_fall_through_into_worker_startup() {
        for arguments in [
            vec!["worker", "complete-original-activatio"],
            vec![
                "worker",
                "complete-original-activation",
                "intent",
                "digest",
                "extra",
            ],
            vec!["worker", "healthcheck", "extra"],
            vec!["worker", "source-custody-restore"],
        ] {
            assert!(
                require_remaining_arguments(
                    &arguments
                        .iter()
                        .map(|v| (*v).to_owned())
                        .collect::<Vec<_>>()
                )
                .is_err()
            );
        }
        for arguments in [
            vec!["worker"],
            vec!["worker", "healthcheck"],
            vec!["worker", "source-custody-initialize"],
            vec!["worker", "fact-admission-once"],
            vec!["worker", "source-custody-restore", "journal"],
        ] {
            require_remaining_arguments(
                &arguments
                    .iter()
                    .map(|v| (*v).to_owned())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        }
    }

    #[test]
    fn seal_requires_unambiguous_effective_read_only_mount() {
        let base = "1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:1 /seal /run/openpc-maintenance ro - ext4 /dev/root rw\n";
        assert!(read_only_seal_mount(base));
        assert!(!read_only_seal_mount(&base.replace(
            "/run/openpc-maintenance ro",
            "/run/openpc-maintenance rw"
        )));
        assert!(!read_only_seal_mount(&format!(
            "{base}3 2 8:1 /other /run/openpc-maintenance/installation.json rw - ext4 /dev/root rw\n"
        )));
        assert!(!read_only_seal_mount(&format!(
            "{base}3 1 8:1 /other /run/openpc-maintenance rw - ext4 /dev/root rw\n"
        )));
        assert!(!read_only_seal_mount(""));
    }

    #[test]
    fn sealed_file_rejects_symlinks_public_permissions_and_oversized_inputs() {
        let root = env::temp_dir().join(format!("activation-maintenance-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        let path = root.join("intent");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(private_file(&path).unwrap(), b"{}");
        let link = root.join("linked");
        symlink(&path, &link).unwrap();
        assert!(private_file(&link).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_file(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, vec![0_u8; 16_385]).unwrap();
        assert!(private_file(&path).is_err());
        assert!(private_file(Path::new("relative")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
