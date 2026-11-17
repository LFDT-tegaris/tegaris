//! Explicit denial and settlement of one expired observed successor. This mode
//! opens no listeners, issues no runtime permit, and never reexecutes activation.
use super::*;
use activation_maintenance::Intent;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::os::unix::fs::MetadataExt;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperatorIntent {
    purpose: String,
    request_id: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    custody: Intent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handover:
        Option<openpc_fleet_controller::runtime_target::disposition::ExpiredUnsignedDenialHandover>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_transition: Option<
        openpc_fleet_controller::runtime_target::disposition::ExpiredDenialCredentialTransition,
    >,
}

pub(super) async fn run(path: &Path, expected: &str) -> WorkerResult<()> {
    run_kind(path, expected, false, false).await
}
pub(super) async fn run_handover(path: &Path, expected: &str) -> WorkerResult<()> {
    run_kind(path, expected, true, false).await
}
pub(super) async fn run_credential_handover(path: &Path, expected: &str) -> WorkerResult<()> {
    run_kind(path, expected, true, true).await
}
async fn run_kind(
    path: &Path,
    expected: &str,
    handover: bool,
    credential_handover: bool,
) -> WorkerResult<()> {
    let bytes = activation_maintenance::private_file(path)?;
    if fs::symlink_metadata(path)
        .map_err(|_| "denial intent unavailable")?
        .uid()
        != 65532
        || expected != format!("sha256:{}", Digest::of(&bytes).as_str())
    {
        return Err("expired denial intent rejected".into());
    }
    let intent: OperatorIntent =
        serde_json::from_slice(&bytes).map_err(|_| "expired denial intent rejected")?;
    if intent.purpose
        != if credential_handover {
            "EXPIRED_OBSERVED_CREDENTIAL_DENIAL_HANDOVER_V1"
        } else if handover {
            "EXPIRED_OBSERVED_UNSIGNED_DENIAL_HANDOVER_V1"
        } else {
            "EXPIRED_OBSERVED_DENIAL_V1"
        }
        || intent.handover.is_some() != handover
        || intent.credential_transition.is_some() != credential_handover
        || uuid::Uuid::parse_str(&intent.request_id).is_err()
        || intent
            .expires_at_ms
            .checked_sub(intent.issued_at_ms)
            .is_none_or(|v| v == 0 || v > 120_000)
    {
        return Err("expired denial intent rejected".into());
    }
    intent.custody.validate()?;
    if let Some(h) = &intent.handover
        && (h.abandoned_revision != h.floor.observed_revision
            || h.abandoned_admission_digest != h.floor.observed_admission_digest
            || h.floor.installed_revision.checked_add(1) != Some(h.abandoned_revision)
            || i64::try_from(h.floor.installed_revision).ok()
                != Some(intent.custody.disposition_revision)
            || format!("sha256:{}", h.floor.installed_delivery_digest.as_str())
                != intent.custody.delivery_digest)
    {
        return Err("expired handover floor rejected".into());
    }
    let config = Config::read()?;
    intent.custody.matches_denial_environment(&config)?;
    require_process()?;
    tokio::time::timeout(
        Duration::from_secs(90),
        execute(&config, &intent, &bytes, expected),
    )
    .await
    .map_err(|_| "expired denial outcome unconfirmed; reconcile original records")?
}

fn require_process() -> WorkerResult<()> {
    let status =
        fs::read_to_string("/proc/self/status").map_err(|_| "denial process unavailable")?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map(str::trim)
    };
    if field("Uid:") != Some("65532\t65532\t65532\t65532")
        || field("NoNewPrivs:") != Some("1")
        || ["CapEff:", "CapPrm:", "CapBnd:", "CapInh:", "CapAmb:"]
            .iter()
            .any(|n| field(n) != Some("0000000000000000"))
    {
        return Err("denial process boundary rejected".into());
    }
    Ok(())
}

async fn execute(
    config: &Config,
    request: &OperatorIntent,
    bytes: &[u8],
    digest: &str,
) -> WorkerResult<()> {
    let i = &request.custody;
    let (agent, manifest) = retained_target::open_expired_denial(config, &i.runtime_target_id)?;
    let pool = config.connect().await?;
    let mut owner = pool
        .acquire()
        .await
        .map_err(|_| "denial owner unavailable")?;
    let locked: bool = sqlx::query_scalar(
        "select pg_try_advisory_lock(hashtextextended('expired-activation-denial:'||$1,0))",
    )
    .bind(&i.runtime_target_id)
    .fetch_one(&mut *owner)
    .await
    .map_err(|_| "denial owner unavailable")?;
    if !locked {
        return Err("denial owner busy".into());
    }
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| "denial context unavailable")?;
    set_context(&mut tx, config).await?;
    let identity:bool=sqlx::query_scalar("select current_user::text=$1 and session_user::text=$1 and current_database()=$2 and host(inet_server_addr())=$3 and (select oid::text from pg_database where datname=current_database())=$4 and current_setting('role')='none' and current_setting('row_security')='on' and current_setting('session_replication_role')='origin' and pg_has_role(current_user,'openpc_control_worker','USAGE') and not pg_has_role(current_user,'openpc_control_owner','USAGE') and not exists(select 1 from pg_roles where rolname=current_user and(rolsuper or rolbypassrls))")
        .bind(&i.database_role).bind(&i.database_name).bind(&i.database_server_address).bind(&i.database_oid)
        .fetch_one(&mut *tx).await.map_err(|_|"denial database identity unavailable")?;
    if !identity {
        return Err("denial database identity rejected".into());
    }
    let replay: bool =
        sqlx::query_scalar("select openpc.expired_denial_terminal_replay($1::text::uuid,$2,$3)")
            .bind(&i.work_id)
            .bind(digest)
            .bind(bytes)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| "denial replay unavailable")?;
    if replay {
        tx.rollback()
            .await
            .map_err(|_| "denial read release unconfirmed")?;
        println!(
            "{}",
            serde_json::json!({"event":"expired_activation_denial_completed","replay":true})
        );
        return Ok(());
    }
    let existing_query = if request.handover.is_some() {
        "select exists(select 1 from control.runtime_expired_denial_handover where configuration_work_id=$1::text::uuid)"
    } else {
        "select exists(select 1 from control.runtime_expired_activation_denial where configuration_work_id=$1::text::uuid)"
    };
    let exists: bool = sqlx::query_scalar(existing_query)
        .bind(&i.work_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| "denial admission read unavailable")?;
    if exists {
        return Err("existing denial outcome unconfirmed; reconcile without re-signing".into());
    }
    let connection = if let Some(transition) = &request.credential_transition {
        Some(openpc_fleet_controller::runtime_target::disposition::read_expired_credential_denial_connection(
            &mut tx,&manifest,transition).await.map_err(|_|"ordinary credential rotation proof unavailable")?)
    } else {
        None
    };
    let state: String = if let Some(connection) = &connection {
        sqlx::query_scalar(
            "select openpc.expired_credential_denial_state_digest($1::text::uuid,$2)",
        )
        .bind(&i.work_id)
        .bind(format!(
            "sha256:{}",
            connection.certificate_digest().as_str()
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| "expired credential state unavailable")?
    } else {
        sqlx::query_scalar(if request.handover.is_some() {
            "select openpc.expired_denial_handover_state_digest($1::text::uuid)"
        } else {
            "select openpc.expired_activation_state_digest($1::text::uuid)"
        })
        .bind(&i.work_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| "expired original state unavailable")?
    };
    if state != i.original_state_digest {
        return Err("expired original state changed".into());
    }
    tx.rollback()
        .await
        .map_err(|_| "denial preflight release unconfirmed")?;
    let now = now_ms()?;
    if now < request.issued_at_ms || now >= request.expires_at_ms {
        return Err("operator request expired".into());
    }
    let original = retained_target::read_installed(config, &i.runtime_target_id)
        .map_err(|_| "expired journal unavailable")?;
    if format!(
        "sha256:{}",
        original
            .capsule
            .digest()
            .map_err(|_| "expired capsule rejected")?
            .as_str()
    ) != i.capsule_digest
        || original.capsule.capsule_id != i.generation_id
    {
        return Err("expired original capsule changed".into());
    }
    if let (Some(connection), Some(h)) = (&connection, &request.handover) {
        openpc_fleet_controller::runtime_target::disposition::prepare_expired_credential_denial_handover(&agent,connection,h)
            .await.map_err(|_|"fresh authenticated credential handover floor unavailable")?;
    } else if let Some(h) = &request.handover {
        openpc_fleet_controller::runtime_target::disposition::prepare_expired_denial_handover(
            &agent, &manifest, h,
        )
        .await
        .map_err(|_| "fresh authenticated original handover floor unavailable")?;
    }
    let bundle=canonical_bytes(&serde_json::json!({"intentBytesHex":hex_bytes(bytes),
        "capsuleHex":hex_bytes(&original.capsule.encode().map_err(|_|"expired capsule encoding rejected")?),
        "tokenHex":hex_bytes(&original.activation_token),"receiptHex":hex_bytes(&original.activation_receipt)}))
        .map_err(|_|"operator request encoding rejected")?;
    let key = read_key(&required("CONTROL_WORKER_TARGET_DISPOSITION_KEY_FILE")?)?;
    let mut nonce = Vec::with_capacity(32);
    nonce.extend_from_slice(uuid::Uuid::now_v7().as_bytes());
    nonce.extend_from_slice(uuid::Uuid::now_v7().as_bytes());
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)
        .map_err(|_| "operator request key rejected")?;
    mac.update(if connection.is_some() {
        b"OPENPC_EXPIRED_CREDENTIAL_DENIAL_HANDOVER_REQUEST_V1".as_slice()
    } else if request.handover.is_some() {
        b"OPENPC_EXPIRED_UNSIGNED_DENIAL_HANDOVER_REQUEST_V1".as_slice()
    } else {
        b"OPENPC_EXPIRED_ACTIVATION_OPERATOR_REQUEST_V1".as_slice()
    });
    mac.update(&(bundle.len() as u64).to_be_bytes());
    mac.update(&Sha256::digest(&bundle));
    mac.update(&nonce);
    let signature = mac.finalize().into_bytes().to_vec();
    let delivery = if let Some(connection)=&connection {
        openpc_fleet_controller::runtime_target::disposition::request_expired_credential_denial_handover(
            connection,bundle,nonce,signature).await
    } else if request.handover.is_some() {
        openpc_fleet_controller::runtime_target::disposition::request_expired_denial_handover(
            &manifest, bundle, nonce, signature,
        )
        .await
    } else {
        openpc_fleet_controller::runtime_target::disposition::request_expired_activation_denial(
            &manifest, bundle, nonce, signature,
        )
        .await
    }
    .map_err(|_| "denial request outcome unconfirmed; read original admission before retry")?;
    let action = if request.handover.is_some() {
        openpc_fleet_controller::runtime_target::disposition::complete_expired_denial_handover(
            &agent,
        )
        .await
    } else {
        openpc_fleet_controller::runtime_target::disposition::establish_target_disposition(
            &agent, &manifest,
        )
        .await
    }
    .map_err(
        |_| "denial acknowledgement outcome unconfirmed; reconcile original journal and Control",
    )?;
    if action != pc_runtime_types::target_disposition::TargetDispositionAction::Withdraw {
        return Err("denial acknowledgement did not establish NewUseDenied".into());
    }
    finish(&pool, config, i, digest, &delivery).await?;
    println!(
        "{}",
        serde_json::json!({"event":"expired_activation_denial_completed","replay":false})
    );
    Ok(())
}

async fn finish(
    pool: &PgPool,
    config: &Config,
    i: &Intent,
    intent_digest: &str,
    delivery: &Digest,
) -> WorkerResult<()> {
    let mut tx = result_roots_with_deadlines(pool, config, "RUNTIME_ACTIVATION", true).await?;
    let result = tokio::time::timeout(Duration::from_secs(20), async {
    let row=sqlx::query("select coalesce(h.admission_revision,e.admission_revision) admission_revision,e.capsule_generation,o.activation_receipt_digest, 'sha256:'||encode(sha256(k.signed_acknowledgement),'hex') acknowledgement_digest,w.predecessor_digest from control.runtime_expired_activation_denial e left join control.runtime_expired_denial_handover h on h.configuration_work_id=e.configuration_work_id and h.participant_id=e.participant_id and h.privacy_domain_id=e.privacy_domain_id and h.runtime_target_id=e.runtime_target_id join control.configuration_work w on w.configuration_work_id=e.configuration_work_id and w.participant_id=e.participant_id and w.privacy_domain_id=e.privacy_domain_id and w.runtime_target_id=e.runtime_target_id and w.execution_attempt_id=e.execution_attempt_id join control.runtime_activation_observation o on o.configuration_work_id=w.configuration_work_id and o.participant_id=w.participant_id and o.privacy_domain_id=w.privacy_domain_id and o.runtime_target_id=w.runtime_target_id and o.execution_attempt_id=w.execution_attempt_id join control.runtime_target_disposition_admission a on a.participant_id=e.participant_id and a.privacy_domain_id=e.privacy_domain_id and a.runtime_target_id=e.runtime_target_id and a.revision=coalesce(h.admission_revision,e.admission_revision) join control.runtime_target_disposition_delivery d on d.participant_id=a.participant_id and d.privacy_domain_id=a.privacy_domain_id and d.runtime_target_id=a.runtime_target_id and d.revision=a.revision join control.runtime_target_disposition_acknowledgement k on k.participant_id=d.participant_id and k.privacy_domain_id=d.privacy_domain_id and k.runtime_target_id=d.runtime_target_id and k.delivery_digest=d.delivery_digest where e.configuration_work_id=$1::text::uuid and coalesce(h.intent_digest,e.intent_digest)=$2 and e.execution_attempt_id=$3::text::uuid and w.state='RECONCILING' and w.reconcile_after='infinity'::timestamptz and w.lease_owner is null and w.lease_until is null and w.attempt_count=$4 and w.result_event_id is null and a.admission_digest=coalesce(h.admission_digest,e.admission_digest) and a.revision=(select max(h.revision)from control.runtime_target_disposition_admission h where h.participant_id=e.participant_id and h.privacy_domain_id=e.privacy_domain_id and h.runtime_target_id=e.runtime_target_id) and a.binding->>'action'='Withdraw' and d.delivery_digest=$5 and k.claims->>'installed_state'='NewUseDenied' for update of w")
        .bind(&i.work_id).bind(intent_digest).bind(&i.execution_attempt_id).bind(i.claim_count)
        .bind(format!("sha256:{}",delivery.as_str())).fetch_one(&mut *tx).await.map_err(|_|"expired denial ACK custody unavailable")?;
    let original_receipt:String=row.try_get("activation_receipt_digest").map_err(|_|"expired original receipt unavailable")?;
    let ack:String=row.try_get("acknowledgement_digest").map_err(|_|"expired denial ACK unavailable")?;
    let predecessor:String=row.try_get("predecessor_digest").map_err(|_|"expired predecessor unavailable")?;
    let revision:i64=row.try_get("admission_revision").map_err(|_|"expired denial revision unavailable")?;
    let generation:i64=row.try_get("capsule_generation").map_err(|_|"expired capsule generation unavailable")?;
    let result=serde_json::json!({"outcome":"EXPIRED_OBSERVED_DENIED","errorCode":"PC-RUNTIME-3002","observedEffect":true,
        "runtimeNewUse":"DENIED","capsuleDigest":i.capsule_digest,"originalReceiptDigest":original_receipt,
        "denialDeliveryDigest":format!("sha256:{}",delivery.as_str()),"denialAcknowledgementDigest":ack,
        "terminal":true,"resourceId":i.runtime_target_id,"workKind":"RUNTIME_ACTIVATION"});
    let payload=canonical_bytes(&result).map_err(|_|"expired result encoding rejected")?;let digest=Digest::of(&payload);
    let event=uuid::Uuid::now_v7().to_string();
    let identity=openpc_fleet_controller::configuration_result::WorkResultIdentity {
        participant_id:&i.participant_id,privacy_domain_id:&i.privacy_domain_id,operation_id:&i.operation_id,
        work_id:&i.work_id,resource_id:&i.runtime_target_id,
    };
    openpc_fleet_controller::configuration_result::append_result_event(&mut tx,&identity,&event,
        "runtime-target.activation-expired-denied.v1","runtime-targets",&payload,&digest).await?;
    let work=sqlx::query("update control.configuration_work set state='FAILED',result_receipt=$1,result_receipt_digest=$2,result_event_id=$3::text::uuid,last_error_code='PC-RUNTIME-3002',completed_at=clock_timestamp(),updated_at=clock_timestamp(),reconcile_after=null where configuration_work_id=$4::text::uuid and state='RECONCILING' and reconcile_after='infinity'::timestamptz and execution_attempt_id=$5::text::uuid and attempt_count=$6 and lease_owner is null and lease_until is null and result_event_id is null")
        .bind(result).bind(format!("sha256:{}",digest.as_str())).bind(&event).bind(&i.work_id)
        .bind(&i.execution_attempt_id).bind(i.claim_count).execute(&mut *tx).await.map_err(|_|"expired work result rejected")?.rows_affected();
    if work!=1{return Err("expired work result changed".into());}
    let changed=sqlx::query("update control.runtime_configuration_generation set state='FAILED',revision=revision+1 where runtime_configuration_generation_id=$1::text::uuid and participant_id=$2::text::uuid and privacy_domain_id=$3::text::uuid and state='ACTIVATING' and activated_at is null")
        .bind(&i.generation_id).bind(&i.participant_id).bind(&i.privacy_domain_id).execute(&mut *tx).await.map_err(|_|"expired generation result rejected")?.rows_affected();
    if changed!=1{return Err("expired generation changed".into());}
    let target_revision:i64=sqlx::query_scalar("update control.runtime_target set state='FAILED',desired_generation_digest=null,revision=revision+1,updated_at=clock_timestamp() where runtime_target_id=$1::text::uuid and participant_id=$2::text::uuid and privacy_domain_id=$3::text::uuid and state='STAGING' and desired_generation_digest=$4 and active_generation_digest=$5 returning revision::bigint")
        .bind(&i.runtime_target_id).bind(&i.participant_id).bind(&i.privacy_domain_id).bind(&i.generation_digest).bind(&predecessor)
        .fetch_one(&mut *tx).await.map_err(|_|"expired target result rejected")?;
    openpc_fleet_controller::configuration_result::update_operation_result(&mut tx,&identity,"FAILED","FAILED",target_revision).await?;
    sqlx::query("insert into control.runtime_denied_predecessor(configuration_work_id,participant_id,privacy_domain_id,runtime_target_id,capsule_digest,last_confirmed_capsule_digest,xds_version_digest,capsule_generation,denial_revision,delivery_digest,acknowledgement_digest,result_event_id)values($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5,$6,$7,$8,$9,$10,$11,$12::text::uuid)")
        .bind(&i.work_id).bind(&i.participant_id).bind(&i.privacy_domain_id).bind(&i.runtime_target_id).bind(&i.capsule_digest)
        .bind(&predecessor).bind(&i.xds_version_digest).bind(generation).bind(revision).bind(format!("sha256:{}",delivery.as_str()))
        .bind(&ack).bind(&event).execute(&mut *tx).await.map_err(|_|"denied physical predecessor rejected")?;
    Ok::<(), String>(())
    }).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => Err("expired result timed out; reconcile original records".into()),
    };
    if let Err(error) = result {
        match tokio::time::timeout(Duration::from_secs(5), tx.rollback()).await {
            Ok(Ok(())) => return Err(error),
            _ => {
                return Err(format!(
                    "{error}; rollback unconfirmed; reconcile original records"
                ));
            }
        }
    }
    tokio::time::timeout(Duration::from_secs(5), tx.commit())
        .await
        .map_err(|_| "expired result commit timed out; reconcile original records")?
        .map_err(|_| "expired result commit unconfirmed; reconcile original records")?;
    Ok(())
}

#[cfg(test)]
#[path = "expired_activation_database_tests.rs"]
mod database_tests;
