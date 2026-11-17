//! A failed authority check before durable dispatch is known no-effect, never provider ambiguity.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};

pub(crate) async fn fail_before_dispatch(
    tx: &mut Transaction<'_, Postgres>,
    participant: &str,
    privacy: &str,
    attempt: &str,
) -> Result<bool, String> {
    let failure = || "signing authority denial unavailable".to_owned();
    let selected=sqlx::query("select c.operation_id::text,c.rotation_id::text,c.idempotency_key,c.action_intent_id,c.action_intent_digest,c.from_revision::text,to_char(date_trunc('milliseconds',c.created_at) at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') as created_at from control.signing_rotation_command c join control.signing_provider_attempt a using(participant_id,privacy_domain_id,operation_id) where c.participant_id=$1::text::uuid and c.privacy_domain_id=$2::text::uuid and a.attempt_id=$3::text::uuid and c.state='ACCEPTED' and a.state='READY' and a.dispatched_at_ns is null for update of c,a")
        .bind(participant).bind(privacy).bind(attempt).fetch_optional(&mut **tx).await.map_err(|_|failure())?;
    let Some(command) = selected else {
        return Ok(false);
    };
    let operation: String = command.try_get("operation_id").map_err(|_| failure())?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,$3::text::uuid,'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',true)")
        .bind(participant).bind(privacy).bind(&operation).execute(&mut **tx).await.map_err(|_|failure())?;
    sqlx::query("select attempt_id from control.signing_provider_attempt where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and operation_id=$3::text::uuid order by attempt_id for update")
        .bind(participant).bind(privacy).bind(&operation).fetch_all(&mut **tx).await.map_err(|_|failure())?;
    sqlx::query("insert into control.signing_rotation_operation_evidence(operation_id,participant_id,privacy_domain_id,rotation_id,provider_attempt_id,kind,preimage,digest,recorded_at_ns) select a.operation_id,a.participant_id,a.privacy_domain_id,a.rotation_id,a.attempt_id,'AUTHORITY_CHANGED_BEFORE_DISPATCH',retained.bytes,sha256(retained.bytes),1 from control.signing_provider_attempt a cross join lateral(select openpc.signing_operation_failure_preimage(a.attempt_id,'AUTHORITY_CHANGED_BEFORE_DISPATCH',null) as bytes) retained where a.attempt_id=$1::text::uuid")
        .bind(attempt).execute(&mut **tx).await.map_err(|_|failure())?;
    sqlx::query("update control.signing_provider_attempt set state='CANCELLED' where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and operation_id=$3::text::uuid and state='READY' and dispatched_at_ns is null")
        .bind(participant).bind(privacy).bind(&operation).execute(&mut **tx).await.map_err(|_|failure())?;
    let updated:String=sqlx::query_scalar("update control.signing_rotation_command set state='FAILED',result_kind='AUTHORITY_CHANGED_BEFORE_DISPATCH',result_revision=from_revision,updated_at=clock_timestamp() where operation_id=$1::text::uuid and state='ACCEPTED' returning to_char(date_trunc('milliseconds',updated_at) at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
        .bind(&operation).fetch_one(&mut **tx).await.map_err(|_|failure())?;
    let revision: String = command.try_get("from_revision").map_err(|_| failure())?;
    let intent_digest: Vec<u8> = command
        .try_get("action_intent_digest")
        .map_err(|_| failure())?;
    let hex: String = intent_digest.iter().map(|b| format!("{b:02x}")).collect();
    let result: Value = json!({"operationId":operation,"resourceRef":format!("urn:openpc:resource:{}",command.try_get::<String,_>("rotation_id").map_err(|_|failure())?),
        "actionIntentId":command.try_get::<String,_>("action_intent_id").map_err(|_|failure())?,"intentDigest":format!("sha256:{hex}"),
        "idempotencyKey":command.try_get::<String,_>("idempotency_key").map_err(|_|failure())?,"state":"FAILED","truthState":"FAILED","revision":revision,
        "signingResult":{"kind":"AUTHORITY_CHANGED_BEFORE_DISPATCH","retryable":false},
        "createdAt":command.try_get::<String,_>("created_at").map_err(|_|failure())?,"updatedAt":updated});
    let digest =
        Sha256::digest(pc_runtime_types::canonical_bytes(&result).map_err(|_| failure())?).to_vec();
    sqlx::query("update control.idempotency_record set terminal_state='COMMITTED',result_aggregate_version=$4::text::bigint,result_payload=$5,result_digest=$6 where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and operation_id=$3::text::uuid and terminal_state is null")
        .bind(participant).bind(privacy).bind(&operation).bind(&revision).bind(result).bind(digest).execute(&mut **tx).await.map_err(|_|failure())?;
    Ok(true)
}
