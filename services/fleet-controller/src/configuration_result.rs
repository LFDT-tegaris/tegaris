//! Existing durable configuration-work result and outbox writer, shared by
//! activation/qualification and non-granting CIGL profile compilation.
use pc_runtime_types::{Digest, canonical_bytes};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
type WorkerResult<T> = Result<T, String>;

pub struct WorkResultIdentity<'a> {
    pub participant_id: &'a str,
    pub privacy_domain_id: &'a str,
    pub operation_id: &'a str,
    pub work_id: &'a str,
    pub resource_id: &'a str,
}

fn digest_bytes(value: &Digest) -> WorkerResult<Vec<u8>> {
    value
        .as_str()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "invalid digest bytes".to_owned())?;
            u8::from_str_radix(text, 16).map_err(|_| "invalid digest bytes".to_owned())
        })
        .collect()
}

pub async fn append_result_event(
    transaction: &mut Transaction<'_, Postgres>,
    work: &WorkResultIdentity<'_>,
    event_id: &str,
    event_type: &str,
    aggregate_type: &str,
    payload: &[u8],
    payload_digest: &Digest,
) -> WorkerResult<()> {
    let sequence: i64 = sqlx::query_scalar(
        "insert into control.outbox_aggregate_head(participant_id,aggregate_type,aggregate_id,last_sequence) values ($1::text::uuid,$2,$3::text::uuid,1) on conflict (participant_id,aggregate_type,aggregate_id) do update set last_sequence=control.outbox_aggregate_head.last_sequence+1,updated_at=clock_timestamp() returning last_sequence::bigint",
    )
    .bind(work.participant_id)
    .bind(aggregate_type)
    .bind(work.resource_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| "result event sequence rejected".to_owned())?;
    // Cohort renewal owns a parent command distinct from the generated child
    // operation. Reuse only that immutable authorization and its exact staging
    // event; a scalar subquery rejects ambiguous provenance. This producer's
    // USER_WEBAUTHN input retains its existing legacy classification. The COSE
    // is original authorization provenance; receipt qualification is unchanged.
    let evidence_signature: Vec<u8> = sqlx::query_scalar(
        "select coalesce((select cose_sign1 from control.mutation_evidence where participant_id=$1::text::uuid and operation_id=$2::text::uuid),(select event.cose_sign1 from control.policy_activation_occurrence_target target join control.outbox_event event on event.participant_id=target.participant_id and event.privacy_domain_id=target.privacy_domain_id and event.aggregate_type='policy-activation-occurrence' and event.aggregate_id=target.activation_occurrence_id and event.webauthn_assertion_binding_digest is not null where target.participant_id=$1::text::uuid and target.configuration_work_id=$3::text::uuid order by event.aggregate_sequence desc limit 1),
         (select event.cose_sign1
          from control.policy_activation_occurrence_target target
          join control.configuration_work original on original.configuration_work_id=target.configuration_work_id
           and original.participant_id=target.participant_id and original.privacy_domain_id=target.privacy_domain_id
           and original.runtime_target_id=target.runtime_target_id
          join control.mutation_evidence authorization_row on authorization_row.participant_id=target.participant_id
           and authorization_row.privacy_domain_id=target.privacy_domain_id
           and authorization_row.operation_id=target.command_operation_id
           and authorization_row.catalog_operation_id='CFG-OP-RENEW-POLICY-ACTIVATION'
           and authorization_row.aggregate_type='policy-activation-renewal'
           and authorization_row.aggregate_id=target.activation_occurrence_id
           and authorization_row.evidence_role='LEGACY_UNQUALIFIED_BUSINESS_EVIDENCE'
           and authorization_row.evidence_format='LEGACY'
          join control.outbox_event event on event.participant_id=authorization_row.participant_id
           and event.privacy_domain_id=authorization_row.privacy_domain_id
           and event.aggregate_type=authorization_row.aggregate_type and event.aggregate_id=authorization_row.aggregate_id
           and event.event_type='openpc.policy.activation-renewal.staging.v1'
           and event.cose_sign1=authorization_row.cose_sign1
           and event.webauthn_assertion_binding_digest=authorization_row.webauthn_assertion_binding_digest
           and event.occurred_at>=original.created_at and event.occurred_at<=original.execution_started_at
          where target.participant_id=$1::text::uuid and target.privacy_domain_id=$4::text::uuid
           and target.configuration_work_id=$3::text::uuid and target.phase='FORWARD'
           and original.operation_id=$2::text::uuid and original.resource_id=$5::text::uuid
           and original.work_kind='RUNTIME_ACTIVATION' and original.execution_started_at is not null
           and authorization_row.webauthn_assertion_binding_digest is not null))",
    )
    .bind(work.participant_id)
    .bind(work.operation_id)
    .bind(work.work_id)
    .bind(work.privacy_domain_id)
    .bind(work.resource_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| "result authorization evidence unavailable".to_owned())?;
    sqlx::query(
        "insert into control.outbox_event(participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,aggregate_sequence,payload_cbor,payload_digest,cose_sign1,occurred_at) values ($1::text::uuid,$2::text::uuid,$3::text::uuid,$4,$5,$6::text::uuid,$7,$8,$9,$10,clock_timestamp())",
    )
    .bind(work.participant_id)
    .bind(work.privacy_domain_id)
    .bind(event_id)
    .bind(event_type)
    .bind(aggregate_type)
    .bind(work.resource_id)
    .bind(sequence)
    .bind(payload)
    .bind(digest_bytes(payload_digest)?)
    .bind(evidence_signature)
    .execute(&mut **transaction)
    .await
    .map_err(|_| "result event append failed".to_owned())?;
    Ok(())
}

pub async fn update_operation_result(
    transaction: &mut Transaction<'_, Postgres>,
    work: &WorkResultIdentity<'_>,
    state: &str,
    truth_state: &str,
    revision: i64,
) -> WorkerResult<()> {
    let row = sqlx::query(
        r#"select result_payload,
             to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as updated_at
           from control.idempotency_record
          where participant_id=$1::text::uuid and operation_id=$2::text::uuid
            and terminal_state='COMMITTED' for update"#,
    )
    .bind(work.participant_id)
    .bind(work.operation_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| "operation result unavailable".to_owned())?;
    let mut result: Value = row
        .try_get("result_payload")
        .map_err(|_| "operation result payload invalid".to_owned())?;
    let updated_at: String = row
        .try_get("updated_at")
        .map_err(|_| "operation result timestamp invalid".to_owned())?;
    let object = result
        .as_object_mut()
        .ok_or_else(|| "operation result payload invalid".to_owned())?;
    object.insert("state".into(), Value::String(state.into()));
    object.insert("truthState".into(), Value::String(truth_state.into()));
    object.insert("revision".into(), Value::String(revision.to_string()));
    object.insert("updatedAt".into(), Value::String(updated_at));
    let result_digest = Digest::of(
        canonical_bytes(&result).map_err(|_| "operation result encoding rejected".to_owned())?,
    );
    let changed = sqlx::query(
        "update control.idempotency_record set result_digest=$1,result_payload=$2,result_aggregate_version=$3 where participant_id=$4::text::uuid and operation_id=$5::text::uuid and terminal_state='COMMITTED'",
    )
    .bind(digest_bytes(&result_digest)?)
    .bind(result)
    .bind(revision)
    .bind(work.participant_id)
    .bind(work.operation_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| "operation result update failed".to_owned())?
    .rows_affected();
    if changed != 1 {
        return Err("operation result compare-and-set rejected".into());
    }
    Ok(())
}
