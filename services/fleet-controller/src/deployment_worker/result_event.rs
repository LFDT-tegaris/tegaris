//! Atomic notification of a verified immutable deployment result. The original
//! authorization COSE remains a reference, never a signature over this result.
use super::{Result, failure};
use openpc_multi_rpc::deployment::projection::ProjectionExpectation;
use pc_policy_core::pc_cbor_1;
use pc_runtime_types::Digest;

pub(super) enum ResultKind {
    Journal(u64),
    ReservationRejection,
}

pub(super) async fn emit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    expected: &ProjectionExpectation,
    digest: &Digest,
    kind: ResultKind,
) -> Result<()> {
    let (event_type, payload) = match kind {
        ResultKind::Journal(sequence) => (
            "openpc.deployment.result.observed.v1",
            serde_json::json!({"operationId":expected.command_id,"targetRuntimeId":expected.target_runtime_id,
                "journalSequence":sequence.to_string(),"resultDigest":digest}),
        ),
        ResultKind::ReservationRejection => (
            "openpc.deployment.reservation.rejected.v1",
            serde_json::json!({"operationId":expected.command_id,"targetRuntimeId":expected.target_runtime_id,
                "resultSequence":"1","resultDigest":digest}),
        ),
    };
    let payload = pc_cbor_1(&payload);
    let participant = &expected.owner.participant_id;
    let privacy = &expected.owner.privacy_domain_id;
    let event_sequence: i64 = sqlx::query_scalar("insert into control.outbox_aggregate_head(participant_id,aggregate_type,aggregate_id,last_sequence) values($1::text::uuid,'deployment-result',$2::text::uuid,1) on conflict(participant_id,aggregate_type,aggregate_id) do update set last_sequence=control.outbox_aggregate_head.last_sequence+1,updated_at=clock_timestamp() returning last_sequence::bigint")
        .bind(participant).bind(&expected.attempt_id).fetch_one(&mut **tx).await.map_err(|_| failure())?;
    let emitted = sqlx::query("insert into control.outbox_event(participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,aggregate_sequence,payload_cbor,payload_digest,cose_sign1,occurred_at) select $1::text::uuid,$2::text::uuid,uuidv7(),$7,'deployment-result',$3::text::uuid,$4,$5,sha256($5),e.cose_sign1,clock_timestamp() from control.mutation_evidence e where e.participant_id=$1::text::uuid and e.privacy_domain_id=$2::text::uuid and e.operation_id=$6::text::uuid and e.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'")
        .bind(participant).bind(privacy).bind(&expected.attempt_id).bind(event_sequence).bind(&payload)
        .bind(&expected.command_id).bind(event_type).execute(&mut **tx).await.map_err(|_| failure())?;
    if emitted.rows_affected() != 1 {
        return Err(failure());
    }
    Ok(())
}
