//! Integration-owned fixtures come from real source/Control admission. No local
//! test may mark a source retired, fabricate hold clearance or mint that proof.
use super::*;
use sqlx::Row;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernedCase {
    expected_host: RetirementHost,
    configuration: RetirementAuthorityConfiguration,
    target_key_file: PathBuf,
    signed_request_file: PathBuf,
}
fn read(path: &Path, maximum: u64) -> Vec<u8> {
    assert!(path.is_absolute());
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && metadata.len() <= maximum);
    fs::read(path).unwrap()
}
fn case_file(variable: &str) -> PathBuf {
    let path = std::env::var_os(variable)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!("OPENPC_CANDIDATE_RETIREMENT|status=BLOCKED|reason=MISSING_GOVERNED_CASE")
        });
    fs::symlink_metadata(&path).unwrap_or_else(|_| {
        panic!("OPENPC_CANDIDATE_RETIREMENT|status=BLOCKED|reason=GOVERNED_CASE_UNAVAILABLE")
    });
    path
}
async fn owner(case: GovernedCase) -> (CandidateRetirementOwner, Vec<u8>) {
    let key = read(&case.target_key_file, 128);
    let key = std::str::from_utf8(&key).unwrap().trim();
    assert_eq!(key.len(), 64);
    assert!(
        key.is_ascii() && key.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid target key encoding"
    );
    let mut secret = [0; 32];
    for (i, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&key[i * 2..i * 2 + 2], 16).unwrap();
    }
    let capability = capability_secret();
    let pool = runtime_pool().await;
    let owner = CandidateRetirementOwner::from_host_configuration(
        CandidateStore { pool },
        case.expected_host,
        case.configuration,
        secret,
        capability,
    )
    .unwrap();
    (owner, read(&case.signed_request_file, 1_048_576))
}
async fn snapshot(
    owner: &CandidateRetirementOwner,
    attempt: &RetirementAttempt,
) -> serde_json::Value {
    let RetirementSelection::Candidates { source, .. } = &attempt.selection else {
        panic!("candidate selection");
    };
    let mut tx = owner.begin().await.unwrap();
    // Sequence heads, checkpoint bytes, immutable source and invalidation lineage
    // must survive candidate physical effects exactly. They are not deletable payloads.
    let value: serde_json::Value=sqlx::query_scalar("select jsonb_build_object(
      'checkpoints',(select coalesce(jsonb_agg(to_jsonb(c) order by c.checkpoint_id),'[]') from candidate.checkpoint c where c.projection_generation_id=$1),
      'heads',(select coalesce(jsonb_agg(to_jsonb(h) order by h.aggregate_id),'[]') from candidate.outbox_aggregate_head h where h.aggregate_id=$2),
      'outbox',(select coalesce(jsonb_agg(to_jsonb(o) order by o.event_id),'[]') from candidate.outbox_event o where o.aggregate_id=$2),
      'relations',(select coalesce(jsonb_agg(to_jsonb(r) order by r.candidate_relation_id),'[]') from candidate.candidate_relation r where r.projection_generation_id=$1),
      'invalidations',(select coalesce(jsonb_agg(to_jsonb(i) order by i.candidate_invalidation_id),'[]') from candidate.candidate_invalidation i where i.projection_generation_id=$1))")
        .bind(uuid(&source.generation_id).unwrap()).bind(uuid(&source.partition_id).unwrap())
        .fetch_one(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    value
}

#[tokio::test]
#[ignore = "BLOCKED until a real governed source retirement case is supplied"]
async fn governed_physical_effect_preserves_lineage_sequences_and_blocks_rebuild() {
    let case: GovernedCase = serde_json::from_slice(&read(
        &case_file("OPENPC_CANDIDATE_RETIREMENT_CASE_FILE"),
        1_048_576,
    ))
    .unwrap();
    let (owner, request) = owner(case).await;
    let mut tx = owner.begin().await.unwrap();
    let verified = owner
        .trust
        .verify_request(&request, now_ms(&mut tx).await.unwrap())
        .unwrap();
    let attempt = &verified.claims().attempt;
    let RetirementSelection::Candidates { source, rows } = &attempt.selection else {
        panic!("candidate selection");
    };
    let mut originals = Vec::new();
    for selected in rows {
        let value: serde_json::Value=sqlx::query_scalar("select jsonb_build_object('row',to_jsonb(e),'identity',i.original_identity) from candidate.candidate_event e join candidate.retained_candidate_identity i using(candidate_event_id) where e.candidate_event_id=$1")
            .bind(uuid(&selected.candidate_id).unwrap()).fetch_one(&mut *tx).await.unwrap();
        originals.push(value);
    }
    tx.rollback().await.unwrap();
    let before = snapshot(&owner, attempt).await;
    assert!(matches!(
        owner.readback(attempt).await.unwrap(),
        CandidateRetirementReadback::Unknown
    ));
    // Drop the returned response after a real target commit; recover only through
    // durable readback. This is not transport-level lost-ACK journey acceptance.
    drop(owner.execute(&request).await.unwrap());
    let (effect, signed) = terminal(owner.readback(attempt).await.unwrap());
    assert!(
        matches!(effect,RetirementEffect::Applied { retired_rows,retired_payload_bytes,.. }
        if retired_rows==rows.len() as u64 && retired_payload_bytes==attempt.selection.payload_bytes().unwrap())
    );
    let (_, replayed) = terminal(owner.execute(&request).await.unwrap());
    assert_eq!(signed, replayed);
    assert_eq!(snapshot(&owner, attempt).await, before);
    for (selected, original) in rows.iter().zip(&originals) {
        let mut tx = owner.begin().await.unwrap();
        let retained=sqlx::query("select original_identity,payload_bytes,
          exists(select 1 from candidate.candidate_event e where e.candidate_event_id=i.candidate_event_id) live
          from candidate.retained_candidate_identity i join candidate.retired_candidate_payload r
          on r.candidate_id=i.candidate_event_id where i.candidate_event_id=$1")
            .bind(uuid(&selected.candidate_id).unwrap()).fetch_one(&mut *tx).await.unwrap();
        let expected = original["identity"].clone();
        assert_eq!(
            retained.get::<serde_json::Value, _>("original_identity"),
            expected
        );
        assert_eq!(
            retained.get::<i64, _>("payload_bytes") as u64,
            selected.payload_bytes
        );
        assert!(!retained.get::<bool, _>("live"));
        tx.rollback().await.unwrap();
        // A normal candidate writer still has INSERT; exact old record bytes may
        // not resurrect either the old ID or its natural identity after deletion.
        for fresh_id in [false, true] {
            let mut old_row = original["row"].clone();
            if fresh_id {
                old_row["candidate_event_id"] = serde_json::json!(Uuid::now_v7());
            }
            let mut tx = owner.begin().await.unwrap();
            let rebuilt=sqlx::query("insert into candidate.candidate_event (candidate_event_id,participant_id,privacy_domain_id,projection_generation_id,candidate_block_id,transaction_hash,transaction_index,log_index,contract_address,event_signature,candidate_key_digest,payload_cbor,payload_digest,state,removed_at,observed_at,candidate_partition_id,record_kind,record_sequence,record_id,schema_digest,normalized_digest,evidence_digest,target_address,call_parameter_digest)
                select candidate_event_id,participant_id,privacy_domain_id,projection_generation_id,candidate_block_id,transaction_hash,transaction_index,log_index,contract_address,event_signature,candidate_key_digest,payload_cbor,payload_digest,state,removed_at,observed_at,candidate_partition_id,record_kind,record_sequence,record_id,schema_digest,normalized_digest,evidence_digest,target_address,call_parameter_digest from jsonb_populate_record(null::candidate.candidate_event,$1::jsonb)")
                .bind(old_row).execute(&mut *tx).await.unwrap_err();
            assert_eq!(
                rebuilt.as_database_error().unwrap().message(),
                "OPENPC_RETIRED_CANDIDATE_GENERATION"
            );
            tx.rollback().await.unwrap();
        }
    }
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("OPENPC_I06_GATE3_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut tx = admin.begin().await.unwrap();
    sqlx::query("set local role openpc_indexer_manager")
        .execute(&mut *tx)
        .await
        .unwrap();
    context(&mut tx, &attempt.scope).await;
    let readiness=sqlx::query("update candidate.projection_generation set state='READY' where projection_generation_id=$1")
        .bind(uuid(&source.generation_id).unwrap()).execute(&mut *tx).await;
    assert_eq!(
        readiness
            .unwrap_err()
            .as_database_error()
            .unwrap()
            .message(),
        "OPENPC_RETIRED_CANDIDATE_READINESS"
    );
    tx.rollback().await.unwrap();
    assert_eq!(terminal(owner.readback(attempt).await.unwrap()).1, signed);
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DenialCase {
    case: GovernedCase,
    expected: RetirementRejection,
}
#[tokio::test]
#[ignore = "BLOCKED until independently governed candidate denial cases are supplied"]
async fn governed_source_finality_readiness_reference_and_retention_denials_have_no_effect() {
    let cases: Vec<DenialCase> = serde_json::from_slice(&read(
        &case_file("OPENPC_CANDIDATE_RETIREMENT_DENIAL_CASES_FILE"),
        1_048_576,
    ))
    .unwrap();
    let required = [
        RetirementRejection::SourceChanged,
        RetirementRejection::GenerationChanged,
        RetirementRejection::ReorgFenced,
        RetirementRejection::CheckpointIncomplete,
        RetirementRejection::ReadinessProtected,
        RetirementRejection::PublicationProtected,
        RetirementRejection::ReferencesProtected,
        RetirementRejection::RetentionNotElapsed,
    ];
    for required in required {
        assert!(
            cases.iter().any(|case| case.expected == required),
            "missing required denial"
        );
    }
    for case in cases {
        let (owner, request) = owner(case.case).await;
        let mut tx = owner.begin().await.unwrap();
        let verified = owner
            .trust
            .verify_request(&request, now_ms(&mut tx).await.unwrap())
            .unwrap();
        let attempt = &verified.claims().attempt;
        let before: i64 =
            sqlx::query_scalar("select count(*) from candidate.retired_candidate_payload")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        tx.rollback().await.unwrap();
        let (effect, original) = terminal(owner.execute(&request).await.unwrap());
        assert_eq!(
            effect,
            RetirementEffect::RejectedNoEffect {
                rejection: case.expected
            }
        );
        let mut tx = owner.begin().await.unwrap();
        let after: i64 =
            sqlx::query_scalar("select count(*) from candidate.retired_candidate_payload")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        tx.rollback().await.unwrap();
        assert_eq!(before, after);
        assert_eq!(terminal(owner.readback(attempt).await.unwrap()).1, original);
    }
}
