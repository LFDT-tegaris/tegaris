//! Actual installed-role proof; source publication and persistence remain with
//! their existing owners. This view test does not establish fact admission.
use super::*;
use openpc_indexer_adapter::GovernedSourcePublication;
use std::collections::BTreeMap;

pub(super) async fn prove(
    owner: &sqlx::PgPool,
    input: &GovernedSourcePublication,
    generation: Uuid,
    fenced: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read original identities from the durable producers, independently of the
    // admission view. A fence adds one event per registered partition, including
    // the empty partition; it does not create another candidate or checkpoint.
    let partitions: Vec<(Uuid, String, String)> = sqlx::query_as(
        "select candidate_partition_id,source_id,partition_id
        from candidate.candidate_partition where participant_id=$1 and privacy_domain_id=$2
          and projection_generation_id=$3 order by source_id,partition_id",
    )
    .bind(input.participant_id)
    .bind(input.privacy_domain_id)
    .bind(generation)
    .fetch_all(owner)
    .await?;
    assert_eq!(
        partitions
            .iter()
            .map(|(_, source, partition)| (source.as_str(), partition.as_str()))
            .collect::<Vec<_>>(),
        [("other-source", "other-partition"), ("source", "partition")]
    );
    let empty_partition = partitions[0].0;
    let active_partition = partitions[1].0;
    let candidates: Vec<(Uuid, String, Uuid)> = sqlx::query_as(
        "select candidate_event_id,record_id,candidate_partition_id from candidate.candidate_event
        where participant_id=$1 and privacy_domain_id=$2 and projection_generation_id=$3
        order by record_sequence",
    )
    .bind(input.participant_id)
    .bind(input.privacy_domain_id)
    .bind(generation)
    .fetch_all(owner)
    .await?;
    assert_eq!(
        candidates
            .iter()
            .map(|(_, record, partition)| (record.as_str(), *partition))
            .collect::<Vec<_>>(),
        [
            ("record-1-1", active_partition),
            ("record-1-2", active_partition)
        ]
    );
    let checkpoints: Vec<(Uuid, Vec<u8>, Uuid, String)> = sqlx::query_as(
        "select checkpoint_id,position_digest,candidate_partition_id,batch_id from candidate.checkpoint
        where participant_id=$1 and privacy_domain_id=$2 and projection_generation_id=$3",
    )
    .bind(input.participant_id)
    .bind(input.privacy_domain_id)
    .bind(generation)
    .fetch_all(owner)
    .await?;
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].2, active_partition);
    assert_eq!(checkpoints[0].3, "publication-batch");
    let publication_digest: Vec<u8> = sqlx::query_scalar(
        "select publication_digest from candidate.source_publication
        where participant_id=$1 and privacy_domain_id=$2 and projection_generation_id=$3",
    )
    .bind(input.participant_id)
    .bind(input.privacy_domain_id)
    .bind(generation)
    .fetch_one(owner)
    .await?;
    let mut expected = BTreeMap::from([
        (
            (active_partition, 1_u64),
            (
                "io.openpc.indexer.projection.candidate.observed.v1",
                Some(candidates[0].0),
                Some(checkpoints[0].0),
            ),
        ),
        (
            (active_partition, 2),
            (
                "io.openpc.indexer.projection.candidate.observed.v1",
                Some(candidates[1].0),
                Some(checkpoints[0].0),
            ),
        ),
        (
            (active_partition, 3),
            (
                "io.openpc.indexer.projection.checkpoint.completed.v1",
                None,
                Some(checkpoints[0].0),
            ),
        ),
    ]);
    if fenced {
        expected.insert(
            (active_partition, 4),
            ("io.openpc.indexer.projection.source.fenced.v1", None, None),
        );
        expected.insert(
            (empty_partition, 1),
            ("io.openpc.indexer.projection.source.fenced.v1", None, None),
        );
    }
    let originals = sqlx::query(
        "select event_id,aggregate_id,aggregate_sequence::text as sequence_text,event_type,
          payload_cbor,payload_digest,payload_json,source,subject,correlation_id,causation_id
        from candidate.outbox_event where participant_id=$1 and privacy_domain_id=$2
          and aggregate_type='candidate-partition' and aggregate_id=any($3::uuid[])",
    )
    .bind(input.participant_id)
    .bind(input.privacy_domain_id)
    .bind(vec![active_partition, empty_partition])
    .fetch_all(owner)
    .await?;
    assert_eq!(originals.len(), expected.len());
    let mut original_events = BTreeMap::new();
    let mut original_ids = BTreeSet::new();
    for original in originals {
        let key = (
            original.try_get::<Uuid, _>("aggregate_id")?,
            original
                .try_get::<String, _>("sequence_text")?
                .parse::<u64>()?,
        );
        let (kind, candidate, checkpoint) = expected
            .get(&key)
            .expect("unexpected producer event or sequence");
        assert_eq!(original.try_get::<String, _>("event_type")?, *kind);
        assert!(
            original_ids.insert(original.try_get::<Uuid, _>("event_id")?),
            "duplicate original event ID"
        );
        let payload = original.try_get::<serde_json::Value, _>("payload_json")?;
        assert_eq!(payload["authority"], "CANDIDATE_ONLY");
        let cbor = original.try_get::<Vec<u8>, _>("payload_cbor")?;
        assert_eq!(canonical_json_cbor(&payload)?, cbor);
        assert_eq!(
            Sha256::digest(&cbor).to_vec(),
            original.try_get::<Vec<u8>, _>("payload_digest")?
        );
        if let Some(candidate) = candidate {
            assert_eq!(
                payload["candidateId"],
                format!("urn:openpc:candidate:{candidate}")
            );
            assert_eq!(
                payload["sourceCursorDigest"],
                format!("sha256:{}", hex_bytes(&checkpoints[0].1))
            );
        } else if checkpoint.is_some() {
            assert_eq!(
                payload["checkpointDigest"],
                format!("sha256:{}", hex_bytes(&checkpoints[0].1))
            );
            assert_eq!(payload["batchId"], "publication-batch");
        } else {
            assert_eq!(
                payload,
                serde_json::json!({
                    "candidatePartitionId":format!("urn:openpc:candidate-partition:{}",key.0),
                    "projectionGenerationId":format!("urn:openpc:projection-generation:{generation}"),
                    "publicationDigest":format!("sha256:{}",hex_bytes(&publication_digest)),
                    "reasonCode":"GOVERNED_SOURCE_NOT_CURRENT","authority":"CANDIDATE_ONLY"
                })
            );
            assert_eq!(
                original.try_get::<String, _>("source")?,
                format!("urn:openpc:projection-generation:{generation}")
            );
            assert_eq!(
                original.try_get::<String, _>("subject")?,
                format!("urn:openpc:candidate-partition:{}", key.0)
            );
            assert_eq!(
                original.try_get::<Uuid, _>("correlation_id")?,
                uuid(OPERATION)
            );
            assert_eq!(
                original.try_get::<Option<Uuid>, _>("causation_id")?,
                Some(uuid(OPERATION))
            );
        }
        assert!(
            original_events.insert(key, original).is_none(),
            "duplicate partition sequence"
        );
    }
    let privileges: (bool, bool, bool) = sqlx::query_as(
        "select has_table_privilege('openpc_fact_bridge_reader','candidate.fact_bridge_admission_v1','SELECT'),
         has_table_privilege('openpc_fact_bridge_reader','candidate.source_profile','SELECT'),
         has_table_privilege('openpc_fact_bridge_reader','candidate.fact_bridge_admission_v1','UPDATE')",
    ).fetch_one(owner).await?;
    assert_eq!(privileges, (true, false, false));
    let barrier: bool = sqlx::query_scalar(
        "select 'security_barrier=true'=any(reloptions) from pg_class where oid='candidate.fact_bridge_admission_v1'::regclass",
    ).fetch_one(owner).await?;
    assert!(barrier);
    let mut unscoped = owner.begin().await?;
    sqlx::query("set local role openpc_fact_bridge_reader")
        .execute(&mut *unscoped)
        .await?;
    let denied = sqlx::query("select event_id from candidate.fact_bridge_admission_v1")
        .fetch_all(&mut *unscoped)
        .await;
    assert!(
        denied.is_err(),
        "a missing request context must fail closed"
    );
    unscoped.rollback().await?;
    for (participant, privacy, visible) in [
        (input.participant_id, input.privacy_domain_id, true),
        (Uuid::now_v7(), input.privacy_domain_id, false),
        (input.participant_id, Uuid::now_v7(), false),
    ] {
        let mut tx = owner.begin().await?;
        sqlx::query("set local role openpc_fact_bridge_reader")
            .execute(&mut *tx)
            .await?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)")
            .bind(participant)
            .bind(privacy)
            .bind(uuid(OPERATION))
            .bind(PROOF_ACTION)
            .execute(&mut *tx)
            .await?;
        let rows = sqlx::query(
            "select *,outbox_sequence::text as sequence_text from candidate.fact_bridge_admission_v1 where projection_generation_id=$1 order by candidate_partition_id,outbox_sequence",
        ).bind(generation).fetch_all(&mut *tx).await?;
        assert_eq!(rows.len(), if visible { expected.len() } else { 0 });
        let mut seen = BTreeSet::new();
        for row in &rows {
            let key = (
                row.try_get::<Uuid, _>("candidate_partition_id")?,
                row.try_get::<String, _>("sequence_text")?.parse::<u64>()?,
            );
            assert!(seen.insert(key), "duplicate admission partition sequence");
            let (kind, candidate, checkpoint) =
                expected.get(&key).expect("unexpected admission event");
            let original = original_events.get(&key).expect("original outbox event");
            assert_eq!(
                row.try_get::<Uuid, _>("event_id")?,
                original.try_get::<Uuid, _>("event_id")?
            );
            assert_eq!(row.try_get::<String, _>("event_type")?, *kind);
            assert_eq!(
                row.try_get::<Uuid, _>("participant_id")?,
                input.participant_id
            );
            assert_eq!(
                row.try_get::<Uuid, _>("privacy_domain_id")?,
                input.privacy_domain_id
            );
            assert_eq!(
                row.try_get::<Uuid, _>("projection_generation_id")?,
                generation
            );
            assert_eq!(
                row.try_get::<Vec<u8>, _>("event_payload_cbor")?,
                original.try_get::<Vec<u8>, _>("payload_cbor")?
            );
            assert_eq!(
                row.try_get::<Vec<u8>, _>("event_payload_digest")?,
                original.try_get::<Vec<u8>, _>("payload_digest")?
            );
            assert_eq!(
                row.try_get::<Option<Uuid>, _>("candidate_event_id")?,
                *candidate
            );
            assert_eq!(
                row.try_get::<Option<Uuid>, _>("checkpoint_id")?,
                *checkpoint
            );
            assert_eq!(
                row.try_get::<Vec<u8>, _>("source_profile_cbor")?,
                input.profile_cbor
            );
            assert_eq!(row.try_get::<Vec<u8>, _>("mapping_cbor")?, input.plan_cbor);
            assert_eq!(
                row.try_get::<Vec<u8>, _>("acquisition_configuration_cbor")?,
                input.acquisition_configuration_cbor
            );
            assert_eq!(
                row.try_get::<Vec<u8>, _>("finality_rule_cbor")?,
                input.finality_rule_cbor
            );
            assert_eq!(
                row.try_get::<i64, _>("source_revision")?,
                input.source_revision
            );
            assert_eq!(
                row.try_get::<Uuid, _>("qualification_operation_id")?,
                input.qualification_operation_id
            );
            assert_eq!(
                row.try_get::<String, _>("publication_state")?,
                if fenced { "FENCED" } else { "PUBLISHED" }
            );
            assert!(!row.try_get::<bool, _>("authority_eligible")?);
            if checkpoint.is_some() {
                assert_eq!(row.try_get::<String, _>("batch_id")?, "publication-batch");
                assert_eq!(
                    row.try_get::<Vec<u8>, _>("checkpoint_digest")?,
                    checkpoints[0].1
                );
            } else {
                // A source fence is not a candidate, checkpoint or reorg observation.
                assert!(row.try_get::<Option<String>, _>("batch_id")?.is_none());
                assert!(
                    row.try_get::<Option<Vec<u8>>, _>("checkpoint_cbor")?
                        .is_none()
                );
                assert!(row.try_get::<Option<Uuid>, _>("invalidation_id")?.is_none());
            }
            if candidate.is_some() {
                assert_eq!(row.try_get::<String, _>("record_kind")?, "STATE_CALL");
                assert!(
                    row.try_get::<Vec<u8>, _>("finality_evidence_digest")
                        .is_ok()
                );
            } else {
                assert!(
                    row.try_get::<Option<Vec<u8>>, _>("candidate_payload_cbor")?
                        .is_none()
                );
                assert!(row.try_get::<Option<String>, _>("record_kind")?.is_none());
                assert!(
                    row.try_get::<Option<Vec<u8>>, _>("finality_evidence_digest")?
                        .is_none()
                );
            }
        }
        tx.rollback().await?;
    }
    for forbidden in [
        "select source_profile_cbor from candidate.source_profile",
        "update candidate.source_publication set state='RETIRED'",
        "delete from candidate.candidate_event",
    ] {
        let mut tx = owner.begin().await?;
        sqlx::query("set local role openpc_fact_bridge_reader")
            .execute(&mut *tx)
            .await?;
        let error = sqlx::query(forbidden).execute(&mut *tx).await.unwrap_err();
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("42501")
        );
        tx.rollback().await?;
    }
    Ok(())
}
