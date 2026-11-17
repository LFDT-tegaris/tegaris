//! Real joined owner check. The surrounding gate must create source publication
//! and acquisition through their supported owners and keep actual Identity and
//! external provider TLS servers alive; this test seeds no business state.
use super::*;
use crate::deployment::DeployedFactBridge;
use serde::Deserialize;
use sqlx::{PgPool, Row};
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    deployment_file: PathBuf,
    fact_database_url_file: PathBuf,
    policy_reader_database_url_file: PathBuf,
    capability_secret_file: PathBuf,
    signing_secret_file: PathBuf,
    artifact_directory: PathBuf,
    participant: Uuid,
    privacy: Uuid,
    partition: Uuid,
    candidate_sequence: u64,
    #[serde(default = "one_record")]
    expected_record_count: u64,
    #[serde(default)]
    expected_family: FactFamily,
    #[serde(default)]
    resume_after_admission: bool,
    #[serde(default)]
    check_source_invalidation: bool,
    #[serde(default)]
    check_reorg_invalidation: bool,
    #[serde(default)]
    check_reorg_denial: bool,
    #[serde(default)]
    recovery: Option<RecoveryExpectation>,
}

#[derive(Default, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum FactFamily {
    #[default]
    State,
    Relationship,
    External,
}
impl FactFamily {
    fn schema(&self) -> u32 {
        if *self == Self::Relationship {
            pc_facts_core::RELATIONSHIP_FACT_SCHEMA_ID
        } else {
            pc_facts_core::FACT_RECORD_SCHEMA_ID
        }
    }
}

fn one_record() -> u64 {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryExpectation {
    predecessor_candidate: Uuid,
    predecessor_signed_digest: String,
    #[serde(default)]
    predecessor_signed_digests: std::collections::BTreeMap<String, String>,
    // A closed acceptance stage, never product authorization or claimed state.
    stage: RecoveryStage,
    #[serde(default)]
    request: Option<crate::deployment::RecoverGapRequest>,
}
#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RecoveryStage {
    Admitted,
    AdmissionRestart,
    PublicationRollback,
    Ready,
    ReadyReplay,
    DeepShortDenied,
    RebootstrapAdmitted,
    RebootstrapReady,
}

fn field<'a>(value: &'a ciborium::Value, name: &str) -> &'a ciborium::Value {
    &value
        .as_map()
        .unwrap()
        .iter()
        .find(|(key, _)| key.as_text() == Some(name))
        .unwrap()
        .1
}
fn secret(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap().trim().into()
}
fn key(path: &Path) -> [u8; 32] {
    let value = secret(path);
    assert_eq!(value.len(), 64);
    (0..32)
        .map(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
async fn snapshot(facts: &PgPool, input: &Input) -> (i64, i64, i64, i64) {
    let mut tx = facts.begin().await.unwrap();
    sqlx::query("select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)")
        .bind(input.participant.to_string()).bind(input.privacy.to_string()).execute(&mut *tx).await.unwrap();
    let result = sqlx::query_as("select (select count(*) from facts.canonical_fact),
        (select count(*) from facts.candidate_feed_receipt), (select count(*) from facts.evidence_occurrence),
        (select count(*) from facts.outbox)").fetch_one(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    result
}

async fn retirement(facts: &PgPool, input: &Input, candidate: Uuid) -> sqlx::postgres::PgRow {
    let mut tx = facts.begin().await.unwrap();
    sqlx::query("select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)")
        .bind(input.participant.to_string()).bind(input.privacy.to_string()).execute(&mut *tx).await.unwrap();
    let row = sqlx::query("select f.cose_sign1 fact_cose,l.cose_sign1 lineage_cose,l.lineage_digest,l.source_event_id,
        l.source_sequence,l.source_payload_digest,l.authority_digest,l.affected_start::text,l.affected_end::text,
        i.reason,i.replacement_candidate_id,g.state::text gate_state,g.shard_verified,c.state::text checkpoint_state,
        (select count(*) from facts.lineage_outbox) lineage_count
        from facts.canonical_fact f join facts.lineage_outbox l using(candidate_id,participant_id,privacy_domain_id,generation_id)
        join facts.fact_invalidation i using(candidate_id,participant_id,privacy_domain_id)
        join facts.readiness_gate g using(participant_id,privacy_domain_id,generation_id)
        join facts.admission_inbox inbox using(candidate_id,participant_id,privacy_domain_id)
        join facts.source_checkpoint c using(participant_id,privacy_domain_id,source_profile_id)
        where f.candidate_id=$1")
        .bind(candidate.to_string()).fetch_one(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    row
}

#[tokio::test]
#[ignore = "requires governed real source/candidate, Identity mTLS, provider TLS and separate Control/Candidate/Fact roles"]
async fn real_scoped_candidate_is_independently_admitted_once_across_restart() {
    let input: Input = serde_json::from_slice(
        &std::fs::read(std::env::var("OPENPC_FACT_ADMISSION_TEST_INPUT_FILE").unwrap()).unwrap(),
    )
    .unwrap();
    let pool = PgPool::connect(&secret(&input.fact_database_url_file))
        .await
        .unwrap();
    let facts = FactStore::new(pool.clone(), key(&input.capability_secret_file));
    let signer =
        PurposeBoundFactSigner::for_local_runtime(key(&input.signing_secret_file)).unwrap();
    let bridge = DeployedFactBridge::connect(&input.deployment_file)
        .await
        .unwrap();
    let scope =
        || CandidateReadScope::new(input.participant, input.privacy, Uuid::now_v7()).unwrap();
    if input.check_source_invalidation || input.check_reorg_invalidation {
        // The surrounding integrated gate has replaced this source through
        // public governance and the real manager's remove-before-publish pass.
        // Read its durable withdrawal; never seed an invalidation or readiness.
        let deployment: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&input.deployment_file).unwrap()).unwrap();
        let candidates = CandidateFeedReader::connect(&secret(&PathBuf::from(
            deployment["candidate_database_url_file"].as_str().unwrap(),
        )))
        .await
        .unwrap();
        let mut feed = candidates
            .read_partition(scope(), input.partition)
            .await
            .unwrap();
        let event = feed.event(input.candidate_sequence).await.unwrap().unwrap();
        if input.check_source_invalidation {
            assert_eq!(event.publication_state.as_deref(), Some("FENCED"));
        }
        let payload: serde_json::Value =
            ciborium::de::from_reader(event.payload_cbor.as_slice()).unwrap();
        let candidate = Uuid::parse_str(
            payload["candidateId"]
                .as_str()
                .unwrap()
                .strip_prefix("urn:openpc:candidate:")
                .unwrap(),
        )
        .unwrap();
        let (event_id, event_sequence, event_payload) = if input.check_source_invalidation {
            let mut fence = feed
                .source_fence(input.candidate_sequence + input.expected_record_count + 1)
                .await
                .unwrap()
                .unwrap();
            assert!(
                fence.terminal_prefix.is_some(),
                "complete native fenced prefix"
            );
            let original = fence.event_id;
            fence.event_id = Uuid::now_v7();
            assert!(feed.withdrawal_prefix(&fence).await.unwrap().is_none());
            fence.event_id = original;
            (fence.event_id, fence.sequence, fence.payload)
        } else {
            let event = feed
                .source_reorg(input.candidate_sequence + input.expected_record_count + 1)
                .await
                .unwrap()
                .unwrap();
            (
                event.event.event_id,
                event.event.sequence,
                event.event.payload_cbor,
            )
        };
        feed.close().await.unwrap();
        candidates.close().await;
        let unchanged_history = snapshot(&pool, &input).await;
        if input.check_reorg_invalidation {
            assert!(
                facts
                    .invalidate_for_reorg(
                        &input.participant.to_string(),
                        &input.privacy.to_string(),
                        &candidate.to_string()
                    )
                    .await
                    .is_err(),
                "complete source facts require signed independently verified invalidation"
            );
        }
        if input.check_reorg_denial {
            let before = facts
                .admission_readback(input.participant, input.privacy, candidate)
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(
                    bridge.reconcile_source_withdrawals(&facts, &signer).await,
                    Err(StateAdmissionError::Source(SourceAuthorityError::Binding))
                ),
                "unconfirmed candidate mismatch cannot sign an invalidation"
            );
            assert_eq!(
                facts
                    .admission_readback(input.participant, input.privacy, candidate)
                    .await
                    .unwrap()
                    .unwrap()
                    .state,
                before.state
            );
            assert_eq!(snapshot(&pool, &input).await, unchanged_history);
            return;
        }
        bridge
            .reconcile_source_withdrawals(&facts, &signer)
            .await
            .expect("durable candidate invalidation must reach the FactStore lifecycle owner");
        let receipt = facts
            .admission_readback(input.participant, input.privacy, candidate)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            receipt.state,
            if input.check_reorg_invalidation {
                "REORG_TOMBSTONED"
            } else {
                "RETIRED"
            },
            "governed source withdrawal must durably invalidate the admitted fact before replacement, independently of policy reads or collector credentials"
        );

        let row = retirement(&pool, &input, candidate).await;
        assert_eq!(
            row.get::<String, _>("gate_state"),
            if input.check_reorg_invalidation {
                "REORG"
            } else {
                "STALE"
            }
        );
        assert!(!row.get::<bool, _>("shard_verified"));
        assert_eq!(
            row.get::<String, _>("checkpoint_state"),
            if input.check_reorg_invalidation {
                "REORG_FENCED"
            } else {
                "COMPLETE"
            }
        );
        assert_eq!(
            row.get::<String, _>("reason"),
            if input.check_reorg_invalidation {
                "REORG"
            } else {
                "RETIREMENT"
            }
        );
        assert!(
            row.get::<Option<String>, _>("replacement_candidate_id")
                .is_none()
        );
        assert_eq!(row.get::<Uuid, _>("source_event_id"), event_id);
        assert_eq!(row.get::<i64, _>("source_sequence") as u64, event_sequence);
        assert_eq!(
            row.get::<Vec<u8>, _>("source_payload_digest"),
            pc_facts_core::sha256(&event_payload)
        );
        let fact_cose: Vec<u8> = row.get("fact_cose");
        let fact_claims = signer
            .verifier()
            .verified_stored_claims(pc_facts_core::FACT_RECORD_SCHEMA_ID, &fact_cose)
            .unwrap();
        let record = pc_facts_core::FactRecord::from_cbor(
            &pc_facts_core::encode_pc_cbor(fact_claims).unwrap(),
        )
        .unwrap();
        let signed: Vec<u8> = row.get("lineage_cose");
        assert_eq!(
            row.get::<Vec<u8>, _>("lineage_digest"),
            pc_facts_core::sha256(&signed)
        );
        let claims = signer
            .verifier()
            .verified_stored_claims(21004, &signed)
            .unwrap();
        assert_eq!(
            field(&claims, "action").as_text(),
            Some(if input.check_reorg_invalidation {
                "INVALIDATE"
            } else {
                "RETIRE"
            })
        );
        assert_eq!(
            field(&claims, "targetFactId").as_text(),
            Some(record.identity.fact_id.as_str())
        );
        assert_eq!(
            field(&claims, "targetGeneration").as_integer().unwrap(),
            record.identity.canonical_generation.into()
        );
        assert_eq!(
            field(&claims, "causationId").as_text(),
            Some(event_id.to_string().as_str())
        );
        assert_eq!(
            field(&claims, "authorityContextDigest").as_text(),
            Some(
                crate::signing::shard::digest_text(&row.get::<Vec<u8>, _>("authority_digest"))
                    .as_str()
            )
        );
        assert_eq!(
            pc_facts_core::encode_pc_cbor(field(&claims, "affectedRange").clone()).unwrap(),
            pc_facts_core::encode_pc_cbor(
                if input.check_reorg_invalidation {
                    ciborium::Value::serialized(&serde_json::json!({"partitionId":record.completeness_scope.partition_id,"rangeStart":10,"rangeEnd":9+input.expected_record_count})).unwrap()
                } else {ciborium::Value::serialized(&record.completeness_scope).unwrap()}
            )
            .unwrap()
        );
        assert_eq!(row.get::<String, _>("affected_start"), "10");
        assert_eq!(
            row.get::<String, _>("affected_end"),
            (9 + input.expected_record_count).to_string()
        );
        let mut forged = signed.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(
            signer
                .verifier()
                .verified_stored_claims(21004, &forged)
                .is_err()
        );
        if input.check_source_invalidation {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)")
                .bind(input.participant.to_string()).bind(input.privacy.to_string())
                .execute(&mut *tx).await.unwrap();
            let closure:(Uuid,i64,Vec<u8>) = sqlx::query_as("select source_event_id,source_sequence,prefix_digest from facts.withdrawal_checkpoint where participant_id=$1 and privacy_domain_id=$2 and partition_id=$3")
                .bind(input.participant.to_string()).bind(input.privacy.to_string()).bind(input.partition)
                .fetch_one(&mut *tx).await.unwrap();
            assert_eq!(closure.0, event_id);
            assert_eq!(closure.1, event_sequence as i64);
            assert_eq!(closure.2.len(), 32);
            tx.rollback().await.unwrap();
        }
        assert_eq!(snapshot(&pool, &input).await, unchanged_history);
        drop(bridge);
        pool.close().await;
        let reopened = PgPool::connect(&secret(&input.fact_database_url_file))
            .await
            .unwrap();
        let facts = FactStore::new(reopened.clone(), key(&input.capability_secret_file));
        let restarted = DeployedFactBridge::connect(&input.deployment_file)
            .await
            .unwrap();
        assert_eq!(
            restarted
                .reconcile_source_withdrawals(&facts, &signer)
                .await
                .unwrap(),
            0
        );
        let after = retirement(&reopened, &input, candidate).await;
        assert_eq!(after.get::<Vec<u8>, _>("lineage_cose"), signed);
        assert_eq!(after.get::<Vec<u8>, _>("fact_cose"), fact_cose);
        assert_eq!(
            after.get::<i64, _>("lineage_count"),
            row.get::<i64, _>("lineage_count")
        );
        let reader_pool = PgPool::connect(&secret(&input.policy_reader_database_url_file))
            .await
            .unwrap();
        let reader = crate::PolicyFactReader::new(reader_pool.clone(), signer.verifier());
        assert_eq!(
            reader
                .read(
                    &input.participant.to_string(),
                    &input.privacy.to_string(),
                    &candidate.to_string()
                )
                .await
                .unwrap()
                .unwrap()
                .outcome,
            if input.check_reorg_invalidation {
                pc_facts_core::FactQueryOutcome::Reorg
            } else {
                pc_facts_core::FactQueryOutcome::Stale
            }
        );
        assert!(
            reader
                .read(
                    &input.participant.to_string(),
                    &Uuid::now_v7().to_string(),
                    &candidate.to_string()
                )
                .await
                .unwrap()
                .is_none()
        );
        let mut tx = reader_pool.begin().await.unwrap();
        sqlx::query("select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)")
            .bind(input.participant.to_string()).bind(Uuid::now_v7().to_string()).execute(&mut *tx).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("select count(*) from facts.lineage_outbox")
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            0
        );
        tx.rollback().await.unwrap();
        reader_pool.close().await;
        reopened.close().await;
        return;
    }
    let before = snapshot(&pool, &input).await;
    if let Some(recovery) = &input.recovery
        && let Some(request) = &recovery.request
        && !input.resume_after_admission
    {
        assert_rebootstrap_authority(&bridge, &facts, &signer, &pool, &input, request).await;
        assert_eq!(snapshot(&pool, &input).await, before);
    }
    assert!(matches!(
        bridge
            .consume(
                CandidateReadScope::new(Uuid::now_v7(), input.privacy, Uuid::now_v7()).unwrap(),
                input.partition,
                input.candidate_sequence,
                &facts,
                &signer
            )
            .await,
        Err(StateAdmissionError::Candidate(CandidateFeedError::Scope))
    ));
    if input
        .recovery
        .as_ref()
        .is_some_and(|r| r.stage == RecoveryStage::DeepShortDenied)
    {
        assert!(
            bridge
                .consume(
                    scope(),
                    input.partition,
                    input.candidate_sequence,
                    &facts,
                    &signer
                )
                .await
                .is_err(),
            "Deep reorg cannot use ordinary replacement authority"
        );
        assert_eq!(
            snapshot(&pool, &input).await,
            before,
            "Denied recovery cannot create a fact, receipt or effect"
        );
        assert_recovery_boundary(&pool, &input, &signer, None, false).await;
        pool.close().await;
        return;
    }
    let outcome = bridge
        .consume(
            scope(),
            input.partition,
            input.candidate_sequence,
            &facts,
            &signer,
        )
        .await
        .unwrap();
    let expected = if input.resume_after_admission {
        assert_eq!(outcome, DurableAdmissionOutcome::IdempotentReplay);
        before
    } else {
        assert_eq!(outcome, DurableAdmissionOutcome::AdmittedNotReady);
        (
            before.0 + input.expected_record_count as i64,
            before.1 + input.expected_record_count as i64 + 1,
            before.2 + input.expected_record_count as i64,
            before.3 + input.expected_record_count as i64,
        )
    };
    assert_eq!(snapshot(&pool, &input).await, expected);
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)")
        .bind(input.participant.to_string()).bind(input.privacy.to_string()).execute(&mut *tx).await.unwrap();
    let row = sqlx::query("select f.state::text,f.candidate_id,f.generation_id,f.canonical_payload,f.cose_sign1,r.canonical_provenance from facts.candidate_feed_receipt r
        join facts.canonical_fact f on f.candidate_id=r.candidate_id where r.partition_id=$1 and r.candidate_sequence=$2")
        .bind(input.partition).bind(input.candidate_sequence as i64).fetch_one(&mut *tx).await.unwrap();
    assert!(matches!(
        row.get::<String, _>("state").as_str(),
        "ADMITTED" | "FINALIZED"
    ));
    let candidate_id: String = row.get("candidate_id");
    let claims = signer
        .verifier()
        .verified_stored_claims(
            input.expected_family.schema(),
            &row.get::<Vec<u8>, _>("cose_sign1"),
        )
        .unwrap();
    let canonical_record = pc_facts_core::encode_pc_cbor(claims).unwrap();
    let record = pc_facts_core::FactRecord::from_cbor(&canonical_record).unwrap();
    assert_eq!(
        record.identity.participant_id,
        format!("urn:openpc:participant:{}", input.participant)
    );
    assert_eq!(
        record.identity.privacy_domain_id,
        Some(format!("urn:openpc:privacy-domain:{}", input.privacy))
    );
    let payload = crate::state_value::StateFactValue::from_payload(
        &row.get::<Vec<u8>, _>("canonical_payload"),
        &input.participant.to_string(),
        &input.privacy.to_string(),
    )
    .unwrap();
    match input.expected_family {
        FactFamily::State => {
            assert_eq!(payload.mapping, "openpc:abi-state-result:v1");
            assert_eq!(payload.signature, "balanceOf(address)");
            let mut expected_value = [0; 32];
            expected_value[30..].copy_from_slice(&[0x12, 0x34]);
            assert_eq!(
                payload.typed_result,
                vec![pc_policy_core::invocation::ArgumentValue::Uint(
                    expected_value
                )]
            );
        }
        FactFamily::Relationship => {
            assert_eq!(payload.mapping, "RGRA_EVENT_RELATIONSHIP_V1");
            assert!(matches!(
                record.identity.typed_subject,
                pc_facts_core::FactSubject::Relationship { .. }
            ));
            assert!(matches!(
                record.value,
                pc_facts_core::FactObject::RelationshipInterval {
                    successful_execution: true,
                    ..
                }
            ));
        }
        FactFamily::External => {
            assert!(payload.typed_result.is_empty());
            assert!(matches!(
                record.identity.typed_subject,
                pc_facts_core::FactSubject::ExternalDecision { .. }
            ));
            assert!(matches!(
                record.value,
                pc_facts_core::FactObject::ExternalObservation {
                    satisfied: true,
                    ..
                }
            ));
        }
    }
    let provenance: ciborium::Value =
        ciborium::de::from_reader(row.get::<Vec<u8>, _>("canonical_provenance").as_slice())
            .unwrap();
    assert_eq!(
        field(&provenance, "purpose").as_text(),
        Some("openpc:independent-state-admission:v1")
    );
    assert!(
        !field(&provenance, "providerObservations")
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        u64::try_from(
            field(
                field(&provenance, "factAdmissionProfile"),
                "maximumStalenessMs"
            )
            .as_integer()
            .unwrap()
        )
        .unwrap(),
        record.max_age_ms
    );
    tx.rollback().await.unwrap();
    drop(bridge);
    let bridge = DeployedFactBridge::connect(&input.deployment_file)
        .await
        .unwrap();
    assert_eq!(
        bridge
            .consume(
                scope(),
                input.partition,
                input.candidate_sequence,
                &facts,
                &signer
            )
            .await
            .unwrap(),
        DurableAdmissionOutcome::IdempotentReplay
    );
    assert_eq!(snapshot(&pool, &input).await, expected);
    if let Some(recovery) = &input.recovery {
        assert_recovery_boundary(
            &pool,
            &input,
            &signer,
            Some(&candidate_id),
            recovery.stage == RecoveryStage::ReadyReplay,
        )
        .await;
        assert!(record.predecessor_digest.is_some());
        assert!(
            record.reorg_replacement_of.is_some(),
            "Replacement must carry the immutable predecessor identity"
        );
        if matches!(
            recovery.stage,
            RecoveryStage::Admitted
                | RecoveryStage::AdmissionRestart
                | RecoveryStage::RebootstrapAdmitted
        ) {
            pool.close().await;
            return;
        }
        if recovery.stage == RecoveryStage::PublicationRollback {
            let mut transaction = pool.begin().await.unwrap();
            let ready = facts
                .publish_candidate_in_transaction(
                    &mut transaction,
                    &input.participant.to_string(),
                    &input.privacy.to_string(),
                    &candidate_id,
                    &signer,
                    &input.artifact_directory,
                )
                .await
                .unwrap();
            assert!(
                ready,
                "Exercise the actual verified publication transaction before rollback"
            );
            transaction.rollback().await.unwrap();
            assert_recovery_boundary(&pool, &input, &signer, Some(&candidate_id), false).await;
            assert_eq!(snapshot(&pool, &input).await, expected);
            pool.close().await;
            return;
        }
    }
    // An unavailable publication destination preserves admission and cannot
    // grant readiness. The same immutable bytes can be retried after recovery.
    if !input.artifact_directory.exists() {
        std::fs::write(&input.artifact_directory, b"unavailable artifact directory").unwrap();
        assert!(
            bridge
                .publish(
                    scope(),
                    Uuid::parse_str(&candidate_id).unwrap(),
                    &facts,
                    &signer
                )
                .await
                .is_err()
        );
        std::fs::remove_file(&input.artifact_directory).unwrap();
    }
    let ready = bridge
        .publish(
            scope(),
            Uuid::parse_str(&candidate_id).unwrap(),
            &facts,
            &signer,
        )
        .await
        .unwrap();
    drop(bridge);
    let bridge = DeployedFactBridge::connect(&input.deployment_file)
        .await
        .unwrap();
    assert_eq!(
        bridge
            .publish(
                scope(),
                Uuid::parse_str(&candidate_id).unwrap(),
                &facts,
                &signer
            )
            .await
            .unwrap(),
        ready
    );
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)")
        .bind(input.participant.to_string()).bind(input.privacy.to_string()).execute(&mut *tx).await.unwrap();
    let published: bool = sqlx::query_scalar("select exists(select 1 from facts.readiness_gate where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3 and state='READY' and shard_verified and shard_cose_sign1 is not null)")
        .bind(input.participant.to_string()).bind(input.privacy.to_string()).bind(row.get::<String, _>("generation_id"))
        .fetch_one(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    assert!(
        (ready && published) || (!ready && input.resume_after_admission),
        "COM-019 must durably publish and verify the complete signed generation"
    );
    drop(bridge);
    let reader_pool = PgPool::connect(&secret(&input.policy_reader_database_url_file))
        .await
        .unwrap();
    let reader = crate::PolicyFactReader::new(reader_pool.clone(), signer.verifier());
    let positive = reader
        .read(
            &input.participant.to_string(),
            &input.privacy.to_string(),
            &candidate_id,
        )
        .await
        .unwrap()
        .expect("durable admitted fact");
    assert_eq!(
        positive.outcome,
        if ready {
            pc_facts_core::FactQueryOutcome::Present
        } else {
            pc_facts_core::FactQueryOutcome::Stale
        },
        "COM-019 must publish and verify the complete signed generation before this acquired fact can be consumed"
    );
    assert!(
        reader
            .read(
                &Uuid::now_v7().to_string(),
                &input.privacy.to_string(),
                &candidate_id
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        reader
            .read(
                &input.participant.to_string(),
                &Uuid::now_v7().to_string(),
                &candidate_id
            )
            .await
            .unwrap()
            .is_none()
    );
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)")
        .bind(input.participant.to_string()).bind(input.privacy.to_string()).execute(&mut *tx).await.unwrap();
    let publication = sqlx::query("select p.manifest_digest,p.content_digest,p.descriptor,g.shard_cose_sign1
        from facts.shard_publication p join facts.readiness_gate g using(participant_id,privacy_domain_id,generation_id)
        where p.participant_id=$1 and p.privacy_domain_id=$2 and p.generation_id=$3")
        .bind(input.participant.to_string()).bind(input.privacy.to_string()).bind(row.get::<String,_>("generation_id"))
        .fetch_optional(&mut *tx).await.unwrap();
    if let Some(publication) = publication {
        let manifest: Vec<u8> = publication.get("shard_cose_sign1");
        assert_eq!(
            publication.get::<Vec<u8>, _>("manifest_digest"),
            pc_facts_core::sha256(&manifest)
        );
        let batch = sqlx::query("select f.candidate_id,f.cose_sign1 from facts.canonical_fact f
            join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id,generation_id)
            where f.participant_id=$1 and f.privacy_domain_id=$2 and f.generation_id=$3 order by a.delta_sequence")
            .bind(input.participant.to_string()).bind(input.privacy.to_string())
            .bind(row.get::<String,_>("generation_id")).fetch_all(&mut *tx).await.unwrap();
        assert_eq!(batch.len() as u64, input.expected_record_count);
        let signed_records: Vec<Vec<u8>> = batch.iter().map(|r| r.get("cose_sign1")).collect();
        let records: Vec<_> = signed_records
            .iter()
            .map(|bytes| {
                let claims = signer
                    .verifier()
                    .verified_stored_claims(input.expected_family.schema(), bytes)
                    .unwrap();
                pc_facts_core::FactRecord::from_cbor(
                    &pc_facts_core::encode_pc_cbor(claims).unwrap(),
                )
                .unwrap()
            })
            .collect();
        pc_facts_core::FactRecord::validate_batch(&records).unwrap();
        let content = crate::signing::shard::content_bytes(&signed_records).unwrap();
        assert_eq!(
            publication.get::<Vec<u8>, _>("content_digest"),
            pc_facts_core::sha256(&content)
        );
        let content_path = input
            .artifact_directory
            .join("blobs/sha256")
            .join(&crate::signing::shard::digest_text(&pc_facts_core::sha256(&content))[7..]);
        assert_eq!(std::fs::read(content_path).unwrap(), content);
        if ready && input.expected_family == FactFamily::External {
            use pc_policy_core::fact_condition::FactCondition;
            use pc_runtime_types::Digest;
            let verified = signer.verifier().verify_shard_cose(&manifest).unwrap();
            let local = signer
                .verifier()
                .verify_local_facts(&verified, &content)
                .unwrap();
            let pc_facts_core::FactSubject::ExternalDecision {
                provider_id,
                provider_version,
                configuration_digest,
                request_digest,
                condition,
                ..
            } = &record.identity.typed_subject
            else {
                panic!("external record required")
            };
            assert_eq!(condition, "eligible");
            let predicate = FactCondition::ExternalObservation {
                fact: pc_policy_core::semantics::FactReference {
                    candidate_id: candidate_id.clone(),
                    generation_id: row.get("generation_id"),
                    fact_digest: record.identity.local_fact_digest.clone(),
                },
                provider_id: provider_id.clone(),
                provider_version: provider_version.clone(),
                provider_configuration_digest: Digest::parse(
                    configuration_digest.trim_start_matches("sha256:"),
                )
                .unwrap(),
                request_digest: Digest::parse(request_digest.trim_start_matches("sha256:"))
                    .unwrap(),
                condition: condition.clone(),
            };
            let workload = "urn:openpc:workload:018f0000-0000-7000-8000-000000000191";
            assert_eq!(
                local.evaluate_at_snapshot_anchor(&predicate, workload),
                pc_facts_core::RelationshipResult::MemberConfirmed
            );
            let mut wrong = predicate;
            if let FactCondition::ExternalObservation { request_digest, .. } = &mut wrong {
                *request_digest = Digest::of(b"wrong occurrence");
            }
            assert_ne!(
                local.evaluate_at_snapshot_anchor(&wrong, workload),
                pc_facts_core::RelationshipResult::MemberConfirmed
            );
        }
        for entry in &batch {
            let value = reader
                .read(
                    &input.participant.to_string(),
                    &input.privacy.to_string(),
                    &entry.get::<String, _>("candidate_id"),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                value.outcome == pc_facts_core::FactQueryOutcome::Present,
                ready
            );
        }
        let descriptor: serde_json::Value = publication.get("descriptor");
        assert_eq!(descriptor["size"].as_u64(), Some(manifest.len() as u64));
        assert_eq!(
            descriptor["digest"].as_str(),
            Some(crate::signing::shard::digest_text(&pc_facts_core::sha256(&manifest)).as_str())
        );
        let mut forged = manifest;
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(signer.verifier().verify_shard_cose(&forged).is_err());
    } else {
        assert!(!ready && input.resume_after_admission);
    }
    tx.rollback().await.unwrap();
    if input.recovery.is_some() {
        assert_recovery_boundary(&pool, &input, &signer, Some(&candidate_id), true).await;
    }
    reader_pool.close().await;
    pool.close().await;
}

// This oracle checks durable business state after real owner calls. It never
// installs approval, activation, candidates, readiness or recovery success.
async fn assert_recovery_boundary(
    pool: &PgPool,
    input: &Input,
    signer: &PurposeBoundFactSigner,
    replacement: Option<&str>,
    ready: bool,
) {
    let expected = input.recovery.as_ref().unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)")
        .bind(input.participant.to_string()).bind(input.privacy.to_string()).execute(&mut *tx).await.unwrap();
    let mut predecessors = expected.predecessor_signed_digests.clone();
    predecessors
        .entry(expected.predecessor_candidate.to_string())
        .or_insert_with(|| expected.predecessor_signed_digest.clone());
    assert_eq!(predecessors.len() as u64, input.expected_record_count);
    let mut old_generation = None;
    let mut replacements = Vec::new();
    for (candidate, signed_digest) in &predecessors {
        let old = sqlx::query("select f.state::text,f.generation_id,encode(sha256(f.cose_sign1),'hex') signed_digest,
            g.state::text gate_state,g.shard_verified,c.state::text checkpoint_state,
            invalidation.replacement_candidate_id,
            (select count(*) from facts.lineage_outbox l where l.candidate_id=f.candidate_id
              and l.event_type='io.openpc.fact.fact.superseded.v1') supersessions
            from facts.canonical_fact f join facts.admission_inbox i using(candidate_id,participant_id,privacy_domain_id)
            join facts.fact_invalidation invalidation using(candidate_id,participant_id,privacy_domain_id)
            join facts.source_checkpoint c on c.participant_id=f.participant_id
              and c.privacy_domain_id=f.privacy_domain_id and c.source_profile_id=i.source_profile_id
            join facts.readiness_gate g on g.participant_id=f.participant_id
              and g.privacy_domain_id=f.privacy_domain_id and g.generation_id=f.generation_id
            where f.candidate_id=$1").bind(candidate).fetch_one(&mut *tx).await.unwrap();
        let generation: String = old.get("generation_id");
        assert_eq!(
            old_generation.get_or_insert_with(|| generation.clone()),
            &generation
        );
        assert_eq!(&old.get::<String, _>("signed_digest"), signed_digest);
        assert_eq!(
            old.get::<String, _>("state"),
            if ready {
                "SUPERSEDED"
            } else {
                "REORG_TOMBSTONED"
            }
        );
        assert_eq!(old.get::<String, _>("gate_state"), "REORG");
        assert!(!old.get::<bool, _>("shard_verified"));
        assert_eq!(
            old.get::<String, _>("checkpoint_state"),
            if ready { "COMPLETE" } else { "REORG_FENCED" }
        );
        assert_eq!(old.get::<i64, _>("supersessions"), i64::from(ready));
        let next: Option<String> = old.get("replacement_candidate_id");
        assert_eq!(next.is_some(), replacement.is_some());
        if let Some(next) = next {
            assert_ne!(&next, candidate);
            assert!(!replacements.contains(&next));
            replacements.push(next);
        }
        if ready {
            let bytes: Vec<u8> = sqlx::query_scalar(
                "select cose_sign1 from facts.lineage_outbox where candidate_id=$1
                and event_type='io.openpc.fact.fact.superseded.v1'",
            )
            .bind(candidate)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            let claims: serde_json::Value = signer
                .verifier()
                .verified_stored_claims(21004, &bytes)
                .unwrap()
                .deserialized()
                .unwrap();
            assert_eq!(claims["action"], "SUPERSEDE");
            assert!(
                claims["predecessorDigest"]
                    .as_str()
                    .unwrap()
                    .starts_with("sha256:")
            );
            assert_ne!(claims["replacementFactId"], claims["targetFactId"]);
            assert_eq!(claims["reorgReplacementOf"], claims["targetFactId"]);
        }
    }
    if let Some(first) = replacement {
        assert!(replacements.iter().any(|candidate| candidate == first));
    }
    let resolved = sqlx::query(
        "select cose_sign1,recovery_cursor_cbor from facts.lineage_outbox
        where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3
        and event_type='io.openpc.fact.gap.resolved.v1'",
    )
    .bind(input.participant.to_string())
    .bind(input.privacy.to_string())
    .bind(old_generation.unwrap())
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    assert_eq!(
        resolved.len(),
        usize::from(ready && expected.request.is_some())
    );
    if let (Some(row), Some(request)) = (resolved.first(), &expected.request) {
        let cursor_bytes: Vec<u8> = row.get("recovery_cursor_cbor");
        // The cursor contains a complete feed batch with byte strings. Keep
        // the oracle in CBOR rather than forcing those bytes through JSON.
        let cursor: ciborium::Value = ciborium::de::from_reader(cursor_bytes.as_slice()).unwrap();
        let actual_request: crate::deployment::RecoverGapRequest =
            field(&cursor, "request").deserialized().unwrap();
        assert_eq!(&actual_request, request);
        assert_eq!(
            field(&cursor, "participant").as_text(),
            Some(input.participant.to_string().as_str())
        );
        assert_eq!(
            field(&cursor, "privacy").as_text(),
            Some(input.privacy.to_string().as_str())
        );
        assert_ne!(
            field(&cursor, "priorSourceGeneration").as_text().unwrap(),
            request.new_source_generation.to_string()
        );
        assert!(
            u64::try_from(field(&cursor, "verifiedDepth").as_integer().unwrap()).unwrap()
                > u64::try_from(field(&cursor, "retainedTailBlocks").as_integer().unwrap())
                    .unwrap()
        );
        let claims: serde_json::Value = signer
            .verifier()
            .verified_stored_claims(21008, &row.get::<Vec<u8>, _>("cose_sign1"))
            .unwrap()
            .deserialized()
            .unwrap();
        assert_eq!(claims["state"], "COMPLETE");
        assert_eq!(claims["partitionId"], request.new_partition.to_string());
        assert_eq!(claims["completedWatermark"], request.end_watermark);
        assert_eq!(
            claims["evidenceRefs"][0],
            crate::signing::shard::digest_text(&pc_facts_core::sha256(&cursor_bytes))
        );
    }
    for candidate in &replacements {
        let next = sqlx::query("select f.state::text,g.state::text gate_state,g.shard_verified from facts.canonical_fact f
            join facts.readiness_gate g using(participant_id,privacy_domain_id,generation_id) where candidate_id=$1")
            .bind(candidate).fetch_one(&mut *tx).await.unwrap();
        assert_eq!(
            next.get::<String, _>("state"),
            if ready { "FINALIZED" } else { "ADMITTED" }
        );
        assert_eq!(
            next.get::<String, _>("gate_state"),
            if ready { "READY" } else { "BLOCKED" }
        );
        assert_eq!(next.get::<bool, _>("shard_verified"), ready);
    }
    tx.rollback().await.unwrap();
    let reader_pool = PgPool::connect(&secret(&input.policy_reader_database_url_file))
        .await
        .unwrap();
    let reader = crate::PolicyFactReader::new(reader_pool.clone(), signer.verifier());
    for candidate in predecessors.keys() {
        let old = reader
            .read(
                &input.participant.to_string(),
                &input.privacy.to_string(),
                candidate,
            )
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            old.outcome,
            pc_facts_core::FactQueryOutcome::Present,
            "Predecessor never revives"
        );
        if !ready {
            assert_eq!(old.outcome, pc_facts_core::FactQueryOutcome::Reorg);
        }
    }
    for candidate in &replacements {
        let next = reader
            .read(
                &input.participant.to_string(),
                &input.privacy.to_string(),
                candidate,
            )
            .await
            .unwrap()
            .unwrap();
        if ready
            && expected.stage == RecoveryStage::ReadyReplay
            && next.snapshot_at_ms >= next.fresh_until_ms
        {
            // Restart preserves the verified cutover, not expired authority.
            // The initial READY stage still requires live positive consumption.
            assert_eq!(next.outcome, pc_facts_core::FactQueryOutcome::Stale);
        } else {
            assert_eq!(
                next.outcome == pc_facts_core::FactQueryOutcome::Present,
                ready
            );
        }
    }
    reader_pool.close().await;
}

async fn assert_rebootstrap_authority(
    bridge: &DeployedFactBridge,
    facts: &FactStore,
    signer: &PurposeBoundFactSigner,
    pool: &PgPool,
    input: &Input,
    request: &crate::deployment::RecoverGapRequest,
) {
    let scope =
        || CandidateReadScope::new(input.participant, input.privacy, Uuid::now_v7()).unwrap();
    let before = snapshot(pool, input).await;
    assert!(
        bridge
            .recover_gap(
                CandidateReadScope::new(input.participant, Uuid::now_v7(), Uuid::now_v7()).unwrap(),
                request,
                facts,
                signer,
            )
            .await
            .is_err()
    );
    // Each negative changes one authority binding, without installing business state.
    let mut invalid = Vec::new();
    let mut changed = request.clone();
    changed.public_operation = Uuid::now_v7();
    invalid.push(changed);
    let mut changed = request.clone();
    changed.action_intent_id = "ACT-WORK_ITEMS_CREATE_RESOURCE-V1".into();
    invalid.push(changed);
    let mut changed = request.clone();
    changed.checkpoint_digest = format!("sha256:{}", "00".repeat(32));
    invalid.push(changed);
    let mut changed = request.clone();
    changed.prior_partition = Uuid::now_v7();
    invalid.push(changed);
    let mut changed = request.clone();
    changed.end_watermark += 1;
    invalid.push(changed);
    for denied in invalid {
        assert!(
            bridge
                .recover_gap(scope(), &denied, facts, signer)
                .await
                .is_err()
        );
        assert_eq!(snapshot(pool, input).await, before);
        assert_recovery_boundary(pool, input, signer, None, false).await;
    }
    let signed = bridge
        .recover_gap(scope(), request, facts, signer)
        .await
        .unwrap();
    let claims: serde_json::Value = signer
        .verifier()
        .verified_stored_claims(21008, &signed)
        .unwrap()
        .deserialized()
        .unwrap();
    assert_eq!(claims["state"], "REORG_FENCED");
    assert_eq!(claims["partitionId"], request.prior_partition.to_string());
    assert_eq!(claims["reorgFenceHeight"], request.bootstrap_start);
    assert_eq!(
        bridge
            .recover_gap(scope(), request, facts, signer)
            .await
            .unwrap(),
        signed
    );
    let mut forged = signed;
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert!(
        signer
            .verifier()
            .verified_stored_claims(21008, &forged)
            .is_err()
    );
    assert_eq!(snapshot(pool, input).await, before);
    assert_recovery_boundary(pool, input, signer, None, false).await;
}
