//! Relationship lineage is checked in the ordinary admission transaction,
//! under the same mutation fence as canonical identity allocation. No mutable
//! membership table or independently writable relationship truth is introduced.
use super::*;
use pc_facts_core::{FactObject, FactRecord, FactSubject};

fn key(record: &FactRecord) -> Result<Option<Vec<u8>>, FactStoreError> {
    let identity = &record.identity;
    let FactSubject::Relationship {
        namespace,
        entity_key_digest,
        subject_key_digest,
        relationship_kind,
        role_predicates,
        profile_digest,
        ..
    } = &identity.typed_subject
    else {
        return Ok(None);
    };
    Ok(Some(crate::state_value::canonical(&(
        &identity.participant_id,
        &identity.privacy_domain_id,
        &identity.fact_profile_id,
        &identity.fact_semantic_version,
        namespace,
        entity_key_digest,
        subject_key_digest,
        relationship_kind,
        role_predicates,
        profile_digest,
        &identity.chain_anchor.chain_id,
        &identity.chain_anchor.genesis_hash,
        &identity.chain_anchor.network_id,
    ))?))
}

fn transition(
    record: &FactRecord,
    previous: Option<&FactRecord>,
) -> Result<Option<String>, FactStoreError> {
    let FactObject::RelationshipInterval {
        transition,
        effective_from_block: from,
        effective_through_block: through,
        completed_watermark,
        successful_execution,
    } = &record.value
    else {
        return Err(FactStoreError::Lifecycle);
    };
    let anchor = &record.identity.chain_anchor;
    if !successful_execution
        || *completed_watermark != record.completeness_scope.range_end
        || *from > anchor.block_height
        || through.is_some_and(|end| end > anchor.block_height || end < *from)
        || (transition == "CLOSE") != through.is_some()
    {
        return Err(FactStoreError::Lifecycle);
    }
    let Some(previous) = previous else {
        return if transition == "OPEN" && *from == anchor.block_height {
            Ok(None)
        } else {
            Err(FactStoreError::Lifecycle)
        };
    };
    let prior = &previous.identity.chain_anchor;
    let FactObject::RelationshipInterval {
        transition: prior_transition,
        effective_from_block: prior_from,
        effective_through_block: prior_through,
        ..
    } = &previous.value
    else {
        return Err(FactStoreError::Lifecycle);
    };
    if key(record)? != key(previous)?
        || (
            anchor.block_height,
            anchor.transaction_index,
            anchor.log_index,
        ) <= (prior.block_height, prior.transaction_index, prior.log_index)
        || (anchor.block_height == prior.block_height && anchor.block_hash != prior.block_hash)
    {
        return Err(FactStoreError::Lifecycle);
    }
    let valid = match transition.as_str() {
        "OPEN" => {
            prior_transition == "CLOSE"
                && *from == anchor.block_height
                && prior_through.is_some_and(|end| end < *from)
        }
        "CLOSE" => {
            prior_transition != "CLOSE"
                && from == prior_from
                && *through == Some(anchor.block_height)
        }
        "REPLACE" => {
            prior_transition != "CLOSE" && *from == anchor.block_height && from > prior_from
        }
        _ => false,
    };
    if !valid {
        return Err(FactStoreError::Lifecycle);
    }
    Ok(Some(previous.identity.local_fact_digest.clone()))
}

impl FactStore {
    pub(super) async fn bind_relationship_transition(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        record: &mut FactRecord,
        preceding: &[FactRecord],
        verifier: &FactSignatureVerifier,
        limit: u64,
    ) -> Result<(), FactStoreError> {
        let Some(expected) = key(record)? else {
            return Ok(());
        };
        let participant = record
            .identity
            .participant_id
            .strip_prefix("urn:openpc:participant:")
            .ok_or(FactStoreError::Lifecycle)?;
        let privacy = record
            .identity
            .privacy_domain_id
            .as_deref()
            .and_then(|v| v.strip_prefix("urn:openpc:privacy-domain:"))
            .ok_or(FactStoreError::Lifecycle)?;
        let candidates: Vec<String> = sqlx::query_scalar("select f.candidate_id from facts.canonical_fact f
            join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id,generation_id)
            join facts.canonical_generation g using(participant_id,privacy_domain_id,generation_id,fact_profile_id)
            where f.participant_id=$1 and f.privacy_domain_id=$2 and a.fact_profile_id=$3
              and f.state in ('ADMITTED','FINALIZED')
            order by g.canonical_generation,a.delta_sequence limit $4")
            .bind(participant).bind(privacy).bind(&record.identity.fact_profile_id)
            .bind(i64::try_from(limit+1).map_err(|_|FactStoreError::Lifecycle)?)
            .fetch_all(&mut **tx).await?;
        if candidates.len() as u64 > limit {
            return Err(FactStoreError::Lifecycle);
        }
        let mut history = Vec::new();
        for candidate in candidates {
            let row = super::signed_record::load(tx, participant, privacy, &candidate).await?;
            let prior = super::signed_record::verify(&row, verifier, participant, privacy)?
                .ok_or(FactStoreError::Lifecycle)?;
            if key(&prior)?.as_ref() == Some(&expected) {
                history.push(prior);
            }
        }
        let mut previous = history.last();
        for prior in preceding {
            if key(prior)?.as_ref() == Some(&expected) {
                previous = Some(prior);
            }
        }
        record.relationship_predecessor_digest = transition(record, previous)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_authority::StateFactRecordSource;
    use pc_facts_core::sha256;
    use pc_policy_core::fact_profile::StateFactMapping;
    use uuid::Uuid;

    fn inputs(
        first: &FactFeedEvent,
        profile: Uuid,
        transitions: &[(&str, u64, Option<u64>)],
    ) -> (
        Vec<crate::source_authority::ObservedStateAdmission>,
        Vec<FactFeedEvent>,
        FactFeedEvent,
    ) {
        let (mut observations, events, closing) =
            super::super::identity::tests::batch_fixture(first, profile);
        for (index, (observation, (transition, from, through))) in
            observations.iter_mut().zip(transitions).enumerate()
        {
            let candidate = &mut observation.candidate;
            let mut value = crate::state_value::StateFactValue::from_payload(
                &candidate.canonical_payload,
                &candidate.participant_id,
                &candidate.privacy_domain_id,
            )
            .unwrap();
            value.mapping = "RGRA_EVENT_RELATIONSHIP_V1".into();
            value.typed_arguments.clear();
            value.typed_result.clear();
            value.transaction_index = Some(0);
            value.log_index = Some(index as u64);
            let mut subject = [0u8; 32];
            subject[16..].copy_from_slice(profile.as_bytes());
            let subject = crate::state_value::canonical(&serde_json::json!([
                "openpc:rgra-scoped-key:v1",
                candidate.participant_id,
                candidate.privacy_domain_id,
                "subject",
                subject.to_vec()
            ]))
            .unwrap();
            value.specialization = Some((
                FactSubject::Relationship {
                    namespace: "membership".into(),
                    entity_key_digest: crate::signing::shard::digest_text(&[1; 32]),
                    subject_key_digest: crate::signing::shard::digest_text(&sha256(&subject)),
                    relationship_kind: "member".into(),
                    role_predicates: vec!["reader".into()],
                    profile_digest: crate::signing::shard::digest_text(&[3; 32]),
                    transaction_hash: format!("0x{}", "44".repeat(32)),
                },
                FactObject::RelationshipInterval {
                    transition: (*transition).into(),
                    effective_from_block: *from,
                    effective_through_block: *through,
                    completed_watermark: first.batch.range_end,
                    successful_execution: true,
                },
            ));
            candidate.schema_id = pc_facts_core::RELATIONSHIP_CANDIDATE_SCHEMA_ID;
            candidate.schema_digest = pc_facts_core::RELATIONSHIP_SCHEMA_DIGEST_V1;
            candidate.schema_purpose = pc_facts_core::fact_schema_identity(candidate.schema_id)
                .unwrap()
                .purpose_separator
                .into();
            candidate.canonical_payload = crate::state_value::canonical(&value).unwrap();
            candidate.declared_payload_digest = sha256(&candidate.canonical_payload);
            let mut provenance: serde_json::Value =
                ciborium::de::from_reader(candidate.canonical_provenance.as_slice()).unwrap();
            provenance["providerObservations"] = serde_json::json!([{"canonicalBlocks": [[first.batch.range_start + index as u64, value.block_hash.trim_start_matches("0x")]]}]);
            candidate.canonical_provenance = crate::state_value::canonical(&provenance).unwrap();
            candidate.declared_provenance_digest = sha256(&candidate.canonical_provenance);
            observation.trusted.independently_derived_provenance_digest =
                candidate.declared_provenance_digest;
            observation.record_source = StateFactRecordSource::fixture_mapping(
                candidate,
                profile,
                StateFactMapping::RgraEventRelationshipV1 {
                    namespace: "membership".into(),
                    relationship_kind: "member".into(),
                    role_predicates: vec!["reader".into()],
                },
            );
        }
        (observations, events, closing)
    }

    #[tokio::test]
    #[ignore = "requires installed FactStore roles; ordinary PostgreSQL gate invokes it"]
    async fn relationship_transitions_are_atomic_ordered_and_replay_safe() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let store = FactStore::new(
            pool.clone(),
            crate::store::tests::external_capability_secret().unwrap(),
        );
        let signer = PurposeBoundFactSigner::generate_ephemeral_local(vec![42; 32]).unwrap();
        let profile = Uuid::now_v7();
        let mut first = super::super::feed::tests::event();
        first.batch.record_count = 2;
        first.batch.range_end = 11;
        for transitions in [
            vec![("CLOSE", 10, Some(10)), ("OPEN", 11, None)],
            vec![("OPEN", 10, None), ("OPEN", 11, None)],
            vec![("OPEN", 10, None), ("CLOSE", 9, Some(11))],
            vec![("OPEN", 10, None), ("REPLACE", 10, None)],
        ] {
            let (observations, events, closing) = inputs(&first, profile, &transitions);
            let mut tx = pool.begin().await.unwrap();
            assert!(
                store
                    .admit_feed_batch_in_transaction(
                        &mut tx,
                        observations,
                        &events,
                        &closing,
                        &signer
                    )
                    .await
                    .is_err(),
                "{transitions:?}"
            );
            tx.rollback().await.unwrap();
            assert!(!store.replay_feed_batch(&events, &closing).await.unwrap());
        }
        let (mut observations, events, closing) = inputs(
            &first,
            profile,
            &[("OPEN", 10, None), ("CLOSE", 10, Some(11))],
        );
        for observation in &mut observations {
            observation.trusted.maximum_age_ms = 2_000;
        }
        let mut tx = pool.begin().await.unwrap();
        store
            .admit_feed_batch_in_transaction(&mut tx, observations, &events, &closing, &signer)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let restarted = FactStore::new(
            pool.clone(),
            crate::store::tests::external_capability_secret().unwrap(),
        );
        assert!(
            restarted
                .replay_feed_batch(&events, &closing)
                .await
                .unwrap()
        );
        let mut tx = pool.begin().await.unwrap();
        set_context(
            &mut tx,
            &first.batch.participant_id,
            &first.batch.privacy_domain_id,
        )
        .await
        .unwrap();
        let mut records = Vec::new();
        for event in &events {
            let row = super::super::signed_record::load(
                &mut tx,
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                event.candidate_id.as_deref().unwrap(),
            )
            .await
            .unwrap();
            records.push(
                super::super::signed_record::verify(
                    &row,
                    &signer.verifier(),
                    &first.batch.participant_id,
                    &first.batch.privacy_domain_id,
                )
                .unwrap()
                .unwrap(),
            );
        }
        for record in &records {
            assert_eq!(
                record.identity.fact_schema_id,
                pc_facts_core::RELATIONSHIP_FACT_SCHEMA_ID
            );
            assert_eq!(
                record.identity.fact_schema_digest,
                crate::signing::shard::digest_text(&pc_facts_core::RELATIONSHIP_SCHEMA_DIGEST_V1)
            );
            let candidate = record.relationship_candidate_cose.as_ref().unwrap();
            signer
                .verifier()
                .verified_stored_claims(pc_facts_core::RELATIONSHIP_CANDIDATE_SCHEMA_ID, candidate)
                .unwrap();
            assert!(
                signer
                    .verifier()
                    .verified_stored_claims(
                        pc_facts_core::FACT_ADMISSION_CANDIDATE_SCHEMA_ID,
                        candidate
                    )
                    .is_err()
            );
        }
        assert_eq!(
            records[1].relationship_predecessor_digest.as_ref(),
            Some(&records[0].identity.local_fact_digest)
        );
        tx.rollback().await.unwrap();
        let mut wrong = events.clone();
        wrong[0].payload_cbor =
            pc_facts_core::encode_pc_cbor(ciborium::Value::Text("changed delivery".into()))
                .unwrap();
        assert!(restarted.replay_feed_batch(&wrong, &closing).await.is_err());
        let artifact_root = std::env::var_os("OPENPC_TEST_ROOT")
            .or_else(|| std::env::var_os("OPENPC_TEST_TMP_ROOT"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("relationship-shard-{}", Uuid::now_v7()));
        store
            .publish_candidate(
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                events[0].candidate_id.as_deref().unwrap(),
                &signer,
                &artifact_root,
            )
            .await
            .unwrap();
        let reader_pool =
            PgPool::connect(&std::env::var("OPENPC_POLICY_FACT_READER_DATABASE_URL").unwrap())
                .await
                .unwrap();
        let reader = PolicyFactReader::new(reader_pool.clone(), signer.verifier());
        let (shard, _) = reader
            .publication(
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                &events
                    .iter()
                    .map(|event| event.candidate_id.clone().unwrap())
                    .collect::<Vec<_>>(),
            )
            .await
            .unwrap()
            .unwrap();
        signer
            .verifier()
            .verified_stored_claims(
                pc_facts_core::RELATIONSHIP_SHARD_SCHEMA_ID,
                shard.cose_sign1(),
            )
            .unwrap();
        assert!(
            signer
                .verifier()
                .verified_stored_claims(
                    pc_facts_core::FACT_SHARD_MANIFEST_SCHEMA_ID,
                    shard.cose_sign1()
                )
                .is_err()
        );
        let local = signer
            .verifier()
            .verify_local_facts(&shard, shard.local_content().unwrap())
            .unwrap();
        let condition = pc_policy_core::fact_condition::FactCondition::Relationship {
            fact: pc_policy_core::semantics::FactReference {
                candidate_id: events[0].candidate_id.clone().unwrap(),
                generation_id: first.batch.fact_generation_id.clone(),
                fact_digest: records[0].identity.local_fact_digest.clone(),
            },
            fact_profile_id: profile.to_string(),
            profile_digest: pc_runtime_types::Digest::parse("03".repeat(32)).unwrap(),
            namespace: "membership".into(),
            entity_key_digest: pc_runtime_types::Digest::parse("01".repeat(32)).unwrap(),
            relationship_kind: "member".into(),
            role_predicate: "reader".into(),
            trusted_subject_selector:
                pc_policy_core::fact_condition::TrustedSubjectSelector::WorkloadUuidV1,
        };
        let block_hash = pc_runtime_types::Digest::parse("22".repeat(32)).unwrap();
        let workload = profile.to_string();
        let mut context = crate::LocalFactContext {
            participant_id: &first.batch.participant_id,
            privacy_domain_id: &first.batch.privacy_domain_id,
            workload_id: &workload,
            chain_id: 31337,
            block_number: 10,
            block_hash: &block_hash,
        };
        assert_eq!(
            local.evaluate(&condition, &context),
            pc_facts_core::RelationshipResult::MemberConfirmed
        );
        // An event cannot borrow an end-of-block grant from its own or a later
        // occurrence. The signed transition at (10,0,0) permits only later logs.
        assert!(!local.permits_condition_at_occurrence(&condition, &context, 0, 0));
        assert!(local.permits_condition_at_occurrence(&condition, &context, 0, 1));
        assert!(local.permits_any_occurrence(&condition, &context));
        let closing_hash = pc_runtime_types::Digest::parse(
            records[1]
                .identity
                .chain_anchor
                .block_hash
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        let closing_context = crate::LocalFactContext {
            participant_id: context.participant_id,
            privacy_domain_id: context.privacy_domain_id,
            workload_id: context.workload_id,
            chain_id: context.chain_id,
            block_number: records[1].identity.chain_anchor.block_height,
            block_hash: &closing_hash,
        };
        assert!(local.permits_condition_at_occurrence(&condition, &closing_context, 0, 1));
        assert!(!local.permits_condition_at_occurrence(&condition, &closing_context, 0, 2));
        assert!(
            local.permits_any_occurrence(&condition, &closing_context),
            "a later close preserves the earlier permitted interval"
        );
        context.workload_id = "018f0000-0000-7000-8000-000000000fff";
        assert!(!local.permits_condition(&condition, &context));
        context.workload_id = &workload;
        context.block_number = 12;
        assert!(!local.permits_condition(&condition, &context));
        context.block_number = 10;
        let mut wrong = condition.clone();
        if let pc_policy_core::fact_condition::FactCondition::Relationship {
            role_predicate, ..
        } = &mut wrong
        {
            *role_predicate = "writer".into();
        }
        assert!(!local.permits_condition(&wrong, &context));
        let mut corrupt = shard.local_content().unwrap().to_vec();
        corrupt[0] ^= 1;
        assert!(
            signer
                .verifier()
                .verify_local_facts(&shard, &corrupt)
                .is_err()
        );
        tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
        assert_eq!(
            local.evaluate(&condition, &context),
            pc_facts_core::RelationshipResult::Stale
        );
        std::fs::remove_dir_all(&artifact_root).unwrap();
        reader_pool.close().await;
    }
    #[tokio::test]
    #[ignore = "requires installed PostgreSQL Fact owners"]
    async fn empty_checkpoint_preserves_latest_signed_relationship_transition() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let read_pool =
            PgPool::connect(&std::env::var("OPENPC_POLICY_FACT_READER_DATABASE_URL").unwrap())
                .await
                .unwrap();
        let store = FactStore::new(
            pool.clone(),
            crate::store::tests::external_capability_secret().unwrap(),
        );
        let signer = PurposeBoundFactSigner::generate_ephemeral_local(vec![42; 32]).unwrap();
        for (terminal, through, expected) in [("REPLACE", None, true), ("CLOSE", Some(11), false)] {
            let profile = Uuid::now_v7();
            let mut first = super::super::feed::tests::event();
            first.batch.record_count = 2;
            first.batch.range_end = 11;
            let transitions = [
                ("OPEN", 10, None),
                (terminal, if terminal == "CLOSE" { 10 } else { 11 }, through),
            ];
            let (observations, events, closing) = inputs(&first, profile, &transitions);
            let mut tx = pool.begin().await.unwrap();
            store
                .admit_feed_batch_in_transaction(&mut tx, observations, &events, &closing, &signer)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            let root = std::env::var_os("OPENPC_TEST_ROOT")
                .or_else(|| std::env::var_os("OPENPC_TEST_TMP_ROOT"))
                .map(std::path::PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join(format!("relationship-empty-{}", Uuid::now_v7()));
            store
                .publish_candidate(
                    &first.batch.participant_id,
                    &first.batch.privacy_domain_id,
                    events[0].candidate_id.as_deref().unwrap(),
                    &signer,
                    &root,
                )
                .await
                .unwrap();
            let reader = PolicyFactReader::new(read_pool.clone(), signer.verifier());
            let (shard, snapshots) = reader
                .publication(
                    &first.batch.participant_id,
                    &first.batch.privacy_domain_id,
                    &[events[0].candidate_id.clone().unwrap()],
                )
                .await
                .unwrap()
                .unwrap();
            let mut local = signer
                .verifier()
                .verify_local_facts(&shard, shard.local_content().unwrap())
                .unwrap();
            let condition = pc_policy_core::fact_condition::FactCondition::Relationship {
                fact: pc_policy_core::semantics::FactReference {
                    candidate_id: events[0].candidate_id.clone().unwrap(),
                    generation_id: first.batch.fact_generation_id.clone(),
                    fact_digest: crate::signing::shard::digest_text(&snapshots[0].fact_digest),
                },
                fact_profile_id: profile.to_string(),
                profile_digest: pc_runtime_types::Digest::parse("03".repeat(32)).unwrap(),
                namespace: "membership".into(),
                entity_key_digest: pc_runtime_types::Digest::parse("01".repeat(32)).unwrap(),
                relationship_kind: "member".into(),
                role_predicate: "reader".into(),
                trusted_subject_selector:
                    pc_policy_core::fact_condition::TrustedSubjectSelector::WorkloadUuidV1,
            };
            let hash = pc_runtime_types::Digest::parse("24".repeat(32)).unwrap();
            let workload = format!("urn:openpc:workload:{profile}");
            let context = crate::LocalFactContext {
                participant_id: &first.batch.participant_id,
                privacy_domain_id: &first.batch.privacy_domain_id,
                workload_id: &workload,
                chain_id: 31337,
                block_number: 12,
                block_hash: &hash,
            };
            assert!(!local.permits_condition(&condition, &context));
            let expiry = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + 2000;
            let claims = serde_json::json!({"schemaId":21104,"schemaVersion":"1.0.0","participantId":first.batch.participant_id,"privacyDomainId":first.batch.privacy_domain_id,"partitionId":first.batch.partition_id,"entryCount":"0","rangeStart":"12","completedWatermark":"12","factProfileId":format!("urn:openpc:fact-profile:{profile}"),"profileDigest":format!("sha256:{}","03".repeat(32)),"expiresAtMs":expiry.to_string(),"observedAtMs":(expiry-2000).to_string(),"blocks":[{"number":"12","hash":format!("sha256:{}",hash.as_str()),"parentHash":format!("sha256:{}",shard.manifest.as_ref().unwrap().canonical_blocks.last().unwrap().1)}]});
            let mut empty = closing.clone();
            empty.sequence += 1;
            empty.event_id = Uuid::now_v7();
            empty.record_ordinal = 1;
            empty.batch.record_count = 0;
            empty.batch.range_start = 12;
            empty.batch.range_end = 12;
            empty.batch.checkpoint_id = Uuid::now_v7();
            empty.batch.fact_generation_id = empty.batch.checkpoint_id.to_string();
            let proof = signer
                .sign_empty_relationship_shard(&empty, &claims, Some(&shard))
                .unwrap()
                .cose_sign1;
            // A signed proof remains unusable if its exact scope or chain link
            // differs. Malformed zero-entry content is refused before signing.
            let verified_empty = signer.verifier().verify_shard_cose(&proof).unwrap();
            for defect in ["scope", "gap", "fork", "stale", "nonempty"] {
                let mut manifest = verified_empty.manifest.clone().unwrap();
                match defect {
                    "scope" => manifest.privacy_domain_id = Uuid::now_v7().to_string(),
                    "gap" => {
                        manifest.canonical_range.range_start += 1;
                        manifest.canonical_range.range_end += 1;
                        let mut wire = serde_json::to_value(&manifest).unwrap();
                        wire["completedWatermark"] =
                            serde_json::json!(manifest.canonical_range.range_end);
                        wire["completenessDigest"] =
                            serde_json::json!(crate::signing::shard::digest_text(&sha256(
                                &crate::state_value::canonical(&manifest.canonical_range).unwrap()
                            )));
                        manifest = serde_json::from_value(wire).unwrap();
                        manifest.canonical_blocks[0].0 += 1;
                    }
                    "fork" => {
                        manifest.predecessor_shard_digest =
                            Some(crate::signing::shard::digest_text(&[99; 32]))
                    }
                    "stale" => {
                        manifest.expires_at = pc_facts_core::fact_timestamp_from_ms(1).unwrap()
                    }
                    "nonempty" => {
                        manifest.shard_content_digest =
                            crate::signing::shard::digest_text(&[99; 32])
                    }
                    _ => unreachable!(),
                }
                let altered = signer.sign_complete_shard(&manifest);
                if defect == "nonempty" {
                    assert!(altered.is_err());
                    continue;
                }
                let altered = altered.unwrap();
                let mut unextended = signer
                    .verifier()
                    .verify_local_facts(&shard, shard.local_content().unwrap())
                    .unwrap();
                let result = signer.verifier().extend_relationship_checkpoints(
                    &mut unextended,
                    [altered.cose_sign1.as_slice()],
                );
                assert!(result.is_err() || result.unwrap().is_empty(), "{defect}");
                assert!(
                    !unextended.permits_condition(&condition, &context),
                    "{defect}"
                );
            }
            let used = signer
                .verifier()
                .extend_relationship_checkpoints(&mut local, [proof.as_slice()])
                .unwrap();
            assert_eq!(used.len(), 1);
            assert_eq!(
                local.permits_condition(&condition, &context),
                expected,
                "{terminal} -> empty"
            );
            assert_eq!(
                local.evaluate_at_snapshot_anchor(&condition, &workload)
                    == pc_facts_core::RelationshipResult::MemberConfirmed,
                expected,
                "simulation must use the latest completed snapshot: {terminal} -> empty"
            );
            assert_eq!(
                signer
                    .verifier()
                    .extend_relationship_checkpoints(&mut local, [proof.as_slice()])
                    .unwrap(),
                used
            );
            let mut bad = proof.clone();
            let end = bad.len() - 1;
            bad[end] ^= 1;
            let mut clean = signer
                .verifier()
                .verify_local_facts(&shard, shard.local_content().unwrap())
                .unwrap();
            assert!(
                signer
                    .verifier()
                    .extend_relationship_checkpoints(&mut clean, [bad.as_slice()])
                    .unwrap()
                    .is_empty()
            );
            assert!(!clean.permits_condition(&condition, &context));
            std::fs::remove_dir_all(root).unwrap();
        }
        read_pool.close().await;
        pool.close().await;
    }
}
