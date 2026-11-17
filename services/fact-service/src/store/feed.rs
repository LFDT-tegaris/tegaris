//! Durable COM-017 delivery, separate from the sequence of admitted facts.
//! These are persistence inputs, not authentication or semantic admission proofs.
use super::*;
use pc_facts_core::{sha256, validate_pc_cbor};
use uuid::Uuid;

#[cfg(test)]
pub(crate) mod tests;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactFeedBatch {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub partition_id: Uuid,
    pub source_profile_id: String,
    pub source_generation_id: String,
    pub fact_generation_id: String,
    pub checkpoint_id: Uuid,
    pub batch_sequence: u64,
    pub batch_digest: [u8; 32],
    pub predecessor_batch_digest: Option<[u8; 32]>,
    pub range_start: u64,
    pub range_end: u64,
    pub record_count: u64,
    pub checkpoint_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactFeedEvent {
    pub batch: FactFeedBatch,
    pub sequence: u64,
    pub event_id: Uuid,
    pub record_ordinal: u64,
    /// The canonical outbox envelope, containing identities/digests only.
    pub payload_cbor: Vec<u8>,
    /// Absent only for the batch's closing checkpoint event.
    pub candidate_id: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct FactFeedPosition {
    pub last_event_sequence: u64,
    pub last_fact_sequence: u64,
    pub completed_watermark: Option<u64>,
}

struct Receipt<'a> {
    event: &'a FactFeedEvent,
    fact_digest: Option<&'a [u8; 32]>,
    canonical_provenance: Option<&'a [u8]>,
}

impl FactFeedEvent {
    fn validate(&self) -> Result<(), FactStoreError> {
        let b = &self.batch;
        if [
            &b.participant_id,
            &b.privacy_domain_id,
            &b.source_profile_id,
            &b.source_generation_id,
            &b.fact_generation_id,
        ]
        .iter()
        .any(|v| v.is_empty() || v.len() > 256)
            || [b.partition_id, b.checkpoint_id, self.event_id]
                .iter()
                .any(|v| v.get_version_num() != 7)
            || b.batch_sequence == 0
            || self.sequence == 0
            || b.range_start > b.range_end
            || self.payload_cbor.len() > 131_072
            || self.payload_cbor.is_empty()
            || self.record_ordinal == 0
            || self
                .candidate_id
                .as_ref()
                .is_some_and(|id| id.is_empty() || id.len() > 256)
            || (self.candidate_id.is_some() && self.record_ordinal > b.record_count)
            || (self.candidate_id.is_none()
                && b.record_count.checked_add(1) != Some(self.record_ordinal))
            || [
                b.batch_sequence,
                b.record_count,
                self.sequence,
                self.record_ordinal,
            ]
            .iter()
            .any(|v| i64::try_from(*v).is_err())
        {
            return Err(FactStoreError::Feed);
        }
        validate_pc_cbor(&self.payload_cbor)?;
        Ok(())
    }

    fn kind(&self) -> &'static str {
        if self.candidate_id.is_some() {
            "CANDIDATE"
        } else {
            "CHECKPOINT"
        }
    }
}

impl Receipt<'_> {
    fn digest(&self) -> [u8; 32] {
        let e = self.event;
        let b = &e.batch;
        let partition = b.partition_id.to_string();
        let event_id = e.event_id.to_string();
        let checkpoint = b.checkpoint_id.to_string();
        let sequence = e.sequence.to_be_bytes();
        let batch_sequence = b.batch_sequence.to_be_bytes();
        let ordinal = e.record_ordinal.to_be_bytes();
        let count = b.record_count.to_be_bytes();
        let start = b.range_start.to_string();
        let end = b.range_end.to_string();
        let event_digest = sha256(&e.payload_cbor);
        let provenance = self.canonical_provenance.map(sha256);
        let fields: [Option<&[u8]>; 22] = [
            Some(b.participant_id.as_bytes()),
            Some(b.privacy_domain_id.as_bytes()),
            Some(partition.as_bytes()),
            Some(&sequence),
            Some(event_id.as_bytes()),
            Some(b.source_profile_id.as_bytes()),
            Some(b.source_generation_id.as_bytes()),
            Some(b.fact_generation_id.as_bytes()),
            Some(e.kind().as_bytes()),
            Some(checkpoint.as_bytes()),
            Some(&batch_sequence),
            Some(&b.batch_digest),
            b.predecessor_batch_digest
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            Some(start.as_bytes()),
            Some(end.as_bytes()),
            Some(&ordinal),
            Some(&count),
            Some(&b.checkpoint_digest),
            Some(&event_digest),
            e.candidate_id.as_deref().map(str::as_bytes),
            self.fact_digest.map(<[u8; 32]>::as_slice),
            provenance.as_ref().map(<[u8; 32]>::as_slice),
        ];
        let mut bytes = Vec::new();
        for (index, field) in fields.into_iter().enumerate() {
            bytes.extend_from_slice(&u16::try_from(index + 1).expect("22 fields").to_be_bytes());
            bytes.push(u8::from(field.is_some()));
            let value = field.unwrap_or_default();
            bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
            bytes.extend_from_slice(value);
        }
        sha256(&bytes)
    }
}

impl FactStore {
    pub(crate) async fn replay_feed_batch(
        &self,
        events: &[FactFeedEvent],
        closing: &FactFeedEvent,
    ) -> Result<bool, FactStoreError> {
        let mut present = 0;
        for event in events.iter().chain(std::iter::once(closing)) {
            present += usize::from(self.replay_feed_receipt(event).await?);
        }
        if present != 0 && present != events.len() + 1 {
            return Err(FactStoreError::Feed);
        }
        Ok(present != 0)
    }

    pub(crate) async fn admit_feed_batch(
        &self,
        observations: Vec<crate::source_authority::ObservedStateAdmission>,
        events: &[FactFeedEvent],
        closing: &FactFeedEvent,
        signer: &PurposeBoundFactSigner,
        source: &mut crate::source_authority::CurrentFactSource,
        binding: Option<&crate::FactOperationBinding>,
    ) -> Result<DurableAdmissionOutcome, FactStoreError> {
        let mut tx = self.pool.begin().await?;
        let outcome = self
            .admit_feed_batch_in_transaction(&mut tx, observations, events, closing, signer)
            .await?;
        if let Some(binding) = binding {
            self.bind_feed_operation_in(
                &mut tx,
                &closing.batch.participant_id,
                &closing.batch.privacy_domain_id,
                binding,
                outcome,
            )
            .await?;
        }
        source
            .confirm_live()
            .await
            .map_err(|_| FactStoreError::Lifecycle)?;
        tx.commit().await?;
        Ok(outcome)
    }

    pub(super) async fn admit_feed_batch_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        observations: Vec<crate::source_authority::ObservedStateAdmission>,
        events: &[FactFeedEvent],
        closing: &FactFeedEvent,
        signer: &PurposeBoundFactSigner,
    ) -> Result<DurableAdmissionOutcome, FactStoreError> {
        let outcome = self
            .admit_feed_records_in_transaction(tx, observations, events, closing, signer)
            .await?;
        for event in events {
            self.record_admission_delivery(
                tx,
                &event.batch.participant_id,
                &event.batch.privacy_domain_id,
                event.candidate_id.as_deref().ok_or(FactStoreError::Feed)?,
                &signer.verifier(),
            )
            .await?;
        }
        Ok(outcome)
    }

    // The historical signed-record owner remains independently usable by its
    // populated-upgrade fixture. Current production admission always invokes
    // the wrapper above, retaining record, checkpoint and event atomicity.
    async fn admit_feed_records_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        observations: Vec<crate::source_authority::ObservedStateAdmission>,
        events: &[FactFeedEvent],
        closing: &FactFeedEvent,
        signer: &PurposeBoundFactSigner,
    ) -> Result<DurableAdmissionOutcome, FactStoreError> {
        use pc_facts_core::FactRecord;
        let first = events.first().ok_or(FactStoreError::Feed)?;
        let b = &first.batch;
        if observations.len() != events.len()
            || events.len() as u64 != b.record_count
            || first.record_ordinal != 1
            || closing.batch != *b
            || closing.candidate_id.is_some()
            || closing.record_ordinal != b.record_count + 1
            || first.sequence.checked_add(b.record_count) != Some(closing.sequence)
        {
            return Err(FactStoreError::Feed);
        }
        closing.validate()?;
        let verifier = signer.verifier();
        set_context(tx, &b.participant_id, &b.privacy_domain_id).await?;
        let mut records: Vec<FactRecord> = Vec::with_capacity(events.len());
        let mut prepared = Vec::with_capacity(events.len());
        for (index, (observed, event)) in observations.into_iter().zip(events).enumerate() {
            event.validate()?;
            let candidate = observed.candidate;
            if event.batch != *b
                || event.record_ordinal != index as u64 + 1
                || first.sequence.checked_add(index as u64) != Some(event.sequence)
                || b.record_count > observed.record_source.shard_entry_limit()
                || event.candidate_id.as_deref() != Some(&candidate.candidate_id)
                || candidate.participant_id != b.participant_id
                || candidate.privacy_domain_id != b.privacy_domain_id
                || candidate.source_profile_id != b.source_profile_id
                || candidate.generation_id != b.fact_generation_id
                || candidate.canonical_provenance.len() > 131_072
            {
                return Err(FactStoreError::Feed);
            }
            validate_pc_cbor(&candidate.canonical_provenance)?;
            let occurrence = crate::state_value::StateFactValue::from_payload(
                &candidate.canonical_payload,
                &candidate.participant_id,
                &candidate.privacy_domain_id,
            )?
            .occurrence()?;
            let provenance = candidate.canonical_provenance.clone();
            let validated = validate_admission(candidate, &observed.trusted)?;
            let allocation = self
                .allocate_identity(tx, &validated, &observed.record_source.profile_urn())
                .await?;
            if allocation.sequence != event.record_ordinal {
                return Err(FactStoreError::Feed);
            }
            let mut record = observed.record_source.record(
                &allocation,
                &validated,
                event,
                &signer.record_key_id()?,
            )?;
            if validated.schema_id() == pc_facts_core::RELATIONSHIP_FACT_SCHEMA_ID {
                record.relationship_candidate_cose =
                    Some(signer.sign_relationship_candidate(&validated)?);
            }
            if let Some(previous) = records.last() {
                record.predecessor_digest = Some(previous.identity.local_fact_digest.clone());
            }
            let predecessor =
                Self::reorg_predecessor(tx, event, &verifier, &provenance, &record).await?;
            if let Some(prior) = &predecessor {
                let old = &prior.record.identity;
                let new = &record.identity;
                if (!prior.authorized_rebootstrap
                    && prior.depth > observed.record_source.retained_tail_blocks())
                    || old.fact_profile_id != new.fact_profile_id
                    || old.fact_semantic_version != new.fact_semantic_version
                    || old.typed_subject != new.typed_subject
                    || old.chain_anchor.chain_id != new.chain_anchor.chain_id
                    || old.chain_anchor.genesis_hash != new.chain_anchor.genesis_hash
                    || old.chain_anchor.network_id != new.chain_anchor.network_id
                    || old.chain_anchor.finality_rule_id != new.chain_anchor.finality_rule_id
                    || old.chain_anchor.block_height != new.chain_anchor.block_height
                    || old.chain_anchor.block_hash == new.chain_anchor.block_hash
                    || old.fact_id == new.fact_id
                    || old.canonical_generation >= new.canonical_generation
                {
                    return Err(FactStoreError::Lifecycle);
                }
                record.reorg_replacement_of = Some(old.fact_id.clone());
                record.predecessor_digest = Some(old.local_fact_digest.clone());
            }
            self.bind_relationship_transition(
                tx,
                &mut record,
                &records,
                &verifier,
                observed.record_source.shard_entry_limit(),
            )
            .await?;
            records.push(record);
            prepared.push((validated, provenance, occurrence, predecessor));
        }
        let root = FactRecord::batch_root(&records)?;
        for record in &mut records {
            record.snapshot_root = root.clone();
        }
        FactRecord::validate_batch(&records)?;
        let mut conflicting = false;
        for ((prepared, record), event) in prepared.into_iter().zip(records).zip(events) {
            let (validated, provenance, occurrence, predecessor) = prepared;
            let validated = validated.bind_complete_record(record)?;
            let signed = signer.sign_admission(&validated)?;
            verifier.verify_fact(&validated, &signed)?;
            let outcome = if let Some(prior) = predecessor {
                self.insert_replacement(tx, &prior.candidate, &validated, &signed)
                    .await?
            } else {
                let sequence = i64::try_from(validated.sequence())
                    .map_err(|_| FactStoreError::SequenceRace)?;
                let capability = self.capabilities.admit(&validated, &signed, sequence);
                Self::insert_admission(tx, &validated, &signed, sequence, &capability).await?
            };
            if outcome == DurableAdmissionOutcome::IdempotentReplay {
                return Err(FactStoreError::ReplayDigestMismatch);
            }
            self.record_feed_receipt(
                tx,
                Receipt {
                    event,
                    fact_digest: Some(validated.canonical_fact_digest()),
                    canonical_provenance: Some(&provenance),
                },
            )
            .await?;
            conflicting |= self.record_occurrence(tx, &validated, &occurrence).await?;
        }
        self.record_feed_receipt(
            tx,
            Receipt {
                event: closing,
                fact_digest: None,
                canonical_provenance: None,
            },
        )
        .await?;
        let fresh: bool = sqlx::query_scalar("select bool_and(fresh_until_ms>floor(extract(epoch from clock_timestamp())*1000)::bigint)
            from facts.canonical_fact where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3")
            .bind(&b.participant_id).bind(&b.privacy_domain_id).bind(&b.fact_generation_id).fetch_one(&mut **tx).await?;
        if !fresh {
            return Err(FactStoreError::Lifecycle);
        }
        Ok(if conflicting {
            DurableAdmissionOutcome::Conflicting
        } else {
            DurableAdmissionOutcome::AdmittedNotReady
        })
    }

    /// Reconcile an already committed feed delivery without observing a provider
    /// again. This is a historical receipt, never current fact readiness. Every
    /// supplied event/batch field must reproduce the original receipt digest.
    pub async fn replay_feed_receipt(&self, event: &FactFeedEvent) -> Result<bool, FactStoreError> {
        event.validate()?;
        let mut transaction = self.pool.begin().await?;
        set_context(
            &mut transaction,
            &event.batch.participant_id,
            &event.batch.privacy_domain_id,
        )
        .await?;
        let row = sqlx::query("select receipt_digest,fact_digest,canonical_provenance from facts.candidate_feed_receipt
            where participant_id=$1 and privacy_domain_id=$2 and partition_id=$3 and candidate_sequence=$4")
            .bind(&event.batch.participant_id).bind(&event.batch.privacy_domain_id).bind(event.batch.partition_id)
            .bind(event.sequence as i64).fetch_optional(&mut *transaction).await?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(false);
        };
        let fact_digest: Option<Vec<u8>> = row.try_get("fact_digest")?;
        let fact_digest: Option<[u8; 32]> = fact_digest
            .map(|value| value.try_into().map_err(|_| FactStoreError::Feed))
            .transpose()?;
        let provenance: Option<Vec<u8>> = row.try_get("canonical_provenance")?;
        let receipt = Receipt {
            event,
            fact_digest: fact_digest.as_ref(),
            canonical_provenance: provenance.as_deref(),
        };
        if row.try_get::<Vec<u8>, _>("receipt_digest")? != receipt.digest() {
            return Err(FactStoreError::ReplayDigestMismatch);
        }
        transaction.commit().await?;
        Ok(true)
    }

    /// Retained legacy feed admission: commits the exact event, independently
    /// derived provenance, fact, evidence and outbox. Complete acquired records
    /// enter through the atomic batch owner. The caller retains source authority.
    pub async fn admit_from_feed(
        &self,
        candidate: FactAdmissionCandidate,
        trusted: &TrustedAdmissionContext,
        event: &FactFeedEvent,
        signer: &PurposeBoundFactSigner,
        verifier: &FactSignatureVerifier,
    ) -> Result<DurableAdmissionOutcome, FactStoreError> {
        event.validate()?;
        let b = &event.batch;
        if event.candidate_id.as_deref() != Some(&candidate.candidate_id)
            || candidate.participant_id != b.participant_id
            || candidate.privacy_domain_id != b.privacy_domain_id
            || candidate.source_profile_id != b.source_profile_id
            || candidate.generation_id != b.fact_generation_id
            || candidate.canonical_provenance.len() > 131_072
        {
            return Err(FactStoreError::Feed);
        }
        validate_pc_cbor(&candidate.canonical_provenance)?;
        let occurrence = crate::state_value::StateFactValue::from_payload(
            &candidate.canonical_payload,
            &candidate.participant_id,
            &candidate.privacy_domain_id,
        )?
        .occurrence()?;
        let provenance = candidate.canonical_provenance.clone();
        let validated = validate_admission(candidate, trusted)?;
        let mut transaction = self.pool.begin().await?;
        set_context(&mut transaction, &b.participant_id, &b.privacy_domain_id).await?;
        let signed = signer.sign_admission(&validated)?;
        verifier.verify_fact(&validated, &signed)?;
        let sequence =
            i64::try_from(validated.sequence()).map_err(|_| FactStoreError::SequenceRace)?;
        let capability = self.capabilities.admit(&validated, &signed, sequence);
        let outcome =
            Self::insert_admission(&mut transaction, &validated, &signed, sequence, &capability)
                .await?;
        self.record_feed_receipt(
            &mut transaction,
            Receipt {
                event,
                fact_digest: Some(validated.canonical_fact_digest()),
                canonical_provenance: Some(&provenance),
            },
        )
        .await?;
        let conflicting = self
            .record_occurrence(&mut transaction, &validated, &occurrence)
            .await?;
        transaction.commit().await?;
        Ok(if conflicting {
            DurableAdmissionOutcome::Conflicting
        } else {
            outcome
        })
    }

    /// Closes a batch only after all of its candidate events committed in order.
    /// This cannot finalize a fact or mark a shard READY.
    pub async fn complete_feed_batch(&self, event: &FactFeedEvent) -> Result<(), FactStoreError> {
        event.validate()?;
        if event.candidate_id.is_some() || event.batch.record_count == 0 {
            return Err(FactStoreError::Feed);
        }
        let mut transaction = self.pool.begin().await?;
        set_context(
            &mut transaction,
            &event.batch.participant_id,
            &event.batch.privacy_domain_id,
        )
        .await?;
        self.record_feed_receipt(
            &mut transaction,
            Receipt {
                event,
                fact_digest: None,
                canonical_provenance: None,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn complete_empty_checkpoint(
        &self,
        event: &FactFeedEvent,
        claims: &serde_json::Value,
        signer: &PurposeBoundFactSigner,
        source: &mut crate::source_authority::CurrentFactSource,
    ) -> Result<(), FactStoreError> {
        event.validate()?;
        if event.candidate_id.is_some() || event.batch.record_count != 0 {
            return Err(FactStoreError::Feed);
        }
        let mut tx = self.pool.begin().await?;
        set_context(
            &mut tx,
            &event.batch.participant_id,
            &event.batch.privacy_domain_id,
        )
        .await?;
        let prior:Option<(i64,Option<Vec<u8>>,String)>=sqlx::query_as("select record_count,canonical_provenance,fact_generation_id from facts.candidate_feed_receipt where participant_id=$1 and privacy_domain_id=$2 and partition_id=$3 order by candidate_sequence desc limit 1")
            .bind(&event.batch.participant_id).bind(&event.batch.privacy_domain_id).bind(event.batch.partition_id).fetch_optional(&mut *tx).await?;
        let predecessor = if let Some((count, proof, generation)) = prior {
            let bytes = if count == 0 {
                proof.ok_or(FactStoreError::Feed)?
            } else {
                sqlx::query_scalar::<_,Vec<u8>>("select shard_cose_sign1 from facts.readiness_gate where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3 and state='READY' and shard_verified=true")
                    .bind(&event.batch.participant_id).bind(&event.batch.privacy_domain_id).bind(generation).fetch_one(&mut *tx).await?
            };
            Some(signer.verifier().verify_shard_cose(&bytes)?)
        } else {
            if event.sequence != 1 {
                return Err(FactStoreError::Feed);
            }
            None
        };
        let proof = signer.sign_empty_relationship_shard(event, claims, predecessor.as_ref())?;
        self.record_feed_receipt(
            &mut tx,
            Receipt {
                event,
                fact_digest: None,
                canonical_provenance: Some(&proof.cose_sign1),
            },
        )
        .await?;
        source
            .confirm_live()
            .await
            .map_err(|_| FactStoreError::Lifecycle)?;
        tx.commit().await?;
        Ok(())
    }

    async fn record_feed_receipt(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        receipt: Receipt<'_>,
    ) -> Result<(), FactStoreError> {
        let capability = self.capabilities.candidate_feed(&receipt.digest());
        Self::write_feed_receipt(transaction, receipt, &capability).await
    }

    async fn write_feed_receipt(
        transaction: &mut Transaction<'_, Postgres>,
        receipt: Receipt<'_>,
        capability: &MutationCapability,
    ) -> Result<(), FactStoreError> {
        let e = receipt.event;
        let b = &e.batch;
        sqlx::query_scalar::<_, String>(
            "select facts.consume_candidate_feed_event(\
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::text::numeric,$15::text::numeric,\
          $16,$17,$18,$19,$20,$21,$22,$23,$24)",
        )
        .bind(&b.participant_id)
        .bind(&b.privacy_domain_id)
        .bind(b.partition_id)
        .bind(e.sequence as i64)
        .bind(e.event_id)
        .bind(&b.source_profile_id)
        .bind(&b.source_generation_id)
        .bind(&b.fact_generation_id)
        .bind(e.kind())
        .bind(b.checkpoint_id)
        .bind(b.batch_sequence as i64)
        .bind(b.batch_digest.as_slice())
        .bind(
            b.predecessor_batch_digest
                .as_ref()
                .map(<[u8; 32]>::as_slice),
        )
        .bind(b.range_start.to_string())
        .bind(b.range_end.to_string())
        .bind(e.record_ordinal as i64)
        .bind(b.record_count as i64)
        .bind(b.checkpoint_digest.as_slice())
        .bind(&e.payload_cbor)
        .bind(&e.candidate_id)
        .bind(receipt.fact_digest.map(<[u8; 32]>::as_slice))
        .bind(receipt.canonical_provenance)
        .bind(capability.nonce.as_slice())
        .bind(capability.mac.as_slice())
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?;
        Ok(())
    }

    pub async fn feed_position(
        &self,
        participant: &str,
        privacy: &str,
        partition: Uuid,
        source_profile: &str,
    ) -> Result<FactFeedPosition, FactStoreError> {
        let mut transaction = self.pool.begin().await?;
        set_context(&mut transaction, participant, privacy).await?;
        let (event, fact, watermark): (i64, i64, Option<String>) = sqlx::query_as(
            "select greatest(coalesce((select max(candidate_sequence) from facts.candidate_feed_receipt
               where participant_id=$1 and privacy_domain_id=$2 and partition_id=$3),0),
             coalesce((select max(source_sequence) from facts.lineage_outbox
               where participant_id=$1 and privacy_domain_id=$2 and partition_id=$3
                 and event_type in ('io.openpc.fact.fact.invalidated.v1','io.openpc.fact.fact.retired.v1')),0)),
             coalesce((select last_sequence from facts.source_checkpoint
               where participant_id=$1 and privacy_domain_id=$2 and source_profile_id=$4),0),
             (select max(range_end)::text from facts.candidate_feed_receipt
               where participant_id=$1 and privacy_domain_id=$2 and partition_id=$3 and event_kind='CHECKPOINT')"
        ).bind(participant).bind(privacy).bind(partition).bind(source_profile)
         .fetch_one(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(FactFeedPosition {
            last_event_sequence: u64::try_from(event).map_err(|_| FactStoreError::Feed)?,
            last_fact_sequence: u64::try_from(fact).map_err(|_| FactStoreError::Feed)?,
            completed_watermark: watermark
                .map(|v| v.parse().map_err(|_| FactStoreError::Feed))
                .transpose()?,
        })
    }
}
