//! Historical COM-017 acknowledgement by the indexer owner. The Fact store stays
//! read-only. No candidate semantics, Fact readiness, holds or retirement change.
use super::*;
use std::time::Duration;

const MAX_EVENTS: usize = 1024;
const FENCED_EVENT: &str = "io.openpc.indexer.projection.source.fenced.v1";

/// Installed database connection, never an acknowledgement supplied by a caller.
/// Only the existing restricted Fact read role can supply immutable receipts.
pub struct FactDeliveryReader {
    pool: PgPool,
}
impl FactDeliveryReader {
    pub async fn connect(options: PgConnectOptions) -> Result<Self, CandidateStoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .after_connect(|connection, _| Box::pin(async move {
                let valid: bool = sqlx::query_scalar("select current_database()='openpc_facts'
                    and current_user='openpc_policy_fact_runtime'
                    and pg_has_role(current_user,'openpc_policy_fact_reader','USAGE') and current_user=session_user
                    and not rolsuper and not rolbypassrls
                    and not pg_has_role(current_user,'openpc_facts_lifecycle_owner','MEMBER')
                    and not has_table_privilege(current_user,'facts.candidate_feed_receipt','INSERT,UPDATE,DELETE,TRUNCATE')
                    and not has_table_privilege(current_user,'facts.withdrawal_checkpoint','INSERT,UPDATE,DELETE,TRUNCATE')
                    from pg_roles where rolname=current_user")
                    .fetch_one(connection).await?;
                if !valid { return Err(sqlx::Error::Protocol("CANDIDATE-FACT-RECEIPT-IDENTITY".into())); }
                Ok(())
            }))
            .connect_with(options).await?;
        Ok(Self { pool })
    }

    async fn closed_prefix(
        &self,
        binding: &CandidatePersistenceBinding,
        profile: Uuid,
        partition: Uuid,
    ) -> Result<ClosedPrefix, CandidateStoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("set transaction isolation level repeatable read read only")
            .execute(&mut *tx)
            .await?;
        sqlx::query("set local statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)")
            .bind(binding.participant_id().to_string()).bind(binding.privacy_domain_id().to_string())
            .execute(&mut *tx).await?;
        let closure = sqlx::query(
            "select material,material_digest from facts.withdrawal_checkpoint
            where participant_id=$1 and privacy_domain_id=$2 and partition_id=$3
              and source_profile_id=$4 and source_generation_id=$5",
        )
        .bind(binding.participant_id().to_string())
        .bind(binding.privacy_domain_id().to_string())
        .bind(partition)
        .bind(profile.to_string())
        .bind(binding.projection_generation_id().to_string())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(CandidateStoreError::InvalidBinding)?;
        let bytes: Vec<u8> = closure.try_get("material")?;
        let receipt: Vec<u8> = closure.try_get("material_digest")?;
        if Sha256::digest(&bytes).as_slice() != receipt || bytes.len() > 4096 {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let material: WithdrawalMaterial =
            serde_json::from_slice(&bytes).map_err(|_| CandidateStoreError::InvalidBinding)?;
        material.validate(binding, profile, partition)?;
        let rows = sqlx::query("select candidate_sequence,event_id,event_kind,event_payload_cbor,receipt_digest,
             source_profile_id,source_generation_id from facts.candidate_feed_receipt
             where participant_id=$1 and privacy_domain_id=$2 and partition_id=$3 order by candidate_sequence limit 1025")
            .bind(binding.participant_id().to_string()).bind(binding.privacy_domain_id().to_string())
            .bind(partition).fetch_all(&mut *tx).await?;
        if rows.is_empty() || rows.len() >= MAX_EVENTS || rows.len() + 1 != material.sequence()? {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let mut events = Vec::with_capacity(rows.len() + 1);
        for (index, row) in rows.into_iter().enumerate() {
            let sequence: i64 = row.try_get("candidate_sequence")?;
            let event_id: Uuid = row.try_get("event_id")?;
            let payload: Vec<u8> = row.try_get("event_payload_cbor")?;
            let receipt: Vec<u8> = row.try_get("receipt_digest")?;
            let kind: String = row.try_get("event_kind")?;
            if sequence != (index + 1) as i64
                || event_id.get_version_num() != 7
                || payload.is_empty()
                || payload.len() > 131072
                || receipt.len() != 32
                || row.try_get::<String, _>("source_profile_id")? != profile.to_string()
                || row.try_get::<String, _>("source_generation_id")?
                    != binding.projection_generation_id().to_string()
                || !matches!(kind.as_str(), "CANDIDATE" | "CHECKPOINT")
            {
                return Err(CandidateStoreError::InvalidBinding);
            }
            events.push(ReceiptEvent {
                event_id,
                sequence,
                payload_digest: Sha256::digest(&payload).to_vec(),
                receipt,
                kind: if kind == "CANDIDATE" {
                    OBSERVED_EVENT
                } else {
                    CHECKPOINT_EVENT
                },
            });
        }
        if events
            .last()
            .is_none_or(|event| event.kind != CHECKPOINT_EVENT)
            || !events.iter().any(|event| event.kind == OBSERVED_EVENT)
            || prefix_digest(&events) != material.prefix_digest
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        events.push(ReceiptEvent {
            event_id: material.source_event_id,
            sequence: material.sequence()? as i64,
            payload_digest: decode_digest(&material.source_payload_digest)?.to_vec(),
            receipt,
            kind: FENCED_EVENT,
        });
        tx.rollback().await?;
        Ok(ClosedPrefix {
            events,
            publication_digest: decode_digest(&material.publication_digest)?.to_vec(),
        })
    }
}

// Private verified projection: callers cannot turn metadata or a digest into ACK authority.
struct ReceiptEvent {
    event_id: Uuid,
    sequence: i64,
    payload_digest: Vec<u8>,
    receipt: Vec<u8>,
    kind: &'static str,
}
struct ClosedPrefix {
    events: Vec<ReceiptEvent>,
    publication_digest: Vec<u8>,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WithdrawalMaterial {
    participant_id: Uuid,
    privacy_domain_id: Uuid,
    source_profile_id: Uuid,
    partition_id: Uuid,
    source_generation_id: Uuid,
    source_event_id: Uuid,
    source_sequence: String,
    source_payload_digest: String,
    publication_digest: String,
    prefix_digest: String,
    authority_digest: String,
}
impl WithdrawalMaterial {
    fn sequence(&self) -> Result<usize, CandidateStoreError> {
        let sequence = self
            .source_sequence
            .parse::<usize>()
            .map_err(|_| CandidateStoreError::InvalidBinding)?;
        if !(2..=MAX_EVENTS).contains(&sequence) || sequence.to_string() != self.source_sequence {
            return Err(CandidateStoreError::InvalidBinding);
        }
        Ok(sequence)
    }
    fn validate(
        &self,
        binding: &CandidatePersistenceBinding,
        profile: Uuid,
        partition: Uuid,
    ) -> Result<(), CandidateStoreError> {
        if self.participant_id != binding.participant_id()
            || self.privacy_domain_id != binding.privacy_domain_id()
            || self.source_generation_id != binding.projection_generation_id()
            || self.source_profile_id != profile
            || self.partition_id != partition
            || self.source_event_id.get_version_num() != 7
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        self.sequence()?;
        for value in [
            &self.source_payload_digest,
            &self.publication_digest,
            &self.prefix_digest,
            &self.authority_digest,
        ] {
            decode_digest(value)?;
        }
        Ok(())
    }
}
fn prefix_digest(events: &[ReceiptEvent]) -> String {
    let material = events
        .iter()
        .map(|event| {
            format!(
                "{}:{}:{}",
                event.sequence,
                event.event_id,
                event
                    .payload_digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("sha256:{}", digest_hex(material.as_bytes()))
}

impl CandidateStore {
    /// Reconcile a complete retired source prefix, never send it again. Both
    /// databases are real installed owners. Missing/foreign/conflicting receipts,
    /// open/reorg/quarantined streams and active leases remain closed to this path.
    /// The existing insert-only delivery-attempt row binds each exact receipt.
    pub async fn reconcile_retired_partition_delivery(
        &self,
        reader: &FactDeliveryReader,
        binding: &CandidatePersistenceBinding,
        profile: Uuid,
        partition: Uuid,
    ) -> Result<u64, CandidateStoreError> {
        require_uuid_v7(profile)?;
        require_uuid_v7(partition)?;
        let prefix = reader.closed_prefix(binding, profile, partition).await?;
        let mut tx = self.pool.begin().await?;
        set_context(&mut tx, binding).await?;
        sqlx::query("set local lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("set local statement_timeout='10s'")
            .execute(&mut *tx)
            .await?;
        // Same generation-root lock as acquisition/retirement. Historical ACK is
        // permitted only after the source's own terminal publication fence.
        let publication: Option<Vec<u8>>=sqlx::query_scalar("select pub.publication_digest
            from candidate.projection_generation g join candidate.source_publication pub
              using(participant_id,privacy_domain_id,projection_generation_id)
            join candidate.candidate_partition part using(participant_id,privacy_domain_id,projection_generation_id)
            where g.participant_id=$1 and g.privacy_domain_id=$2 and g.projection_generation_id=$3
              and part.source_profile_id=$4 and part.candidate_partition_id=$5
              and g.state in ('STALE','RETIRED') and pub.state='FENCED' for update of g")
            .bind(binding.participant_id()).bind(binding.privacy_domain_id()).bind(binding.projection_generation_id())
            .bind(profile).bind(partition).fetch_optional(&mut *tx).await?;
        if publication.as_deref() != Some(prefix.publication_digest.as_slice()) {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let rows=sqlx::query("select event_id,aggregate_sequence::text,event_type::text,payload_cbor,payload_digest,
              state::text,attempt_count from candidate.outbox_event
            where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='candidate-partition'
              and aggregate_id=$3 order by aggregate_sequence limit 1025 for update")
            .bind(binding.participant_id()).bind(binding.privacy_domain_id()).bind(partition).fetch_all(&mut *tx).await?;
        if rows.len() != prefix.events.len() {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let mut changed = 0;
        for (row, receipt) in rows.iter().zip(&prefix.events) {
            let event: Uuid = row.try_get("event_id")?;
            let payload: Vec<u8> = row.try_get("payload_cbor")?;
            let attempts: i16 = row.try_get("attempt_count")?;
            if event != receipt.event_id
                || row.try_get::<String, _>("aggregate_sequence")? != receipt.sequence.to_string()
                || row.try_get::<String, _>("event_type")? != receipt.kind
                || Sha256::digest(&payload).as_slice() != receipt.payload_digest
                || row.try_get::<Vec<u8>, _>("payload_digest")? != receipt.payload_digest
            {
                return Err(CandidateStoreError::InvalidBinding);
            }
            let state: String = row.try_get("state")?;
            if state == "DELIVERED" {
                let prior: Option<Vec<u8>> = sqlx::query_scalar(
                    "select transport_receipt_digest from candidate.outbox_delivery_attempt
                    where participant_id=$1 and event_id=$2 and attempt_number=$3
                      and state='RECONCILED' and finished_at is not null",
                )
                .bind(binding.participant_id())
                .bind(event)
                .bind(attempts)
                .fetch_optional(&mut *tx)
                .await?;
                if prior.as_deref() != Some(receipt.receipt.as_slice()) {
                    return Err(CandidateStoreError::InvalidBinding);
                }
                continue;
            }
            if !matches!(state.as_str(), "PENDING" | "RETRY_WAIT") || !(0..10).contains(&attempts) {
                return Err(CandidateStoreError::InvalidBinding);
            }
            sqlx::query("insert into candidate.outbox_delivery_attempt(participant_id,event_id,attempt_number,worker_id,
                state,started_at,finished_at,transport_receipt_digest)
                values($1,$2,$3,$4,'RECONCILED',transaction_timestamp(),transaction_timestamp(),$5)")
                .bind(binding.participant_id()).bind(event).bind(attempts+1).bind(binding.operation_id()).bind(&receipt.receipt)
                .execute(&mut *tx).await?;
            sqlx::query("update candidate.outbox_event set state='DELIVERED',published_at=clock_timestamp(),attempt_count=$3
                where participant_id=$1 and event_id=$2")
                .bind(binding.participant_id()).bind(event).bind(attempts+1).execute(&mut *tx).await?;
            changed += 1;
        }
        tx.commit().await?;
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_receipt_scope_and_sequence_are_exact() {
        let ids: Vec<_> = (0..7).map(|_| Uuid::now_v7()).collect();
        let binding =
            CandidatePersistenceBinding::try_new(ids[0], ids[1], ids[2], ids[3], ids[3]).unwrap();
        let digest = format!("sha256:{}", "01".repeat(32));
        let mut receipt = WithdrawalMaterial {
            participant_id: ids[0],
            privacy_domain_id: ids[1],
            source_generation_id: ids[2],
            source_profile_id: ids[4],
            partition_id: ids[5],
            source_event_id: ids[6],
            source_sequence: "3".into(),
            source_payload_digest: digest.clone(),
            publication_digest: digest.clone(),
            prefix_digest: digest.clone(),
            authority_digest: digest,
        };
        assert!(receipt.validate(&binding, ids[4], ids[5]).is_ok());
        assert!(receipt.validate(&binding, ids[5], ids[5]).is_err());
        assert!(receipt.validate(&binding, ids[4], ids[4]).is_err());
        for value in ["0", "1", "03", "1025", "-1", "18446744073709551616"] {
            receipt.source_sequence = value.into();
            assert!(receipt.validate(&binding, ids[4], ids[5]).is_err());
        }
    }
    #[test]
    fn prefix_is_ordered_and_binds_identity_sequence_and_original_bytes() {
        let mut events = vec![
            ReceiptEvent {
                event_id: Uuid::now_v7(),
                sequence: 1,
                payload_digest: vec![1; 32],
                receipt: vec![2; 32],
                kind: OBSERVED_EVENT,
            },
            ReceiptEvent {
                event_id: Uuid::now_v7(),
                sequence: 2,
                payload_digest: vec![3; 32],
                receipt: vec![4; 32],
                kind: CHECKPOINT_EVENT,
            },
        ];
        let original = prefix_digest(&events);
        assert!(original.starts_with("sha256:"));
        assert_eq!(original.len(), 71);
        events.reverse();
        assert_ne!(prefix_digest(&events), original);
        events.reverse();
        events[0].payload_digest[0] ^= 1;
        assert_ne!(prefix_digest(&events), original);
        events[0].payload_digest[0] ^= 1;
        events[0].sequence = 3;
        assert_ne!(prefix_digest(&events), original);
        events[0].sequence = 1;
        events[0].event_id = Uuid::now_v7();
        assert_ne!(prefix_digest(&events), original);
    }
}
