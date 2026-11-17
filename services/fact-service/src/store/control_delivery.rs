//! Bounded producer reconciliation of real Control custody. Fleet and shard
//! delivery are independent prerequisites, so this never completes the outbox.
use super::*;
use crate::source_authority::{FactSourceAuthority, delivery::ControlDeliveryBinding};
use uuid::Uuid;

#[cfg(test)]
pub(super) mod tests;

impl FactStore {
    pub(crate) async fn reconcile_control_deliveries(
        &self,
        participant: Uuid,
        privacy: Uuid,
        verifier: &FactSignatureVerifier,
        control: &FactSourceAuthority,
    ) -> Result<u64, crate::admission::StateAdmissionError> {
        let participant_text = participant.to_string();
        let privacy_text = privacy.to_string();
        let mut tx = self.pool.begin().await.map_err(FactStoreError::from)?;
        set_context(&mut tx, &participant_text, &privacy_text)
            .await
            .map_err(FactStoreError::from)?;
        sqlx::query("set local statement_timeout='5s'")
            .execute(&mut *tx)
            .await
            .map_err(FactStoreError::from)?;
        let pending = sqlx::query("select pending.* from
            (values ('CONTRACT_STATE_CALL'),('RELATIONSHIP'),('EXTERNAL_DECISION')) kinds(fact_type)
            cross join lateral (
              select e.candidate_id,e.generation_id,e.fact_type,e.sequence,
                convert_from(e.source_material,'UTF8')::jsonb->>'signedFactDigest' signed_fact_digest
              from facts.admission_delivery_event e
              left join facts.control_admission_custody_ack a using(candidate_id,participant_id,privacy_domain_id)
              where e.participant_id=$1 and e.privacy_domain_id=$2 and e.fact_type=kinds.fact_type
                and a.candidate_id is null order by e.sequence limit 64
            ) pending order by pending.fact_type,pending.sequence")
            .bind(&participant_text).bind(&privacy_text)
            .fetch_all(&mut *tx).await.map_err(FactStoreError::from)?;
        tx.rollback().await.map_err(FactStoreError::from)?;
        let mut acknowledged = 0;
        for row in pending {
            let candidate: String = row.try_get("candidate_id").map_err(FactStoreError::from)?;
            let mut tx = self.pool.begin().await.map_err(FactStoreError::from)?;
            set_context(&mut tx, &participant_text, &privacy_text)
                .await
                .map_err(FactStoreError::from)?;
            sqlx::query("set local statement_timeout='5s'")
                .execute(&mut *tx)
                .await
                .map_err(FactStoreError::from)?;
            let event = super::delivery::read_verified(
                &mut tx,
                &participant_text,
                &privacy_text,
                &candidate,
                verifier,
            )
            .await?
            .ok_or(FactStoreError::Feed)?;
            tx.rollback().await.map_err(FactStoreError::from)?;
            let expected = ControlDeliveryBinding {
                participant,
                privacy,
                candidate: Uuid::parse_str(&candidate).map_err(|_| FactStoreError::Feed)?,
                generation: row.try_get("generation_id").map_err(FactStoreError::from)?,
                fact_type: row.try_get("fact_type").map_err(FactStoreError::from)?,
                sequence: row.try_get("sequence").map_err(FactStoreError::from)?,
                event,
                signed_fact_digest: row
                    .try_get("signed_fact_digest")
                    .map_err(FactStoreError::from)?,
            };
            let Some(receipt) = control.control_delivery(&expected).await? else {
                continue;
            };
            let capability = self.capabilities.control_delivery_ack(receipt.material());
            let mut tx = self.pool.begin().await.map_err(FactStoreError::from)?;
            set_context(&mut tx, &participant_text, &privacy_text)
                .await
                .map_err(FactStoreError::from)?;
            sqlx::query("set local lock_timeout='2s'")
                .execute(&mut *tx)
                .await
                .map_err(FactStoreError::from)?;
            sqlx::query("set local statement_timeout='5s'")
                .execute(&mut *tx)
                .await
                .map_err(FactStoreError::from)?;
            let inserted: bool =
                sqlx::query_scalar("select facts.acknowledge_control_custody($1,$2,$3)")
                    .bind(receipt.material())
                    .bind(capability.nonce.as_slice())
                    .bind(capability.mac.as_slice())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(FactStoreError::from)?;
            tx.commit().await.map_err(FactStoreError::from)?;
            acknowledged += u64::from(inserted);
        }
        Ok(acknowledged)
    }
}
