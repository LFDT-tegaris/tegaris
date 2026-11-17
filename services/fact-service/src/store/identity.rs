//! SQLx-owned allocation is part of the same transaction as signed admission.
use super::*;
use pc_facts_core::sha256;
use uuid::Uuid;

#[cfg(test)]
pub(super) mod tests;

pub(crate) struct FactIdentityAllocation {
    pub fact_id: Uuid,
    pub generation: u64,
    pub sequence: u64,
    pub admitted_at: String,
    pub predecessor_digest: Option<[u8; 32]>,
}

impl FactStore {
    pub(crate) async fn allocate_identity(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        admission: &ValidatedAdmission,
        profile: &str,
    ) -> Result<FactIdentityAllocation, FactStoreError> {
        let fields = [
            admission.participant_id(),
            admission.privacy_domain_id(),
            admission.candidate_id(),
            profile,
            admission.generation_id(),
        ];
        let mut bytes = Vec::new();
        for (index, field) in fields.iter().enumerate() {
            bytes.extend_from_slice(&u16::try_from(index + 1).expect("five fields").to_be_bytes());
            bytes.push(1);
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        let capability = self.capabilities.fact_identity(&sha256(&bytes));
        let row = sqlx::query(
            "select * from facts.allocate_canonical_fact_identity($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(fields[0])
        .bind(fields[1])
        .bind(fields[2])
        .bind(fields[3])
        .bind(fields[4])
        .bind(capability.nonce.as_slice())
        .bind(capability.mac.as_slice())
        .fetch_one(&mut **transaction)
        .await?;
        let parse = |column| {
            row.try_get::<String, _>(column)?
                .parse::<u64>()
                .map_err(|_| FactStoreError::Feed)
        };
        let allocation = FactIdentityAllocation {
            fact_id: row.try_get("fact_id")?,
            generation: parse("canonical_generation")?,
            sequence: parse("delta_sequence")?,
            admitted_at: row.try_get("admitted_at")?,
            predecessor_digest: row
                .try_get::<Option<Vec<u8>>, _>("predecessor_digest")?
                .map(|v| v.try_into().map_err(|_| FactStoreError::Feed))
                .transpose()?,
        };
        if allocation.generation == 0
            || allocation.sequence == 0
            || (allocation.sequence == 1 && allocation.predecessor_digest.is_some())
        {
            return Err(FactStoreError::Feed);
        }
        Ok(allocation)
    }
}
