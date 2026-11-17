//! Occurrence custody shares the admission transaction and policy mutation
//! fence. Contradictory admitted observations persist a terminal conflict;
//! they do not overwrite either signed historical fact.
use super::*;
use crate::state_value::SemanticOccurrence;
use pc_facts_core::sha256;

#[cfg(test)]
mod tests;

fn binding_digest(admission: &ValidatedAdmission, occurrence: &SemanticOccurrence) -> [u8; 32] {
    let fields: [&[u8]; 6] = [
        admission.participant_id().as_bytes(),
        admission.privacy_domain_id().as_bytes(),
        admission.candidate_id().as_bytes(),
        admission.canonical_fact_digest(),
        &occurrence.digest,
        &occurrence.value_digest,
    ];
    let mut bytes = Vec::new();
    for (index, field) in fields.into_iter().enumerate() {
        bytes.extend_from_slice(&((index + 1) as u16).to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    sha256(&bytes)
}

impl FactStore {
    pub(super) async fn record_occurrence(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        admission: &ValidatedAdmission,
        occurrence: &SemanticOccurrence,
    ) -> Result<bool, FactStoreError> {
        let capability = self
            .capabilities
            .fact_occurrence(&binding_digest(admission, occurrence));
        sqlx::query_scalar("select facts.bind_fact_occurrence($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(admission.participant_id())
            .bind(admission.privacy_domain_id())
            .bind(admission.candidate_id())
            .bind(admission.canonical_fact_digest().as_slice())
            .bind(&occurrence.canonical)
            .bind(occurrence.value_digest.as_slice())
            .bind(capability.nonce.as_slice())
            .bind(capability.mac.as_slice())
            .fetch_one(&mut **transaction)
            .await
            .map_err(map_database_error)
    }
}
