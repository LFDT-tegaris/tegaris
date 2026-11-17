//! Replay-safe terminal closure after the existing source/Fact owners have
//! established a complete prefix and signed retirement. Never renew readiness.
use super::*;
use pc_facts_core::FactRecord;

#[cfg(test)]
mod tests;

pub(super) async fn close(
    store: &FactStore,
    tx: &mut Transaction<'_, Postgres>,
    proof: &VerifiedSourceWithdrawal,
    signer: &PurposeBoundFactSigner,
    records: &[(String, FactRecord)],
) -> Result<(), FactStoreError> {
    let fence = &proof.fence;
    let Some(prefix) = &fence.terminal_prefix else {
        return Ok(());
    };
    if records.is_empty() {
        return Ok(());
    }
    for (candidate, record) in records {
        let row = sqlx::query(
            "select lineage_action_id,cose_sign1 from facts.lineage_outbox
             where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3
               and source_event_id=$4 and event_type='io.openpc.fact.fact.retired.v1'",
        )
        .bind(fence.participant.to_string())
        .bind(fence.privacy.to_string())
        .bind(candidate)
        .bind(fence.event_id)
        .fetch_one(&mut **tx)
        .await?;
        let cose: Vec<u8> = row.try_get("cose_sign1")?;
        let claims = signer.verifier().verified_stored_claims(21004, &cose)?;
        let value: serde_json::Value =
            ciborium::de::from_reader(encode_pc_cbor(claims)?.as_slice())
                .map_err(|_| FactStoreError::Lifecycle)?;
        if value["purpose"] != "openpc:fact-lineage-action:v1"
            || value["action"] != "RETIRE"
            || value["reasonCode"] != "SOURCE_QUALIFICATION_WITHDRAWN"
            || value["lineageActionId"] != row.try_get::<Uuid, _>("lineage_action_id")?.to_string()
            || value["targetFactId"] != record.identity.fact_id
            || value["targetGeneration"] != record.identity.canonical_generation
            || value["predecessorDigest"] != record.identity.local_fact_digest
            || value["participantId"] != record.identity.participant_id
            || value["privacyDomainId"] != serde_json::json!(record.identity.privacy_domain_id)
            || value["causationId"] != fence.event_id.to_string()
            || value["evidenceRefs"]
                != serde_json::json!([
                    digest_text(&sha256(&fence.payload)),
                    record.provenance_digest
                ])
        {
            return Err(FactStoreError::Lifecycle);
        }
    }
    let material = serde_json::to_vec(&serde_json::json!({
        "participantId":fence.participant.to_string(),"privacyDomainId":fence.privacy.to_string(),
        "sourceProfileId":fence.source_profile.to_string(),"partitionId":fence.partition.to_string(),
        "sourceGenerationId":fence.generation.to_string(),"sourceEventId":fence.event_id.to_string(),
        "sourceSequence":fence.sequence.to_string(),"sourcePayloadDigest":digest_text(&sha256(&fence.payload)),
        "publicationDigest":digest_text(&fence.publication_digest),"prefixDigest":digest_text(&prefix.digest),
        "authorityDigest":digest_text(&proof.authority_digest),
    }))
    .map_err(|_| FactStoreError::Lifecycle)?;
    let capability = store.capabilities.withdrawal_checkpoint(&sha256(&material));
    let _: bool = sqlx::query_scalar("select facts.close_source_withdrawal($1,$2,$3)")
        .bind(material)
        .bind(capability.nonce.as_slice())
        .bind(capability.mac.as_slice())
        .fetch_one(&mut **tx)
        .await?;
    Ok(())
}
