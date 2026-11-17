use std::collections::BTreeSet;

use pc_runtime_types::store_retirement::{
    RetirementAttempt, RetirementEffect, RetirementOutcome, RetirementRejection,
    RetirementSelection, RetirementStore,
};
use pc_runtime_types::store_retirement_authority::{
    RetirementAuthorityConfiguration, RetirementAuthorityTrust, RetirementHost,
    RetirementOutcomeClaims, RetirementOutcomeSigner, VerifiedRetirementRequest,
};
use pc_runtime_types::{Digest, canonical_bytes};
use sqlx::{Postgres, Row, Transaction};

use super::{FactStore, set_context, signed_record};
use crate::{
    FactSignatureVerifier,
    retirement::{FactRetirementError, Result},
};

#[cfg(test)]
mod tests;

/// An absent attempt is UNKNOWN, including when an earlier response was lost.
/// Terminal readback retains and authenticates the original signed bytes.
pub enum FactRetirementReadback {
    Unknown,
    Terminal {
        claims: Box<RetirementOutcomeClaims>,
        signed_outcome: Vec<u8>,
    },
}

pub struct FactRetirementOwner {
    store: FactStore,
    host: RetirementHost,
    trust: RetirementAuthorityTrust,
    signer: RetirementOutcomeSigner,
    fact_verifier: FactSignatureVerifier,
}

impl FactRetirementOwner {
    /// Arguments come from installed service configuration, never a request.
    pub fn from_host_configuration(
        store: FactStore,
        expected_host: RetirementHost,
        configuration: RetirementAuthorityConfiguration,
        target_signing_key: [u8; 32],
        fact_verifier: FactSignatureVerifier,
    ) -> Result<Self> {
        if expected_host.store != RetirementStore::Facts {
            return Err(FactRetirementError::Authority);
        }
        let trust = configuration.install(&expected_host).map_err(authority)?;
        let signer =
            RetirementOutcomeSigner::from_host_key(expected_host.clone(), target_signing_key)
                .map_err(authority)?;
        Ok(Self {
            store,
            host: expected_host,
            trust,
            signer,
            fact_verifier,
        })
    }

    pub async fn readback(&self, attempt: &RetirementAttempt) -> Result<FactRetirementReadback> {
        self.check_attempt(attempt)?;
        let mut tx = self.begin().await?;
        let found = self.readback_in(&mut tx, attempt).await?;
        tx.rollback().await?;
        Ok(found)
    }

    pub async fn execute(&self, signed_request: &[u8]) -> Result<FactRetirementReadback> {
        let mut tx = self.begin().await?;
        let request = self
            .trust
            .verify_request(signed_request, now_ms(&mut tx).await?)
            .map_err(authority)?;
        let attempt = &request.claims().attempt;
        self.lock(&mut tx).await?;
        request
            .ensure_live(now_ms(&mut tx).await?)
            .map_err(authority)?;
        if let terminal @ FactRetirementReadback::Terminal { .. } =
            self.readback_in(&mut tx, attempt).await?
        {
            tx.rollback().await?;
            return Ok(terminal);
        }
        let document = serde_json::to_string(attempt).map_err(authority)?;
        let blocker: Option<String> =
            sqlx::query_scalar("select facts.check_store_retirement($1::jsonb)")
                .bind(&document)
                .fetch_one(&mut *tx)
                .await?;
        let blocker = match blocker {
            Some(value) => Some(rejection(&value)?),
            None => {
                verify_signed_sources_and_references(
                    &mut tx,
                    &self.fact_verifier,
                    attempt,
                    Some(&request),
                )
                .await?
            }
        };
        let RetirementSelection::Facts { rows, .. } = &attempt.selection else {
            return Err(FactRetirementError::Authority);
        };
        let lineage = canonical_bytes(rows).map_err(authority)?;
        let event = canonical_bytes(&serde_json::json!({
            "type":"io.openpc.fact.payload.retired.v1",
            "attemptDigest":attempt.digest().map_err(authority)?,
            "selectionDigest":attempt.selection_digest,
            "retiredRows":rows.len(),
            "retiredPayloadBytes":attempt.selection.payload_bytes().map_err(authority)?
        }))
        .map_err(authority)?;
        let effect = match blocker {
            Some(rejection) => RetirementEffect::RejectedNoEffect { rejection },
            None => RetirementEffect::Applied {
                retired_rows: rows.len() as u64,
                retired_payload_bytes: attempt.selection.payload_bytes().map_err(authority)?,
                retained_lineage_digest: Digest::of(&lineage),
                outbox_event_digest: Digest::of(&event),
            },
        };
        let now = now_ms(&mut tx).await?;
        request.ensure_live(now).map_err(authority)?;
        let outcome = self.sign(attempt, effect, now)?;
        // Minting checks the real request and target signature again. The SQL
        // verifier consumes this exact domain/binding/nonce inside the effect TX.
        let capability = self
            .store
            .capabilities
            .retirement_execution(signed_request, &outcome, &self.trust, now)
            .map_err(authority)?;
        let original: Vec<u8> =
            sqlx::query_scalar("select facts.execute_store_retirement($1,$2,$3,$4,$5,$6)")
                .bind(signed_request)
                .bind(&outcome)
                .bind(event)
                .bind(lineage)
                .bind(capability.nonce.as_slice())
                .bind(capability.mac.as_slice())
                .fetch_one(&mut *tx)
                .await?;
        let result = self.terminal(attempt, original)?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn cancel(&self, signed_cancellation: &[u8]) -> Result<FactRetirementReadback> {
        let mut tx = self.begin().await?;
        let cancellation = self
            .trust
            .verify_cancel(signed_cancellation, now_ms(&mut tx).await?)
            .map_err(authority)?;
        let attempt = &cancellation.claims().attempt;
        self.lock(&mut tx).await?;
        let now = now_ms(&mut tx).await?;
        cancellation.ensure_live(now).map_err(authority)?;
        if let terminal @ FactRetirementReadback::Terminal { .. } =
            self.readback_in(&mut tx, attempt).await?
        {
            tx.rollback().await?;
            return Ok(terminal);
        }
        let outcome = self.sign(attempt, RetirementEffect::CancelledNoEffect {}, now)?;
        let capability = self
            .store
            .capabilities
            .retirement_cancellation(signed_cancellation, &outcome, &self.trust, now)
            .map_err(authority)?;
        let original: Vec<u8> =
            sqlx::query_scalar("select facts.cancel_store_retirement($1,$2,$3,$4)")
                .bind(signed_cancellation)
                .bind(outcome)
                .bind(capability.nonce.as_slice())
                .bind(capability.mac.as_slice())
                .fetch_one(&mut *tx)
                .await?;
        let result = self.terminal(attempt, original)?;
        tx.commit().await?;
        Ok(result)
    }

    fn check_attempt(&self, attempt: &RetirementAttempt) -> Result<()> {
        attempt.validate().map_err(authority)?;
        if attempt.scope != self.host.scope || attempt.store != self.host.store {
            return Err(FactRetirementError::Authority);
        }
        Ok(())
    }

    async fn begin(&self) -> Result<Transaction<'_, Postgres>> {
        let mut tx = self.store.pool.begin().await?;
        set_context(
            &mut tx,
            &self.host.scope.participant_id,
            &self.host.scope.privacy_domain_id,
        )
        .await?;
        sqlx::query("set local lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("set local statement_timeout='10s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("set local idle_in_transaction_session_timeout='10s'")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    async fn lock(&self, tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        sqlx::query("select facts.lock_store_retirement($1,$2)")
            .bind(&self.host.scope.participant_id)
            .bind(&self.host.scope.privacy_domain_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn readback_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        attempt: &RetirementAttempt,
    ) -> Result<FactRetirementReadback> {
        self.check_attempt(attempt)?;
        let stored: Option<(String, Vec<u8>)> = sqlx::query_as(
            "select encode(attempt_digest,'hex'),signed_outcome from facts.store_retirement_attempt
             where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3",
        )
        .bind(&attempt.scope.participant_id)
        .bind(&attempt.scope.privacy_domain_id)
        .bind(&attempt.attempt_id)
        .fetch_optional(&mut **tx)
        .await?;
        match stored {
            None => Ok(FactRetirementReadback::Unknown),
            Some((digest, bytes)) => {
                if digest != attempt.digest().map_err(authority)?.as_str() {
                    return Err(FactRetirementError::AlteredReplay);
                }
                self.terminal(attempt, bytes)
            }
        }
    }

    fn terminal(
        &self,
        attempt: &RetirementAttempt,
        signed_outcome: Vec<u8>,
    ) -> Result<FactRetirementReadback> {
        let claims = self
            .trust
            .verify_outcome(&signed_outcome, attempt)
            .map_err(|_| FactRetirementError::StoredOutcome)?;
        Ok(FactRetirementReadback::Terminal {
            claims: Box::new(claims),
            signed_outcome,
        })
    }

    fn sign(
        &self,
        attempt: &RetirementAttempt,
        effect: RetirementEffect,
        completed_at_ms: u64,
    ) -> Result<Vec<u8>> {
        self.signer
            .sign_in_transaction(
                RetirementOutcomeClaims {
                    version: 1,
                    host: self.host.clone(),
                    business_intent_id: attempt.business_intent_id.clone(),
                    attempt_id: attempt.attempt_id.clone(),
                    outcome: RetirementOutcome {
                        attempt_digest: attempt.digest().map_err(authority)?,
                        effect,
                    },
                    completed_at_ms,
                },
                attempt,
            )
            .map_err(authority)
    }
}

// Shared exact source/reference verifier. Only execute supplies signed authority;
// the advisory caller cannot construct or retain an execution capability.
pub(super) async fn verify_signed_sources_and_references(
    tx: &mut Transaction<'_, Postgres>,
    verifier: &FactSignatureVerifier,
    attempt: &RetirementAttempt,
    request: Option<&VerifiedRetirementRequest>,
) -> Result<Option<RetirementRejection>> {
    if request.is_some_and(|request| request.claims().attempt != *attempt) {
        return Err(FactRetirementError::Authority);
    }
    let RetirementSelection::Facts { source, rows, .. } = &attempt.selection else {
        return Err(FactRetirementError::Authority);
    };
    let p = &attempt.scope.participant_id;
    let d = &attempt.scope.privacy_domain_id;
    let mut selected_references = BTreeSet::new();
    for selected in rows {
        let stored = signed_record::load(tx, p, d, &selected.candidate_id).await?;
        let Some(record) = signed_record::verify(&stored, verifier, p, d)? else {
            return Ok(Some(RetirementRejection::SourceChanged));
        };
        let provenance: ciborium::Value = ciborium::de::from_reader(
            stored
                .try_get::<Vec<u8>, _>("canonical_provenance")?
                .as_slice(),
        )
        .map_err(authority)?;
        let publication = provenance
            .as_map()
            .and_then(|fields| {
                fields
                    .iter()
                    .find(|(key, _)| key.as_text() == Some("publicationDigest"))
            })
            .and_then(|(_, value)| value.as_text());
        if publication != Some(format!("sha256:{}", source.identity_digest.as_str()).as_str()) {
            return Ok(Some(RetirementRejection::SourceChanged));
        }
        selected_references.insert(record.identity.local_fact_digest.clone());
        selected_references.insert(record.identity.fact_id.clone());
        for reference in [
            record.predecessor_digest,
            record.relationship_predecessor_digest,
            record.reorg_replacement_of,
        ]
        .into_iter()
        .flatten()
        {
            let retained: bool =
                sqlx::query_scalar("select facts.retirement_reference_retained($1,$2,$3)")
                    .bind(p)
                    .bind(d)
                    .bind(reference)
                    .fetch_one(&mut **tx)
                    .await?;
            if !retained {
                return Ok(Some(RetirementRejection::ReferencesProtected));
            }
        }
    }
    // Exact signed incoming references, read in bounded keyset pages. No
    // caller-provided reference summary or fabricated readiness is accepted.
    let mut cursor = String::new();
    let mut scanned = 0_usize;
    loop {
        if let Some(request) = request {
            request.ensure_live(now_ms(tx).await?).map_err(authority)?;
        }
        let candidates: Vec<String> = sqlx::query_scalar("select candidate_id from facts.canonical_fact
            where participant_id=$1 and privacy_domain_id=$2 and candidate_id collate \"C\">$3
              and state not in ('RETIRED','SUPERSEDED') order by candidate_id collate \"C\" limit 32")
            .bind(p).bind(d).bind(&cursor).fetch_all(&mut **tx).await?;
        if candidates.is_empty() {
            break;
        }
        scanned += candidates.len();
        // Advisory reads have no signed request deadline. Their caller also
        // applies a wall-clock deadline; never report CLEAR after truncation.
        if request.is_none() && scanned > 4096 {
            return Err(FactRetirementError::Authority);
        }
        for candidate in &candidates {
            let stored = signed_record::load(tx, p, d, candidate).await?;
            let Some(record) = signed_record::verify(&stored, verifier, p, d)? else {
                return Ok(Some(RetirementRejection::ReferencesProtected));
            };
            if [
                record.predecessor_digest,
                record.relationship_predecessor_digest,
                record.reorg_replacement_of,
            ]
            .into_iter()
            .flatten()
            .any(|reference| selected_references.contains(&reference))
            {
                return Ok(Some(RetirementRejection::ReferencesProtected));
            }
        }
        cursor = candidates.last().expect("nonempty keyset page").clone();
    }
    Ok(None)
}

async fn now_ms(tx: &mut Transaction<'_, Postgres>) -> Result<u64> {
    let value: i64 =
        sqlx::query_scalar("select floor(extract(epoch from clock_timestamp())*1000)::bigint")
            .fetch_one(&mut **tx)
            .await?;
    u64::try_from(value).map_err(authority)
}

fn rejection(value: &str) -> Result<RetirementRejection> {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(authority)
}

fn authority<T>(_: T) -> FactRetirementError {
    FactRetirementError::Authority
}

/// Historical artifact metadata can still be authenticated after the projection
/// bytes are gone. This verifies original custody and returns no Fact value or
/// policy eligibility; it never reconstructs a replacement payload.
pub(super) async fn verify_retired_identity(
    tx: &mut Transaction<'_, Postgres>,
    verifier: &FactSignatureVerifier,
    participant: &str,
    privacy: &str,
    candidate: &str,
) -> std::result::Result<(), super::FactStoreError> {
    use crate::signing::shard::digest_text;
    use pc_facts_core::{
        FACT_RECORD_SCHEMA_ID, FactRecord, encode_pc_cbor, fact_timestamp_from_ms, sha256,
    };
    let row = sqlx::query("select i.*,c.cose_sign1,a.fact_id,a.fact_profile_id,
        a.delta_sequence::text,g.canonical_generation::text,r.canonical_provenance,l.provenance_digest,
        exists(select 1 from facts.canonical_fact f where f.candidate_id=i.candidate_id
          and f.participant_id=i.participant_id and f.privacy_domain_id=i.privacy_domain_id) payload_present
        from facts.retained_fact_identity i
        join facts.retired_fact_payload retired using(candidate_id,participant_id,privacy_domain_id)
        join facts.signed_fact_custody c using(candidate_id,participant_id,privacy_domain_id)
        join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id,generation_id)
        join facts.canonical_generation g using(participant_id,privacy_domain_id,fact_profile_id,generation_id)
        join facts.candidate_feed_receipt r using(candidate_id,participant_id,privacy_domain_id)
        join facts.fact_lineage l using(candidate_id,participant_id,privacy_domain_id)
        where i.participant_id=$1 and i.privacy_domain_id=$2 and i.candidate_id=$3")
        .bind(participant).bind(privacy).bind(candidate).fetch_one(&mut **tx).await?;
    let cose: Vec<u8> = row.try_get("cose_sign1")?;
    let claims = verifier.verified_stored_claims(FACT_RECORD_SCHEMA_ID, &cose)?;
    let record = FactRecord::from_cbor(&encode_pc_cbor(claims)?)?;
    let fact: uuid::Uuid = row.try_get("fact_id")?;
    let provenance: Vec<u8> = row.try_get("canonical_provenance")?;
    let bound = !row.try_get::<bool, _>("payload_present")?
        && record.identity.fact_id == format!("urn:openpc:fact:{fact}")
        && record.identity.participant_id == format!("urn:openpc:participant:{participant}")
        && record.identity.privacy_domain_id.as_deref()
            == Some(format!("urn:openpc:privacy-domain:{privacy}").as_str())
        && record.identity.fact_profile_id == row.try_get::<String, _>("fact_profile_id")?
        && record.identity.canonical_generation.to_string()
            == row.try_get::<String, _>("canonical_generation")?
        && record.delta_sequence.to_string() == row.try_get::<String, _>("delta_sequence")?
        && record.identity.local_fact_digest
            == digest_text(&row.try_get::<Vec<u8>, _>("fact_digest")?)
        && record.derivation_digest == digest_text(&row.try_get::<Vec<u8>, _>("payload_digest")?)
        && record.provenance_digest == digest_text(&sha256(&provenance))
        && record.provenance_digest
            == digest_text(&row.try_get::<Vec<u8>, _>("provenance_digest")?)
        && sha256(&cose).as_slice() == row.try_get::<Vec<u8>, _>("signed_fact_digest")?.as_slice()
        && record.not_before == fact_timestamp_from_ms(row.try_get("observed_at_ms")?)?
        && record.expires_at == fact_timestamp_from_ms(row.try_get("fresh_until_ms")?)?;
    if !bound {
        return Err(super::FactStoreError::Lifecycle);
    }
    Ok(())
}
