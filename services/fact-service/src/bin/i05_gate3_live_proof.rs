use std::{
    io::{Error, ErrorKind},
    time::{SystemTime, UNIX_EPOCH},
};

use ciborium::value::Value;
use openpc_fact_service::{
    DurableAdmissionOutcome, FactStore, FactStoreError, PurposeBoundFactSigner,
};
use pc_facts_core::{
    AdmissionError, FACT_ADMISSION_CANDIDATE_SCHEMA_ID, FACT_BRIDGE_SCHEMA_DIGEST_V1,
    FACT_SCHEMA_VERSION_V1, FactAdmissionCandidate, TrustedAdmissionContext, encode_pc_cbor,
    fact_schema_identity, sha256,
};
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LiveProof {
    proof_id: &'static str,
    operation_owner: &'static str,
    admission: DurableAdmissionOutcome,
    idempotent_replay: DurableAdmissionOutcome,
    readiness_before_finalization_rejected: bool,
    wrong_finality_anchor_rejected: bool,
    finalization_observed: bool,
    signed_shard_ready_observed: bool,
    replacement_before_invalidation_rejected: bool,
    same_generation_rejected: bool,
    incomplete_replacement_rejected: bool,
    stale_replacement_rejected: bool,
    nonfinal_replacement_rejected: bool,
    replacement: DurableAdmissionOutcome,
    replacement_signed_shard_ready_observed: bool,
    batch_dependency_fence_observed: bool,
    snapshot: openpc_fact_service::LifecycleSnapshot,
    private_key_persisted: bool,
    production_claim: &'static str,
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_millis(),
    )
    .expect("current epoch milliseconds fit i64")
}

fn capability_secret() -> Result<[u8; 32], Error> {
    let encoded = std::env::var("OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX").map_err(|_| {
        Error::new(
            ErrorKind::NotFound,
            "FactStore capability secret is required",
        )
    })?;
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "FactStore capability secret must be exactly 32 hex-encoded bytes",
        ));
    }
    let mut secret = [0_u8; 32];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "FactStore capability secret contains invalid hex",
            )
        })?;
    }
    Ok(secret)
}

fn candidate(
    candidate_id: &str,
    generation_id: &str,
    sequence: u64,
    observed_at_ms: i64,
) -> FactAdmissionCandidate {
    let canonical_payload = encode_pc_cbor(Value::Map(vec![
        (
            Value::Text("factType".into()),
            Value::Text("membership".into()),
        ),
        (
            Value::Text("candidate".into()),
            Value::Text(candidate_id.into()),
        ),
    ]))
    .expect("fixture payload is PC-CBOR-1");
    let canonical_provenance = format!("lineage:{candidate_id}").into_bytes();
    FactAdmissionCandidate {
        candidate_id: candidate_id.into(),
        participant_id: "participant-a".into(),
        privacy_domain_id: "privacy-a".into(),
        source_profile_id: "profile-a".into(),
        generation_id: generation_id.into(),
        schema_id: FACT_ADMISSION_CANDIDATE_SCHEMA_ID,
        schema_version: FACT_SCHEMA_VERSION_V1.into(),
        schema_digest: FACT_BRIDGE_SCHEMA_DIGEST_V1,
        schema_purpose: fact_schema_identity(FACT_ADMISSION_CANDIDATE_SCHEMA_ID)
            .expect("frozen FactAdmissionCandidateV1 schema identity exists")
            .purpose_separator
            .into(),
        sequence,
        observed_at_ms,
        declared_payload_digest: sha256(&canonical_payload),
        canonical_payload,
        declared_provenance_digest: sha256(&canonical_provenance),
        canonical_provenance,
        finality_anchor: sha256(format!("finality:{candidate_id}").as_bytes()),
        complete: true,
        semantic_valid: true,
        conflict_detected: false,
        terminal_denial: false,
    }
}

fn trusted(candidate: &FactAdmissionCandidate, now_ms: i64) -> TrustedAdmissionContext {
    TrustedAdmissionContext {
        participant_id: candidate.participant_id.clone(),
        privacy_domain_id: candidate.privacy_domain_id.clone(),
        source_profile_id: candidate.source_profile_id.clone(),
        generation_id: candidate.generation_id.clone(),
        expected_sequence: candidate.sequence,
        now_ms,
        maximum_age_ms: 60_000,
        independently_derived_provenance_digest: candidate.declared_provenance_digest,
        trusted_finality_anchor: candidate.finality_anchor,
        profile_active: true,
        generation_fenced: false,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    let store = FactStore::new(pool, capability_secret()?);
    let signer = PurposeBoundFactSigner::generate_ephemeral_local(b"i05-gate3-ephemeral".to_vec())?;
    let verifier = signer.verifier();
    let current = now_ms();

    let first = candidate("candidate-1", "generation-1", 1, current);
    let first_context = trusted(&first, current + 1);
    let admission = store
        .admit(first.clone(), &first_context, &signer, &verifier)
        .await?;
    let idempotent_replay = store
        .admit(first.clone(), &first_context, &signer, &verifier)
        .await?;
    assert_eq!(
        store
            .read_policy_fact(
                &first.participant_id,
                &first.privacy_domain_id,
                &first.candidate_id,
                &verifier
            )
            .await?
            .expect("admitted fact read")
            .outcome,
        pc_facts_core::FactQueryOutcome::NotReady,
    );

    let first_shard = signer.sign_shard(
        &first.participant_id,
        &first.privacy_domain_id,
        &first.generation_id,
        sha256(b"signed-shard-1"),
    )?;
    let first_verified_shard = verifier.verify_shard_cose(&first_shard.cose_sign1)?;
    let readiness_before_finalization_rejected = matches!(
        store.mark_signed_shard_ready(&first_verified_shard).await,
        Err(FactStoreError::Lifecycle)
    );
    let wrong_finality_anchor_rejected = matches!(
        store
            .finalize(
                &first.participant_id,
                &first.privacy_domain_id,
                &first.candidate_id,
                [0; 32],
            )
            .await,
        Err(FactStoreError::Lifecycle)
    );
    store
        .finalize(
            &first.participant_id,
            &first.privacy_domain_id,
            &first.candidate_id,
            first.finality_anchor,
        )
        .await?;
    store.mark_signed_shard_ready(&first_verified_shard).await?;
    let current_fact = store
        .read_policy_fact(
            &first.participant_id,
            &first.privacy_domain_id,
            &first.candidate_id,
            &verifier,
        )
        .await?
        .expect("finalized fact read");
    assert_eq!(
        current_fact.outcome,
        pc_facts_core::FactQueryOutcome::Present
    );
    assert!(current_fact.snapshot_at_ms >= current_fact.observed_at_ms);
    assert!(current_fact.snapshot_at_ms < current_fact.fresh_until_ms);
    assert!(
        store
            .read_policy_fact(
                "foreign-participant",
                &first.privacy_domain_id,
                &first.candidate_id,
                &verifier
            )
            .await?
            .is_none()
    );
    assert!(
        store
            .read_policy_fact(
                &first.participant_id,
                "foreign-privacy",
                &first.candidate_id,
                &verifier
            )
            .await?
            .is_none()
    );
    let foreign_verifier =
        PurposeBoundFactSigner::generate_ephemeral_local(b"i05-gate3-ephemeral".to_vec())?
            .verifier();
    assert_eq!(
        store
            .read_policy_fact(
                &first.participant_id,
                &first.privacy_domain_id,
                &first.candidate_id,
                &foreign_verifier
            )
            .await?
            .expect("wrong-key read")
            .outcome,
        pc_facts_core::FactQueryOutcome::Tampered
    );
    let reopened = FactStore::new(
        PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await?,
        capability_secret()?,
    );
    let reread = reopened
        .read_policy_fact(
            &first.participant_id,
            &first.privacy_domain_id,
            &first.candidate_id,
            &verifier,
        )
        .await?
        .expect("read through fresh connection");
    assert_eq!(reread.outcome, pc_facts_core::FactQueryOutcome::Present);
    assert_eq!(reread.fact_digest, current_fact.fact_digest);
    assert_eq!(reread.shard_digest, current_fact.shard_digest);
    drop(reopened);
    let reader_url = std::env::var("OPENPC_POLICY_FACT_READER_DATABASE_URL")?;
    let reader_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&reader_url)
        .await?;
    let reader = openpc_fact_service::PolicyFactReader::new(reader_pool.clone(), verifier.clone());
    assert_eq!(
        reader
            .read(
                &first.participant_id,
                &first.privacy_domain_id,
                &first.candidate_id
            )
            .await?
            .expect("read-only role")
            .outcome,
        pc_facts_core::FactQueryOutcome::Present
    );
    assert!(
        reader
            .read(
                "foreign-participant",
                &first.privacy_domain_id,
                &first.candidate_id
            )
            .await?
            .is_none()
    );
    assert!(!sqlx::query_scalar::<_, bool>("select has_table_privilege(current_user,'facts.canonical_fact','INSERT,UPDATE,DELETE') or has_table_privilege(current_user,'facts.mutation_capability_secret','SELECT')")
        .fetch_one(&reader_pool).await?);
    assert!(
        sqlx::query("delete from facts.canonical_fact where candidate_id='candidate-1'")
            .execute(&reader_pool)
            .await
            .is_err()
    );

    let replacement = candidate("candidate-2", "generation-2", 2, current + 10);
    let replacement_context = trusted(&replacement, current + 20);
    let replacement_before_invalidation_rejected = matches!(
        store
            .admit_replacement(
                &first.candidate_id,
                replacement.clone(),
                &replacement_context,
                &signer,
                &verifier,
            )
            .await,
        Err(FactStoreError::Replacement)
    );
    // The synchronous target client retains a second actual database fence,
    // not an in-memory copy of a transaction that has already been released.
    let target_reader =
        openpc_fact_service::FactLeaseReader::connect(reader_url, verifier.clone())?;
    assert!(
        target_reader
            .acquire(
                "foreign-participant",
                &first.privacy_domain_id,
                &first.candidate_id,
                1000
            )
            .is_err()
    );
    for (generation, digest) in [
        ("generation-stale", first_shard.shard_digest),
        (first.generation_id.as_str(), sha256(b"substituted shard")),
    ] {
        let other = signer.sign_shard(
            &first.participant_id,
            &first.privacy_domain_id,
            generation,
            digest,
        )?;
        let other = verifier.verify_shard_cose(&other.cose_sign1)?;
        assert!(matches!(
            target_reader.acquire_for_shard(&other, &first.candidate_id, 1000),
            Err(openpc_fact_service::FactLeaseError::Denied)
        ));
    }
    let target_lease =
        target_reader.acquire_for_shard(&first_verified_shard, &first.candidate_id, 1000)?;
    assert_eq!(
        target_lease.snapshot().fact_digest,
        current_fact.fact_digest
    );
    target_lease.revalidate()?;
    let mut fact_lease = reader
        .lease(
            &first.participant_id,
            &first.privacy_domain_id,
            &first.candidate_id,
            1000,
        )
        .await?
        .expect("runtime fact lease");
    fact_lease.revalidate().await?;
    let invalidation = store.invalidate_for_reorg(
        &first.participant_id,
        &first.privacy_domain_id,
        &first.candidate_id,
    );
    tokio::pin!(invalidation);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(75), &mut invalidation)
            .await
            .is_err(),
        "reorg must wait for the actual decision/evidence fence"
    );
    fact_lease.revalidate().await?;
    fact_lease.release().await?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(75), &mut invalidation)
            .await
            .is_err(),
        "the target adapter must retain its own database fence"
    );
    target_lease.revalidate()?;
    drop(target_lease);
    tokio::time::timeout(std::time::Duration::from_secs(2), invalidation).await??;
    let mut after_lease = reader
        .lease(
            &first.participant_id,
            &first.privacy_domain_id,
            &first.candidate_id,
            1000,
        )
        .await?
        .expect("retained reorg fact");
    assert_eq!(
        after_lease.snapshot().outcome,
        pc_facts_core::FactQueryOutcome::Reorg
    );
    assert!(after_lease.revalidate().await.is_err());
    after_lease.release().await?;
    assert!(
        target_reader
            .acquire(
                &first.participant_id,
                &first.privacy_domain_id,
                &first.candidate_id,
                1000
            )
            .is_err()
    );
    drop(target_reader);
    reader_pool.close().await;
    assert_eq!(
        store
            .read_policy_fact(
                &first.participant_id,
                &first.privacy_domain_id,
                &first.candidate_id,
                &verifier
            )
            .await?
            .expect("reorg fact read")
            .outcome,
        pc_facts_core::FactQueryOutcome::Reorg,
    );

    let same_generation = candidate("candidate-same-generation", "generation-1", 2, current + 10);
    let same_generation_context = trusted(&same_generation, current + 20);
    let same_generation_rejected = matches!(
        store
            .admit_replacement(
                &first.candidate_id,
                same_generation,
                &same_generation_context,
                &signer,
                &verifier,
            )
            .await,
        Err(FactStoreError::Replacement)
    );
    let mut incomplete = candidate(
        "candidate-incomplete",
        "generation-incomplete",
        2,
        current + 10,
    );
    incomplete.complete = false;
    let incomplete_context = trusted(&incomplete, current + 20);
    let incomplete_replacement_rejected = matches!(
        store
            .admit_replacement(
                &first.candidate_id,
                incomplete,
                &incomplete_context,
                &signer,
                &verifier,
            )
            .await,
        Err(FactStoreError::Validation(
            AdmissionError::CompletenessOrSequence
        ))
    );
    let stale = candidate("candidate-stale", "generation-stale", 2, current - 120_000);
    let stale_context = trusted(&stale, current);
    let stale_replacement_rejected = matches!(
        store
            .admit_replacement(
                &first.candidate_id,
                stale,
                &stale_context,
                &signer,
                &verifier,
            )
            .await,
        Err(FactStoreError::Validation(
            AdmissionError::FreshnessOrProfile
        ))
    );
    let nonfinal = candidate("candidate-nonfinal", "generation-nonfinal", 2, current + 10);
    let mut nonfinal_context = trusted(&nonfinal, current + 20);
    nonfinal_context.trusted_finality_anchor = [0; 32];
    let nonfinal_replacement_rejected = matches!(
        store
            .admit_replacement(
                &first.candidate_id,
                nonfinal,
                &nonfinal_context,
                &signer,
                &verifier,
            )
            .await,
        Err(FactStoreError::Validation(AdmissionError::FinalityOrFence))
    );

    let replacement_outcome = store
        .admit_replacement(
            &first.candidate_id,
            replacement.clone(),
            &replacement_context,
            &signer,
            &verifier,
        )
        .await?;
    let replacement_shard = signer.sign_shard(
        &replacement.participant_id,
        &replacement.privacy_domain_id,
        &replacement.generation_id,
        sha256(b"signed-shard-2"),
    )?;
    let replacement_verified_shard = verifier.verify_shard(&replacement_shard)?;
    store
        .mark_signed_shard_ready(&replacement_verified_shard)
        .await?;
    let snapshot = store
        .snapshot(
            &first.participant_id,
            &first.privacy_domain_id,
            &first.candidate_id,
            &replacement.candidate_id,
        )
        .await?;

    // A historically admitted and finalized fact stays ineligible after its
    // signed freshness bound, including through a fresh read connection.
    let mut expired = candidate(
        "expired-candidate",
        "expired-generation",
        1,
        current - 120_000,
    );
    expired.participant_id = "expired-participant".into();
    expired.privacy_domain_id = "expired-privacy".into();
    let expired_context = trusted(&expired, expired.observed_at_ms);
    store
        .admit(expired.clone(), &expired_context, &signer, &verifier)
        .await?;
    store
        .finalize(
            &expired.participant_id,
            &expired.privacy_domain_id,
            &expired.candidate_id,
            expired.finality_anchor,
        )
        .await?;
    let expired_shard = signer.sign_shard(
        &expired.participant_id,
        &expired.privacy_domain_id,
        &expired.generation_id,
        sha256(b"expired-shard"),
    )?;
    store
        .mark_signed_shard_ready(&verifier.verify_shard(&expired_shard)?)
        .await?;
    assert_eq!(
        store
            .read_policy_fact(
                &expired.participant_id,
                &expired.privacy_domain_id,
                &expired.candidate_id,
                &verifier
            )
            .await?
            .expect("expired fact read")
            .outcome,
        pc_facts_core::FactQueryOutcome::Stale
    );

    println!(
        "{}",
        serde_json::to_string(&LiveProof {
            proof_id: "OPENPC-I05-GATE3-R1-LIVE-FACT-STORE",
            operation_owner: "openpc_fact_service::FactStore",
            admission,
            idempotent_replay,
            readiness_before_finalization_rejected,
            wrong_finality_anchor_rejected,
            finalization_observed: true,
            signed_shard_ready_observed: true,
            replacement_before_invalidation_rejected,
            same_generation_rejected,
            incomplete_replacement_rejected,
            stale_replacement_rejected,
            nonfinal_replacement_rejected,
            replacement: replacement_outcome,
            replacement_signed_shard_ready_observed: true,
            batch_dependency_fence_observed: batch_dependency_fence(&store, &signer, &verifier)
                .await?,
            snapshot,
            private_key_persisted: false,
            production_claim: "NOT_PROVEN_OPEN",
        })?
    );
    Ok(())
}

async fn batch_dependency_fence(
    store: &FactStore,
    signer: &PurposeBoundFactSigner,
    verifier: &openpc_fact_service::FactSignatureVerifier,
) -> Result<bool, Box<dyn std::error::Error>> {
    let observed = now_ms();
    let mut candidates = Vec::new();
    for sequence in 1..=2 {
        let mut input = candidate(
            &format!("batch-candidate-{sequence}"),
            "batch-generation",
            sequence,
            observed,
        );
        input.participant_id = "batch-participant".into();
        input.privacy_domain_id = "batch-privacy".into();
        store
            .admit(input.clone(), &trusted(&input, observed), signer, verifier)
            .await?;
        store
            .finalize(
                &input.participant_id,
                &input.privacy_domain_id,
                &input.candidate_id,
                input.finality_anchor,
            )
            .await?;
        candidates.push(input.candidate_id);
    }
    let signed = signer.sign_shard(
        "batch-participant",
        "batch-privacy",
        "batch-generation",
        sha256(b"batch-shard"),
    )?;
    let shard = verifier.verify_shard_cose(&signed.cose_sign1)?;
    store.mark_signed_shard_ready(&shard).await?;
    let reader = openpc_fact_service::FactLeaseReader::connect(
        std::env::var("OPENPC_POLICY_FACT_READER_DATABASE_URL")?,
        verifier.clone(),
    )?;
    assert!(matches!(
        reader.acquire_many_for_shard(
            &shard,
            &[candidates[0].clone(), candidates[0].clone()],
            1000
        ),
        Err(openpc_fact_service::FactLeaseError::InvalidInput)
    ));
    assert!(matches!(
        reader.acquire_many_for_shard(&shard, &[candidates[0].clone(), "missing".into()], 1000),
        Err(openpc_fact_service::FactLeaseError::Denied)
    ));
    let lease = reader.acquire_many_for_shard(&shard, &candidates, 1000)?;
    assert_eq!(
        lease
            .snapshots()
            .iter()
            .map(|s| s.candidate_id.clone())
            .collect::<Vec<_>>(),
        candidates
    );
    lease.revalidate()?;
    // Reorg of the second dependency must wait for the same held transaction.
    let invalidation =
        store.invalidate_for_reorg("batch-participant", "batch-privacy", &candidates[1]);
    tokio::pin!(invalidation);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(75), &mut invalidation)
            .await
            .is_err()
    );
    lease.revalidate()?;
    drop(lease);
    tokio::time::timeout(std::time::Duration::from_secs(2), invalidation).await??;
    assert!(
        reader
            .acquire_many_for_shard(&shard, &candidates, 1000)
            .is_err()
    );
    Ok(true)
}
