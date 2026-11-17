//! Consumes a fresh fixture produced by the real governed Control/source path.
//! It deliberately cannot seed terminal Fact state or mint Control authority.
//! The integration runner supplies this case only after its prerequisites pass.
use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernedCase {
    expected_host: RetirementHost,
    configuration: RetirementAuthorityConfiguration,
    target_key_file: PathBuf,
    fact_public_key_file: PathBuf,
    fact_signer_key_id: String,
    signed_request_file: PathBuf,
}

fn read(path: &Path, maximum: u64) -> Vec<u8> {
    assert!(path.is_absolute());
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && metadata.len() <= maximum);
    fs::read(path).unwrap()
}

#[tokio::test]
#[ignore = "BLOCKED until a fresh governed terminal Fact case, migrated writer and test admin connection are supplied"]
async fn governed_physical_effect_preserves_identity_signed_custody_and_rebuild_barrier() {
    // Prepare stable dependencies before the producer acquires this request's
    // finite authority. Never change the supplied intent to bypass a denial.
    let case_file = std::env::var_os("OPENPC_FACT_RETIREMENT_CASE_FILE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!("OPENPC_FACT_RETIREMENT|status=BLOCKED|reason=MISSING_GOVERNED_CASE")
        });
    // A missing prerequisite fails the selected gate with a fixed BLOCKED
    // marker before any database connection. It never returns a successful skip.
    fs::symlink_metadata(&case_file).unwrap_or_else(|_| {
        panic!("OPENPC_FACT_RETIREMENT|status=BLOCKED|reason=GOVERNED_CASE_UNAVAILABLE")
    });
    let case: GovernedCase = serde_json::from_slice(&read(&case_file, 1_048_576)).unwrap();
    let key_text = read(&case.target_key_file, 128);
    let key_text = std::str::from_utf8(&key_text).unwrap().trim();
    assert_eq!(key_text.len(), 64);
    let mut target_key = [0_u8; 32];
    for (index, byte) in target_key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&key_text[index * 2..index * 2 + 2], 16).unwrap();
    }
    let verifier = FactSignatureVerifier::from_key_identifier(
        &case.fact_signer_key_id,
        &read(&case.fact_public_key_file, 1024),
    )
    .unwrap();
    let secret = capability_secret();
    let pool = runtime_pool().await;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("OPENPC_I05_GATE3_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let owner = FactRetirementOwner::from_host_configuration(
        FactStore::new(pool, secret),
        case.expected_host,
        case.configuration,
        target_key,
        verifier,
    )
    .unwrap();
    let request = read(&case.signed_request_file, 1_048_576);
    let mut tx = owner.begin().await.unwrap();
    let verified = owner
        .trust
        .verify_request(&request, now_ms(&mut tx).await.unwrap())
        .unwrap();
    let attempt = &verified.claims().attempt;
    let RetirementSelection::Facts { rows, .. } = &attempt.selection else {
        panic!("Fact selection");
    };
    let mut originals = Vec::new();
    for selected in rows {
        let original: (String,Vec<u8>,String,String) = sqlx::query_as("select to_jsonb(f)::text,f.cose_sign1,
            a.fact_id::text,a.delta_sequence::text from facts.canonical_fact f
            join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id,generation_id)
            where f.participant_id=$1 and f.privacy_domain_id=$2 and f.candidate_id=$3")
            .bind(&attempt.scope.participant_id).bind(&attempt.scope.privacy_domain_id).bind(&selected.candidate_id)
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(Digest::of(&original.1), selected.signed_fact_digest);
        assert_eq!(original.2, selected.fact_id);
        assert_eq!(original.3, selected.fact_delta_sequence.to_string());
        originals.push(original);
    }
    tx.rollback().await.unwrap();
    assert!(matches!(
        owner.readback(attempt).await.unwrap(),
        FactRetirementReadback::Unknown
    ));
    // Drop the response after the actual target commit. Recovery must reload the
    // committed signature, not infer no-effect or submit another business intent.
    drop(owner.execute(&request).await.unwrap());
    let (effect, original_outcome) = terminal(owner.readback(attempt).await.unwrap());
    let RetirementEffect::Applied {
        retired_rows,
        retired_payload_bytes,
        ..
    } = effect
    else {
        panic!("governed positive case did not physically retire its selection");
    };
    assert_eq!(retired_rows, rows.len() as u64);
    assert_eq!(
        retired_payload_bytes,
        attempt.selection.payload_bytes().unwrap()
    );
    let (_, replay) = terminal(owner.execute(&request).await.unwrap());
    assert_eq!(replay, original_outcome);
    let mut tx = owner.begin().await.unwrap();
    for (selected, original) in rows.iter().zip(&originals) {
        let retained: (Vec<u8>,String,String,bool) = sqlx::query_as("select c.cose_sign1,a.fact_id::text,a.delta_sequence::text,
            exists(select 1 from facts.canonical_fact f where f.candidate_id=c.candidate_id
              and f.participant_id=c.participant_id and f.privacy_domain_id=c.privacy_domain_id)
            from facts.signed_fact_custody c join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id)
            where c.participant_id=$1 and c.privacy_domain_id=$2 and c.candidate_id=$3")
            .bind(&attempt.scope.participant_id).bind(&attempt.scope.privacy_domain_id).bind(&selected.candidate_id)
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(retained.0, original.1);
        assert_eq!(retained.1, original.2);
        assert_eq!(retained.2, original.3);
        assert!(!retained.3);
        verify_retired_identity(
            &mut tx,
            &owner.fact_verifier,
            &attempt.scope.participant_id,
            &attempt.scope.privacy_domain_id,
            &selected.candidate_id,
        )
        .await
        .unwrap();
    }
    tx.rollback().await.unwrap();
    for (selected, original) in rows.iter().zip(&originals) {
        let readback = owner
            .store
            .admission_readback(
                Uuid::parse_str(&attempt.scope.participant_id).unwrap(),
                Uuid::parse_str(&attempt.scope.privacy_domain_id).unwrap(),
                Uuid::parse_str(&selected.candidate_id).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(readback.state, "RETIRED");
        assert_eq!(readback.authority, "HISTORICAL_RECEIPT_ONLY");
        // Simulate an obsolete rebuild using the lifecycle role and exact old
        // row. The retained identity prevents resurrection even with old bytes.
        let mut tx = admin.begin().await.unwrap();
        sqlx::query("set local role openpc_facts_lifecycle_owner")
            .execute(&mut *tx)
            .await
            .unwrap();
        set_context(
            &mut tx,
            &attempt.scope.participant_id,
            &attempt.scope.privacy_domain_id,
        )
        .await
        .unwrap();
        let rebuild = sqlx::query(
            "insert into facts.canonical_fact
            select * from jsonb_populate_record(null::facts.canonical_fact,$1::jsonb)",
        )
        .bind(&original.0)
        .execute(&mut *tx)
        .await;
        assert!(rebuild.is_err());
        tx.rollback().await.unwrap();
    }
    let (_, unchanged) = terminal(owner.readback(attempt).await.unwrap());
    assert_eq!(unchanged, original_outcome);
}
