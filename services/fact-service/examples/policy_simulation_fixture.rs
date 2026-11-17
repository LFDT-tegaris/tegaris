//! Local acceptance fixture: only the external source is synthetic. Admission,
//! finalization, signed readiness, reorg and readback use the durable fact owner.
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use ciborium::value::Value;
use openpc_fact_service::{FactStore, PurposeBoundFactSigner};
use pc_facts_core::{
    FACT_ADMISSION_CANDIDATE_SCHEMA_ID, FACT_BRIDGE_SCHEMA_DIGEST_V1, FACT_SCHEMA_VERSION_V1,
    FactAdmissionCandidate, TrustedAdmissionContext, encode_pc_cbor, fact_schema_identity, sha256,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

fn secret(root: &Path, name: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let text = fs::read_to_string(root.join(format!("{name}.txt")))?;
    let text = text.trim();
    if text.len() != 64 {
        return Err("invalid local secret".into());
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)?;
    }
    Ok(bytes)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !(4..=5).contains(&args.len()) {
        return Err("expected local secret directory, participant, privacy, admit/reorg and optional source sequence".into());
    }
    let [root, participant, privacy, action] = &args[..4] else {
        unreachable!()
    };
    let sequence = args
        .get(4)
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(1);
    if sequence == 0 || sequence > 1000 {
        return Err("local source sequence outside fixture bound".into());
    }
    let root = Path::new(root);
    let password = fs::read_to_string(root.join("fact_runtime_db_password.txt"))?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(55433)
                .database("openpc_facts")
                .username("openpc_fact_runtime")
                .password(password.trim()),
        )
        .await?;
    let store = FactStore::new(pool.clone(), secret(root, "fact_capability_secret")?);
    let signer = PurposeBoundFactSigner::for_local_runtime(secret(root, "fact_signing_secret")?)?;
    let verifier = signer.verifier();
    // A fresh source observation is a new immutable fact, never an extension
    // of old signed freshness. Reusing a sequence retains ordinary replay.
    let candidate_id = if sequence == 1 {
        "astra04-policy-membership".into()
    } else {
        format!("astra04-policy-membership-{sequence}")
    };
    let generation_id = format!("astra04-membership-generation-{sequence}");
    if action == "admit" {
        let observed_at_ms =
            i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        let canonical_payload = encode_pc_cbor(Value::Map(vec![(
            Value::Text("membership".into()),
            Value::Bool(true),
        )]))?;
        let canonical_provenance = b"local-external-membership-source-v1".to_vec();
        let candidate = FactAdmissionCandidate {
            candidate_id: candidate_id.clone(),
            participant_id: participant.clone(),
            privacy_domain_id: privacy.clone(),
            source_profile_id: "local-policy-membership".into(),
            generation_id,
            schema_id: FACT_ADMISSION_CANDIDATE_SCHEMA_ID,
            schema_version: FACT_SCHEMA_VERSION_V1.into(),
            schema_digest: FACT_BRIDGE_SCHEMA_DIGEST_V1,
            schema_purpose: fact_schema_identity(FACT_ADMISSION_CANDIDATE_SCHEMA_ID)
                .ok_or("schema missing")?
                .purpose_separator
                .into(),
            sequence,
            observed_at_ms,
            declared_payload_digest: sha256(&canonical_payload),
            canonical_payload,
            declared_provenance_digest: sha256(&canonical_provenance),
            canonical_provenance,
            finality_anchor: sha256(
                format!("local-external-finalized-block-{sequence}").as_bytes(),
            ),
            complete: true,
            semantic_valid: true,
            conflict_detected: false,
            terminal_denial: false,
        };
        let context = TrustedAdmissionContext {
            participant_id: participant.clone(),
            privacy_domain_id: privacy.clone(),
            source_profile_id: candidate.source_profile_id.clone(),
            generation_id: candidate.generation_id.clone(),
            expected_sequence: sequence,
            now_ms: observed_at_ms,
            maximum_age_ms: 1_200_000,
            independently_derived_provenance_digest: sha256(b"local-external-membership-source-v1"),
            trusted_finality_anchor: candidate.finality_anchor,
            profile_active: true,
            generation_fenced: false,
        };
        store
            .admit(candidate.clone(), &context, &signer, &verifier)
            .await?;
        store
            .finalize(
                participant,
                privacy,
                &candidate_id,
                candidate.finality_anchor,
            )
            .await?;
        let shard = signer.sign_shard(
            participant,
            privacy,
            &candidate.generation_id,
            sha256(format!("local-membership-shard-{sequence}").as_bytes()),
        )?;
        store
            .mark_signed_shard_ready(&verifier.verify_shard(&shard)?)
            .await?;
    } else if action == "reorg" {
        store
            .invalidate_for_reorg(participant, privacy, &candidate_id)
            .await?;
    } else {
        return Err("unsupported local fixture action".into());
    }
    let snapshot = store
        .read_policy_fact(participant, privacy, &candidate_id, &verifier)
        .await?
        .ok_or("fact missing")?;
    println!("{}", serde_json::to_string(&snapshot)?);
    pool.close().await;
    Ok(())
}
