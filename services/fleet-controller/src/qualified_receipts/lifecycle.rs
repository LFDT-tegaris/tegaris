//! Qualified lifecycle receipts advance their own ordinal, including states with no event.
use super::*;
use serde_json::Value as Json;
use sqlx::postgres::PgRow;

const LIFECYCLE: &str = "CONTROL_SIGNING_LIFECYCLE_V1";
const AGGREGATE: &str = "signing-key-rotation";
const V2_DEFINITION: &str = "4e7de36861819909275bdec8103d1df04984c03b34cb593437dfe68f5c2c1d9a";
const ADVANCE: &str = "b4a8a3751e2906c5f2b085434afca448e035e1ae0e797c6b183a6e8d0c876a96";
const RECOVER: &str = "d711d975d1702ba4cebbf04d802023c1d573cdcd911dd511367292cc524f2aa8";
const STATES: &[&str] = &[
    "REQUESTED",
    "APPROVED",
    "PREPARED",
    "DISTRIBUTED",
    "VERIFIED",
    "CUTOVER_FENCED",
    "OBSERVING",
    "OLD_REVOKED",
    "OLD_RETIRED",
    "COMPLETE",
    "FAILED",
    "RECOVERING",
];

fn column(row: &PgRow, name: &str) -> Result<Vec<u8>> {
    row.try_get(name).map_err(|_| failure())
}
fn string(row: &PgRow, name: &str) -> Result<String> {
    row.try_get(name).map_err(|_| failure())
}
fn exact_map(value: &Value, keys: &[u64]) -> Result<()> {
    if !value.as_map().is_some_and(|m| m.len() == keys.len())
        || keys.iter().any(|&k| field(value, k).is_err())
    {
        return Err(failure());
    }
    Ok(())
}
fn h32(value: &Value) -> Result<&[u8]> {
    let b = bytes(value)?;
    if b.len() != 32 || b.iter().all(|&b| b == 0) {
        return Err(failure());
    }
    Ok(b)
}
fn profile(receipt: &Value) -> Result<(&'static str, &'static str, &'static str)> {
    match text(field(receipt, 2)?)? {
        "pc.control.signing-rotation.advance" => Ok((
            ADVANCE,
            "ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1",
            "OPS-OP-ADVANCE-SIGNING-KEY-ROTATION",
        )),
        "pc.control.signing-rotation.recover" => Ok((
            RECOVER,
            "ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1",
            "OPS-OP-RECOVER-SIGNING-KEY-ROTATION",
        )),
        _ => Err(failure()),
    }
}
fn state_projection(receipt: &Value, which: u64, preimage: &[u8]) -> Result<Value> {
    let state = field(receipt, which)?;
    exact_map(state, &[0, 1, 2])?;
    let value = decode(preimage)?;
    let a = value
        .as_array()
        .filter(|a| a.len() == 9)
        .ok_or_else(failure)?;
    if text(&a[0])? != "pc.control.transition-state.v1"
        || bytes(&a[1])? != bytes(field(receipt, 4)?)?
        || bytes(&a[2])? != bytes(field(receipt, 6)?)?
        || bytes(&a[3])? != bytes(field(receipt, 7)?)?
        || text(&a[4])? != AGGREGATE
        || bytes(&a[5])? != bytes(field(receipt, 12)?)?
        || integer(&a[6])? != 1
        || integer(field(state, 0)?)? != 1
        || integer(&a[7])? != integer(field(state, 1)?)?
        || Sha256::digest(preimage).as_slice() != h32(field(state, 2)?)?
    {
        return Err(failure());
    }
    let p = &a[8];
    let presence = integer(field(p, 5)?)?;
    match presence {
        0 => exact_map(p, &[0, 1, 2, 3, 4, 5])?,
        1 => {
            exact_map(p, &[0, 1, 2, 3, 4, 5, 6])?;
            if h32(field(p, 6)?)? == h32(field(p, 4)?)? {
                return Err(failure());
            }
        }
        _ => return Err(failure()),
    }
    if !STATES.contains(&text(field(p, 0)?)?)
        || !["BUSINESS_EFFECT", "LIFECYCLE_EVIDENCE"].contains(&text(field(p, 3)?)?)
    {
        return Err(failure());
    }
    for k in [1, 2, 4] {
        h32(field(p, k)?)?;
    }
    Ok(p.clone())
}
fn verify_states(receipt: &Value, before: &Value, after: &Value) -> Result<()> {
    let from = text(field(before, 0)?)?;
    let to = text(field(after, 0)?)?;
    let recovery = text(field(receipt, 2)?)? == "pc.control.signing-rotation.recover";
    let valid = if recovery {
        !matches!(from, "REQUESTED" | "COMPLETE")
            && to != "FAILED"
            && (to == "RECOVERING" || to == from)
    } else if to == "FAILED" {
        !matches!(from, "REQUESTED" | "COMPLETE" | "FAILED")
    } else if from == "RECOVERING" {
        STATES[2..10].contains(&to)
    } else {
        STATES[1..10].windows(2).any(|pair| pair == [from, to])
    };
    if !valid
        || integer(field(field(receipt, 18)?, 1)?)?.checked_add(1)
            != Some(integer(field(field(receipt, 19)?, 1)?)?)
        || [1, 3, 4]
            .iter()
            .any(|&k| field(before, k) != field(after, k))
        || field(before, 2)? == field(after, 2)?
        || (integer(field(before, 5)?)? == 1 && field(before, 6)? != field(after, 6)?)
        || ((recovery || to != "PREPARED") && field(before, 5)? != field(after, 5)?)
    {
        return Err(failure());
    }
    Ok(())
}
fn verify_trust(receipt: &Value, public: &[u8], preimage: &[u8], epoch: u64) -> Result<()> {
    let value = decode(preimage)?;
    let a = value
        .as_array()
        .filter(|a| a.len() == 21)
        .ok_or_else(failure)?;
    let grants = a[20]
        .as_array()
        .filter(|a| a.len() == 2)
        .ok_or_else(failure)?;
    let mut admitted = std::collections::BTreeSet::new();
    for grant in grants {
        let g = grant
            .as_array()
            .filter(|a| a.len() == 5)
            .ok_or_else(failure)?;
        let expected = match text(&g[0])? {
            "pc.control.signing-rotation.advance" => (
                ADVANCE,
                "ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1",
                "OPS-OP-ADVANCE-SIGNING-KEY-ROTATION",
            ),
            "pc.control.signing-rotation.recover" => (
                RECOVER,
                "ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1",
                "OPS-OP-RECOVER-SIGNING-KEY-ROTATION",
            ),
            _ => return Err(failure()),
        };
        if !admitted.insert(text(&g[0])?)
            || integer(&g[1])? != 1
            || hex(h32(&g[2])?) != expected.0
            || text(&g[3])? != expected.1
            || text(&g[4])? != expected.2
        {
            return Err(failure());
        }
    }
    let recorded = integer(field(receipt, 23)?)?;
    if text(&a[0])? != "pc.control.business-signing-trust.v1"
        || bytes(&a[1])? != bytes(field(receipt, 6)?)?
        || bytes(&a[2])? != bytes(field(receipt, 7)?)?
        || text(&a[3])? != text(field(receipt, 5)?)?
        || text(&a[4])? != text(field(receipt, 24)?)?
        || bytes(&a[5])? != public
        || integer(&a[8])? != epoch
        || recorded < integer(&a[9])?
        || recorded >= integer(&a[10])?
        || integer(&a[17])? != 24001
        || integer(&a[18])? != 2
        || integer(&a[19])? != 338
        || text(&a[14])? != "SECRET-SIGNING-KEY"
        || Sha256::digest(preimage).as_slice() != h32(field(receipt, 25)?)?
        || text(field(receipt, 24)?)? != format!("sha256:{}", hex(&Sha256::digest(public)))
    {
        return Err(failure());
    }
    Ok(())
}
fn verify_occurrence(
    row: &PgRow,
    participant: &str,
    privacy: &str,
    id: &str,
    ordinal: u64,
) -> Result<Value> {
    let payload = column(row, "receipt_cbor")?;
    let receipt = decode(&payload)?;
    exact_map(&receipt, &(0..27).collect::<Vec<_>>())?;
    let (digest, action, operation) = profile(&receipt)?;
    let public = column(row, "public_key_spki_der")?;
    verify_cose_version(&public, &payload, &column(row, "cose_sign1")?, 2)?;
    if hex(h32(field(&receipt, 1)?)?) != V2_DEFINITION
        || hex(h32(field(&receipt, 4)?)?) != digest
        || integer(field(&receipt, 3)?)? != 1
        || integer(field(&receipt, 22)?)? != 1
        || text(field(&receipt, 9)?)? != action
        || text(field(&receipt, 10)?)? != operation
        || text(field(&receipt, 11)?)? != AGGREGATE
        || bytes(field(&receipt, 6)?)? != uuid(participant)?
        || bytes(field(&receipt, 7)?)? != uuid(privacy)?
        || bytes(field(&receipt, 12)?)? != uuid(id)?
        || !integer(field(&receipt, 23)?)?.is_multiple_of(1000)
        || Sha256::digest(&payload).as_slice() != column(row, "receipt_digest")?
    {
        return Err(failure());
    }
    for (key, col) in [
        (0, "receipt_uuid"),
        (8, "operation_uuid"),
        (17, "idempotency_uuid"),
    ] {
        if bytes(field(&receipt, key)?)? != uuid(&string(row, col)?)? {
            return Err(failure());
        }
    }
    for (key, col) in [
        (13, "actor_key_digest"),
        (14, "pre_commit_authority_digest"),
        (15, "action_intent_digest"),
        (16, "candidate_digest"),
        (26, "request_digest"),
    ] {
        if h32(field(&receipt, key)?)? != column(row, col)? {
            return Err(failure());
        }
    }
    if Sha256::digest(column(row, "authority_snapshot")?).as_slice() != bytes(field(&receipt, 14)?)?
    {
        return Err(failure());
    }
    let epoch = string(row, "epoch")?.parse().map_err(|_| failure())?;
    verify_trust(&receipt, &public, &column(row, "trust_preimage")?, epoch)?;
    let before = state_projection(&receipt, 18, &column(row, "before_state_preimage")?)?;
    let after = state_projection(&receipt, 19, &column(row, "after_state_preimage")?)?;
    verify_states(&receipt, &before, &after)?;
    let history_bytes = column(row, "history_preimage")?;
    let history: Json = serde_json::from_slice(&history_bytes).map_err(|_| failure())?;
    let previous_bytes = column(row, "previous_preimage")?;
    let previous: Json = serde_json::from_slice(&previous_bytes).map_err(|_| failure())?;
    let history_digest = Sha256::digest(&history_bytes);
    let previous_digest = Sha256::digest(&previous_bytes);
    if history_digest.as_slice() != h32(field(&after, 2)?)?
        || previous_digest.as_slice() != h32(field(&before, 2)?)?
        || history["schema"] != "pc.control.signing-rotation-history.v1"
        || history["participantId"] != participant
        || history["privacyDomainId"] != privacy
        || history["rotationId"] != id
        || history["receiptNamespace"] != LIFECYCLE
        || history["receiptOrdinal"].as_u64() != Some(ordinal)
        || history["revision"].as_u64() != Some(integer(field(field(&receipt, 19)?, 1)?)?)
        || previous["revision"].as_u64() != Some(integer(field(field(&receipt, 18)?, 1)?)?)
        || history["priorDigest"] != hex(&previous_digest)
        || history["operationId"] != string(row, "operation_uuid")?
        || history["state"] != text(field(&after, 0)?)?
        || history["priorState"] != text(field(&before, 0)?)?
        || previous["state"] != text(field(&before, 0)?)?
        || history["signerRole"] != text(field(&after, 3)?)?
        || previous["signerRole"] != history["signerRole"]
        || history["candidate"]["digest"] != hex(bytes(field(&after, 1)?)?)
        || previous["candidate"]["digest"] != history["candidate"]["digest"]
        || history["attester"]["signerId"] != text(field(&receipt, 24)?)?
        || history["attester"]["trustDigest"] != hex(bytes(field(&receipt, 25)?)?)
        || history["attester"]["keyEpoch"].as_u64() != Some(epoch)
        || history["attester"]["selectionVersion"].as_u64()
            != Some(
                string(row, "selection_version")?
                    .parse()
                    .map_err(|_| failure())?,
            )
        || history["attester"]["admissionVersion"].as_u64()
            != Some(
                string(row, "admission_version")?
                    .parse()
                    .map_err(|_| failure())?,
            )
        || history["attester"]["fenceGeneration"].as_u64()
            != Some(
                string(row, "fence_generation")?
                    .parse()
                    .map_err(|_| failure())?,
            )
        || string(row, "target_old")? != format!("sha256:{}", hex(h32(field(&after, 4)?)?))
        || column(row, "rotation_candidate")? != h32(field(&after, 1)?)?
        || history["oldTrustDigest"] != hex(&column(row, "rotation_old_trust")?)
        || history["command"]["operationId"] != history["operationId"]
        || history["command"]["actionIntentId"] != text(field(&receipt, 9)?)?
        || history["command"]["actionIntentDigest"] != hex(h32(field(&receipt, 15)?)?)
        || history["command"]["inputDigest"] != hex(h32(field(&receipt, 16)?)?)
        || string(row, "key_state")? == "COMPROMISED"
    {
        return Err(failure());
    }
    for (p, h) in [(&before, &previous), (&after, &history)] {
        let expected = if integer(field(p, 5)?)? == 0 {
            Json::Null
        } else {
            Json::String(format!("sha256:{}", hex(h32(field(p, 6)?)?)))
        };
        if h["newFingerprint"] != expected {
            return Err(failure());
        }
    }
    // Recompute the immutable attempt identity independently of the producer.
    let mut normalized = receipt.clone();
    let map = normalized.as_map_mut().ok_or_else(failure)?;
    let operation_id = field(&receipt, 8)?.clone();
    map.iter_mut()
        .find(|(k, _)| integer(k) == Ok(0))
        .ok_or_else(failure)?
        .1 = operation_id;
    let mut identity = b"pc.control.receipt-signing-attempt.v1\0".to_vec();
    identity.extend(encode(&normalized)?);
    let d = Sha256::digest(identity);
    let mut expected = bytes(field(&receipt, 8)?)?.to_vec();
    expected[6..].copy_from_slice(&d[..10]);
    expected[6] = (expected[6] & 15) | 0x70;
    expected[8] = (expected[8] & 63) | 0x80;
    if expected != bytes(field(&receipt, 0)?)? {
        return Err(failure());
    }
    Ok(receipt)
}

/// Scope and checkpoint locking are independent of business CloudEvent sequences.
pub async fn consume_next(pool: &PgPool, participant: &str, privacy: &str) -> Result<bool> {
    let mut tx = pool.begin().await.map_err(|_| failure())?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-OPERATIONS_READ_OPERATION-V1',true)")
        .bind(participant).bind(privacy).execute(&mut *tx).await.map_err(|_|failure())?;
    let id: Option<String> = sqlx::query_scalar("select h.rotation_id::text from control.signing_rotation_history h left join control.qualified_receipt_checkpoint c on c.participant_id=h.participant_id and c.privacy_domain_id=h.privacy_domain_id and c.namespace=h.receipt_namespace and c.aggregate_type='signing-key-rotation' and c.aggregate_id=h.rotation_id where h.participant_id=$1::text::uuid and h.privacy_domain_id=$2::text::uuid and h.receipt_namespace=$3 and h.receipt_ordinal>coalesce(c.last_sequence,0) order by h.rotation_id,h.receipt_ordinal limit 1")
        .bind(participant).bind(privacy).bind(LIFECYCLE).fetch_optional(&mut *tx).await.map_err(|_|failure())?;
    let Some(id) = id else {
        tx.commit().await.map_err(|_| failure())?;
        return Ok(false);
    };
    sqlx::query("insert into control.qualified_receipt_checkpoint(participant_id,privacy_domain_id,namespace,aggregate_type,aggregate_id) values($1::text::uuid,$2::text::uuid,$3,'signing-key-rotation',$4::text::uuid) on conflict do nothing")
        .bind(participant).bind(privacy).bind(LIFECYCLE).bind(&id).execute(&mut *tx).await.map_err(|_|failure())?;
    let last: String = sqlx::query_scalar("select last_sequence::text from control.qualified_receipt_checkpoint where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and namespace=$3 and aggregate_type='signing-key-rotation' and aggregate_id=$4::text::uuid for update")
        .bind(participant).bind(privacy).bind(LIFECYCLE).bind(&id).fetch_one(&mut *tx).await.map_err(|_|failure())?;
    let ordinal = last
        .parse::<u64>()
        .map_err(|_| failure())?
        .checked_add(1)
        .ok_or_else(failure)?;
    let row = sqlx::query("select a.*,a.receipt_id::text receipt_uuid,a.operation_id::text operation_uuid,a.idempotency_record_id::text idempotency_uuid,k.public_key_spki_der,k.trust_preimage,k.key_epoch::text epoch,s.state key_state,h.history_preimage,prior.history_preimage previous_preimage,r.old_signer_id target_old,r.candidate_digest rotation_candidate,r.old_trust_digest rotation_old_trust,i.selection_version::text selection_version,i.admission_version::text admission_version,i.fence_generation::text fence_generation from control.signing_rotation_history h join control.signing_key_rotation r on r.participant_id=h.participant_id and r.privacy_domain_id=h.privacy_domain_id and r.rotation_id=h.rotation_id join control.signing_rotation_history prior on prior.participant_id=h.participant_id and prior.privacy_domain_id=h.privacy_domain_id and prior.rotation_id=h.rotation_id and prior.revision=h.revision-1 join control.audit_occurrence a on a.participant_id=h.participant_id and a.privacy_domain_id=h.privacy_domain_id and a.receipt_id=h.receipt_id join control.business_signing_key k on k.participant_id=a.participant_id and k.privacy_domain_id=a.privacy_domain_id and k.signer_id=a.signer_id join control.business_signing_key_state s on s.participant_id=k.participant_id and s.privacy_domain_id=k.privacy_domain_id and s.signer_id=k.signer_id join control.signing_rotation_attestation t on t.participant_id=h.participant_id and t.privacy_domain_id=h.privacy_domain_id and t.attempt_id=h.receipt_id and t.rotation_id=h.rotation_id and t.operation_id=h.operation_id and t.from_revision=h.revision-1 and t.to_state=h.state and t.history_preimage=h.history_preimage and t.receipt_ordinal=h.receipt_ordinal and t.receipt_cbor=a.receipt_cbor join control.receipt_signing_attempt i on i.attempt_id=a.receipt_id and i.operation_id=a.operation_id and i.reservation_kind='LIFECYCLE_DURABLE' and i.schema_version=2 and i.payload_cbor=a.receipt_cbor and i.payload_digest=a.receipt_digest and i.signer_id=a.signer_id and i.signer_trust_digest=k.trust_digest and i.key_epoch=k.key_epoch join control.signing_provider_attempt p on p.attempt_id=i.attempt_id and p.state='ACCEPTED' and p.observation->>'outcome'='SUCCEEDED' and p.observation->>'resultHex'=encode(a.cose_sign1,'hex') where h.participant_id=$1::text::uuid and h.privacy_domain_id=$2::text::uuid and h.rotation_id=$3::text::uuid and h.receipt_namespace=$4 and h.receipt_ordinal=$5::text::numeric")
        .bind(participant).bind(privacy).bind(&id).bind(LIFECYCLE).bind(ordinal.to_string()).fetch_optional(&mut *tx).await.map_err(|_|failure())?;
    // A competing consumer may already have consumed the last committed ordinal.
    let Some(row) = row else {
        let missing: bool=sqlx::query_scalar("select exists(select 1 from control.signing_rotation_history where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and rotation_id=$3::text::uuid and receipt_namespace=$4 and receipt_ordinal>=$5::text::numeric)")
            .bind(participant).bind(privacy).bind(&id).bind(LIFECYCLE).bind(ordinal.to_string()).fetch_one(&mut *tx).await.map_err(|_|failure())?;
        if missing {
            return Err("qualified lifecycle occurrence rejected".into());
        }
        tx.commit().await.map_err(|_| failure())?;
        return Ok(false);
    };
    let receipt = verify_occurrence(&row, participant, privacy, &id, ordinal)
        .map_err(|_| "qualified lifecycle occurrence rejected".to_owned())?;
    verify_evidence_and_events(&mut tx, &receipt)
        .await
        .map_err(|_| "qualified lifecycle evidence or event rejected".to_owned())?;
    let signer = text(field(&receipt, 24)?)?;
    let epoch = string(&row, "epoch")?;
    let receipt_id = string(&row, "receipt_uuid")?;
    verify_registry(
        &mut tx,
        participant,
        privacy,
        signer,
        &column(&row, "trust_preimage")?,
        &epoch,
        RegistryReceipt {
            recorded: integer(field(&receipt, 23)?)?,
            schema_version: 2,
            lifecycle_receipt: Some(&receipt_id),
        },
    )
    .await?;
    sqlx::query("insert into control.qualified_receipt_inbox(participant_id,privacy_domain_id,namespace,aggregate_type,aggregate_id,sequence,receipt_id,receipt_digest,signer_id,key_epoch) values($1::text::uuid,$2::text::uuid,$3,'signing-key-rotation',$4::text::uuid,$5::text::numeric,$6::text::uuid,$7,$8,$9::text::numeric)")
        .bind(participant).bind(privacy).bind(LIFECYCLE).bind(&id).bind(ordinal.to_string()).bind(&receipt_id).bind(column(&row,"receipt_digest")?).bind(signer).bind(epoch).execute(&mut *tx).await.map_err(|_|failure())?;
    sqlx::query("update control.qualified_receipt_checkpoint set last_sequence=$5::text::numeric,last_receipt_id=$6::text::uuid where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and namespace=$3 and aggregate_type='signing-key-rotation' and aggregate_id=$4::text::uuid")
        .bind(participant).bind(privacy).bind(LIFECYCLE).bind(&id).bind(ordinal.to_string()).bind(receipt_id).execute(&mut *tx).await.map_err(|_|failure())?;
    tx.commit().await.map_err(|_| failure())?;
    Ok(true)
}

fn uuid_text(value: &Value) -> Result<String> {
    let b = bytes(value)?;
    if b.len() != 16 {
        return Err(failure());
    }
    let h = hex(b);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
fn authorization_proof(proof: &Value) -> Result<(&str, &[u8])> {
    exact_map(proof, &[0, 1, 2])?;
    if integer(field(proof, 0)?)? != 2 {
        return Err(failure());
    }
    // EvidenceRef.id is TEXT in both schema versions; it is not the receipt's UUID7 byte type.
    let id = text(field(proof, 1)?)?;
    if uuid_text(&Value::Bytes(uuid(id)?))? != id {
        return Err(failure());
    }
    Ok((id, h32(field(proof, 2)?)?))
}
async fn verify_evidence_and_events(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    receipt: &Value,
) -> Result<()> {
    let participant = uuid_text(field(receipt, 6)?)?;
    let privacy = uuid_text(field(receipt, 7)?)?;
    let operation = uuid_text(field(receipt, 8)?)?;
    let id = uuid_text(field(receipt, 12)?)?;
    let receipt_id = uuid_text(field(receipt, 0)?)?;
    let proofs = field(receipt, 20)?
        .as_array()
        .filter(|a| (1..=2).contains(&a.len()))
        .ok_or_else(failure)?;
    let mut authorization_count = 0;
    let mut continuation_count = 0;
    for proof in proofs {
        let (evidence_id, evidence_digest) = authorization_proof(proof)?;
        let matched: bool=sqlx::query_scalar("select exists(select 1 from control.mutation_evidence where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and operation_id=$3::text::uuid and mutation_evidence_id=$4::text::uuid and evidence_digest=$5 and evidence_role='AUTHORIZATION_INPUT' and evidence_format='IDENTITY_RUNTIME_ASSERTION_3002_2_13')")
            .bind(&participant).bind(&privacy).bind(&operation).bind(evidence_id).bind(evidence_digest).fetch_one(&mut **tx).await.map_err(|_|failure())?;
        if matched {
            authorization_count += 1;
            continue;
        }
        if proofs.len() != 2 {
            return Err(failure());
        }
        let continued: bool=sqlx::query_scalar(r#"select exists(
          select 1 from control.signing_continuation c
          join control.signing_rotation_attestation a on a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id
            and a.operation_id=c.operation_id and a.continuation_assertion_id=c.assertion_id and a.attempt_id=c.consumed_receipt_id
          join control.signing_provider_attempt p on p.participant_id=c.participant_id and p.privacy_domain_id=c.privacy_domain_id
            and p.operation_id=c.operation_id and p.attempt_id=c.provider_attempt_id
          join control.signing_rotation_history h on h.participant_id=c.participant_id and h.privacy_domain_id=c.privacy_domain_id
            and h.operation_id=c.operation_id and h.receipt_id=c.consumed_receipt_id
          cross join lateral(select convert_from(c.context_preimage,'UTF8')::jsonb context) binding
          where c.participant_id=$1::text::uuid and c.privacy_domain_id=$2::text::uuid and c.operation_id=$3::text::uuid
           and c.assertion_id=$4::text::uuid and c.assertion_digest=$5 and c.consumed_receipt_id=$6::text::uuid
           and c.state='CONSUMED' and c.consumed_at_ns<c.expires_at_ns and c.consumed_at_ns>=c.issued_at_ns
           and c.context_digest=sha256(c.context_preimage) and p.state in ('ACCEPTED','REJECTED') and p.dispatched_at_ns is not null
           and binding.context->>'purpose'='SIGNING_ROTATION_ATTEMPT_RECONCILE_V1'
           and binding.context->>'effect'='FINALIZE_EXISTING_SIGNING_ROTATION_ATTEMPT'
           and binding.context->>'actionIntentId'='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1'
           and binding.context->>'participantId'=$1 and binding.context->>'privacyDomainId'=$2 and binding.context->>'operationId'=$3
           and binding.context->>'providerAttemptId'=p.attempt_id::text and binding.context->>'providerMethod'=p.request->>'method'
           and binding.context->>'providerRequestDigest'='sha256:'||encode(p.request_digest,'hex')
           and binding.context->>'providerObservationDigest'='sha256:'||encode(p.observation_digest,'hex')
           and binding.context->>'rotationRevision'=a.from_revision::text and h.revision=a.from_revision+1
           and p.request->>'method' in ('PREPARE','DISTRIBUTE','REVOKE','RETIRE')
           and ((binding.context->>'resultDisposition'='APPLY_RESERVED_TARGET' and binding.context->>'targetState'=h.state
             and p.observation->>'outcome'='SUCCEEDED') or
            (binding.context->>'resultDisposition'='ENTER_FAILED_STATE' and h.state='FAILED' and p.observation->>'outcome'='REJECTED'))
           and (binding.context->>'currentAuthorityStatus'='UNCHANGED_LIVE' or exists(
            select 1 from control.signing_rotation_authority_hold hold where hold.participant_id=c.participant_id
             and hold.privacy_domain_id=c.privacy_domain_id and hold.operation_id=c.operation_id
             and hold.continuation_assertion_id=c.assertion_id and hold.reason='AUTHORITY_CHANGED_AFTER_DISPATCH'))
        )"#).bind(&participant).bind(&privacy).bind(&operation).bind(evidence_id).bind(evidence_digest).bind(&receipt_id)
            .fetch_one(&mut **tx).await.map_err(|_|failure())?;
        if !continued {
            return Err(failure());
        }
        continuation_count += 1;
    }
    if authorization_count != 1 || continuation_count != proofs.len() - 1 {
        return Err(failure());
    }
    let governed: bool = sqlx::query_scalar(r#"select exists(
      select 1 from control.signing_rotation_command c join control.signing_rotation_history h
       using(participant_id,privacy_domain_id,operation_id)
      left join control.signing_authorization_generation g on g.generation_id=c.authorization_generation_id
      where c.participant_id=$1::text::uuid and c.privacy_domain_id=$2::text::uuid and c.operation_id=$3::text::uuid
       and h.receipt_id=$4::text::uuid and h.revision=c.result_revision
       and (c.authorization_generation_id is null or (g.state='CONSUMED' and g.participant_id=c.participant_id
        and g.privacy_domain_id=c.privacy_domain_id and g.rotation_id=c.rotation_id and exists(
         select 1 from control.mutation_candidate candidate join control.approval_request a
          on a.participant_id=candidate.participant_id and a.privacy_domain_id=candidate.privacy_domain_id
           and a.subject_id=candidate.mutation_candidate_id and a.subject_digest=candidate.candidate_digest
         join control.approval_decision_record d on d.participant_id=a.participant_id and d.privacy_domain_id=a.privacy_domain_id
          and d.approval_request_id=a.approval_request_id
         join control.signing_rotation_history accepted on accepted.participant_id=g.participant_id
          and accepted.privacy_domain_id=g.privacy_domain_id and accepted.operation_id=g.consumed_operation_id
          and accepted.revision=g.result_revision and accepted.receipt_id is not null
         where candidate.mutation_candidate_id=g.candidate_id and candidate.candidate_digest=g.candidate_digest
          and candidate.state='CONSUMED' and candidate.consumed_operation_id=g.consumed_operation_id
          and a.approval_request_id=c.approval_request_id and a.subject_digest=c.approval_candidate_digest
          and d.decision='APPROVE' and d.approver_principal_id<>a.maker_principal_id and d.candidate_digest=g.candidate_digest
          and (c.operation_id=g.consumed_operation_id or (c.from_revision>=g.result_revision and not exists(
           select 1 from control.signing_authorization_generation newer where newer.participant_id=g.participant_id
            and newer.privacy_domain_id=g.privacy_domain_id and newer.rotation_id=g.rotation_id and newer.state='CONSUMED'
            and newer.result_revision>g.result_revision and newer.result_revision<=c.from_revision)))
       )))
       and (c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' or
        (c.result_kind in ('AUTHORITY_RENEWED','FORWARD_RECOVERY') and g.consumed_operation_id=c.operation_id
         and h.event_id is null and h.state=g.target_state and h.revision=g.from_revision+1
         and ((c.result_kind='AUTHORITY_RENEWED' and h.state=h.prior_state) or
          (c.result_kind='FORWARD_RECOVERY' and h.state='RECOVERING'))
         and (g.hold_id is null or exists(select 1 from control.signing_rotation_authority_hold hold
          where hold.hold_id=g.hold_id and hold.state='CLEARED' and hold.cleared_by_operation_id=c.operation_id))) or
        (c.result_kind='NEW_OBSERVATION' and h.state='RECOVERING' and h.prior_state<>'FAILED' and exists(
         select 1 from control.signing_rotation_observation observed join control.signing_provider_attempt attempt
          on attempt.participant_id=observed.participant_id and attempt.privacy_domain_id=observed.privacy_domain_id
           and attempt.attempt_id=observed.attempt_id and attempt.operation_id=observed.operation_id
         join control.signing_rotation_command original on original.participant_id=attempt.participant_id
          and original.privacy_domain_id=attempt.privacy_domain_id and original.operation_id=attempt.operation_id
         where observed.participant_id=c.participant_id and observed.privacy_domain_id=c.privacy_domain_id
          and observed.operation_id=c.original_operation_id and observed.attempt_id=c.recovery_attempt_id
          and observed.observation_digest=c.recovery_observation_digest and observed.observation_digest<>c.prior_observation_digest
          and observed.observation_digest=sha256(observed.observation_preimage) and observed.kind in ('NOT_FOUND','PROVIDER_RESULT')
          and original.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' and original.rotation_id=c.rotation_id
        )))
    )"#).bind(&participant).bind(&privacy).bind(&operation).bind(&receipt_id)
        .fetch_one(&mut **tx).await.map_err(|_|failure())?;
    if !governed {
        return Err(failure());
    }
    let rows=sqlx::query("select e.sequence_namespace,e.aggregate_type,e.aggregate_id::text,e.proof_kind,e.event_id::text,e.event_type,e.data_schema_uri,e.source,e.subject,e.business_sequence::text sequence,e.payload_cbor,e.payload_digest,e.correlation_id::text,e.causation_id::text,e.authority_generation,(floor(extract(epoch from e.occurred_at)*1000000)*1000)::text event_time from control.outbox_event e where e.participant_id=$1::text::uuid and e.privacy_domain_id=$2::text::uuid and e.receipt_id=$3::text::uuid")
        .bind(&participant).bind(&privacy).bind(receipt_id).fetch_all(&mut **tx).await.map_err(|_|failure())?;
    let state: String=sqlx::query_scalar("select state from control.signing_rotation_history where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and rotation_id=$3::text::uuid and revision=$4::text::bigint")
        .bind(&participant).bind(&privacy).bind(&id).bind(integer(field(field(receipt,19)?,1)?)?.to_string()).fetch_one(&mut **tx).await.map_err(|_|failure())?;
    let expected = if text(field(receipt, 2)?)? == "pc.control.signing-rotation.recover" {
        None
    } else {
        match state.as_str() {
            "OLD_REVOKED" => Some(("revoked", "SecretRevoked")),
            "COMPLETE" => Some(("rotated", "SecretRotated")),
            _ => None,
        }
    };
    let events = field(receipt, 21)?.as_array().ok_or_else(failure)?;
    if rows.len() != events.len() || events.len() != usize::from(expected.is_some()) {
        return Err(failure());
    }
    let Some((suffix, schema)) = expected else {
        return Ok(());
    };
    let event = &events[0];
    let row = &rows[0];
    exact_map(event, &[0, 1, 2, 3, 4, 5, 6, 7, 9])?;
    let payload = column(row, "payload_cbor")?;
    let data = decode(&payload)?;
    exact_map(&data, &[0, 1, 2, 3])?;
    let preimage: Vec<u8> = sqlx::query_scalar("select after_state_preimage from control.audit_occurrence where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and receipt_id=$3::text::uuid")
        .bind(&participant).bind(&privacy).bind(uuid_text(field(receipt,0)?)?).fetch_one(&mut **tx).await.map_err(|_|failure())?;
    let after = state_projection(receipt, 19, &preimage)?;
    if string(row, "sequence_namespace")? != NAMESPACE
        || string(row, "aggregate_type")? != AGGREGATE
        || string(row, "aggregate_id")? != id
        || string(row, "proof_kind")? != "BUSINESS_RECEIPT_REFERENCE"
        || uuid_text(field(event, 0)?)? != string(row, "event_id")?
        || text(field(event, 1)?)? != format!("io.openpc.ops.secret.{suffix}.v1")
        || text(field(event, 1)?)? != string(row, "event_type")?
        || text(field(event, 2)?)?
            != format!("https://schemas.openpc.local/event-payloads.schema.json#/$defs/{schema}")
        || text(field(event, 2)?)? != string(row, "data_schema_uri")?
        || text(field(event, 3)?)? != "urn:openpc:service:control-api"
        || text(field(event, 3)?)? != string(row, "source")?
        || text(field(event, 4)?)? != format!("urn:openpc:signing-key-rotation:{id}")
        || text(field(event, 4)?)? != string(row, "subject")?
        || integer(field(event, 5)?)? == 0
        || integer(field(event, 5)?)?.to_string() != string(row, "sequence")?
        || integer(field(event, 6)?)? != integer(field(receipt, 23)?)?
        || integer(field(event, 6)?)?.to_string() != string(row, "event_time")?
        || uuid_text(field(event, 7)?)? != operation
        || string(row, "correlation_id")? != operation
        || row
            .try_get::<Option<String>, _>("causation_id")
            .map_err(|_| failure())?
            .is_some()
        || row
            .try_get::<Option<Vec<u8>>, _>("authority_generation")
            .map_err(|_| failure())?
            .is_some()
        || h32(field(event, 9)?)? != Sha256::digest(&payload).as_slice()
        || h32(field(event, 9)?)? != column(row, "payload_digest")?
        || bytes(field(&data, 0)?)? != bytes(field(receipt, 12)?)?
        || field(&data, 1)? != field(&after, 3)?
        || field(&data, 2)? != field(&after, 4)?
        || field(&data, 3)? != field(&after, 6)?
    {
        return Err(failure());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn b(value: u8) -> Value {
        Value::Bytes(vec![value; 32])
    }
    fn projection() -> Value {
        Value::Map(vec![
            (uint(0), Value::Text("APPROVED".into())),
            (uint(1), b(1)),
            (uint(2), b(2)),
            (uint(3), Value::Text("LIFECYCLE_EVIDENCE".into())),
            (uint(4), b(4)),
            (uint(5), uint(0)),
        ])
    }
    fn bound(p: Value) -> (Value, Vec<u8>) {
        let id = Value::Bytes(vec![8; 16]);
        let preimage = encode(&Value::Array(vec![
            Value::Text("pc.control.transition-state.v1".into()),
            b(5),
            id.clone(),
            id.clone(),
            Value::Text(AGGREGATE.into()),
            id.clone(),
            uint(1),
            uint(2),
            p,
        ]))
        .unwrap();
        let receipt = Value::Map(vec![
            (uint(4), b(5)),
            (uint(6), id.clone()),
            (uint(7), id.clone()),
            (uint(12), id),
            (
                uint(18),
                Value::Map(vec![
                    (uint(0), uint(1)),
                    (uint(1), uint(2)),
                    (uint(2), Value::Bytes(Sha256::digest(&preimage).to_vec())),
                ]),
            ),
        ]);
        (receipt, preimage)
    }
    #[test]
    fn lifecycle_optional_fingerprint_is_closed_and_state_is_bound() {
        let (receipt, preimage) = bound(projection());
        assert!(state_projection(&receipt, 18, &preimage).is_ok());
        for invalid in [Value::Null, Value::Bytes(vec![]), b(0), b(4)] {
            let mut p = projection();
            let m = p.as_map_mut().unwrap();
            m[5].1 = uint(1);
            m.push((uint(6), invalid));
            let (r, s) = bound(p);
            assert!(state_projection(&r, 18, &s).is_err());
        }
        let mut p = projection();
        p.as_map_mut().unwrap().push((uint(6), b(6)));
        let (r, s) = bound(p);
        assert!(state_projection(&r, 18, &s).is_err());
        let mut p = projection();
        p.as_map_mut().unwrap()[5].1 = uint(1);
        let (r, s) = bound(p);
        assert!(state_projection(&r, 18, &s).is_err());
        let mut p = projection();
        p.as_map_mut().unwrap()[5].1 = uint(2);
        let (r, s) = bound(p);
        assert!(state_projection(&r, 18, &s).is_err());
        let mut p = projection();
        p.as_map_mut().unwrap().push((uint(7), b(7)));
        let (r, s) = bound(p);
        assert!(state_projection(&r, 18, &s).is_err());
        let mut p = projection();
        let m = p.as_map_mut().unwrap();
        m[5].1 = uint(1);
        m.push((uint(6), b(6)));
        let (r, s) = bound(p);
        assert!(state_projection(&r, 18, &s).is_ok());
        assert!(state_projection(&receipt, 18, &s).is_err());
    }
    #[test]
    fn action_state_matrix_excludes_recovery_effects_and_creation_receipts() {
        let chain = [
            "APPROVED",
            "PREPARED",
            "DISTRIBUTED",
            "VERIFIED",
            "CUTOVER_FENCED",
            "OBSERVING",
            "OLD_REVOKED",
            "OLD_RETIRED",
            "COMPLETE",
        ];
        for recovery in [false, true] {
            for from in STATES {
                for to in STATES {
                    let expected = if recovery {
                        !["REQUESTED", "COMPLETE"].contains(from)
                            && *to != "FAILED"
                            && (*to == "RECOVERING" || from == to)
                    } else {
                        chain.windows(2).any(|p| p == [*from, *to])
                            || (*from == "RECOVERING" && chain[1..].contains(to))
                            || (*to == "FAILED"
                                && !["REQUESTED", "COMPLETE", "FAILED"].contains(from))
                    };
                    let mut before = projection();
                    before.as_map_mut().unwrap()[0].1 = Value::Text((*from).into());
                    let mut after = before.clone();
                    after.as_map_mut().unwrap()[0].1 = Value::Text((*to).into());
                    after.as_map_mut().unwrap()[2].1 = b(9);
                    let receipt = Value::Map(vec![
                        (
                            uint(2),
                            Value::Text(
                                if recovery {
                                    "pc.control.signing-rotation.recover"
                                } else {
                                    "pc.control.signing-rotation.advance"
                                }
                                .into(),
                            ),
                        ),
                        (uint(18), Value::Map(vec![(uint(1), uint(2))])),
                        (uint(19), Value::Map(vec![(uint(1), uint(3))])),
                    ]);
                    assert_eq!(
                        verify_states(&receipt, &before, &after).is_ok(),
                        expected,
                        "recovery={recovery}, {from}->{to}"
                    );
                    if recovery && expected {
                        after.as_map_mut().unwrap()[5].1 = uint(1);
                        after.as_map_mut().unwrap().push((uint(6), b(6)));
                        assert!(
                            verify_states(&receipt, &before, &after).is_err(),
                            "recovery cannot install a key"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn authorization_evidence_id_uses_text_and_rejects_uuid_bytes() {
        let id = "018f0000-0000-7000-8000-000000000001";
        let mut proof = Value::Map(vec![
            (uint(0), uint(2)),
            (uint(1), Value::Text(id.into())),
            (uint(2), b(2)),
        ]);
        assert_eq!(authorization_proof(&proof).unwrap().0, id);
        proof.as_map_mut().unwrap()[1].1 = Value::Bytes(uuid(id).unwrap());
        assert!(authorization_proof(&proof).is_err());
        proof.as_map_mut().unwrap()[1].1 = Value::Text("not-a-scoped-evidence-id".into());
        assert!(authorization_proof(&proof).is_err());
    }
    #[test]
    fn admitted_lifecycle_profiles_match_the_canonical_contracts() {
        for (source, digest) in [
            (
                include_str!(
                    "../../../../schemas/canonical/business-transition-profiles/signing-rotation-advance-v1.json"
                ),
                ADVANCE,
            ),
            (
                include_str!(
                    "../../../../schemas/canonical/business-transition-profiles/signing-rotation-recover-v1.json"
                ),
                RECOVER,
            ),
        ] {
            let mut document: Json = serde_json::from_str(source).unwrap();
            assert_eq!(document["definitionDigest"], format!("sha256:{digest}"));
            document.as_object_mut().unwrap().remove("definitionDigest");
            assert_eq!(
                hex(&Sha256::digest(
                    pc_runtime_types::canonical_bytes(&document).unwrap()
                )),
                digest
            );
            assert_eq!(
                document["schemaDefinitionDigest"],
                format!("sha256:{V2_DEFINITION}")
            );
        }
    }
}
