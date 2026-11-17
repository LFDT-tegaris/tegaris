//! Durable, privacy-scoped receipt acceptance in DU-PC-CONTROL. Evidence never grants authority.
use ciborium::Value;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

mod indexer;
pub mod lifecycle;
pub(crate) mod runtime_artifact;

type Result<T> = std::result::Result<T, String>;
const NAMESPACE: &str = "CONTROL_BUSINESS_TRANSITION_V1";
const DEFINITION: &str = "41a877ca7e00e74f32c8becf8daee38f26c12ab9d9dcf6ff80ed8e75608b3c1f";
const CREATE_PROFILE: &str = "d1a1871de2c1f4a2384cc084eb65523ce39c15b968c413e0578c66e177482348";
const UPDATE_PROFILE: &str = "c5e4dddece0f5e1132cc2df0bcaad338b5e12a7021589f62f292e2962503b672";
const CREATE_PROFILE_V2: &str = "47f934877eef5446cf1879d06842209e6512174274d39810ef832c2982a7c938";
const UPDATE_PROFILE_V2: &str = "0d9012e193c3610a6923cb050b8391b4d697785ff8ec2161ea475d04482940a5";

/// Profile version and receipt schema version are separate admissions. Optional
/// policy provenance changes the indexer profile, not its COSE purpose/schema.
fn indexer_profile(receipt: &Value) -> Result<(u64, &'static str, &'static str)> {
    let version = integer(field(receipt, 3)?)?;
    let (digest, action, operation) = match (text(field(receipt, 2)?)?, version) {
        ("pc.control.indexer-profile.create", 1) => (
            CREATE_PROFILE,
            "ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1",
            "CFG-OP-CREATE-INDEXER-PROFILE",
        ),
        ("pc.control.indexer-profile.create", 2) => (
            CREATE_PROFILE_V2,
            "ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1",
            "CFG-OP-CREATE-INDEXER-PROFILE",
        ),
        ("pc.control.indexer-profile.update", 1) => (
            UPDATE_PROFILE,
            "ACT-INDEXER_PROFILES_UPDATE_RESOURCE-V1",
            "CFG-OP-UPDATE-INDEXER-PROFILE",
        ),
        ("pc.control.indexer-profile.update", 2) => (
            UPDATE_PROFILE_V2,
            "ACT-INDEXER_PROFILES_UPDATE_RESOURCE-V1",
            "CFG-OP-UPDATE-INDEXER-PROFILE",
        ),
        _ => return Err(failure()),
    };
    if hex(bytes(field(receipt, 4)?)?) != digest
        || text(field(receipt, 9)?)? != action
        || text(field(receipt, 10)?)? != operation
        || integer(field(receipt, 22)?)? != 1
    {
        return Err(failure());
    }
    Ok((version, action, operation))
}

fn failure() -> String {
    "qualified receipt rejected".into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn bytes(value: &Value) -> Result<&[u8]> {
    value.as_bytes().map(Vec::as_slice).ok_or_else(failure)
}
fn text(value: &Value) -> Result<&str> {
    value.as_text().ok_or_else(failure)
}
fn integer(value: &Value) -> Result<u64> {
    value
        .as_integer()
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(failure)
}
fn field(value: &Value, key: u64) -> Result<&Value> {
    value
        .as_map()
        .and_then(|m| {
            m.iter()
                .find(|(k, _)| integer(k) == Ok(key))
                .map(|(_, v)| v)
        })
        .ok_or_else(failure)
}
fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(|_| failure())?;
    Ok(out)
}
fn decode(value: &[u8]) -> Result<Value> {
    if value.is_empty() || value.len() > 66560 {
        return Err(failure());
    }
    pc_provider_api::validate_canonical_pc_cbor_bytes(value).map_err(|_| failure())?;
    ciborium::de::from_reader(value).map_err(|_| failure())
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn uuid(value: &str) -> Result<Vec<u8>> {
    let raw = value.replace('-', "");
    if raw.len() != 32 {
        return Err(failure());
    }
    (0..32)
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).map_err(|_| failure()))
        .collect()
}
fn verify_signature(public: &[u8], payload: &[u8], signature: &[u8]) -> Result<()> {
    // SPKI is exactly the canonical P-256 algorithm identifier and uncompressed point.
    if public.len() != 91
        || hex(&public[..27]) != "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
    {
        return Err(failure());
    }
    VerifyingKey::from_sec1_bytes(&public[26..])
        .map_err(|_| failure())?
        .verify(
            payload,
            &Signature::from_slice(signature).map_err(|_| failure())?,
        )
        .map_err(|_| failure())
}
pub fn verify_receipt_cose(public: &[u8], payload: &[u8], cose: &[u8]) -> Result<()> {
    verify_cose_version(public, payload, cose, 1)
}
fn verify_cose_version(public: &[u8], payload: &[u8], cose: &[u8], version: u64) -> Result<()> {
    if ![1, 2].contains(&version) || cose.first() != Some(&0xd2) {
        return Err(failure());
    }
    let container = decode(&cose[1..])?;
    let array = container
        .as_array()
        .filter(|a| a.len() == 4)
        .ok_or_else(failure)?;
    let kid = format!("sha256:{}", hex(&Sha256::digest(public)));
    let protected = encode(&Value::Map(vec![
        (uint(1), Value::Integer((-7).into())),
        (
            uint(2),
            Value::Array(vec![uint(100), uint(101), uint(102), uint(103)]),
        ),
        (uint(3), Value::Text("application/pc+cbor".into())),
        (uint(4), Value::Bytes(kid.into_bytes())),
        (uint(100), uint(24001)),
        (uint(101), uint(version)),
        (uint(102), uint(338)),
        (uint(103), uint(2)),
    ]))?;
    if bytes(&array[0])? != protected
        || !array[1].as_map().is_some_and(Vec::is_empty)
        || bytes(&array[2])? != payload
    {
        return Err(failure());
    }
    let signed = encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected),
        Value::Bytes(b"pcplane:cose-sign1:v2\0".to_vec()),
        Value::Bytes(payload.to_vec()),
    ]))?;
    verify_signature(public, &signed, bytes(&array[3])?)
}

/// Accept one next occurrence. A missing predecessor never becomes a checkpoint.
pub async fn consume_next(pool: &PgPool, participant: &str, privacy: &str) -> Result<bool> {
    let mut tx = pool.begin().await.map_err(|_| failure())?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-OPERATIONS_READ_OPERATION-V1',true)")
        .bind(participant).bind(privacy).execute(&mut *tx).await.map_err(|_|failure())?;
    let head=sqlx::query("select h.aggregate_type,h.aggregate_id::text from control.business_outbox_head h left join control.qualified_receipt_checkpoint c on c.participant_id=h.participant_id and c.privacy_domain_id=h.privacy_domain_id and c.namespace=h.sequence_namespace and c.aggregate_type=h.aggregate_type and c.aggregate_id=h.aggregate_id where h.participant_id=$1::text::uuid and h.privacy_domain_id=$2::text::uuid and h.sequence_namespace=$3 and h.aggregate_type='indexer-profile' and h.last_sequence>coalesce(c.last_sequence,0) order by h.aggregate_id limit 1")
        .bind(participant).bind(privacy).bind(NAMESPACE).fetch_optional(&mut *tx).await.map_err(|_|failure())?;
    let Some(head) = head else {
        tx.commit().await.map_err(|_| failure())?;
        return Ok(false);
    };
    let aggregate: String = head.try_get("aggregate_type").map_err(|_| failure())?;
    let id: String = head.try_get("aggregate_id").map_err(|_| failure())?;
    sqlx::query("insert into control.qualified_receipt_checkpoint(participant_id,privacy_domain_id,namespace,aggregate_type,aggregate_id) values($1::text::uuid,$2::text::uuid,$3,$4,$5::text::uuid) on conflict do nothing")
        .bind(participant).bind(privacy).bind(NAMESPACE).bind(&aggregate).bind(&id).execute(&mut *tx).await.map_err(|_|failure())?;
    let last:String=sqlx::query_scalar("select last_sequence::text from control.qualified_receipt_checkpoint where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and namespace=$3 and aggregate_type=$4 and aggregate_id=$5::text::uuid for update")
        .bind(participant).bind(privacy).bind(NAMESPACE).bind(&aggregate).bind(&id).fetch_one(&mut *tx).await.map_err(|_|failure())?;
    let sequence = last
        .parse::<u64>()
        .map_err(|_| failure())?
        .checked_add(1)
        .ok_or_else(failure)?;
    let rows=sqlx::query("select e.event_id::text,e.event_type,e.data_schema_uri,e.source,e.subject,e.payload_digest,e.payload_cbor,e.correlation_id::text,e.causation_id::text,e.authority_generation,(floor(extract(epoch from e.occurred_at)*1000000)*1000)::text event_time, a.*,a.receipt_id::text receipt_uuid,a.operation_id::text operation_uuid,a.recorded_at_ns::text receipt_time,k.public_key_spki_der,k.trust_preimage,k.trust_digest,k.key_epoch::text key_epoch_text,k.valid_from_ns::text valid_from,k.valid_until_ns::text valid_until,k.admission_kind,k.admission_reference,s.state key_state,p.profile_digest admitted_profile_digest from control.outbox_event e join control.audit_occurrence a on a.participant_id=e.participant_id and a.privacy_domain_id=e.privacy_domain_id and a.receipt_id=e.receipt_id join control.business_signing_key k on k.participant_id=a.participant_id and k.privacy_domain_id=a.privacy_domain_id and k.signer_id=a.signer_id join control.business_signing_key_state s on s.participant_id=k.participant_id and s.privacy_domain_id=k.privacy_domain_id and s.signer_id=k.signer_id join control.business_transition_profile p on p.profile_digest=a.profile_digest where e.participant_id=$1::text::uuid and e.privacy_domain_id=$2::text::uuid and e.sequence_namespace=$3 and e.aggregate_type=$4 and e.aggregate_id=$5::text::uuid and e.business_sequence=$6::text::numeric and e.proof_kind='BUSINESS_RECEIPT_REFERENCE'")
        .bind(participant).bind(privacy).bind(NAMESPACE).bind(&aggregate).bind(&id).bind(sequence.to_string()).fetch_all(&mut *tx).await.map_err(|_|failure())?;
    if rows.len() != 1 {
        return Err(failure());
    }
    let row = &rows[0];
    let payload: Vec<u8> = row.try_get("receipt_cbor").map_err(|_| failure())?;
    let cose: Vec<u8> = row.try_get("cose_sign1").map_err(|_| failure())?;
    let public: Vec<u8> = row.try_get("public_key_spki_der").map_err(|_| failure())?;
    let receipt = indexer::verify(&indexer::Inputs {
        public: &public,
        payload: &payload,
        cose: &cose,
        trust: &row
            .try_get::<Vec<u8>, _>("trust_preimage")
            .map_err(|_| failure())?,
        before: &row
            .try_get::<Vec<u8>, _>("before_state_preimage")
            .map_err(|_| failure())?,
        after: &row
            .try_get::<Vec<u8>, _>("after_state_preimage")
            .map_err(|_| failure())?,
        authority: &row
            .try_get::<Vec<u8>, _>("authority_snapshot")
            .map_err(|_| failure())?,
        event: &row
            .try_get::<Vec<u8>, _>("payload_cbor")
            .map_err(|_| failure())?,
    })?;
    let signer: String = row.try_get("signer_id").map_err(|_| failure())?;
    let receipt_id: String = row.try_get("receipt_uuid").map_err(|_| failure())?;
    let operation: String = row.try_get("operation_uuid").map_err(|_| failure())?;
    let receipt_digest: Vec<u8> = row.try_get("receipt_digest").map_err(|_| failure())?;
    let trust_digest: Vec<u8> = row.try_get("trust_digest").map_err(|_| failure())?;
    let trust_preimage: Vec<u8> = row.try_get("trust_preimage").map_err(|_| failure())?;
    let recorded: u64 = row
        .try_get::<String, _>("receipt_time")
        .map_err(|_| failure())?
        .parse()
        .map_err(|_| failure())?;
    let from: u64 = row
        .try_get::<String, _>("valid_from")
        .map_err(|_| failure())?
        .parse()
        .map_err(|_| failure())?;
    let until: u64 = row
        .try_get::<String, _>("valid_until")
        .map_err(|_| failure())?
        .parse()
        .map_err(|_| failure())?;
    let epoch: String = row.try_get("key_epoch_text").map_err(|_| failure())?;
    let (_, expected_action, _) = indexer_profile(&receipt)?;
    if hex(bytes(field(&receipt, 1)?)?) != DEFINITION
        || bytes(field(&receipt, 0)?)? != uuid(&receipt_id)?
        || bytes(field(&receipt, 6)?)? != uuid(participant)?
        || bytes(field(&receipt, 7)?)? != uuid(privacy)?
        || bytes(field(&receipt, 8)?)? != uuid(&operation)?
        || text(field(&receipt, 11)?)? != aggregate
        || bytes(field(&receipt, 12)?)? != uuid(&id)?
        || text(field(&receipt, 24)?)? != signer
        || signer != format!("sha256:{}", hex(&Sha256::digest(&public)))
        || bytes(field(&receipt, 25)?)? != trust_digest
        || Sha256::digest(&payload).as_slice() != receipt_digest
        || Sha256::digest(&trust_preimage).as_slice() != trust_digest
        || recorded < from
        || recorded >= until
        || integer(field(&receipt, 23)?)? != recorded
        || row
            .try_get::<String, _>("key_state")
            .map_err(|_| failure())?
            == "COMPROMISED"
    {
        return Err(failure());
    }
    let events = field(&receipt, 21)?
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or_else(failure)?;
    let event = &events[0];
    let event_id: String = row.try_get("event_id").map_err(|_| failure())?;
    let event_payload: Vec<u8> = row.try_get("payload_cbor").map_err(|_| failure())?;
    let event_digest: Vec<u8> = row.try_get("payload_digest").map_err(|_| failure())?;
    let event_time: String = row.try_get("event_time").map_err(|_| failure())?;
    let event_type: String = row.try_get("event_type").map_err(|_| failure())?;
    let event_schema: String = row.try_get("data_schema_uri").map_err(|_| failure())?;
    let event_source: String = row.try_get("source").map_err(|_| failure())?;
    let event_subject: String = row.try_get("subject").map_err(|_| failure())?;
    let correlation: String = row.try_get("correlation_id").map_err(|_| failure())?;
    let causation: Option<String> = row.try_get("causation_id").map_err(|_| failure())?;
    let generation: Option<Vec<u8>> = row.try_get("authority_generation").map_err(|_| failure())?;
    let event_data = decode(&event_payload)?;
    if !event.as_map().is_some_and(|m| m.len() == 9)
        || bytes(field(event, 0)?)? != uuid(&event_id)?
        || text(field(event, 1)?)? != event_type
        || event_type != "io.openpc.control.command.committed.v1"
        || text(field(event, 2)?)? != event_schema
        || event_schema
            != "https://schemas.openpc.local/event-payloads.schema.json#/$defs/CommandCommitted"
        || text(field(event, 3)?)? != event_source
        || event_source != "urn:openpc:service:control-api"
        || text(field(event, 4)?)? != event_subject
        || event_subject != format!("urn:openpc:{aggregate}:{id}")
        || integer(field(event, 5)?)? != sequence
        || integer(field(event, 6)?)?.to_string() != event_time
        || integer(field(event, 6)?)? != recorded
        || bytes(field(event, 7)?)? != uuid(&correlation)?
        || correlation != operation
        || causation.is_some()
        || generation.is_some()
        || bytes(field(event, 9)?)? != event_digest
        || Sha256::digest(&event_payload).as_slice() != event_digest
        || !event_data.as_map().is_some_and(|m| m.len() == 4)
        || bytes(field(&event_data, 0)?)? != uuid(&operation)?
        || text(field(&event_data, 1)?)? != event_subject
        || text(field(&event_data, 2)?)? != expected_action
        || bytes(field(&event_data, 3)?)? != bytes(field(&receipt, 15)?)?
    {
        return Err(failure());
    }
    let trust = decode(&trust_preimage)?;
    let parts = trust
        .as_array()
        .filter(|v| v.len() == 21)
        .ok_or_else(failure)?;
    if text(&parts[0])? != "pc.control.business-signing-trust.v1"
        || bytes(&parts[1])? != uuid(participant)?
        || bytes(&parts[2])? != uuid(privacy)?
        || text(&parts[3])? != text(field(&receipt, 5)?)?
        || text(&parts[4])? != signer
        || bytes(&parts[5])? != public
        || integer(&parts[8])?.to_string() != epoch
        || integer(&parts[9])? != from
        || integer(&parts[10])? != until
        || integer(&parts[17])? != 24001
        || integer(&parts[18])? != 1
        || integer(&parts[19])? != 338
        || text(&parts[14])? != "SECRET-SIGNING-KEY"
    {
        return Err(failure());
    }
    verify_registry(
        &mut tx,
        participant,
        privacy,
        &signer,
        &trust_preimage,
        &epoch,
        RegistryReceipt {
            recorded,
            schema_version: 1,
            lifecycle_receipt: None,
        },
    )
    .await?;
    sqlx::query("insert into control.qualified_receipt_inbox(participant_id,privacy_domain_id,namespace,aggregate_type,aggregate_id,sequence,receipt_id,receipt_digest,signer_id,key_epoch) values($1::text::uuid,$2::text::uuid,$3,$4,$5::text::uuid,$6::text::numeric,$7::text::uuid,$8,$9,$10::text::numeric)")
        .bind(participant).bind(privacy).bind(NAMESPACE).bind(&aggregate).bind(&id).bind(sequence.to_string()).bind(&receipt_id).bind(receipt_digest).bind(&signer).bind(epoch).execute(&mut *tx).await.map_err(|_|failure())?;
    sqlx::query("update control.qualified_receipt_checkpoint set last_sequence=$6::text::numeric,last_receipt_id=$7::text::uuid where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and namespace=$3 and aggregate_type=$4 and aggregate_id=$5::text::uuid")
        .bind(participant).bind(privacy).bind(NAMESPACE).bind(&aggregate).bind(&id).bind(sequence.to_string()).bind(receipt_id).execute(&mut *tx).await.map_err(|_|failure())?;
    tx.commit().await.map_err(|_| failure())?;
    Ok(true)
}

fn unhex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.is_ascii() {
        return Err(failure());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| failure()))
        .collect()
}
struct RegistryReceipt<'a> {
    recorded: u64,
    schema_version: u64,
    lifecycle_receipt: Option<&'a str>,
}
async fn verify_registry(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    participant: &str,
    privacy: &str,
    signer: &str,
    preimage: &[u8],
    epoch: &str,
    receipt: RegistryReceipt<'_>,
) -> Result<()> {
    let recorded = receipt.recorded;
    let cutover:Option<String>=sqlx::query_scalar("select min(cutover_at_ns)::text from control.signing_key_rotation where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and old_signer_id=$3 and cutover_at_ns is not null")
        .bind(participant).bind(privacy).bind(signer).fetch_one(&mut **tx).await.map_err(|_|failure())?;
    if cutover.is_some_and(|t| t.parse::<u64>().map_or(true, |t| recorded >= t)) {
        // The only old-key receipt at the cutover instant is its own durably reserved
        // lifecycle cutover attestation. It is never a general historical-key allowance.
        let exact: bool = sqlx::query_scalar("select exists(select 1 from control.signing_key_rotation r join control.signing_rotation_history h on h.participant_id=r.participant_id and h.privacy_domain_id=r.privacy_domain_id and h.rotation_id=r.rotation_id join control.signing_rotation_attestation a on a.participant_id=h.participant_id and a.privacy_domain_id=h.privacy_domain_id and a.attempt_id=h.receipt_id join control.receipt_signing_attempt s on s.attempt_id=a.attempt_id join control.signing_provider_attempt p on p.attempt_id=a.attempt_id where r.participant_id=$1::text::uuid and r.privacy_domain_id=$2::text::uuid and r.old_signer_id=$3 and r.request->>'signerRole'='LIFECYCLE_EVIDENCE' and r.cutover_at_ns=$4::text::numeric and h.state='CUTOVER_FENCED' and h.receipt_namespace='CONTROL_SIGNING_LIFECYCLE_V1' and h.receipt_id=$5::text::uuid and h.operation_id=a.operation_id and h.revision=a.from_revision+1 and h.history_digest=a.history_digest and a.to_state='CUTOVER_FENCED' and a.signer_id=r.old_signer_id and a.receipt_cbor=s.payload_cbor and a.selection_version=s.selection_version and s.reservation_kind='LIFECYCLE_DURABLE' and s.schema_version=2 and s.operation_id=a.operation_id and s.signer_id=r.old_signer_id and p.state='ACCEPTED' and p.observation->>'outcome'='SUCCEEDED')")
            .bind(participant).bind(privacy).bind(signer).bind(recorded.to_string())
            .bind(receipt.lifecycle_receipt).fetch_one(&mut **tx).await.map_err(|_|failure())?;
        if receipt.schema_version != 2 || !exact {
            return Err(failure());
        }
    }
    let mut current_signer = signer.to_owned();
    let mut current = preimage.to_vec();
    let mut current_epoch = epoch.parse::<u64>().map_err(|_| failure())?;
    for _ in 0..32 {
        let decoded = decode(&current)?;
        let trust = decoded
            .as_array()
            .filter(|a| a.len() == 21)
            .ok_or_else(failure)?;
        if text(&trust[0])? != "pc.control.business-signing-trust.v1"
            || text(&trust[4])? != current_signer
            || current_signer != format!("sha256:{}", hex(&Sha256::digest(bytes(&trust[5])?)))
            || integer(&trust[9])? >= integer(&trust[10])?
            || text(&trust[14])? != "SECRET-SIGNING-KEY"
            || integer(&trust[17])? != 24001
            || integer(&trust[18])? != receipt.schema_version
            || integer(&trust[19])? != 338
            || integer(&trust[8])? != current_epoch
            || bytes(&trust[1])? != uuid(participant)?
            || bytes(&trust[2])? != uuid(privacy)?
        {
            return Err(failure());
        }
        if text(&trust[11])? == "BOOTSTRAP" {
            return if current_epoch == 1 {
                Ok(())
            } else {
                Err(failure())
            };
        }
        if text(&trust[11])? != "GOVERNED" || current_epoch < 2 {
            return Err(failure());
        }
        let rotation = text(&trust[12])?
            .strip_prefix("urn:openpc:resource:")
            .ok_or_else(failure)?;
        let rows=sqlx::query("select a.slot,a.request,a.observation,r.old_signer_id,r.cutover_at_ns::text cutover,k.public_key_spki_der,k.trust_preimage,k.trust_digest old_trust_digest,r.old_trust_digest rotation_old_digest,k.key_epoch::text old_epoch,k.valid_from_ns::text valid_from,k.valid_until_ns::text valid_until from control.signing_key_rotation r join control.signing_provider_attempt a on a.participant_id=r.participant_id and a.privacy_domain_id=r.privacy_domain_id and a.rotation_id=r.rotation_id join control.business_signing_key k on k.participant_id=r.participant_id and k.privacy_domain_id=r.privacy_domain_id and k.signer_id=r.old_signer_id where r.participant_id=$1::text::uuid and r.privacy_domain_id=$2::text::uuid and r.rotation_id=$3::text::uuid and r.new_signer_id=$4 and r.approval_request_id is not null and a.to_state='VERIFIED' and a.state='ACCEPTED' and a.request->>'method'='PROVE' order by a.slot")
            .bind(participant).bind(privacy).bind(rotation).bind(&current_signer).fetch_all(&mut **tx).await.map_err(|_|failure())?;
        if rows.len() != 2 {
            return Err(failure());
        }
        let mut slots = std::collections::BTreeSet::new();
        for row in &rows {
            let slot: String = row.try_get("slot").map_err(|_| failure())?;
            if !slots.insert(slot.clone()) || !["old", "new"].contains(&slot.as_str()) {
                return Err(failure());
            }
            let request: serde_json::Value = row.try_get("request").map_err(|_| failure())?;
            let observation: serde_json::Value =
                row.try_get("observation").map_err(|_| failure())?;
            let request_bytes =
                pc_runtime_types::canonical_bytes(&request).map_err(|_| failure())?;
            let old_public: Vec<u8> = row.try_get("public_key_spki_der").map_err(|_| failure())?;
            let old_preimage: Vec<u8> = row.try_get("trust_preimage").map_err(|_| failure())?;
            let old_digest: Vec<u8> = row.try_get("old_trust_digest").map_err(|_| failure())?;
            let expected_old: Vec<u8> =
                row.try_get("rotation_old_digest").map_err(|_| failure())?;
            let old_decoded = decode(&old_preimage)?;
            let old_trust = old_decoded
                .as_array()
                .filter(|t| t.len() == 21)
                .ok_or_else(failure)?;
            if bytes(&old_trust[5])? != old_public
                || Sha256::digest(&old_preimage).as_slice() != old_digest
                || old_digest != expected_old
                || text(&old_trust[3])? != text(&trust[3])?
                || bytes(&old_trust[6])? != bytes(&trust[6])?
                || integer(&old_trust[7])? != integer(&trust[7])?
                || old_trust[20] != trust[20]
                || integer(&old_trust[18])? != receipt.schema_version
            {
                return Err(failure());
            }
            let proof_trust = if slot == "old" { old_trust } else { trust };
            let observed_time = observation["recordedAtNs"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or_else(failure)?;
            let cutover_time: Option<String> = row.try_get("cutover").map_err(|_| failure())?;
            if observed_time < integer(&proof_trust[9])?
                || observed_time >= integer(&proof_trust[10])?
                || !observed_time.is_multiple_of(1000)
                || cutover_time
                    .is_none_or(|v| v.parse::<u64>().map_or(true, |v| observed_time >= v))
            {
                return Err(failure());
            }
            let public = if slot == "old" {
                old_public.as_slice()
            } else {
                bytes(&trust[5])?
            };
            let fingerprint = format!("sha256:{}", hex(&Sha256::digest(public)));
            let mut digest_input = b"pc.control.signing-provider-request.v1\0".to_vec();
            digest_input.extend_from_slice(&request_bytes);
            if request["method"] != "PROVE"
                || request["rotationId"] != rotation
                || request["participantId"] != participant
                || request["privacyDomainId"] != privacy
                || request["environmentId"] != text(&proof_trust[3])?
                || request["workloadCredentialId"].as_str().is_none_or(|v| {
                    uuid(v).map_or(true, |v| v != bytes(&proof_trust[6]).unwrap_or_default())
                })
                || request["callerWorkloadCredentialId"] != request["workloadCredentialId"]
                || request["reference"] != text(&proof_trust[15])?
                || request["version"] != text(&proof_trust[16])?
                || request["purpose"] != "pc.cose.control-business-transition.v1"
                || request["secretClass"] != "SECRET-SIGNING-KEY"
                || request["expectedFingerprint"] != fingerprint
                || request["challengeHex"] != hex(&Sha256::digest(&current))
                || observation["outcome"] != "SUCCEEDED"
                || observation["requestDigest"]
                    != format!("sha256:{}", hex(&Sha256::digest(digest_input)))
                || observation["attemptId"] != request["attemptId"]
                || observation["operationId"] != request["operationId"]
                || observation["method"] != "PROVE"
                || observation["descriptor"]["publicKeySpkiHex"] != hex(public)
                || observation["descriptor"]["fingerprint"] != fingerprint
                || observation["descriptor"]["algorithm"] != "ES256"
                || observation["descriptor"]["state"] != "ACTIVE"
                || observation["descriptor"]["validFromNs"]
                    .as_str()
                    .and_then(|v| v.parse::<u64>().ok())
                    != Some(integer(&proof_trust[9])?)
                || observation["descriptor"]["validUntilNs"]
                    .as_str()
                    .and_then(|v| v.parse::<u64>().ok())
                    != Some(integer(&proof_trust[10])?)
                || [
                    "participantId",
                    "privacyDomainId",
                    "workloadCredentialId",
                    "environmentId",
                    "reference",
                    "version",
                    "purpose",
                    "secretClass",
                ]
                .iter()
                .any(|k| observation["descriptor"][k] != request[k])
            {
                return Err(failure());
            }
            let mut signed = b"pc.control.signing-provider-possession.v1\0".to_vec();
            signed.extend_from_slice(&request_bytes);
            verify_signature(
                public,
                &signed,
                &unhex(observation["resultHex"].as_str().ok_or_else(failure)?)?,
            )?;
        }
        let cutover: Option<String> = rows[0].try_get("cutover").map_err(|_| failure())?;
        if current_signer == signer
            && cutover.is_none_or(|v| v.parse::<u64>().map_or(true, |v| recorded < v))
        {
            return Err(failure());
        }
        current_signer = rows[0].try_get("old_signer_id").map_err(|_| failure())?;
        current = rows[0].try_get("trust_preimage").map_err(|_| failure())?;
        let prior: u64 = rows[0]
            .try_get::<String, _>("old_epoch")
            .map_err(|_| failure())?
            .parse()
            .map_err(|_| failure())?;
        if prior.checked_add(1) != Some(current_epoch) {
            return Err(failure());
        }
        current_epoch = prior;
    }
    Err(failure())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    #[test]
    fn indexer_profiles_bind_each_canonical_version_and_reject_mixed_admissions() {
        for source in [
            include_str!(
                "../../../schemas/canonical/business-transition-profiles/indexer-profile-create-v1.json"
            ),
            include_str!(
                "../../../schemas/canonical/business-transition-profiles/indexer-profile-update-v1.json"
            ),
            include_str!(
                "../../../schemas/canonical/business-transition-profiles/indexer-profile-create-v2.json"
            ),
            include_str!(
                "../../../schemas/canonical/business-transition-profiles/indexer-profile-update-v2.json"
            ),
        ] {
            let profile: serde_json::Value = serde_json::from_str(source).unwrap();
            let version = profile["profileVersion"].as_u64().unwrap();
            let value = |key: &str| Value::Text(profile[key].as_str().unwrap().into());
            let receipt = Value::Map(vec![
                (uint(2), value("profileId")),
                (uint(3), uint(version)),
                (
                    uint(4),
                    Value::Bytes(
                        unhex(
                            profile["definitionDigest"]
                                .as_str()
                                .unwrap()
                                .strip_prefix("sha256:")
                                .unwrap(),
                        )
                        .unwrap(),
                    ),
                ),
                (uint(9), value("actionIntentId")),
                (uint(10), value("catalogOperationId")),
                (uint(22), uint(profile["transitionKind"].as_u64().unwrap())),
            ]);
            assert_eq!(indexer_profile(&receipt).unwrap().0, version);
            for (key, replacement) in [
                (2, Value::Text("pc.control.provider-profile.create".into())),
                (3, uint(3 - version)),
                (3, uint(3)),
                (4, Value::Bytes(vec![0; 32])),
                (9, Value::Text("ACT-RUNTIME_READ_RPC-V1".into())),
                (10, Value::Text("CFG-OP-CREATE-PROVIDER-PROFILE".into())),
                (22, uint(2)),
            ] {
                let mut malformed = receipt.clone();
                malformed
                    .as_map_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|(k, _)| integer(k) == Ok(key))
                    .unwrap()
                    .1 = replacement;
                assert!(indexer_profile(&malformed).is_err(), "changed field {key}");
            }
        }
    }

    #[test]
    fn cose_requires_the_receipt_purpose_payload_and_canonical_p256_identity() {
        for version in [1, 2] {
            // Deterministic test-only signing key; never enters a runtime trust registry.
            let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
            let point = key.verifying_key().to_sec1_point(false);
            let mut public = unhex("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
            public.extend_from_slice(point.as_bytes());
            let payload = vec![0xa0];
            let protected = encode(&Value::Map(vec![
                (uint(1), Value::Integer((-7).into())),
                (
                    uint(2),
                    Value::Array(vec![uint(100), uint(101), uint(102), uint(103)]),
                ),
                (uint(3), Value::Text("application/pc+cbor".into())),
                (
                    uint(4),
                    Value::Bytes(format!("sha256:{}", hex(&Sha256::digest(&public))).into_bytes()),
                ),
                (uint(100), uint(24001)),
                (uint(101), uint(version)),
                (uint(102), uint(338)),
                (uint(103), uint(2)),
            ]))
            .unwrap();
            let signed = encode(&Value::Array(vec![
                Value::Text("Signature1".into()),
                Value::Bytes(protected.clone()),
                Value::Bytes(b"pcplane:cose-sign1:v2\0".to_vec()),
                Value::Bytes(payload.clone()),
            ]))
            .unwrap();
            let signature: Signature = key.sign(&signed);
            let mut cose = vec![0xd2];
            cose.extend(
                encode(&Value::Array(vec![
                    Value::Bytes(protected),
                    Value::Map(vec![]),
                    Value::Bytes(payload.clone()),
                    Value::Bytes(signature.to_bytes().to_vec()),
                ]))
                .unwrap(),
            );
            assert!(verify_cose_version(&public, &payload, &cose, version).is_ok());
            assert!(verify_cose_version(&public, &payload, &cose, 3 - version).is_err());
            assert!(verify_cose_version(&public, &[0x80], &cose, version).is_err());
            let mut tampered = cose.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(verify_cose_version(&public, &payload, &tampered, version).is_err());
            let mut trailing = cose.clone();
            trailing.push(0);
            assert!(verify_cose_version(&public, &payload, &trailing, version).is_err());
            let mut wrong_key = public.clone();
            wrong_key[10] ^= 1;
            assert!(verify_cose_version(&wrong_key, &payload, &cose, version).is_err());
            assert!(verify_cose_version(&public, &payload, &cose[1..], version).is_err());
        }
    }
}
