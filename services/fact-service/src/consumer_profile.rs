//! Installed Fact consumer scheduling policy. Signature/profile admission never
//! replaces current workload, source, effect, inbox or cursor authorization.
use ciborium::Value;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use pc_runtime_types::runtime_source_identity::runtime_source_login;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub mod failure;
mod failure_generated;
mod generated;
#[cfg(test)]
mod tests;

const SAFE_UINT: u64 = 9_007_199_254_740_991;
#[derive(Debug, thiserror::Error)]
#[error("installed Fact consumer profile rejected")]
pub struct ConsumerProfileError;
type Result<T> = std::result::Result<T, ConsumerProfileError>;

/// Only a trusted installer may supply this pin set. It is never read from a
/// delivered event, public request or the signed profile being verified.
#[derive(Clone)]
pub struct InstalledFactConsumerProfile {
    pub issuer_spki_der: Vec<u8>,
    pub signed_profile_digest: String,
    pub environment_id: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub profile_id: String,
    pub revision: String,
    pub consumer_id: String,
    pub subscription_id: String,
    pub workload_credential_id: String,
    pub workload_credential_epoch: String,
    pub database_role: String,
}

pub struct VerifiedFactConsumerProfile {
    profile_digest: String,
    valid_from_ms: u64,
    valid_until_ms: u64,
    maximum_attempts: u64,
    initial_backoff_ms: u64,
    maximum_backoff_ms: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ConsumerRetryDecision {
    Retry { not_before_ms: u64 },
    Quarantine,
    ProfileNotCurrent,
}

impl VerifiedFactConsumerProfile {
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }
    /// The committing owner supplies its durable attempt count and database
    /// clock. Capacity refusals do not call this or consume a business attempt.
    pub fn retry_after_failure(
        &self,
        completed_attempts: u64,
        failed_at_ms: u64,
    ) -> Result<ConsumerRetryDecision> {
        if !(1..=1000).contains(&completed_attempts) || failed_at_ms > SAFE_UINT {
            return Err(ConsumerProfileError);
        }
        if completed_attempts >= self.maximum_attempts {
            return Ok(ConsumerRetryDecision::Quarantine);
        }
        if failed_at_ms < self.valid_from_ms || failed_at_ms >= self.valid_until_ms {
            return Ok(ConsumerRetryDecision::ProfileNotCurrent);
        }
        let mut delay = self.initial_backoff_ms;
        for _ in 1..completed_attempts {
            if delay >= self.maximum_backoff_ms {
                break;
            }
            delay = (delay * 2).min(self.maximum_backoff_ms);
        }
        let not_before_ms = failed_at_ms + delay;
        if not_before_ms > SAFE_UINT || not_before_ms >= self.valid_until_ms {
            return Ok(ConsumerRetryDecision::ProfileNotCurrent);
        }
        Ok(ConsumerRetryDecision::Retry { not_before_ms })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode(bytes: &[u8], max: usize) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(ConsumerProfileError);
    }
    pc_provider_api::validate_canonical_pc_cbor_bytes(bytes).map_err(|_| ConsumerProfileError)?;
    ciborium::de::from_reader(bytes).map_err(|_| ConsumerProfileError)
}
fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).map_err(|_| ConsumerProfileError)?;
    Ok(bytes)
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn number(value: &Value) -> Result<u64> {
    value
        .as_integer()
        .and_then(|v| u64::try_from(v).ok())
        .ok_or(ConsumerProfileError)
}
fn bytes(value: &Value) -> Result<&[u8]> {
    value
        .as_bytes()
        .map(Vec::as_slice)
        .ok_or(ConsumerProfileError)
}
fn text(value: &Value) -> Result<&str> {
    let text = value.as_text().ok_or(ConsumerProfileError)?;
    if text.is_empty()
        || text.len() > 160
        || !text.as_bytes()[0].is_ascii_alphanumeric()
        || !text
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b":._-".contains(&c))
    {
        return Err(ConsumerProfileError);
    }
    Ok(text)
}
fn uuid(value: &Value, expected: &str, v7: bool) -> Result<()> {
    let id = Uuid::from_slice(bytes(value)?).map_err(|_| ConsumerProfileError)?;
    if id.to_string() != expected
        || id.get_variant() != uuid::Variant::RFC4122
        || !matches!(id.get_version_num(), 1..=8)
        || (v7 && id.get_version_num() != 7)
    {
        return Err(ConsumerProfileError);
    }
    Ok(())
}
fn protected(spki: &[u8]) -> Result<Vec<u8>> {
    protected_for(spki, generated::SCHEMA_ID, generated::PURPOSE_CODE)
}
fn protected_for(spki: &[u8], schema_id: u64, purpose_code: u64) -> Result<Vec<u8>> {
    encode(&Value::Map(vec![
        (uint(1), Value::Integer((-7).into())),
        (
            uint(2),
            Value::Array(vec![uint(100), uint(101), uint(102), uint(103)]),
        ),
        (uint(3), Value::Text("application/pc+cbor".into())),
        (
            uint(4),
            Value::Bytes(format!("sha256:{}", hex(&Sha256::digest(spki))).into_bytes()),
        ),
        (uint(100), uint(schema_id)),
        (uint(101), uint(1)),
        (uint(102), uint(purpose_code)),
        (uint(103), uint(2)),
    ]))
}

/// Authenticates exact canonical bytes and every installation pin. Historical
/// signatures do not renew validity and an otherwise valid old profile cannot
/// roll back the installed profile digest. No database effects occur here.
pub fn verify_installed_fact_consumer_profile(
    installed: &InstalledFactConsumerProfile,
    payload: &[u8],
    cose: &[u8],
    now_ms: u64,
) -> Result<VerifiedFactConsumerProfile> {
    if now_ms > SAFE_UINT
        || cose.first() != Some(&0xd2)
        || cose.len() > 66560
        || installed.signed_profile_digest != format!("sha256:{}", hex(&Sha256::digest(cose)))
    {
        return Err(ConsumerProfileError);
    }
    let spki = &installed.issuer_spki_der;
    if spki.len() != 91
        || hex(&spki[..27]) != "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
    {
        return Err(ConsumerProfileError);
    }
    let container = decode(&cose[1..], 66560)?;
    let parts = container
        .as_array()
        .filter(|v| v.len() == 4)
        .ok_or(ConsumerProfileError)?;
    let header = protected(spki)?;
    if bytes(&parts[0])? != header
        || !parts[1].as_map().is_some_and(Vec::is_empty)
        || bytes(&parts[2])? != payload
    {
        return Err(ConsumerProfileError);
    }
    let sig_structure = encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(header),
        Value::Bytes(b"pcplane:cose-sign1:v2\0".to_vec()),
        Value::Bytes(payload.to_vec()),
    ]))?;
    VerifyingKey::from_sec1_bytes(&spki[26..])
        .map_err(|_| ConsumerProfileError)?
        .verify(
            &sig_structure,
            &Signature::from_slice(bytes(&parts[3])?).map_err(|_| ConsumerProfileError)?,
        )
        .map_err(|_| ConsumerProfileError)?;
    let value = decode(payload, 65536)?;
    let fields = value
        .as_map()
        .filter(|v| v.len() == 17)
        .ok_or(ConsumerProfileError)?;
    for (i, (key, _)) in fields.iter().enumerate() {
        if number(key)? != i as u64 {
            return Err(ConsumerProfileError);
        }
    }
    let field = |index: usize| &fields[index].1;
    if hex(bytes(field(0))?) != generated::DEFINITION_DIGEST {
        return Err(ConsumerProfileError);
    }
    for (index, expected) in [
        (1, installed.environment_id.as_str()),
        (4, &installed.profile_id),
        (6, &installed.consumer_id),
        (7, &installed.subscription_id),
        (13, &installed.database_role),
    ] {
        if text(field(index))? != expected {
            return Err(ConsumerProfileError);
        }
    }
    uuid(field(2), &installed.participant_id, false)?;
    uuid(field(3), &installed.privacy_domain_id, false)?;
    uuid(field(11), &installed.workload_credential_id, true)?;
    if number(field(5))? == 0
        || number(field(5))?.to_string() != installed.revision
        || number(field(12))?.to_string() != installed.workload_credential_epoch
        || bytes(field(10))? != Sha256::digest(spki).as_slice()
        || !matches!(
            (
                installed.consumer_id.as_str(),
                installed.subscription_id.as_str()
            ),
            (
                "LS-CONTROL-WORK",
                "SUB-FACTCANDIDATEADMITTED-CONTROL_WORK-V1"
            ) | (
                "LS-FLEET-CONTROL",
                "SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1"
            )
        )
    {
        return Err(ConsumerProfileError);
    }
    let role = installed.database_role.as_bytes();
    let simple_role = !role.is_empty()
        && role.len() <= 63
        && (role[0].is_ascii_lowercase() || role[0] == b'_')
        && role
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_');
    if !simple_role
        && !runtime_source_login(&installed.participant_id, &installed.privacy_domain_id)
            .is_ok_and(|expected| expected == installed.database_role)
    {
        return Err(ConsumerProfileError);
    }
    let profile = VerifiedFactConsumerProfile {
        profile_digest: installed.signed_profile_digest.clone(),
        valid_from_ms: number(field(8))?,
        valid_until_ms: number(field(9))?,
        maximum_attempts: number(field(14))?,
        initial_backoff_ms: number(field(15))?,
        maximum_backoff_ms: number(field(16))?,
    };
    if profile.valid_from_ms >= profile.valid_until_ms
        || profile.valid_until_ms > SAFE_UINT
        || now_ms < profile.valid_from_ms
        || now_ms >= profile.valid_until_ms
        || !(1..=1000).contains(&profile.maximum_attempts)
        || !(1..=3600000).contains(&profile.initial_backoff_ms)
        || !(profile.initial_backoff_ms..=3600000).contains(&profile.maximum_backoff_ms)
    {
        return Err(ConsumerProfileError);
    }
    Ok(profile)
}

/// The database owner selects installed trust and holds the profile and live
/// workload locks in this same transaction. The native owner independently
/// verifies its exact signature before producing an effect capability.
pub async fn lock_installed_fact_consumer_profile(
    tx: &mut Transaction<'_, Postgres>,
    participant: &str,
    privacy: &str,
    consumer: &str,
) -> Result<VerifiedFactConsumerProfile> {
    let row = sqlx::query(
        "select p.*,floor(extract(epoch from clock_timestamp())*1000)::text now_ms
        from openpc.require_fact_consumer_profile($1) p",
    )
    .bind(consumer)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ConsumerProfileError)?;
    let claim: serde_json::Value = row.try_get("claims").map_err(|_| ConsumerProfileError)?;
    let claim_text = |name: &str| -> Result<String> {
        claim
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or(ConsumerProfileError)
    };
    let text = |name| -> Result<String> { row.try_get(name).map_err(|_| ConsumerProfileError) };
    // UUID/numeric columns are projected by the claims that SQL independently
    // binds to their typed columns at installation. Expected scope/consumer
    // still comes from the current worker, never from the source event.
    if claim_text("participantId")? != participant
        || claim_text("privacyDomainId")? != privacy
        || claim_text("consumerId")? != consumer
    {
        return Err(ConsumerProfileError);
    }
    let installed = InstalledFactConsumerProfile {
        issuer_spki_der: row
            .try_get("issuer_spki")
            .map_err(|_| ConsumerProfileError)?,
        signed_profile_digest: text("profile_digest")?,
        environment_id: claim_text("environmentId")?,
        participant_id: participant.into(),
        privacy_domain_id: privacy.into(),
        profile_id: text("profile_id")?,
        revision: claim_text("revision")?,
        consumer_id: consumer.into(),
        subscription_id: claim_text("subscriptionId")?,
        workload_credential_id: claim_text("workloadCredentialId")?,
        workload_credential_epoch: claim_text("workloadCredentialEpoch")?,
        database_role: text("database_role")?,
    };
    verify_installed_fact_consumer_profile(
        &installed,
        &row.try_get::<Vec<u8>, _>("payload")
            .map_err(|_| ConsumerProfileError)?,
        &row.try_get::<Vec<u8>, _>("cose")
            .map_err(|_| ConsumerProfileError)?,
        text("now_ms")?.parse().map_err(|_| ConsumerProfileError)?,
    )
}
