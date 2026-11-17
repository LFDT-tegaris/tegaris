//! Pure canonical provenance for separately admitted trust v2. Every current
//! DB/provider/permission/instance/transport fence remains independently required.
use super::{
    Authorization, DomainUuid, Hash32, Identifier, Nanos, Positive, Unsigned, Wire, Workload,
    digest, generated, generated_signing::*, invalid, pc_cbor_1,
};
use ciborium::value::Value;
use pc_runtime_types::{PurposeVerifier, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigningTrust {
    pub participant_id: DomainUuid,
    pub privacy_domain_id: DomainUuid,
    pub environment_id: Identifier,
    pub principal_id: DomainUuid,
    pub workload_id: Workload,
    pub family_id: DomainUuid,
    pub family_security_epoch: Unsigned,
    pub participant_security_invalidation_epoch: Unsigned,
    pub key_security_generation: Positive,
    pub signer_id: Hash32,
    pub public_key_spki_der: Vec<u8>,
    pub key_epoch: Positive,
    pub valid_from_ns: Nanos,
    pub valid_until_ns: Nanos,
    pub provider_qualification_digest: Hash32,
    pub admission_kind: String,
    pub admission_reference: String,
    pub admission_digest: Hash32,
    pub secret_class: String,
    pub secret_reference: String,
    pub secret_version: String,
    pub purpose: String,
    pub profile_id: String,
    pub profile_version: u64,
    pub profile_digest: Hash32,
}
fn text(value: &str, max: usize) -> RuntimeResult<Value> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(|c| c < '\u{20}' || c == '\u{7f}')
        || !value.nfc().eq(value.chars())
    {
        return invalid();
    }
    Ok(Value::Text(value.to_owned()))
}
fn exact_secret(reference: &str, version: &str) -> bool {
    let Some((location, actual)) = reference
        .strip_prefix("secret://")
        .and_then(|s| s.split_once('#'))
    else {
        return false;
    };
    let Some((provider, path)) = location.split_once('/') else {
        return false;
    };
    (2..=32).contains(&provider.len())
        && provider.as_bytes()[0].is_ascii_lowercase()
        && provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && (1..=192).contains(&path.len())
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && actual == version
        && (1..=96).contains(&version.len())
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && !matches!(version.to_ascii_lowercase().as_str(), "latest" | "current")
}
impl SigningTrust {
    pub fn preimage(&self) -> RuntimeResult<Vec<u8>> {
        const PREFIX: &[u8] = &[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        if self.purpose != "pc.cose.identity.workload-renewal-policy-authorization.v1"
            || self.profile_id != "pc.identity.workload-renewal.policy-authorization.v1"
            || self.profile_version != SIGNING_PROFILE_VERSION
            || self.profile_digest.0 != SIGNING_PROFILE_DIGEST
            || self.valid_until_ns.value()? <= self.valid_from_ns.value()?
            || !exact_secret(&self.secret_reference, &self.secret_version)
            || self.secret_class != "SECRET-SIGNING-KEY"
            || !matches!(self.admission_kind.as_str(), "BOOTSTRAP" | "GOVERNED")
            || self.public_key_spki_der.len() != 91
            || !self.public_key_spki_der.starts_with(PREFIX)
            || self.signer_id != digest(&self.public_key_spki_der)
        {
            return invalid();
        }
        // Reuse the existing accepted P-256 point parser; a DER prefix alone does
        // not authenticate a canonical on-curve public key.
        PurposeVerifier::from_sec1_bytes(
            "pc.cose.identity.workload-renewal-policy-authorization.v1",
            &self.public_key_spki_der[26..],
        )
        .map_err(|_| RuntimeError::InvalidInput)?;
        let mut values = vec![Value::Text(SIGNING_TRUST_DOMAIN.to_owned())];
        for (name, kind) in SIGNING_TRUST_FIELDS {
            values.push(match (*name, *kind) {
                ("participantId", "uuid") => self.participant_id.encode_value()?,
                ("privacyDomainId", "uuid") => self.privacy_domain_id.encode_value()?,
                ("environmentId", "identifier") => self.environment_id.encode_value()?,
                ("principalId", "uuid") => self.principal_id.encode_value()?,
                ("workloadId", "workload") => self.workload_id.encode_value()?,
                ("familyId", "uuid") => self.family_id.encode_value()?,
                ("familySecurityEpoch", "unsigned") => self.family_security_epoch.encode_value()?,
                ("participantSecurityInvalidationEpoch", "unsigned") => self
                    .participant_security_invalidation_epoch
                    .encode_value()?,
                ("keySecurityGeneration", "positive") => {
                    self.key_security_generation.encode_value()?
                }
                ("signerId", "hash") => self.signer_id.encode_value()?,
                ("publicKeySpkiDer", "p256spki") => Value::Bytes(self.public_key_spki_der.clone()),
                ("keyEpoch", "positive") => self.key_epoch.encode_value()?,
                ("validFromNs", "nanos") => self.valid_from_ns.encode_value()?,
                ("validUntilNs", "nanos") => self.valid_until_ns.encode_value()?,
                ("providerQualificationDigest", "hash") => {
                    self.provider_qualification_digest.encode_value()?
                }
                ("admissionKind", "admissionKind") => text(&self.admission_kind, 16)?,
                ("admissionReference", "admissionReference") => {
                    text(&self.admission_reference, 256)?
                }
                ("admissionDigest", "hash") => self.admission_digest.encode_value()?,
                ("secretClass", "secretClass") => text(&self.secret_class, 32)?,
                ("secretReference", "secretReference") => text(&self.secret_reference, 331)?,
                ("secretVersion", "secretVersion") => text(&self.secret_version, 96)?,
                _ => return invalid(),
            });
        }
        values.extend([
            Value::Integer(24039.into()),
            Value::Integer(1.into()),
            Value::Integer(376.into()),
            Hash32(generated::AUTHORIZATION_DEFINITION_DIGEST.to_owned()).encode_value()?,
            Value::Text(self.profile_id.clone()),
            Value::Integer(SIGNING_PROFILE_VERSION.into()),
            self.profile_digest.encode_value()?,
            Value::Text("POLICY_AUTHORIZED".to_owned()),
            Value::Text("ACT-IDENTITY_RENEW_WORKLOAD_CREDENTIAL-V1".to_owned()),
            Value::Text("ID-OP-WORKLOAD-RENEWAL-ADMIT".to_owned()),
        ]);
        Ok(pc_cbor_1(&Value::Array(values)))
    }
    pub fn digest(&self) -> RuntimeResult<Hash32> {
        Ok(digest(&self.preimage()?))
    }
    /// Crypto plus exact stable signer/current credential tuple. The caller must
    /// authenticate every current fence; this method grants no signing authority.
    pub fn verify_authorization(
        &self,
        payload: &[u8],
        cose: &[u8],
        credential: &DomainUuid,
        credential_epoch: &Positive,
        now_ns: u64,
    ) -> RuntimeResult<Authorization> {
        let trust_digest = self.digest()?;
        credential.encode_value()?;
        credential_epoch.value()?;
        let artifact = Authorization::verify_cose(payload, &self.public_key_spki_der, cose)?;
        let signer = &artifact.signer;
        if signer.participant_id != self.participant_id
            || signer.privacy_domain_id != self.privacy_domain_id
            || signer.environment_id != self.environment_id
            || signer.workload_id != self.workload_id
            || signer.key_id != self.signer_id
            || signer.key_epoch != self.key_epoch
            || signer.profile_digest != self.profile_digest
            || signer.trust_digest != trust_digest
            || &signer.credential_id != credential
            || &signer.credential_epoch != credential_epoch
            || now_ns < self.valid_from_ns.value()?
            || now_ns >= self.valid_until_ns.value()?
            || artifact.issued_at_ns.value()? < self.valid_from_ns.value()?
            || artifact.issued_at_ns.value()? > now_ns
            || artifact.valid_until_ns.value()? <= now_ns
            || artifact.valid_until_ns.value()? > self.valid_until_ns.value()?
        {
            return invalid();
        }
        Ok(artifact)
    }
}
