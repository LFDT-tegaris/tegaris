//! AES-256-GCM local storage using the already selected ring provider. These
//! objects authenticate storage, not workload authority or response delivery.
use super::*;
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use serde::de::DeserializeOwned;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSpoolBinding {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub target_runtime_id: String,
    pub spool_id: String,
    pub key_id: String,
}
impl EvidenceSpoolBinding {
    pub(super) fn validate(&self) -> RuntimeResult<()> {
        for value in [&self.participant_id, &self.privacy_domain_id] {
            if uuid::Uuid::parse_str(value).is_err() {
                return Err(RuntimeError::InvalidInput);
            }
        }
        for value in [&self.target_runtime_id, &self.spool_id, &self.key_id] {
            if value.is_empty()
                || value.len() > 160
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b":._-".contains(&byte))
            {
                return Err(RuntimeError::InvalidInput);
            }
        }
        Ok(())
    }
}

/// Durable admission describes the local write only. It is never a provider
/// execution receipt, sink acknowledgement, or proof of delivery to a caller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAdmissionReceipt {
    pub spool_id: String,
    pub sequence: u64,
    pub segment_id: String,
    pub record_id: String,
    pub record_digest: Digest,
    pub admitted_at_ns: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SealedChain {
    version: String,
    pub binding: EvidenceSpoolBinding,
    pub legacy_digest: Option<Digest>,
    pub genesis: Option<Ciphertext>,
    head: Option<Ciphertext>,
    pub records: Vec<SealedRecord>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ciphertext {
    nonce: Vec<u8>,
    ciphertext_and_tag: Vec<u8>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SealedRecord {
    pub receipt: EvidenceAdmissionReceipt,
    pub previous_segment_digest: Option<Digest>,
    encrypted: Ciphertext,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Payload<T> {
    record: T,
    footer: Digest,
}

const VERSION: &str = "OPENPC_RPC_DECISION_SPOOL_V1";
pub(super) const MAX_RECORDS: usize = 4096;
const MAX_RECORD_BYTES: usize = 16 * 1024;

impl SealedChain {
    pub fn empty(binding: EvidenceSpoolBinding) -> Self {
        Self {
            version: VERSION.into(),
            binding,
            legacy_digest: None,
            genesis: None,
            head: None,
            records: vec![],
        }
    }
    fn context(&self) -> RuntimeResult<Vec<u8>> {
        canonical_bytes(&(&self.version, &self.binding, &self.legacy_digest))
    }
    pub fn initialize(&mut self, key: &aead::LessSafeKey) -> RuntimeResult<()> {
        self.genesis = Some(Ciphertext::seal(
            key,
            &self.context()?,
            b"legacy-unverified;no-authority",
        )?);
        self.seal_head(key)?;
        Ok(())
    }
    pub fn verify_genesis(&self, key: &aead::LessSafeKey) -> RuntimeResult<()> {
        if self.version != VERSION
            || self.records.len() > MAX_RECORDS
            || self
                .genesis
                .as_ref()
                .ok_or(RuntimeError::InvalidDigest)?
                .open(key, &self.context()?)?
                != b"legacy-unverified;no-authority"
            || self
                .head
                .as_ref()
                .ok_or(RuntimeError::InvalidDigest)?
                .open(key, &self.context()?)?
                != self.head_bytes()?
        {
            return Err(RuntimeError::InvalidDigest);
        }
        Ok(())
    }
    fn head_bytes(&self) -> RuntimeResult<Vec<u8>> {
        canonical_bytes(&(
            self.records.len(),
            self.records.last().map(SealedRecord::digest).transpose()?,
        ))
    }
    pub fn seal_head(&mut self, key: &aead::LessSafeKey) -> RuntimeResult<()> {
        self.head = Some(Ciphertext::seal(
            key,
            &self.context()?,
            &self.head_bytes()?,
        )?);
        Ok(())
    }
}
impl SealedRecord {
    fn aad(
        chain: &SealedChain,
        receipt: &EvidenceAdmissionReceipt,
        previous: &Option<Digest>,
    ) -> RuntimeResult<Vec<u8>> {
        canonical_bytes(&(chain.context()?, receipt, previous))
    }
    pub fn seal<T: Serialize>(
        chain: &SealedChain,
        id: &str,
        record: &T,
        key: &aead::LessSafeKey,
    ) -> RuntimeResult<Self> {
        if chain.records.len() >= MAX_RECORDS {
            return Err(RuntimeError::EvidenceCapacity);
        }
        let record_digest = Digest::of(canonical_bytes(record)?);
        let receipt = EvidenceAdmissionReceipt {
            spool_id: chain.binding.spool_id.clone(),
            sequence: chain.records.len() as u64 + 1,
            segment_id: uuid::Uuid::now_v7().to_string(),
            record_id: id.into(),
            record_digest: record_digest.clone(),
            admitted_at_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| RuntimeError::RuntimeUnavailable)?
                .as_nanos()
                .to_string(),
        };
        let previous_segment_digest = chain.records.last().map(Self::digest).transpose()?;
        let plaintext = canonical_bytes(&Payload {
            record,
            footer: record_digest,
        })?;
        if plaintext.len() > MAX_RECORD_BYTES {
            return Err(RuntimeError::EvidenceCapacity);
        }
        let encrypted = Ciphertext::seal(
            key,
            &Self::aad(chain, &receipt, &previous_segment_digest)?,
            &plaintext,
        )?;
        Ok(Self {
            receipt,
            previous_segment_digest,
            encrypted,
        })
    }
    pub fn open<T: DeserializeOwned + Serialize>(
        &self,
        chain: &SealedChain,
        key: &aead::LessSafeKey,
    ) -> RuntimeResult<T> {
        if self.receipt.spool_id != chain.binding.spool_id
            || self.receipt.sequence == 0
            || self.receipt.admitted_at_ns.parse::<u64>().is_err()
            || uuid::Uuid::parse_str(&self.receipt.segment_id).is_err()
        {
            return Err(RuntimeError::InvalidInput);
        }
        let plaintext = self.encrypted.open(
            key,
            &Self::aad(chain, &self.receipt, &self.previous_segment_digest)?,
        )?;
        let payload: Payload<T> =
            serde_json::from_slice(&plaintext).map_err(|_| RuntimeError::InvalidInput)?;
        if payload.footer != self.receipt.record_digest
            || Digest::of(canonical_bytes(&payload.record)?) != payload.footer
        {
            return Err(RuntimeError::InvalidDigest);
        }
        Ok(payload.record)
    }
    pub fn digest(&self) -> RuntimeResult<Digest> {
        Ok(Digest::of(canonical_bytes(self)?))
    }
}
impl Ciphertext {
    fn seal(key: &aead::LessSafeKey, aad: &[u8], plaintext: &[u8]) -> RuntimeResult<Self> {
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut ciphertext_and_tag = plaintext.to_vec();
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut ciphertext_and_tag,
        )
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        Ok(Self {
            nonce: nonce.to_vec(),
            ciphertext_and_tag,
        })
    }
    fn open(&self, key: &aead::LessSafeKey, aad: &[u8]) -> RuntimeResult<Vec<u8>> {
        if self.ciphertext_and_tag.len() > MAX_RECORD_BYTES + 16 {
            return Err(RuntimeError::EvidenceCapacity);
        }
        let nonce = aead::Nonce::try_assume_unique_for_key(&self.nonce)
            .map_err(|_| RuntimeError::InvalidInput)?;
        let mut bytes = self.ciphertext_and_tag.clone();
        let plaintext = key
            .open_in_place(nonce, aead::Aad::from(aad), &mut bytes)
            .map_err(|_| RuntimeError::InvalidDigest)?;
        Ok(plaintext.to_vec())
    }
}
