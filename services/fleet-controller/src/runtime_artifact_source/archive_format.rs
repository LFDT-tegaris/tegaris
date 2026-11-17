//! Independent readback of the existing OPENPC_EVIDENCE_SEGMENT_V1 wire.
//! No new encryption format, authority flag or archive producer is introduced.
use super::*;
use base64ct::{Base64, Encoding};
use serde_json::{Value, json};

fn invalid<T>() -> RuntimeResult<T> {
    Err(RuntimeError::InvalidAuthorization)
}
fn text<'a>(value: &'a Value, key: &str) -> RuntimeResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(RuntimeError::InvalidInput)
}
fn integer(value: &Value, key: &str) -> RuntimeResult<u64> {
    text(value, key)?
        .parse()
        .map_err(|_| RuntimeError::InvalidInput)
}
fn digest(bytes: impl AsRef<[u8]>) -> String {
    format!("sha256:{}", Digest::of(bytes).as_str())
}
fn json_digest(value: &Value) -> RuntimeResult<String> {
    Ok(digest(canonical_bytes(value)?))
}
fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|value| {
        value.len() == keys.len() && keys.iter().all(|key| value.contains_key(*key))
    })
}
fn hex(value: &str, size: usize) -> RuntimeResult<Vec<u8>> {
    if value.len() != size * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return invalid();
    }
    (0..size)
        .map(|i| {
            u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| RuntimeError::InvalidInput)
        })
        .collect()
}
fn base64(value: &str) -> RuntimeResult<Vec<u8>> {
    let bytes = Base64::decode_vec(value).map_err(|_| RuntimeError::InvalidInput)?;
    if Base64::encode_string(&bytes) != value {
        return invalid();
    }
    Ok(bytes)
}

pub(super) fn open_segment(
    bytes: &[u8],
    expected_header: &Value,
    expected_digest: &str,
    custody: &Custody,
) -> RuntimeResult<Vec<Value>> {
    if bytes.len() > 2 * 1024 * 1024 || digest(bytes) != expected_digest {
        return invalid();
    }
    let envelope: Value = serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidInput)?;
    if canonical_bytes(&envelope)? != bytes
        || !exact_keys(&envelope, &["header", "nonce", "ciphertext", "tag"])
        || &envelope["header"] != expected_header
    {
        return invalid();
    }
    let header = &envelope["header"];
    if !exact_keys(
        header,
        &[
            "version",
            "participantId",
            "privacyDomainId",
            "streamId",
            "segmentId",
            "firstSequence",
            "throughSequence",
            "previousSegmentDigest",
            "keyId",
            "retentionUntil",
        ],
    ) || header["version"] != "OPENPC_EVIDENCE_SEGMENT_V1"
    {
        return invalid();
    }
    let key = custody
        .keys
        .get(text(header, "keyId")?)
        .ok_or(RuntimeError::InvalidAuthorization)?;
    let key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
            .map_err(|_| RuntimeError::InvalidInput)?,
    );
    let nonce: [u8; 12] = hex(text(&envelope, "nonce")?, 12)?
        .try_into()
        .map_err(|_| RuntimeError::InvalidInput)?;
    let mut plaintext = base64(text(&envelope, "ciphertext")?)?;
    plaintext.extend(hex(text(&envelope, "tag")?, 16)?);
    let result = (|| {
        let opened = key
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::from(canonical_bytes(header)?),
                &mut plaintext,
            )
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
        if opened.len() > 1024 * 1024 {
            return invalid();
        }
        let payload: Value =
            serde_json::from_slice(opened).map_err(|_| RuntimeError::InvalidInput)?;
        if canonical_bytes(&payload)? != opened
            || !exact_keys(&payload, &["records", "footer"])
            || !exact_keys(&payload["footer"], &["count", "lastRecordDigest"])
        {
            return invalid();
        }
        let records = payload["records"]
            .as_array()
            .ok_or(RuntimeError::InvalidInput)?;
        let first = integer(header, "firstSequence")?;
        let through = integer(header, "throughSequence")?;
        if first == 0
            || through < first
            || through - first >= 128
            || records.len() as u64 != through - first + 1
            || payload["footer"]["count"].as_u64() != Some(records.len() as u64)
            || (first == 1) != header["previousSegmentDigest"].is_null()
        {
            return invalid();
        }
        let mut previous = header["previousSegmentDigest"].clone();
        let mut ids = BTreeSet::new();
        for (index, record) in records.iter().enumerate() {
            if !exact_keys(
                record,
                &[
                    "recordId",
                    "evidenceClass",
                    "sourceFormat",
                    "occurredAt",
                    "receiptDigest",
                    "receiptBase64",
                    "sequence",
                    "previousRecordDigest",
                    "recordDigest",
                ],
            ) || integer(record, "sequence")? != first + index as u64
                || record["previousRecordDigest"] != previous
                || !ids.insert(text(record, "recordId")?)
            {
                return invalid();
            }
            let receipt = base64(text(record, "receiptBase64")?)?;
            if digest(&receipt) != text(record, "receiptDigest")? {
                return invalid();
            }
            let mut source = record.clone();
            source
                .as_object_mut()
                .ok_or(RuntimeError::InvalidInput)?
                .remove("recordDigest");
            if json_digest(&source)? != text(record, "recordDigest")? {
                return invalid();
            }
            previous = record["recordDigest"].clone();
        }
        if payload["footer"]["lastRecordDigest"] != previous {
            return invalid();
        }
        Ok(records.clone())
    })();
    plaintext.fill(0);
    result
}

pub(super) fn verify_manifest(
    manifest: &Value,
    records: &[Value],
    pending: &Pending,
    installation: &SourceCustodyInstallation,
) -> RuntimeResult<()> {
    let identity = &manifest["identity"];
    let input = &pending.materialization.input;
    if !exact_keys(
        manifest,
        &[
            "version",
            "class",
            "store",
            "authority",
            "currentReadiness",
            "identity",
            "identityDigest",
            "chunks",
        ],
    ) || manifest["version"] != "OPENPC_RUNTIME_ARTIFACT_MANIFEST_V1"
        || manifest["class"] != "RUNTIME_ARTIFACT"
        || manifest["store"] != "openpc_control"
        || manifest["authority"] != "NONE"
        || manifest["currentReadiness"] != "NOT_ESTABLISHED"
        || !exact_keys(
            identity,
            &[
                "participantId",
                "privacyDomainId",
                "runtimeConfigurationInputId",
                "moduleInstallationId",
                "moduleConfigurationGenerationId",
                "configurationDigest",
                "configurationBytes",
                "resourceBindingsDigest",
                "createdAt",
            ],
        )
        || identity["participantId"] != installation.participant_id
        || identity["privacyDomainId"] != installation.privacy_domain_id
        || identity["runtimeConfigurationInputId"] != input.input_id
        || identity["moduleInstallationId"] != input.module_installation_id
        || identity["moduleConfigurationGenerationId"] != input.module_configuration_generation_id
        || identity["configurationDigest"]
            != format!("sha256:{}", input.configuration_digest.as_str())
    {
        return invalid();
    }
    let identity_digest = json_digest(
        &json!({"domain":"pc.runtime-artifact.archive-identity.v1","identity":identity}),
    )?;
    if manifest["identityDigest"] != identity_digest {
        return invalid();
    }
    let size = identity["configurationBytes"]
        .as_u64()
        .ok_or(RuntimeError::InvalidInput)?;
    let chunks = manifest["chunks"]
        .as_array()
        .ok_or(RuntimeError::InvalidInput)?;
    if size == 0
        || size > 4194304
        || chunks.len() as u64 != size.div_ceil(65536)
        || records.len() != chunks.len() + 1
    {
        return invalid();
    }
    let prefix = format!("runtime-artifact:{}", &identity_digest[7..]);
    let mut assembled = Vec::with_capacity(size as usize);
    let result = (|| {
        for (index, chunk) in chunks.iter().enumerate() {
            let offset = index as u64 * 65536;
            let size = 65536.min(size - offset);
            let record = &records[index];
            if chunk
                != &json!({"index":index,"offset":offset,"bytes":size,"recordId":format!("{prefix}:chunk:{index}"),"digest":chunk["digest"]})
                || record["recordId"] != chunk["recordId"]
                || record["receiptDigest"] != chunk["digest"]
                || record["sourceFormat"] != "OPENPC_RUNTIME_ARTIFACT_CHUNK_V1"
                || record["evidenceClass"] != "EFFECT"
                || record["occurredAt"] != identity["createdAt"]
            {
                return invalid();
            }
            let mut bytes = base64(text(record, "receiptBase64")?)?;
            if bytes.len() as u64 != size || digest(&bytes) != text(chunk, "digest")? {
                bytes.fill(0);
                return invalid();
            }
            assembled.extend_from_slice(&bytes);
            bytes.fill(0);
        }
        if Digest::of(&assembled) != input.configuration_digest {
            return invalid();
        }
        let record = records.last().ok_or(RuntimeError::InvalidInput)?;
        let bytes = base64(text(record, "receiptBase64")?)?;
        if record["recordId"] != format!("{prefix}:manifest")
            || record["sourceFormat"] != "OPENPC_RUNTIME_ARTIFACT_MANIFEST_V1"
            || record["evidenceClass"] != "EFFECT"
            || record["occurredAt"] != identity["createdAt"]
            || bytes != canonical_bytes(manifest)?
            || digest(&bytes) != text(record, "receiptDigest")?
        {
            return invalid();
        }
        Ok(())
    })();
    assembled.fill(0);
    result
}
