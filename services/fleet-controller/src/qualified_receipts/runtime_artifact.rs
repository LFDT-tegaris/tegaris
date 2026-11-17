//! The physical runtime-input receipt is a separate closed admission profile.
//! Verified historical bytes establish an original result, never current use.
use super::*;
use serde_json::Value as Json;

const PROFILE: &str = "pc.control.evidence-deletion.runtime-artifact";
const PROFILE_DIGEST: &str = "d1f1c8ccfbd049063197e8511e1b0604888963b29cc40fec7ca8e72f539d85c5";
const ACTION: &str = "ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1";
const OPERATION: &str = "CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH";

pub(crate) struct Inputs<'a> {
    pub public: &'a [u8],
    pub payload: &'a [u8],
    pub cose: &'a [u8],
    pub trust: &'a [u8],
    pub before: &'a [u8],
    pub after: &'a [u8],
    pub authority: &'a [u8],
    pub event: &'a [u8],
    pub participant: &'a str,
    pub privacy: &'a str,
    pub receipt_id: &'a str,
    pub operation_id: &'a str,
    pub event_id: &'a str,
    pub event_recorded_ns: u64,
    pub metadata: &'a Json,
    pub selection: &'a Json,
}

fn exact(value: &Value, keys: &[u64]) -> Result<()> {
    if !value.as_map().is_some_and(|m| m.len() == keys.len())
        || keys.iter().any(|key| field(value, *key).is_err())
    {
        return Err(failure());
    }
    Ok(())
}
fn json_text<'a>(value: &'a Json, key: &str) -> Result<&'a str> {
    value.get(key).and_then(Json::as_str).ok_or_else(failure)
}
fn json_digest(value: &Json) -> Result<Vec<u8>> {
    Ok(Sha256::digest(serde_json::to_vec(value).map_err(|_| failure())?).to_vec())
}
fn prefixed_digest(value: &str) -> Result<Vec<u8>> {
    let hex = value.strip_prefix("sha256:").ok_or_else(failure)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(failure());
    }
    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| failure()))
        .collect()
}
fn uuid7(value: &Value) -> Result<()> {
    let value = bytes(value)?;
    if value.len() != 16 || value[6] >> 4 != 7 || value[8] & 0xc0 != 0x80 {
        return Err(failure());
    }
    Ok(())
}
fn state(receipt: &Value, key: u64, encoded: &[u8], existence: u64) -> Result<Value> {
    let reference = field(receipt, key)?;
    exact(reference, &[0, 1, 2])?;
    let decoded = decode(encoded)?;
    let parts = decoded
        .as_array()
        .filter(|v| v.len() == 9)
        .ok_or_else(failure)?;
    if text(&parts[0])? != "pc.control.transition-state.v1"
        || parts[1] != *field(receipt, 4)?
        || parts[2] != *field(receipt, 6)?
        || parts[3] != *field(receipt, 7)?
        || parts[4] != *field(receipt, 11)?
        || parts[5] != *field(receipt, 12)?
        || parts[6] != *field(reference, 0)?
        || parts[7] != *field(reference, 1)?
        || integer(&parts[6])? != existence
        || integer(&parts[7])? != existence
        || Sha256::digest(encoded).as_slice() != bytes(field(reference, 2)?)?
    {
        return Err(failure());
    }
    exact(
        &parts[8],
        if existence == 0 {
            &[]
        } else {
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        },
    )?;
    Ok(parts[8].clone())
}

pub(crate) fn verify(input: &Inputs<'_>) -> Result<()> {
    let receipt = decode(input.payload)?;
    exact(&receipt, &(0..27).collect::<Vec<_>>())?;
    verify_receipt_cose(input.public, input.payload, input.cose)?;
    for key in [0, 6, 7, 8, 12, 17] {
        uuid7(field(&receipt, key)?)?;
    }
    for key in [1, 4, 13, 14, 15, 16, 25, 26] {
        if bytes(field(&receipt, key)?)?.len() != 32 {
            return Err(failure());
        }
    }
    if text(field(&receipt, 5)?)?.is_empty() || integer(field(&receipt, 23)?)? % 1000 != 0 {
        return Err(failure());
    }
    let job = json_text(input.metadata, "deletionJobId")?;
    let source = &input.metadata["source"];
    let count = source["configurationBytes"]
        .as_u64()
        .filter(|v| (1..=4_194_304).contains(v))
        .ok_or_else(failure)?;
    let retirement = json_digest(
        &serde_json::json!({"domain":"pc.evidence.runtime-artifact-retirement.v1","deletionJobId":job,"source":source}),
    )?;
    if retirement != prefixed_digest(json_text(input.metadata, "retirementDigest")?)?
        || input.selection["source"] != *source
        || source["participantId"] != input.participant
        || source["privacyDomainId"] != input.privacy
        || hex(bytes(field(&receipt, 1)?)?) != DEFINITION
        || text(field(&receipt, 2)?)? != PROFILE
        || integer(field(&receipt, 3)?)? != 1
        || hex(bytes(field(&receipt, 4)?)?) != PROFILE_DIGEST
        || bytes(field(&receipt, 0)?)? != uuid(input.receipt_id)?
        || bytes(field(&receipt, 6)?)? != uuid(input.participant)?
        || bytes(field(&receipt, 7)?)? != uuid(input.privacy)?
        || bytes(field(&receipt, 8)?)? != uuid(input.operation_id)?
        || text(field(&receipt, 9)?)? != ACTION
        || text(field(&receipt, 10)?)? != OPERATION
        || text(field(&receipt, 11)?)? != "evidence-deletion"
        || bytes(field(&receipt, 12)?)? != uuid(job)?
        || integer(field(&receipt, 22)?)? != 1
        || Sha256::digest(input.authority).as_slice() != bytes(field(&receipt, 14)?)?
        || Sha256::digest(input.trust).as_slice() != bytes(field(&receipt, 25)?)?
    {
        return Err(failure());
    }
    let authority: Json = serde_json::from_slice(input.authority).map_err(|_| failure())?;
    if authority["decision"] != "ALLOW" || authority["operationId"] != input.operation_id {
        return Err(failure());
    }
    let references = field(&receipt, 20)?
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or_else(failure)?;
    let mut kinds = Vec::new();
    for reference in references {
        exact(reference, &[0, 1, 2])?;
        kinds.push(integer(field(reference, 0)?)?);
        if text(field(reference, 1)?)?.is_empty() || bytes(field(reference, 2)?)?.len() != 32 {
            return Err(failure());
        }
    }
    if kinds != [3, 4] {
        return Err(failure());
    }
    let trust = decode(input.trust)?;
    let parts = trust
        .as_array()
        .filter(|v| v.len() == 21)
        .ok_or_else(failure)?;
    let recorded = integer(field(&receipt, 23)?)?;
    if text(&parts[0])? != "pc.control.business-signing-trust.v1"
        || parts[1] != *field(&receipt, 6)?
        || parts[2] != *field(&receipt, 7)?
        || parts[3] != *field(&receipt, 5)?
        || parts[4] != *field(&receipt, 24)?
        || bytes(&parts[5])? != input.public
        || text(&parts[4])? != format!("sha256:{}", hex(&Sha256::digest(input.public)))
        || integer(&parts[8])? == 0
        || recorded < integer(&parts[9])?
        || recorded >= integer(&parts[10])?
        || !["BOOTSTRAP", "GOVERNED"].contains(&text(&parts[11])?)
        || text(&parts[12])?.is_empty()
        || bytes(&parts[13])?.len() != 32
        || text(&parts[14])? != "SECRET-SIGNING-KEY"
        || integer(&parts[17])? != 24001
        || integer(&parts[18])? != 1
        || integer(&parts[19])? != 338
    {
        return Err(failure());
    }
    uuid7(&parts[6])?;
    integer(&parts[7])?;
    if integer(&parts[9])? % 1000 != 0
        || integer(&parts[10])? % 1000 != 0
        || text(&parts[15])?.is_empty()
        || text(&parts[16])?.is_empty()
    {
        return Err(failure());
    }
    let grants = parts[20].as_array().ok_or_else(failure)?;
    if grants
        .iter()
        .filter(|g| {
            g.as_array().is_some_and(|v| {
                v.len() == 5
                    && text(&v[0]) == Ok(PROFILE)
                    && integer(&v[1]) == Ok(1)
                    && bytes(&v[2]).is_ok_and(|v| hex(v) == PROFILE_DIGEST)
                    && text(&v[3]) == Ok(ACTION)
                    && text(&v[4]) == Ok(OPERATION)
            })
        })
        .count()
        != 1
    {
        return Err(failure());
    }
    state(&receipt, 18, input.before, 0)?;
    let after = state(&receipt, 19, input.after, 1)?;
    for key in [0, 5, 6, 7] {
        uuid7(field(&after, key)?)?;
    }
    let selector = json_digest(
        &serde_json::json!({"domain":"pc.evidence.runtime-artifact-selector.v1","source":source}),
    )?;
    let before = json_digest(
        &serde_json::json!({"domain":"pc.evidence.runtime-artifact-before.v1","source":source}),
    )?;
    let after_digest = json_digest(
        &serde_json::json!({"domain":"pc.evidence.runtime-artifact-after.v1","retirementDigest":input.metadata["retirementDigest"]}),
    )?;
    if bytes(field(&after, 0)?)?
        != uuid(
            json_text(input.selection, "retentionPolicyId")?
                .strip_prefix("urn:openpc:resource:")
                .ok_or_else(failure)?,
        )?
        || bytes(field(&after, 1)?)? != selector
        || bytes(field(&after, 2)?)? != json_digest(input.selection)?
        || bytes(field(&after, 3)?)? != before
        || bytes(field(&after, 4)?)? != after_digest
        || bytes(field(&after, 5)?)?.len() != 16
        || bytes(field(&after, 6)?)? != uuid(input.operation_id)?
        || bytes(field(&after, 7)?)?.len() != 16
        || integer(field(&after, 8)?)? != 1
        || integer(field(&after, 9)?)? != count
        || integer(field(&after, 10)?)? != 0
        || integer(field(&after, 11)?)? == 0
        || integer(field(&after, 12)?)? < integer(field(&after, 11)?)?
        || integer(field(&after, 12)?)? > recorded
        || integer(field(&after, 13)?)? != count
        || integer(field(&after, 14)?)? != 0
    {
        return Err(failure());
    }
    let events = field(&receipt, 21)?
        .as_array()
        .filter(|v| v.len() == 1)
        .ok_or_else(failure)?;
    let event = &events[0];
    exact(event, &[0, 1, 2, 3, 4, 5, 6, 7, 9])?;
    let payload = decode(input.event)?;
    exact(&payload, &[0, 1, 2, 3])?;
    if bytes(field(event, 0)?)? != uuid(input.event_id)?
        || text(field(event, 1)?)? != "io.openpc.control.command.committed.v1"
        || text(field(event, 2)?)?
            != "https://schemas.openpc.local/event-payloads.schema.json#/$defs/CommandCommitted"
        || text(field(event, 3)?)? != "urn:openpc:service:control-api"
        || text(field(event, 4)?)? != format!("urn:openpc:evidence-deletion:{job}")
        || integer(field(event, 5)?)? != 1
        || integer(field(event, 6)?)? != recorded
        || recorded != input.event_recorded_ns
        || bytes(field(event, 7)?)? != uuid(input.operation_id)?
        || Sha256::digest(input.event).as_slice() != bytes(field(event, 9)?)?
        || field(&payload, 0)? != field(&receipt, 8)?
        || field(&payload, 1)? != field(event, 4)?
        || field(&payload, 2)? != field(&receipt, 9)?
        || field(&payload, 3)? != field(&receipt, 15)?
    {
        return Err(failure());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn consume(value: &Json) -> Result<()> {
        let data = |key: &str| -> Result<Vec<u8>> {
            serde_json::from_value(value[key].clone()).map_err(|_| failure())
        };
        verify(&Inputs {
            public: &data("public")?,
            payload: &data("payload")?,
            cose: &data("cose")?,
            trust: &data("trust")?,
            before: &data("before")?,
            after: &data("after")?,
            authority: &data("authority")?,
            event: &data("event")?,
            participant: json_text(value, "participant")?,
            privacy: json_text(value, "privacy")?,
            receipt_id: json_text(value, "receipt_id")?,
            operation_id: json_text(value, "operation_id")?,
            event_id: json_text(value, "event_id")?,
            event_recorded_ns: json_text(value, "event_recorded_ns")?
                .parse()
                .map_err(|_| failure())?,
            metadata: &value["metadata"],
            selection: &value["selection"],
        })
    }

    #[test]
    fn physical_retirement_consumes_real_typescript_profile_cose_trust_state_and_event() {
        let result = Command::new("timeout")
            .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .args([
                "--kill-after=2s",
                "30s",
                "node",
                "--import",
                "tsx",
                "tests/integration/control-api/runtime-artifact-retirement-wire.ts",
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "physical wire producer: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let cases: Json = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(cases.as_array().unwrap().len(), 2);
        for case in cases.as_array().unwrap() {
            consume(&case["base"]).expect("exact canonical physical retirement profile");
            let malformed = case["malformed"].as_array().unwrap();
            assert!(malformed.len() >= 50);
            for mutation in malformed {
                assert!(
                    consume(&mutation["value"]).is_err(),
                    "accepted mutation {}",
                    mutation["name"]
                );
            }
        }
    }
}
