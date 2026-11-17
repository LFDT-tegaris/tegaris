//! Pure verification shared by the durable inbox owner and its preflight corpus.
use super::*;

pub(super) struct Inputs<'a> {
    pub public: &'a [u8],
    pub payload: &'a [u8],
    pub cose: &'a [u8],
    pub trust: &'a [u8],
    pub before: &'a [u8],
    pub after: &'a [u8],
    pub authority: &'a [u8],
    pub event: &'a [u8],
}

fn exact_map(value: &Value, keys: &[u64]) -> Result<()> {
    if !value.as_map().is_some_and(|map| map.len() == keys.len())
        || keys.iter().any(|key| field(value, *key).is_err())
    {
        return Err(failure());
    }
    Ok(())
}

fn state(receipt: &Value, key: u64, encoded: &[u8], version: u64) -> Result<Value> {
    let reference = field(receipt, key)?;
    exact_map(reference, &[0, 1, 2])?;
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
        || Sha256::digest(encoded).as_slice() != bytes(field(reference, 2)?)?
    {
        return Err(failure());
    }
    let projection = &parts[8];
    match integer(&parts[6])? {
        0 => {
            if integer(&parts[7])? != 0 {
                return Err(failure());
            }
            exact_map(projection, &[])?;
        }
        1 => {
            if integer(&parts[7])? == 0 {
                return Err(failure());
            }
            if !["CLIENT_INDEXER", "EXTERNAL_ENGINE_ADAPTER"]
                .contains(&text(field(projection, 0)?)?)
                || bytes(field(projection, 2)?)?.len() != 32
                || ![
                    "REGISTERED",
                    "SHADOW",
                    "QUALIFIED",
                    "ACTIVE",
                    "QUARANTINED",
                    "RETIRED",
                ]
                .contains(&text(field(projection, 3)?)?)
            {
                return Err(failure());
            }
            let engine_version = text(field(projection, 1)?)?;
            if engine_version.is_empty()
                || engine_version.len() > 64
                || !engine_version.as_bytes()[0].is_ascii_alphanumeric()
                || !engine_version
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            {
                return Err(failure());
            }
            match version {
                1 => {
                    exact_map(projection, &[0, 1, 2, 3, 4])?;
                    if bytes(field(projection, 4)?)?.len() != 32 {
                        return Err(failure());
                    }
                }
                2 => match integer(field(projection, 4)?)? {
                    0 => exact_map(projection, &[0, 1, 2, 3, 4])?,
                    1 => {
                        exact_map(projection, &[0, 1, 2, 3, 4, 5])?;
                        if bytes(field(projection, 5)?)?.len() != 32 {
                            return Err(failure());
                        }
                    }
                    _ => return Err(failure()),
                },
                _ => return Err(failure()),
            }
        }
        _ => return Err(failure()),
    }
    Ok(decoded)
}

pub(super) fn verify(input: &Inputs<'_>) -> Result<Value> {
    let receipt = decode(input.payload)?;
    exact_map(&receipt, &(0..27).collect::<Vec<_>>())?;
    verify_receipt_cose(input.public, input.payload, input.cose)?;
    let (version, action, operation) = indexer_profile(&receipt)?;
    if hex(bytes(field(&receipt, 1)?)?) != DEFINITION
        || text(field(&receipt, 11)?)? != "indexer-profile"
        || Sha256::digest(input.authority).as_slice() != bytes(field(&receipt, 14)?)?
        || Sha256::digest(input.trust).as_slice() != bytes(field(&receipt, 25)?)?
    {
        return Err(failure());
    }
    let authority: serde_json::Value =
        serde_json::from_slice(input.authority).map_err(|_| failure())?;
    if authority["decision"] != "ALLOW"
        || uuid(authority["operationId"].as_str().ok_or_else(failure)?)?
            != bytes(field(&receipt, 8)?)?
    {
        return Err(failure());
    }
    let evidence = field(&receipt, 20)?
        .as_array()
        .filter(|v| v.len() == 1)
        .ok_or_else(failure)?;
    exact_map(&evidence[0], &[0, 1, 2])?;
    if integer(field(&evidence[0], 0)?)? != 2
        || text(field(&evidence[0], 1)?)?.is_empty()
        || bytes(field(&evidence[0], 2)?)?.len() != 32
    {
        return Err(failure());
    }
    let trust = decode(input.trust)?;
    let parts = trust
        .as_array()
        .filter(|v| v.len() == 21)
        .ok_or_else(failure)?;
    if text(&parts[0])? != "pc.control.business-signing-trust.v1"
        || parts[1] != *field(&receipt, 6)?
        || parts[2] != *field(&receipt, 7)?
        || parts[3] != *field(&receipt, 5)?
        || parts[4] != *field(&receipt, 24)?
        || bytes(&parts[5])? != input.public
        || text(&parts[4])? != format!("sha256:{}", hex(&Sha256::digest(input.public)))
        || text(&parts[14])? != "SECRET-SIGNING-KEY"
        || integer(&parts[17])? != 24001
        || integer(&parts[18])? != 1
        || integer(&parts[19])? != 338
    {
        return Err(failure());
    }
    let grants = parts[20].as_array().ok_or_else(failure)?;
    let matches = grants
        .iter()
        .filter(|g| {
            g.as_array().is_some_and(|v| {
                v.len() == 5
                    && v[0] == *field(&receipt, 2).unwrap_or(&Value::Null)
                    && integer(&v[1]) == Ok(version)
                    && v[2] == *field(&receipt, 4).unwrap_or(&Value::Null)
                    && text(&v[3]) == Ok(action)
                    && text(&v[4]) == Ok(operation)
            })
        })
        .count();
    if matches != 1 {
        return Err(failure());
    }
    let before = state(&receipt, 18, input.before, version)?;
    let after = state(&receipt, 19, input.after, version)?;
    let before = before.as_array().ok_or_else(failure)?;
    let after = after.as_array().ok_or_else(failure)?;
    if integer(&after[6])? != 1 || integer(&before[7])?.checked_add(1) != Some(integer(&after[7])?)
    {
        return Err(failure());
    }
    if action == "ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1" {
        if integer(&before[6])? != 0 || text(field(&after[8], 3)?)? != "REGISTERED" {
            return Err(failure());
        }
    } else if integer(&before[6])? != 1
        || before[8] == after[8]
        || [0, 1, 3]
            .iter()
            .any(|key| field(&before[8], *key) != field(&after[8], *key))
    {
        return Err(failure());
    }
    let events = field(&receipt, 21)?
        .as_array()
        .filter(|v| v.len() == 1)
        .ok_or_else(failure)?;
    exact_map(&events[0], &[0, 1, 2, 3, 4, 5, 6, 7, 9])?;
    let event = decode(input.event)?;
    exact_map(&event, &[0, 1, 2, 3])?;
    if field(&event, 0)? != field(&receipt, 8)?
        || field(&event, 1)? != field(&events[0], 4)?
        || field(&event, 2)? != field(&receipt, 9)?
        || field(&event, 3)? != field(&receipt, 15)?
        || Sha256::digest(input.event).as_slice() != bytes(field(&events[0], 9)?)?
    {
        return Err(failure());
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests;
