//! Stable cluster identity for one installed runtime source scope. This derives
//! a name only; installation, actual login and current authority remain separate.
use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest as _, Sha256};

use crate::{RuntimeError, RuntimeResult, canonical_bytes};

pub const RUNTIME_SOURCE_SCOPE_PREFIX: &str = "openpc_rs_scope_";

pub fn runtime_source_scope_marker(participant: &str, privacy: &str) -> RuntimeResult<String> {
    for value in [participant, privacy] {
        let parsed = uuid::Uuid::parse_str(value).map_err(|_| RuntimeError::InvalidInput)?;
        if parsed.get_version_num() != 7 || parsed.hyphenated().to_string() != value {
            return Err(RuntimeError::InvalidInput);
        }
    }
    let digest = Sha256::digest(canonical_bytes(&(
        "openpc:runtime-source-scope:v1",
        participant,
        privacy,
    ))?);
    Ok(format!(
        "{RUNTIME_SOURCE_SCOPE_PREFIX}{}",
        Base64UrlUnpadded::encode_string(&digest)
    ))
}

pub fn runtime_source_login(participant: &str, privacy: &str) -> RuntimeResult<String> {
    Ok(runtime_source_scope_marker(participant, privacy)?.replacen(
        RUNTIME_SOURCE_SCOPE_PREFIX,
        "openpc_rs_login_",
        1,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_scope_login_is_byte_stable_and_scope_specific() {
        let participant = "018f0000-0000-7000-8000-000000000101";
        let privacy = "018f0000-0000-7000-8000-000000007201";
        let expected = "openpc_rs_login_MKKiERMDsgOMN-RH8MIkV68t_AtuGWZCx26uBYoE4c8";
        assert_eq!(
            runtime_source_login(participant, privacy).unwrap(),
            expected
        );
        assert_eq!(
            runtime_source_scope_marker(participant, privacy).unwrap(),
            expected.replacen("login", "scope", 1)
        );
        assert_ne!(
            runtime_source_login(privacy, participant).unwrap(),
            expected
        );
        for invalid in [
            "",
            "018f0000-0000-4000-8000-000000007201",
            "018F0000-0000-7000-8000-000000007201",
            "018f0000000070008000000000007201",
        ] {
            assert!(runtime_source_login(participant, invalid).is_err());
            assert!(runtime_source_login(invalid, privacy).is_err());
        }
    }
}
