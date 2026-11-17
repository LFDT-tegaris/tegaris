use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{RuntimeError, RuntimeResult};

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> RuntimeResult<Self> {
        let value = value.into();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(RuntimeError::InvalidDigest);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    #[must_use]
    pub fn of(bytes: impl AsRef<[u8]>) -> Self {
        let digest = Sha256::digest(bytes.as_ref());
        Self(hex(&digest))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> RuntimeResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| RuntimeError::CanonicalEncoding)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(TABLE[(byte >> 4) as usize] as char);
        value.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    value
}

pub(crate) fn decode_hex(value: &str) -> RuntimeResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RuntimeError::InvalidAuthorization);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| RuntimeError::InvalidAuthorization)?;
            u8::from_str_radix(text, 16).map_err(|_| RuntimeError::InvalidAuthorization)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_closed_lowercase_hex() {
        assert!(Digest::parse("a".repeat(64)).is_ok());
        assert_eq!(
            Digest::parse("A".repeat(64)).unwrap().as_str(),
            "a".repeat(64)
        );
        assert!(Digest::parse("z".repeat(64)).is_err());
        assert!(Digest::parse("a".repeat(63)).is_err());
    }
}
