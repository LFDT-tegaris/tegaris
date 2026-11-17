//! ActivationTokenV1 (schema 21703) for the canonical target boundary.

use crate::{
    RuntimeWireSigner, RuntimeWireVerifier,
    capsule::{digest, field, fields, map, number, read_digest, string, text, uint},
    cose,
};
use pc_policy_core::{pc_cbor_1, runtime_wire::Profile};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeActivationToken {
    pub token_id: String,
    pub target_runtime_id: String,
    pub occurrence_id: String,
    pub desired_generation_digest: Digest,
    pub xds_version_digest: Digest,
    pub expected_previous_generation_digest: Option<Digest>,
    pub issued_at_ns: u64,
    pub expires_at_ns: u64,
}

impl RuntimeActivationToken {
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        let token =
            uuid::Uuid::parse_str(&self.token_id).map_err(|_| RuntimeError::InvalidInput)?;
        if token.get_version_num() != 7
            || token.to_string() != self.token_id
            || self.issued_at_ns >= self.expires_at_ns
        {
            return Err(RuntimeError::InvalidInput);
        }
        let mut fields = vec![
            (0, text(&self.token_id, 160)?),
            (1, text(&self.target_runtime_id, 160)?),
            (2, text(&self.occurrence_id, 160)?),
            (3, digest(&self.desired_generation_digest)?),
            (4, digest(&self.xds_version_digest)?),
            (6, uint(self.issued_at_ns)),
            (7, uint(self.expires_at_ns)),
            (8, ciborium::value::Value::Bool(true)),
        ];
        if let Some(previous) = &self.expected_previous_generation_digest {
            fields.push((5, digest(previous)?));
        }
        Ok(pc_cbor_1(&map(fields)))
    }

    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let value = cose::decode(bytes, 4096)?;
        let fields = fields(&value, &(0..9).collect::<Vec<_>>())?;
        if fields.len() != 8 && fields.len() != 9 {
            return Err(RuntimeError::InvalidInput);
        }
        if field(&fields, 8)?.as_bool() != Some(true) {
            return Err(RuntimeError::InvalidInput);
        }
        let token = Self {
            token_id: string(field(&fields, 0)?)?,
            target_runtime_id: string(field(&fields, 1)?)?,
            occurrence_id: string(field(&fields, 2)?)?,
            desired_generation_digest: read_digest(field(&fields, 3)?)?,
            xds_version_digest: read_digest(field(&fields, 4)?)?,
            expected_previous_generation_digest: fields
                .iter()
                .find(|(key, _)| *key == 5)
                .map(|(_, value)| read_digest(value))
                .transpose()?,
            issued_at_ns: number(field(&fields, 6)?)?,
            expires_at_ns: number(field(&fields, 7)?)?,
        };
        if token.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(token)
    }
}

impl RuntimeWireSigner {
    pub fn sign_activation_token(&self, token: &RuntimeActivationToken) -> RuntimeResult<Vec<u8>> {
        self.sign(Profile::ActivationToken, &token.encode()?)
    }
}

impl RuntimeWireVerifier {
    pub fn verify_activation_token(&self, signed: &[u8]) -> RuntimeResult<RuntimeActivationToken> {
        RuntimeActivationToken::decode(&self.verify(Profile::ActivationToken, signed, 8192)?)
    }
}
