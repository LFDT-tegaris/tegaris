//! Canonical workload context bindings shared by Identity snapshot consumers.
//! These digests identify context; they do not authenticate or authorize it.
use ciborium::value::Value;
use pc_runtime_types::{RuntimeError, RuntimeResult};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest as _, Sha256};

#[derive(Clone)]
pub struct RuntimeIdentityContext {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub target_runtime_id: String,
}

/// A mapping carried by the authenticated, target-bound Identity projection.
/// Parsing alone is not authentication; runtime admission verifies that signed
/// projection before this constructor is used.
pub struct RuntimeTargetProfileBinding {
    profile_id: String,
    participant_id: String,
    privacy_domain_id: String,
}
impl RuntimeTargetProfileBinding {
    pub fn from_projection(
        value: &JsonValue,
        context: &RuntimeIdentityContext,
    ) -> RuntimeResult<Self> {
        use crate::identity_source::{field, keys, object, string};
        let value = object(value)?;
        keys(
            value,
            &[
                "binding_id",
                "participant_id",
                "privacy_domain_id",
                "runtime_target_id",
                "target_profile_id",
                "binding_digest",
            ],
        )?;
        string(value, "binding_id")?;
        let profile_id = string(value, "target_profile_id")?;
        if string(value, "participant_id")? != context.participant_id
            || string(value, "privacy_domain_id")? != context.privacy_domain_id
            || string(value, "runtime_target_id")? != context.target_runtime_id
            || profile_id.len() > 128
            || !profile_id
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !profile_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        {
            return Err(RuntimeError::TargetIdentity);
        }
        let canonical = serde_json::to_vec(&json!({
            "purpose":"openpc.identity.runtime-target-profile-binding.v1",
            "participant_id":context.participant_id,
            "privacy_domain_id":context.privacy_domain_id,
            "runtime_target_id":context.target_runtime_id,
            "target_profile_id":profile_id,
        }))
        .map_err(|_| RuntimeError::InvalidInput)?;
        let digest = format!(
            "sha256:{}",
            Sha256::digest(canonical)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        if field(value, "binding_digest")?.as_str() != Some(digest.as_str()) {
            return Err(RuntimeError::InvalidDigest);
        }
        Ok(Self {
            profile_id: profile_id.into(),
            participant_id: context.participant_id.clone(),
            privacy_domain_id: context.privacy_domain_id.clone(),
        })
    }
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    pub fn matches_context(&self, participant: &str, privacy: &str) -> bool {
        self.participant_id == participant && self.privacy_domain_id == privacy
    }
}

pub fn tuple_digest(values: Vec<Value>) -> [u8; 32] {
    Sha256::digest(crate::pc_cbor_1(&Value::Array(values))).into()
}

pub fn workload_actor_key_digest(participant: &str, principal: &str) -> RuntimeResult<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"pc.identity.actor-key.v2\0");
    for value in [participant, principal] {
        let length = u32::try_from(value.len()).map_err(|_| RuntimeError::InvalidInput)?;
        hash.update(length.to_be_bytes());
        hash.update(value.as_bytes());
    }
    Ok(hash.finalize().into())
}

impl RuntimeIdentityContext {
    pub fn participant_context_digest(&self) -> [u8; 32] {
        tuple_digest(vec![
            Value::Text(self.participant_id.clone()),
            Value::Text(self.privacy_domain_id.clone()),
        ])
    }
    pub fn target_scope_digest(&self) -> [u8; 32] {
        tuple_digest(vec![
            Value::Text(self.participant_id.clone()),
            Value::Text(self.privacy_domain_id.clone()),
            Value::Text(self.target_runtime_id.clone()),
        ])
    }
}

#[cfg(test)]
mod profile_binding_tests {
    use super::*;
    use serde_json::json;

    fn context() -> RuntimeIdentityContext {
        RuntimeIdentityContext {
            participant_id: "018f0000-0000-7000-8000-000000000101".into(),
            privacy_domain_id: "018f0000-0000-7000-8000-000000000201".into(),
            target_runtime_id: "018f0000-0000-7000-8000-000000000902".into(),
        }
    }
    #[test]
    fn native_profile_tuple_matches_the_independent_cross_language_vector() {
        let binding = json!({
            "binding_id":"018f0000-0000-7000-8000-000000000903",
            "participant_id":context().participant_id,
            "privacy_domain_id":context().privacy_domain_id,
            "runtime_target_id":context().target_runtime_id,
            "target_profile_id":"devnet-rpc-v1",
            "binding_digest":"sha256:8aa9f53cde6159c76a028c910ac010aaf2ab278d744f306c674c49ec2373f195",
        });
        assert_eq!(
            RuntimeTargetProfileBinding::from_projection(&binding, &context())
                .unwrap()
                .profile_id(),
            "devnet-rpc-v1"
        );
        for key in [
            "participant_id",
            "privacy_domain_id",
            "runtime_target_id",
            "target_profile_id",
            "binding_digest",
        ] {
            let mut changed = binding.clone();
            changed[key] = json!("foreign");
            assert!(
                RuntimeTargetProfileBinding::from_projection(&changed, &context()).is_err(),
                "{key}"
            );
        }
        let mut alias = binding.clone();
        alias["target_profile_id"] = json!("devnet-rpc-v1 ");
        assert!(RuntimeTargetProfileBinding::from_projection(&alias, &context()).is_err());
        let mut extra = binding.clone();
        extra["authority"] = json!("ALLOW");
        assert!(RuntimeTargetProfileBinding::from_projection(&extra, &context()).is_err());
    }
}
