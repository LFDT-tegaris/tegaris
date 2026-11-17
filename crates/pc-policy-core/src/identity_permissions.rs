//! Exact grant-path intersection shared by signed runtime snapshots and owner-resolved
//! simulations. A selected permission is not authentication or execution authority.
use crate::identity_source::{self as source, Permission, Principal};
use pc_runtime_types::{RuntimeError, RuntimeResult};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

struct GrantPath {
    grants: Vec<Permission>,
    principals: Vec<Principal>,
}

pub struct WorkloadPermissions {
    paths: Vec<GrantPath>,
    envelopes: BTreeMap<String, Permission>,
    revoked: BTreeSet<String>,
}
pub struct SelectedPermissions {
    pub roles: BTreeSet<String>,
    pub groups: BTreeSet<String>,
    pub valid_until_ns: u64,
    /// Exact source rows contributing to this selection. Consumers that read
    /// Control directly must retain their current versions through the effect.
    pub dependencies: BTreeSet<String>,
}
impl WorkloadPermissions {
    pub fn parse(
        raw_envelopes: &[Value],
        raw_paths: &[Value],
        raw_revocations: &[Value],
        principal: &Principal,
        participant_id: &str,
    ) -> RuntimeResult<Self> {
        if raw_envelopes.len() > 4096 || raw_paths.len() > 4096 || raw_revocations.len() > 4096 {
            return Err(RuntimeError::BudgetExhausted);
        }
        let mut envelopes = BTreeMap::new();
        for value in raw_envelopes {
            let envelope = Permission::parse(value)?;
            if envelope.participant != participant_id
                || envelope.parent.is_some()
                || envelope.envelope.is_some()
                || envelopes.insert(envelope.id.clone(), envelope).is_some()
            {
                return Err(RuntimeError::InvalidInput);
            }
        }
        let mut paths = Vec::new();
        let mut referenced_envelopes = BTreeSet::new();
        let mut relevant_ids = BTreeSet::from([principal.id.clone()]);
        for value in raw_paths {
            let values = value
                .as_array()
                .filter(|v| !v.is_empty() && v.len() <= 33)
                .ok_or(RuntimeError::InvalidInput)?;
            let mut grants = Vec::new();
            let mut principals = Vec::new();
            let mut seen = BTreeSet::new();
            for entry in values {
                let entry = source::object(entry)?;
                source::keys(entry, &["grant", "principal"])?;
                let grant = Permission::parse(source::field(entry, "grant")?)?;
                let owner = Principal::parse(source::field(entry, "principal")?)?;
                if owner.id != grant.principal
                    || owner.participant != participant_id
                    || grant.participant != participant_id
                    || !seen.insert(grant.id.clone())
                {
                    return Err(RuntimeError::InvalidInput);
                }
                relevant_ids.insert(grant.id.clone());
                relevant_ids.insert(owner.id.clone());
                grants.push(grant);
                principals.push(owner);
            }
            let first = &grants[0];
            let envelope_id = first.envelope.as_ref().ok_or(RuntimeError::InvalidInput)?;
            if !envelopes.contains_key(envelope_id)
                || first.parent.is_some()
                || grants.last().is_none_or(|g| g.principal != principal.id)
            {
                return Err(RuntimeError::InvalidInput);
            }
            relevant_ids.insert(envelope_id.clone());
            referenced_envelopes.insert(envelope_id.clone());
            for pair in grants.windows(2) {
                if pair[1].parent.as_ref() != Some(&pair[0].id)
                    || pair[1].grantor.as_ref() != Some(&pair[0].principal)
                    || pair[1].envelope.is_some()
                    || pair[1].role.is_some()
                {
                    return Err(RuntimeError::InvalidInput);
                }
            }
            paths.push(GrantPath { grants, principals });
        }
        if referenced_envelopes != envelopes.keys().cloned().collect() {
            return Err(RuntimeError::InvalidInput);
        }
        let mut revoked = BTreeSet::new();
        for value in raw_revocations {
            let value = source::object(value)?;
            source::keys(
                value,
                &[
                    "revocation_id",
                    "participant_id",
                    "target_type",
                    "target_id",
                    "effective_at",
                    "reason_code",
                    "authority_epoch",
                    "receipt_digest",
                    "created_by_principal_id",
                    "effective_now",
                ],
            )?;
            let target = source::string(value, "target_id")?;
            if source::string(value, "participant_id")? != participant_id
                || !relevant_ids.contains(target)
            {
                return Err(RuntimeError::InvalidInput);
            }
            source::unsigned(value, "authority_epoch")?;
            if source::boolean(value, "effective_now")? {
                revoked.insert(target.to_owned());
            }
        }
        Ok(Self {
            paths,
            envelopes,
            revoked,
        })
    }
    pub fn is_revoked(&self, id: &str) -> bool {
        self.revoked.contains(id)
    }
    pub fn select(
        &self,
        principal: &Principal,
        permission: impl Fn(&Permission) -> bool,
    ) -> RuntimeResult<SelectedPermissions> {
        if !principal.active || self.is_revoked(&principal.id) {
            return Err(RuntimeError::Denied);
        }
        let mut roles = BTreeSet::new();
        let mut groups = BTreeSet::new();
        let mut valid_until_ns = u64::MAX;
        let mut dependencies = BTreeSet::from([principal.id.clone()]);
        for path in &self.paths {
            let root = &path.grants[0];
            let Some(role) = &root.role else {
                continue;
            };
            let envelope = self
                .envelopes
                .get(root.envelope.as_ref().ok_or(RuntimeError::InvalidInput)?)
                .ok_or(RuntimeError::InvalidInput)?;
            let permits = |p: &Permission| !self.revoked.contains(&p.id) && permission(p);
            if !permits(envelope)
                || !root.subset_of(envelope)
                || !path.grants.iter().all(permits)
                || path
                    .principals
                    .iter()
                    .any(|p| !p.active || self.revoked.contains(&p.id))
                || path.grants.windows(2).any(|pair| {
                    !pair[1].subset_of(&pair[0])
                        || pair[1].epoch != pair[0].epoch
                        || pair[1].depth >= pair[0].depth
                })
            {
                continue;
            }
            roles.insert(role.clone());
            dependencies.insert(envelope.id.clone());
            dependencies.extend(path.principals.iter().map(|p| p.id.clone()));
            dependencies.extend(path.grants.iter().map(|p| p.id.clone()));
            valid_until_ns = valid_until_ns.min(envelope.valid_until_ns());
            for grant in &path.grants {
                valid_until_ns = valid_until_ns.min(grant.valid_until_ns());
                if let Some(group) = grant.group_for_principal(&principal.id) {
                    groups.insert(group.to_owned());
                }
            }
        }
        if roles.is_empty() {
            return Err(RuntimeError::Denied);
        }
        Ok(SelectedPermissions {
            roles,
            groups,
            valid_until_ns,
            dependencies,
        })
    }
}

#[cfg(test)]
mod native_scope_tests {
    use super::*;
    use crate::invocation_capability::InvocationCapability;

    #[test]
    #[ignore = "requires the retained native permission projection, never a seeded grant"]
    fn retained_typed_runtime_scope_cannot_be_lost_or_resolved_by_a_label() {
        let path = std::env::var("OPENPC_TYPED_RUNTIME_PERMISSION_FIXTURE")
            .expect("native projection fixture required");
        let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let principal = Principal::parse(&fixture["principal"]).unwrap();
        let parse = |envelopes: &[Value]| {
            WorkloadPermissions::parse(
                envelopes,
                fixture["paths"].as_array().unwrap(),
                fixture["revocations"].as_array().unwrap(),
                &principal,
                fixture["participantId"].as_str().unwrap(),
            )
        };
        let denied = |envelopes: &[Value]| {
            let permissions = parse(envelopes).unwrap();
            assert!(matches!(
                permissions.select(&principal, |permission| permission.permits_runtime(
                    fixture["privacyDomainId"].as_str().unwrap(),
                    InvocationCapability::CallResultDisclosure,
                    fixture["resourceId"].as_str().unwrap(),
                    "LOW",
                    fixture["evaluatedAtNs"].as_str().unwrap().parse().unwrap(),
                )),
                Err(RuntimeError::Denied)
            ));
        };
        let original = fixture["envelopes"].as_array().unwrap();
        assert_eq!(original.len(), 1);
        assert_eq!(original[0]["representation"], "TYPED_V1");
        assert_eq!(
            original[0]["runtime_scope"]["target_profile_ids"],
            serde_json::json!(["devnet-rpc-v1"])
        );
        let envelope = Permission::parse(&original[0]).unwrap();
        let grant = Permission::parse(&fixture["paths"][0][0]["grant"]).unwrap();
        let evaluated_at_ns = fixture["evaluatedAtNs"].as_str().unwrap().parse().unwrap();
        assert!(principal.active && envelope.active && grant.active);
        assert!(envelope.start <= evaluated_at_ns && evaluated_at_ns < envelope.end);
        assert!(grant.role.is_some() && grant.subset_of(&envelope));
        assert!(grant.permits_runtime(
            fixture["privacyDomainId"].as_str().unwrap(),
            InvocationCapability::CallResultDisclosure,
            fixture["resourceId"].as_str().unwrap(),
            "LOW",
            evaluated_at_ns,
        ));
        denied(original);
        let mut omitted = original.clone();
        omitted[0].as_object_mut().unwrap().remove("runtime_scope");
        assert!(parse(&omitted).is_err());
        for target in ["foreign-profile", "018f0000-0000-7000-8000-000000000902"] {
            let mut substituted = original.clone();
            substituted[0]["runtime_scope"]["target_profile_ids"] = serde_json::json!([target]);
            denied(&substituted);
        }
    }
}
