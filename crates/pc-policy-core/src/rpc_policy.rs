//! RPC policy meaning shared by compilation, simulation and target evaluation.

use std::collections::BTreeSet;

use pc_runtime_types::{Digest, RequestClass};
use serde::{Deserialize, Serialize};

use crate::pc_cbor_1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RpcEffect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RpcRule {
    pub method: String,
    pub effect: RpcEffect,
    pub required_roles: Vec<String>,
}

/// An immutable authored rule set. Its digest is resolved from admitted policy
/// bytes; a request cannot supply either these rules or their authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RpcSurfacePolicy {
    pub schema_version: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub rules: Vec<RpcRule>,
}

impl RpcSurfacePolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != "1.0.0"
            || self.participant_id.is_empty()
            || self.privacy_domain_id.is_empty()
            || self.rules.is_empty()
            || self.rules.len() > 256
        {
            return Err("RPC policy scope or schema rejected".into());
        }
        let mut methods = BTreeSet::new();
        for rule in &self.rules {
            if (request_class(&rule.method).is_none()
                && rule.method != "pc_getOperationStatus"
                && crate::indexer_policy::IndexerDataClass::for_profile_method(&rule.method)
                    .is_none())
                || !methods.insert(&rule.method)
                || rule.required_roles.len() > 64
                || rule
                    .required_roles
                    .iter()
                    .any(|role| role.is_empty() || role.len() > 160)
                || rule.required_roles.iter().collect::<BTreeSet<_>>().len()
                    != rule.required_roles.len()
                || (rule.effect == RpcEffect::Allow && rule.required_roles.is_empty())
            {
                return Err("RPC rule rejected".into());
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest, String> {
        self.validate()?;
        Ok(Digest::of(pc_cbor_1(self)))
    }

    pub fn resolve(
        policies: &[Self],
        digest: &Digest,
        participant_id: &str,
        privacy_domain_id: &str,
        method: &str,
    ) -> Result<RpcRule, String> {
        let mut referenced = false;
        let mut digests = BTreeSet::new();
        let mut effect = RpcEffect::Allow;
        let mut required_roles = BTreeSet::new();
        for policy in policies {
            let policy_digest = policy.digest()?;
            if !digests.insert(policy_digest.clone())
                || policy.participant_id != participant_id
                || policy.privacy_domain_id != privacy_domain_id
            {
                return Err("RPC policy scope or duplicate rejected".into());
            }
            let rule = policy.rules.iter().find(|rule| rule.method == method);
            if policy_digest == *digest {
                if rule.is_none() {
                    return Err("RPC policy reference or method unresolved".into());
                }
                referenced = true;
            }
            if let Some(rule) = rule {
                if rule.effect == RpcEffect::Deny {
                    effect = RpcEffect::Deny;
                }
                required_roles.extend(rule.required_roles.iter().cloned());
            }
        }
        if !referenced {
            return Err("RPC policy reference or method unresolved".into());
        }
        // The exact dependency remains mandatory, but it cannot exclude other
        // admitted contributions. Permission intersects; denial is terminal.
        Ok(RpcRule {
            method: method.into(),
            effect,
            required_roles: required_roles.into_iter().collect(),
        })
    }

    /// Local operation status has no selector or provider route. Every active
    /// matching RPC rule still participates, with terminal denial precedence.
    pub fn authorize_operation_status(
        policies: &[Self],
        participant: &str,
        privacy: &str,
        roles: &[String],
    ) -> Result<(), pc_runtime_types::RuntimeError> {
        Self::authorize_method(
            policies,
            participant,
            privacy,
            "pc_getOperationStatus",
            roles,
        )
    }

    pub fn authorize_read(
        policies: &[Self],
        participant: &str,
        privacy: &str,
        method: &str,
        roles: &[String],
    ) -> Result<(), pc_runtime_types::RuntimeError> {
        if !matches!(
            method,
            "eth_getTransactionByHash" | "eth_getTransactionReceipt" | "eth_getLogs"
        ) {
            return Err(pc_runtime_types::RuntimeError::Denied);
        }
        Self::authorize_method(policies, participant, privacy, method, roles)
    }

    fn authorize_method(
        policies: &[Self],
        participant: &str,
        privacy: &str,
        method: &str,
        roles: &[String],
    ) -> Result<(), pc_runtime_types::RuntimeError> {
        use pc_runtime_types::RuntimeError;
        let mut matched = false;
        for policy in policies {
            policy
                .validate()
                .map_err(|_| RuntimeError::InvalidAuthorization)?;
            if policy.participant_id != participant || policy.privacy_domain_id != privacy {
                return Err(RuntimeError::InvalidAuthorization);
            }
            if let Some(rule) = policy.rules.iter().find(|r| r.method == method) {
                matched = true;
                if rule.effect == RpcEffect::Deny
                    || !rule.required_roles.iter().all(|role| roles.contains(role))
                {
                    return Err(RuntimeError::Denied);
                }
            }
        }
        if matched {
            Ok(())
        } else {
            Err(RuntimeError::Denied)
        }
    }
}

/// Supported contract invocation methods. Other policy families and
/// RPC methods require their own admitted semantics before becoming usable.
#[must_use]
pub fn request_class(method: &str) -> Option<RequestClass> {
    match method {
        "eth_call" | "eth_getTransactionByHash" | "eth_getTransactionReceipt" | "eth_getLogs" => {
            Some(RequestClass::Read)
        }
        "eth_sendRawTransaction" => Some(RequestClass::Write),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RpcSurfacePolicy {
        RpcSurfacePolicy {
            schema_version: "1.0.0".into(),
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            rules: vec![RpcRule {
                method: "eth_call".into(),
                effect: RpcEffect::Allow,
                required_roles: vec!["reader".into()],
            }],
        }
    }

    #[test]
    fn resolves_exact_scoped_rules_and_separates_call_from_execute() {
        let policy = policy();
        let digest = policy.digest().unwrap();
        let policies = [policy];
        assert!(
            RpcSurfacePolicy::resolve(&policies, &digest, "participant", "privacy", "eth_call")
                .is_ok()
        );
        for (participant, privacy, method) in [
            ("foreign", "privacy", "eth_call"),
            ("participant", "foreign", "eth_call"),
            ("participant", "privacy", "eth_sendRawTransaction"),
        ] {
            assert!(
                RpcSurfacePolicy::resolve(&policies, &digest, participant, privacy, method)
                    .is_err()
            );
        }
        assert!(
            RpcSurfacePolicy::resolve(&[], &digest, "participant", "privacy", "eth_call").is_err()
        );
    }

    #[test]
    fn rejects_duplicate_unknown_and_denied_rules_without_priority_override() {
        let mut denied = policy();
        denied.rules[0].effect = RpcEffect::Deny;
        let digest = denied.digest().unwrap();
        assert_eq!(
            RpcSurfacePolicy::resolve(&[denied], &digest, "participant", "privacy", "eth_call")
                .unwrap()
                .effect,
            RpcEffect::Deny
        );
        let mut duplicate = policy();
        duplicate.rules.push(duplicate.rules[0].clone());
        duplicate.rules[1].effect = RpcEffect::Deny;
        assert!(duplicate.validate().is_err());
        let mut unknown = policy();
        unknown.rules[0].method = "debug_traceTransaction".into();
        assert!(unknown.validate().is_err());
        let mut forged = serde_json::to_value(policy()).unwrap();
        forged["current"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RpcSurfacePolicy>(forged).is_err());
    }

    #[test]
    fn operation_status_requires_its_own_surface_and_terminal_denials_win() {
        let mut status = policy();
        assert!(
            RpcSurfacePolicy::authorize_operation_status(
                &[status.clone()],
                "participant",
                "privacy",
                &["reader".into()]
            )
            .is_err()
        );
        status.rules[0].method = "pc_getOperationStatus".into();
        status.validate().unwrap();
        // Authorable status policy never opens the contract-call simulator.
        assert_eq!(request_class("pc_getOperationStatus"), None);
        assert!(
            RpcSurfacePolicy::authorize_operation_status(
                &[status.clone()],
                "participant",
                "privacy",
                &["reader".into()]
            )
            .is_ok()
        );
        for (participant, privacy, roles) in [
            ("foreign", "privacy", vec!["reader".into()]),
            ("participant", "foreign", vec!["reader".into()]),
            ("participant", "privacy", vec!["submitter".into()]),
        ] {
            assert!(
                RpcSurfacePolicy::authorize_operation_status(
                    &[status.clone()],
                    participant,
                    privacy,
                    &roles
                )
                .is_err()
            );
        }
        let mut deny = status.clone();
        deny.rules[0].effect = RpcEffect::Deny;
        for policies in [vec![status.clone(), deny.clone()], vec![deny, status]] {
            assert!(
                RpcSurfacePolicy::authorize_operation_status(
                    &policies,
                    "participant",
                    "privacy",
                    &["reader".into()]
                )
                .is_err()
            );
        }
    }

    #[test]
    fn referenced_allow_cannot_override_an_applicable_peer_denial() {
        let allow = policy();
        let digest = allow.digest().unwrap();
        let mut deny = allow.clone();
        deny.rules[0].effect = RpcEffect::Deny;
        for policies in [vec![allow.clone(), deny.clone()], vec![deny, allow]] {
            let rule =
                RpcSurfacePolicy::resolve(&policies, &digest, "participant", "privacy", "eth_call")
                    .unwrap();
            assert_eq!(rule.effect, RpcEffect::Deny);
            assert_eq!(rule.required_roles, ["reader"]);
        }
    }

    #[test]
    fn applicable_peer_roles_intersect_deterministically() {
        let allow = policy();
        let digest = allow.digest().unwrap();
        let mut peer = allow.clone();
        peer.rules[0].required_roles = vec!["auditor".into(), "reader".into()];
        for policies in [vec![allow.clone(), peer.clone()], vec![peer, allow]] {
            let rule =
                RpcSurfacePolicy::resolve(&policies, &digest, "participant", "privacy", "eth_call")
                    .unwrap();
            assert_eq!(rule.effect, RpcEffect::Allow);
            assert_eq!(rule.required_roles, ["auditor", "reader"]);
        }
    }

    #[test]
    fn other_method_deny_does_not_deny_call_or_resolve_a_missing_reference() {
        let allow = policy();
        let digest = allow.digest().unwrap();
        let mut peer = allow.clone();
        peer.rules[0].method = "eth_sendRawTransaction".into();
        peer.rules[0].effect = RpcEffect::Deny;
        let peer_digest = peer.digest().unwrap();
        let policies = [allow, peer];
        assert_eq!(
            RpcSurfacePolicy::resolve(&policies, &digest, "participant", "privacy", "eth_call",)
                .unwrap()
                .effect,
            RpcEffect::Allow
        );
        for reference in [peer_digest, Digest::of(b"missing")] {
            assert!(
                RpcSurfacePolicy::resolve(
                    &policies,
                    &reference,
                    "participant",
                    "privacy",
                    "eth_call",
                )
                .is_err()
            );
        }
    }

    #[test]
    fn duplicate_foreign_or_malformed_peer_is_not_ignored_after_a_denial() {
        let allow = policy();
        let digest = allow.digest().unwrap();
        let mut deny = allow.clone();
        deny.rules[0].effect = RpcEffect::Deny;
        let mut foreign = deny.clone();
        foreign.privacy_domain_id = "foreign".into();
        let mut malformed = deny.clone();
        malformed.rules[0].method = "unknown".into();
        for peer in [allow.clone(), foreign, malformed] {
            assert!(
                RpcSurfacePolicy::resolve(
                    &[allow.clone(), deny.clone(), peer],
                    &digest,
                    "participant",
                    "privacy",
                    "eth_call",
                )
                .is_err()
            );
        }
    }
}
