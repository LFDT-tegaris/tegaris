//! Identity-owned permission records shared by runtime admission and advisory
//! policy simulation. Callers must resolve and authenticate their source: these
//! parsers and predicates alone never establish an authenticated workload.
use crate::identity_context::RuntimeTargetProfileBinding;
use crate::invocation_capability::InvocationCapability;
use pc_runtime_types::{RuntimeError, RuntimeResult};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub type Object = Map<String, Value>;
pub fn object(value: &Value) -> RuntimeResult<&Object> {
    value.as_object().ok_or(RuntimeError::InvalidInput)
}

pub fn field<'a>(value: &'a Object, key: &str) -> RuntimeResult<&'a Value> {
    value.get(key).ok_or(RuntimeError::InvalidInput)
}
pub fn string<'a>(value: &'a Object, key: &str) -> RuntimeResult<&'a str> {
    field(value, key)?
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 1024)
        .ok_or(RuntimeError::InvalidInput)
}
pub fn keys(value: &Object, expected: &[&str]) -> RuntimeResult<()> {
    if value.len() != expected.len() || value.keys().any(|key| !expected.contains(&key.as_str())) {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(())
}
pub fn boolean(value: &Object, key: &str) -> RuntimeResult<bool> {
    field(value, key)?
        .as_bool()
        .ok_or(RuntimeError::InvalidInput)
}
pub fn unsigned(value: &Object, key: &str) -> RuntimeResult<u64> {
    let text = string(value, key)?;
    let number = text
        .parse::<u64>()
        .map_err(|_| RuntimeError::InvalidInput)?;
    if number.to_string() != text {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(number)
}
fn optional_string<'a>(value: &'a Object, key: &str) -> RuntimeResult<Option<&'a str>> {
    if field(value, key)?.is_null() {
        Ok(None)
    } else {
        string(value, key).map(Some)
    }
}
fn strings(value: &Object, key: &str) -> RuntimeResult<BTreeSet<String>> {
    let values = field(value, key)?
        .as_array()
        .filter(|v| (key == "action_intent_ids" || !v.is_empty()) && v.len() <= 4096)
        .ok_or(RuntimeError::InvalidInput)?;
    let mut output = BTreeSet::new();
    for value in values {
        let text = value
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 1024)
            .ok_or(RuntimeError::InvalidInput)?;
        if !output.insert(text.into()) {
            return Err(RuntimeError::InvalidInput);
        }
    }
    Ok(output)
}
fn capabilities(value: &Object) -> RuntimeResult<BTreeSet<InvocationCapability>> {
    // Older immutable snapshots omit this field and convey no invocation grant.
    let Some(raw) = value.get("runtime_capability_ids") else {
        return Ok(BTreeSet::new());
    };
    let values = raw
        .as_array()
        .filter(|v| v.len() <= 7)
        .ok_or(RuntimeError::InvalidInput)?;
    let mut result = BTreeSet::new();
    for value in values {
        let capability = value
            .as_str()
            .and_then(InvocationCapability::from_registry_id)
            .ok_or(RuntimeError::InvalidInput)?;
        if !result.insert(capability) {
            return Err(RuntimeError::InvalidInput);
        }
    }
    Ok(result)
}
pub fn canonical_json(bytes: &[u8]) -> RuntimeResult<Value> {
    if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
        return Err(RuntimeError::InvalidInput);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidInput)?;
    // The publisher sorts object keys. Round-trip equality also rejects duplicate
    // keys, alternate number spellings, and trailing/unaccounted material.
    if serde_json::to_vec(&value).map_err(|_| RuntimeError::InvalidInput)? != bytes {
        return Err(RuntimeError::CanonicalEncoding);
    }
    fn budget(value: &Value, depth: usize, remaining: &mut usize) -> bool {
        if depth == 0 {
            return false;
        }
        let children: Vec<_> = match value {
            Value::Array(values) => values.iter().collect(),
            Value::Object(values) => values.values().collect(),
            Value::String(value) => return value.len() <= 65_536,
            Value::Number(value) => return value.is_i64() || value.is_u64(),
            _ => return true,
        };
        if children.len() > 4096 || children.len() > *remaining {
            return false;
        }
        *remaining -= children.len();
        children
            .into_iter()
            .all(|v| budget(v, depth - 1, remaining))
    }
    if !budget(&value, 16, &mut 65_536) {
        return Err(RuntimeError::BudgetExhausted);
    }
    Ok(value)
}

#[derive(Clone)]
pub struct Principal {
    pub id: String,
    pub participant: String,
    pub kind: String,
    pub active: bool,
}
impl Principal {
    pub fn parse(value: &Value) -> RuntimeResult<Self> {
        let value = object(value)?;
        keys(
            value,
            &[
                "principal_id",
                "participant_id",
                "kind",
                "state",
                "authority_epoch",
                "row_version",
            ],
        )?;
        unsigned(value, "authority_epoch")?;
        if unsigned(value, "row_version")? == 0 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self {
            id: string(value, "principal_id")?.into(),
            participant: string(value, "participant_id")?.into(),
            kind: string(value, "kind")?.into(),
            active: string(value, "state")? == "ACTIVE",
        })
    }
}

#[derive(Clone)]
pub struct Permission {
    pub id: String,
    pub participant: String,
    pub principal: String,
    pub parent: Option<String>,
    pub grantor: Option<String>,
    pub envelope: Option<String>,
    pub role: Option<String>,
    pub epoch: u64,
    pub depth: u64,
    pub active: bool,
    pub start: u64,
    pub end: u64,
    group_fresh_until: u64,
    group_id: Option<String>,
    privacy: BTreeSet<String>,
    actions: BTreeSet<String>,
    capabilities: BTreeSet<InvocationCapability>,
    runtime_scope: Option<RuntimeScope>,
    resources: BTreeSet<String>,
    risks: BTreeSet<String>,
    approval: bool,
    step_up: bool,
}
#[derive(Clone)]
struct RuntimeScope {
    target_profiles: BTreeSet<String>,
    data_classes: BTreeSet<String>,
}
impl Permission {
    pub fn parse(value: &Value) -> RuntimeResult<Self> {
        let value = object(value)?;
        let mut expected = vec![
            "participant_id",
            "delegation_epoch",
            "privacy_domain_ids",
            "action_intent_ids",
            "resource_ids",
            "risk_classes",
            "maker_checker_required",
            "step_up_required",
            "onward_delegation_depth",
            "state",
            "row_version",
            "valid_from_ns",
            "valid_until_ns",
            "valid_now",
        ];
        let (id, principal, parent, grantor, envelope, role) =
            if value.contains_key("assignment_id") {
                expected.extend([
                    "assignment_id",
                    "principal_id",
                    "role_id",
                    "authority_group_id",
                    "authority_envelope_id",
                    "scope_digest",
                    "valid_during",
                    "created_by_principal_id",
                ]);
                if value.contains_key("group_scope") {
                    expected.push("group_scope");
                }
                (
                    string(value, "assignment_id")?,
                    string(value, "principal_id")?,
                    None,
                    None,
                    Some(string(value, "authority_envelope_id")?),
                    optional_string(value, "role_id")?,
                )
            } else if value.contains_key("delegation_id") {
                expected.extend([
                    "delegation_id",
                    "parent_assignment_id",
                    "parent_delegation_id",
                    "grantor_principal_id",
                    "delegate_principal_id",
                    "scope_digest",
                    "valid_during",
                ]);
                let assignment = optional_string(value, "parent_assignment_id")?;
                let delegation = optional_string(value, "parent_delegation_id")?;
                if assignment.is_some() == delegation.is_some() {
                    return Err(RuntimeError::InvalidInput);
                }
                (
                    string(value, "delegation_id")?,
                    string(value, "delegate_principal_id")?,
                    assignment.or(delegation),
                    Some(string(value, "grantor_principal_id")?),
                    None,
                    None,
                )
            } else {
                expected.extend([
                    "authority_envelope_id",
                    "principal_id",
                    "maker_principal_id",
                    "checker_principal_id",
                    "authority_epoch",
                    "valid_from",
                    "valid_until",
                    "semantic_digest",
                ]);
                unsigned(value, "authority_epoch")?;
                let maker = string(value, "maker_principal_id")?;
                if optional_string(value, "checker_principal_id")? == Some(maker) {
                    return Err(RuntimeError::InvalidAuthorization);
                }
                let principal = if value.contains_key("representation") {
                    expected.extend([
                        "representation",
                        "issuer_participant_id",
                        "issuer_privacy_domain_id",
                    ]);
                    match string(value, "representation")? {
                        "TYPED_V1" => {
                            if !field(value, "principal_id")?.is_null()
                                || string(value, "issuer_participant_id")?
                                    != string(value, "participant_id")?
                                || !strings(value, "privacy_domain_ids")?
                                    .contains(string(value, "issuer_privacy_domain_id")?)
                            {
                                return Err(RuntimeError::InvalidAuthorization);
                            }
                            ""
                        }
                        "LEGACY" => {
                            if !field(value, "issuer_participant_id")?.is_null()
                                || !field(value, "issuer_privacy_domain_id")?.is_null()
                            {
                                return Err(RuntimeError::InvalidAuthorization);
                            }
                            string(value, "principal_id")?
                        }
                        _ => return Err(RuntimeError::InvalidInput),
                    }
                } else {
                    string(value, "principal_id")?
                };
                (
                    string(value, "authority_envelope_id")?,
                    principal,
                    None,
                    None,
                    None,
                    None,
                )
            };
        if value.contains_key("runtime_capability_ids") {
            expected.push("runtime_capability_ids");
        }
        let capabilities = capabilities(value)?;
        let unresolved_runtime_scope = value.get("representation")
            == Some(&Value::from("TYPED_V1"))
            && !capabilities.is_empty();
        let runtime_scope = if unresolved_runtime_scope {
            expected.push("runtime_scope");
            let scope = object(field(value, "runtime_scope")?)?;
            keys(scope, &["data_classes", "target_profile_ids"])?;
            let dimension = |key| {
                let dimensions = field(scope, key)?
                    .as_array()
                    .filter(|v| v.len() <= 4096)
                    .ok_or(RuntimeError::InvalidInput)?;
                let mut seen = BTreeSet::new();
                for dimension in dimensions {
                    let dimension = dimension
                        .as_str()
                        .filter(|v| !v.is_empty() && v.len() <= 1024)
                        .ok_or(RuntimeError::InvalidInput)?;
                    if !seen.insert(dimension.to_owned()) {
                        return Err(RuntimeError::InvalidInput);
                    }
                }
                Ok(seen)
            };
            Some(RuntimeScope {
                target_profiles: dimension("target_profile_ids")?,
                data_classes: dimension("data_classes")?,
            })
        } else {
            None
        };
        keys(value, &expected)?;
        if unsigned(value, "row_version")? == 0 {
            return Err(RuntimeError::InvalidInput);
        }
        let start = unsigned(value, "valid_from_ns")?;
        let end = if field(value, "valid_until_ns")?.is_null() {
            u64::MAX
        } else {
            unsigned(value, "valid_until_ns")?
        };
        let depth = field(value, "onward_delegation_depth")?
            .as_u64()
            .filter(|v| *v <= 32)
            .ok_or(RuntimeError::InvalidInput)?;
        if start >= end {
            return Err(RuntimeError::InvalidInput);
        }
        let (group_active, group_fresh_until) = if value.contains_key("assignment_id") {
            assignment_group(value, start, end)?
        } else {
            (true, u64::MAX)
        };
        Ok(Self {
            id: id.into(),
            principal: principal.into(),
            participant: string(value, "participant_id")?.into(),
            parent: parent.map(str::to_owned),
            grantor: grantor.map(str::to_owned),
            envelope: envelope.map(str::to_owned),
            role: role.map(str::to_owned),
            epoch: unsigned(value, "delegation_epoch")?,
            depth,
            active: group_active
                && string(value, "state")? == "ACTIVE"
                && boolean(value, "valid_now")?,
            start,
            end,
            group_fresh_until,
            group_id: if value.contains_key("assignment_id") {
                optional_string(value, "authority_group_id")?.map(str::to_owned)
            } else {
                None
            },
            privacy: strings(value, "privacy_domain_ids")?,
            actions: strings(value, "action_intent_ids")?,
            capabilities,
            runtime_scope,
            resources: strings(value, "resource_ids")?,
            risks: strings(value, "risk_classes")?,
            approval: boolean(value, "maker_checker_required")?,
            step_up: boolean(value, "step_up_required")?,
        })
    }
    pub fn permits(
        &self,
        privacy: &str,
        action: &str,
        resource: &str,
        risk: &str,
        now: u64,
    ) -> bool {
        self.actions.contains(action) && self.permits_context(privacy, resource, risk, now)
    }
    pub fn valid_until_ns(&self) -> u64 {
        self.end.min(self.group_fresh_until)
    }

    /// A delegator's membership does not make the current actor a group member.
    pub fn group_for_principal(&self, principal: &str) -> Option<&str> {
        if self.active && self.principal == principal {
            self.group_id.as_deref()
        } else {
            None
        }
    }

    pub fn permits_runtime(
        &self,
        privacy: &str,
        capability: InvocationCapability,
        resource: &str,
        risk: &str,
        now: u64,
    ) -> bool {
        // A legacy caller without target-profile custody cannot resolve typed
        // scope. It must use the authenticated projection-bound method below.
        self.runtime_scope.is_none()
            && self.capabilities.contains(&capability)
            && self.permits_context(privacy, resource, risk, now)
    }
    pub fn permits_runtime_for_profile(
        &self,
        privacy: &str,
        capability: InvocationCapability,
        resource: &str,
        risk: &str,
        now: u64,
        profile: &RuntimeTargetProfileBinding,
    ) -> bool {
        // These classes come from the supported route owner's exact forms.
        // Unknown forms remain closed until their owning route is implemented.
        let data_class = match capability {
            InvocationCapability::CallResultDisclosure => Some("STATE_CALL"),
            InvocationCapability::SignedTransactionSubmission => Some("transaction"),
            _ => None,
        };
        profile.matches_context(&self.participant, privacy)
            && self.capabilities.contains(&capability)
            && self.permits_context(privacy, resource, risk, now)
            && self.runtime_scope.as_ref().is_none_or(|scope| {
                scope.target_profiles.contains(profile.profile_id())
                    && data_class.is_some_and(|class| scope.data_classes.contains(class))
            })
    }
    fn permits_context(&self, privacy: &str, resource: &str, risk: &str, now: u64) -> bool {
        self.active
            && self.start <= now
            && now < self.end
            && now < self.group_fresh_until
            && self.privacy.contains(privacy)
            && (self.resources.contains(resource) || self.resources.contains("*"))
            && self.risks.contains(risk)
            && !self.approval
            && !self.step_up
    }
    pub fn subset_of(&self, parent: &Self) -> bool {
        self.participant == parent.participant
            && self.start >= parent.start
            && self.end <= parent.end
            && self.privacy.is_subset(&parent.privacy)
            && self.actions.is_subset(&parent.actions)
            && self.capabilities.is_subset(&parent.capabilities)
            && (parent.resources.contains("*") || self.resources.is_subset(&parent.resources))
            && self.risks.is_subset(&parent.risks)
            && (!parent.approval || self.approval)
            && (!parent.step_up || self.step_up)
            && self.depth <= parent.depth
    }
}

/// Membership constrains an explicit grant. Its refresh deadline is separate
/// from the grant interval so it cannot change delegation subset semantics.
fn assignment_group(value: &Object, start: u64, end: u64) -> RuntimeResult<(bool, u64)> {
    let group_id = optional_string(value, "authority_group_id")?;
    let scope = value.get("group_scope").filter(|v| !v.is_null());
    let Some(group_id) = group_id else {
        return if scope.is_none() {
            Ok((true, u64::MAX))
        } else {
            Err(RuntimeError::InvalidInput)
        };
    };
    // Older signed sources and revoked/missing memberships convey no group authority.
    let Some(scope) = scope else {
        return Ok((false, 0));
    };
    let scope = object(scope)?;
    keys(
        scope,
        &[
            "group_id",
            "principal_id",
            "group_revision",
            "member_id",
            "active",
            "valid_from_ns",
            "valid_until_ns",
            "fresh_until_ns",
        ],
    )?;
    if string(scope, "group_id")? != group_id
        || string(scope, "principal_id")? != string(value, "principal_id")?
        || unsigned(scope, "group_revision")? == 0
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    string(scope, "member_id")?;
    let member_start = unsigned(scope, "valid_from_ns")?;
    let member_end = if field(scope, "valid_until_ns")?.is_null() {
        u64::MAX
    } else {
        unsigned(scope, "valid_until_ns")?
    };
    if member_start >= member_end || start < member_start || end > member_end {
        return Err(RuntimeError::InvalidAuthorization);
    }
    let fresh_until = if field(scope, "fresh_until_ns")?.is_null() {
        u64::MAX
    } else {
        unsigned(scope, "fresh_until_ns")?
    };
    Ok((boolean(scope, "active")?, fresh_until))
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn typed_participant_envelope_has_issuer_scope_without_a_principal() {
        let envelope = json!({
            "authority_envelope_id":"envelope", "participant_id":"participant",
            "representation":"TYPED_V1", "principal_id":null,
            "issuer_participant_id":"participant", "issuer_privacy_domain_id":"privacy",
            "maker_principal_id":"maker", "checker_principal_id":"checker",
            "authority_epoch":"1", "delegation_epoch":"1", "row_version":"1",
            "valid_from":"time", "valid_until":"time", "semantic_digest":"digest",
            "privacy_domain_ids":["privacy"], "action_intent_ids":[],
            "runtime_capability_ids":["CALL_RESULT_DISCLOSURE"],
            "runtime_scope":{"data_classes":["STATE_CALL"],"target_profile_ids":["devnet-rpc-v1"]},
            "resource_ids":["*"], "risk_classes":["LOW"],
            "maker_checker_required":false, "step_up_required":false,
            "onward_delegation_depth":0, "state":"ACTIVE",
            "valid_from_ns":"100", "valid_until_ns":"1000", "valid_now":true
        });
        assert!(Permission::parse(&envelope).is_ok());
        assert!(!Permission::parse(&envelope).unwrap().permits_runtime(
            "privacy",
            InvocationCapability::CallResultDisclosure,
            "resource",
            "LOW",
            150,
        ));
        let context = crate::identity_context::RuntimeIdentityContext {
            participant_id: "018f0000-0000-7000-8000-000000000101".into(),
            privacy_domain_id: "018f0000-0000-7000-8000-000000000201".into(),
            target_runtime_id: "018f0000-0000-7000-8000-000000000902".into(),
        };
        let profile = RuntimeTargetProfileBinding::from_projection(&json!({
            "binding_id":"018f0000-0000-7000-8000-000000000903",
            "participant_id":context.participant_id,
            "privacy_domain_id":context.privacy_domain_id,
            "runtime_target_id":context.target_runtime_id,
            "target_profile_id":"devnet-rpc-v1",
            "binding_digest":"sha256:8aa9f53cde6159c76a028c910ac010aaf2ab278d744f306c674c49ec2373f195",
        }), &context).unwrap();
        let mut scoped = envelope.clone();
        scoped["participant_id"] = json!(context.participant_id);
        scoped["issuer_participant_id"] = json!(context.participant_id);
        scoped["issuer_privacy_domain_id"] = json!(context.privacy_domain_id);
        scoped["privacy_domain_ids"] = json!([context.privacy_domain_id]);
        assert!(
            Permission::parse(&scoped)
                .unwrap()
                .permits_runtime_for_profile(
                    &context.privacy_domain_id,
                    InvocationCapability::CallResultDisclosure,
                    "resource",
                    "LOW",
                    150,
                    &profile,
                )
        );
        assert!(
            !Permission::parse(&envelope)
                .unwrap()
                .permits_runtime_for_profile(
                    "privacy",
                    InvocationCapability::CallResultDisclosure,
                    "resource",
                    "LOW",
                    150,
                    &profile,
                )
        );
        for scope in [
            json!({"data_classes":[],"target_profile_ids":["devnet-rpc-v1"]}),
            json!({"data_classes":["STATE_CALL"],"target_profile_ids":[]}),
            json!({"data_classes":["METADATA"],"target_profile_ids":["devnet-rpc-v1"]}),
            json!({"data_classes":["STATE_CALL"],"target_profile_ids":["foreign"]}),
        ] {
            let mut changed = scoped.clone();
            changed["runtime_scope"] = scope;
            assert!(
                !Permission::parse(&changed)
                    .unwrap()
                    .permits_runtime_for_profile(
                        &context.privacy_domain_id,
                        InvocationCapability::CallResultDisclosure,
                        "resource",
                        "LOW",
                        150,
                        &profile,
                    )
            );
        }
        for (key, invalid) in [
            ("principal_id", json!("principal")),
            ("issuer_participant_id", json!("foreign")),
            ("issuer_privacy_domain_id", json!("foreign")),
            ("representation", json!("UNKNOWN")),
            ("runtime_scope", json!(null)),
            (
                "runtime_scope",
                json!({"data_classes":[],"target_profile_ids":["devnet-rpc-v1","devnet-rpc-v1"]}),
            ),
            (
                "runtime_scope",
                json!({"data_classes":["STATE_CALL"],"target_profile_ids":["devnet-rpc-v1"],"target_runtime_id":"native-uuid"}),
            ),
        ] {
            let mut changed = envelope.clone();
            changed[key] = invalid;
            assert!(Permission::parse(&changed).is_err(), "{key}");
        }
        let mut omitted = envelope.clone();
        omitted.as_object_mut().unwrap().remove("runtime_scope");
        assert!(Permission::parse(&omitted).is_err());
        for scope in [
            json!({"data_classes":[],"target_profile_ids":[]}),
            json!({"data_classes":["STATE_CALL"],"target_profile_ids":["foreign-target"]}),
            json!({"data_classes":["STATE_CALL"],"target_profile_ids":["018f0000-0000-7000-8000-000000000902"]}),
        ] {
            let mut changed = envelope.clone();
            changed["runtime_scope"] = scope;
            assert!(!Permission::parse(&changed).unwrap().permits_runtime(
                "privacy",
                InvocationCapability::CallResultDisclosure,
                "resource",
                "LOW",
                150,
            ));
        }
    }

    #[test]
    fn group_membership_bounds_explicit_authority_and_expires_without_a_new_snapshot() {
        let mut value = json!({
            "assignment_id":"assignment", "participant_id":"participant", "principal_id":"member",
            "role_id":null, "authority_group_id":"group", "authority_envelope_id":"envelope",
            "scope_digest":"digest", "valid_during":"[)", "created_by_principal_id":"maker",
            "row_version":"1", "delegation_epoch":"0", "privacy_domain_ids":["privacy"],
            "action_intent_ids":["read"], "resource_ids":["resource"], "risk_classes":["LOW"],
            "maker_checker_required":false, "step_up_required":false, "onward_delegation_depth":1,
            "state":"ACTIVE", "valid_from_ns":"100", "valid_until_ns":"1000", "valid_now":true
        });
        assert!(
            !Permission::parse(&value)
                .unwrap()
                .permits("privacy", "read", "resource", "LOW", 150)
        );
        value["group_scope"] = json!({"group_id":"group", "principal_id":"member", "member_id":"membership",
            "group_revision":"2", "active":true, "valid_from_ns":"50", "valid_until_ns":null,
            "fresh_until_ns":"200"});
        let grant = Permission::parse(&value).unwrap();
        assert!(grant.permits("privacy", "read", "resource", "LOW", 199));
        assert!(!grant.permits("privacy", "read", "resource", "LOW", 200));
        assert!(!grant.permits("privacy", "write", "resource", "LOW", 199));
        assert_eq!(grant.end, 1000); // freshness does not rewrite the durable grant interval
        assert_eq!(grant.valid_until_ns(), 200);
        assert_eq!(grant.group_for_principal("member"), Some("group"));
        assert_eq!(grant.group_for_principal("delegatee"), None);
        for (key, invalid) in [
            ("group_id", json!("other")),
            ("principal_id", json!("other")),
            ("group_revision", json!("0")),
            ("valid_from_ns", json!("101")),
            ("valid_until_ns", json!("999")),
        ] {
            let mut changed = value.clone();
            changed["group_scope"][key] = invalid;
            assert!(Permission::parse(&changed).is_err());
        }
        value["group_scope"]["active"] = json!(false);
        assert!(
            !Permission::parse(&value)
                .unwrap()
                .permits("privacy", "read", "resource", "LOW", 150)
        );
        value["group_scope"]["active"] = json!(true);
        value["group_scope"]["fresh_until_ns"] = Value::Null;
        assert!(
            Permission::parse(&value)
                .unwrap()
                .permits("privacy", "read", "resource", "LOW", 999)
        );
        value["authority_group_id"] = Value::Null;
        assert!(Permission::parse(&value).is_err());
    }

    #[test]
    fn legacy_and_empty_grants_confer_no_runtime_capability() {
        assert!(
            capabilities(object(&json!({})).unwrap())
                .unwrap()
                .is_empty()
        );
        assert!(
            capabilities(object(&json!({"runtime_capability_ids": []})).unwrap())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            capabilities(
                object(&json!({"runtime_capability_ids": ["CALL_RESULT_DISCLOSURE"]})).unwrap()
            )
            .unwrap(),
            BTreeSet::from([InvocationCapability::CallResultDisclosure])
        );
        for value in [
            json!(null),
            json!([null]),
            json!(["eth_call"]),
            json!(["CALL_RESULT_DISCLOSURE", "CALL_RESULT_DISCLOSURE"]),
            json!(["SEALED_INTERNAL_SAFETY_PREFLIGHT"]),
            json!(["ACT-POLICY_READ_EFFECTIVE_ACCESS-V1"]),
        ] {
            assert!(
                capabilities(object(&json!({"runtime_capability_ids": value})).unwrap()).is_err()
            );
        }
    }
}
