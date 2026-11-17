//! Complete signed identity state resolved to the actual transport workload.
//! Neither a role list nor an actor identifier comes from request metadata.
pub use crate::identity_wallet::WalletAssociation;
use crate::{
    WorkloadPeer,
    identity_credentials::WorkloadCredentials,
    identity_source::{self as source, Permission, Principal},
    identity_wallet::WalletAssociations,
};
use ciborium::value::Value;
use openpc_pds::{
    IdentityAssertionBindings, InvocationAuthorization, RuntimeAuthorityProfile,
    ValidatedInvocationAuthorization, VerifiedActorProjection, VerifiedIdentitySnapshot,
};
use pc_policy_core::{
    identity_context::RuntimeTargetProfileBinding, identity_permissions::WorkloadPermissions,
    invocation_capability::InvocationCapability,
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::collections::{BTreeMap, BTreeSet};

mod cigl;

use pc_policy_core::identity_context::tuple_digest;
pub use pc_policy_core::identity_context::{RuntimeIdentityContext, workload_actor_key_digest};
struct Workload {
    participant_epoch: Option<u64>,
    principal: Principal,
    projection: VerifiedActorProjection,
    permissions: WorkloadPermissions,
    credentials: WorkloadCredentials,
    wallets: WalletAssociations,
    target_profile: Option<RuntimeTargetProfileBinding>,
}
pub struct InstalledWorkloadIdentities {
    context: RuntimeIdentityContext,
    profile_digest: [u8; 32],
    snapshot: VerifiedIdentitySnapshot,
    workloads: BTreeMap<String, Workload>,
}
pub struct WorkloadAuthorization {
    pub(crate) participant_epoch: Option<u64>,
    pub authorization: ValidatedInvocationAuthorization,
    pub identity: IdentityAssertionBindings,
    pub valid_until_ns: u64,
    wallet: Option<WalletAssociation>,
    authorized_at_ns: u64,
    groups: BTreeSet<String>,
}
impl WorkloadAuthorization {
    /// Epoch from the authenticated complete Participant snapshot. Adapter
    /// contexts bind this authority; absent legacy epochs fail closed.
    pub fn participant_authority_epoch(&self) -> RuntimeResult<u64> {
        self.participant_epoch
            .ok_or(RuntimeError::InvalidAuthorization)
    }

    pub(crate) fn submission_wallet(&self) -> RuntimeResult<&WalletAssociation> {
        self.wallet
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)
    }
}
/// Registered-action permission query outside the closed invocation capability
/// path. An action grant does not grant invocation access; a source-read owner
/// must additionally intersect its exact source policies and live fences.
pub struct RuntimeAuthorityRequest<'a> {
    pub action_intent_id: &'a str,
    pub resource_id: &'a str,
    pub risk_class: &'a str,
}
/// Capability and scope resolved from an admitted invocation profile and request,
/// never from caller-supplied roles, HTTP headers or management action names.
pub struct RuntimeInvocationAuthorityRequest<'a> {
    pub capability: InvocationCapability,
    pub resource_id: &'a str,
    pub risk_class: &'a str,
}
fn content<'a>(
    artifacts: &'a BTreeMap<Digest, Vec<u8>>,
    digest: &[u8; 32],
) -> RuntimeResult<&'a [u8]> {
    let key = Digest::parse(
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )?;
    let bytes = artifacts.get(&key).ok_or(RuntimeError::InvalidInput)?;
    if Digest::of(bytes) != key {
        return Err(RuntimeError::InvalidDigest);
    }
    Ok(bytes)
}
fn array_digest(digest: &Digest) -> RuntimeResult<[u8; 32]> {
    let bytes = crate::capsule::digest(digest)?;
    bytes
        .as_bytes()
        .and_then(|v| v.as_slice().try_into().ok())
        .ok_or(RuntimeError::InvalidDigest)
}
impl InstalledWorkloadIdentities {
    pub fn admit(
        snapshot: VerifiedIdentitySnapshot,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
        context: RuntimeIdentityContext,
        profile: &RuntimeAuthorityProfile,
    ) -> RuntimeResult<Self> {
        if context.participant_id.is_empty()
            || context.privacy_domain_id.is_empty()
            || context.target_runtime_id.is_empty()
            || profile.profile_id() != "pc.identity.r1.workload-mtls"
            || profile.profile_version() != 1
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let mut workloads = BTreeMap::new();
        for (actor_index, projection) in snapshot.actors().enumerate() {
            if projection.actor_kind() != 1
                || *projection.participant_context_digest() != context.participant_context_digest()
            {
                return Err(RuntimeError::TargetIdentity);
            }
            let roles = source::canonical_json(content(
                artifacts,
                projection.role_assignment_set_digest(),
            )?)
            .inspect_err(|error| {
                eprintln!(
                    "runtime_identity_actor actor={actor_index} stage=roles_json reason={error:?}"
                )
            })?;
            let roles = source::object(&roles)?;
            let mut role_keys = vec![
                "participant_id",
                "privacy_domain_id",
                "principal_id",
                "workload_id",
                "principal",
                "paths",
                "revocations",
            ];
            if roles.contains_key("wallet_bindings") {
                role_keys.push("wallet_bindings");
            }
            if roles.contains_key("participant") {
                role_keys.push("participant");
            }
            if roles.contains_key("credentials") {
                role_keys.push("credentials");
            }
            if roles.contains_key("runtime_target_profile") {
                role_keys.push("runtime_target_profile");
            }
            source::keys(roles, &role_keys)?;
            let target_profile = roles
                .get("runtime_target_profile")
                .filter(|value| !value.is_null())
                .map(|value| RuntimeTargetProfileBinding::from_projection(value, &context))
                .transpose()?;
            // The vector's participant component is a publication revision, not
            // the control-store authority epoch. Preserve the actual signed root.
            let participant_epoch = roles
                .get("participant")
                .map(|value| {
                    let participant = source::object(value)?;
                    source::keys(participant, &["id", "state", "epoch"])?;
                    if source::string(participant, "id")? != context.participant_id
                        || source::string(participant, "state")? != "ACTIVE"
                    {
                        return Err(RuntimeError::TargetIdentity);
                    }
                    source::unsigned(participant, "epoch")
                })
                .transpose()?;
            let principal = Principal::parse(source::field(roles, "principal")?)
                .inspect_err(|error| eprintln!("runtime_identity_actor actor={actor_index} stage=principal reason={error:?}"))?;
            let workload_id = source::string(roles, "workload_id")?.to_owned();
            if source::string(roles, "participant_id")? != context.participant_id
                || source::string(roles, "privacy_domain_id")? != context.privacy_domain_id
                || source::string(roles, "principal_id")? != principal.id
                || principal.participant != context.participant_id
                || principal.kind != "WORKLOAD"
                || workload_actor_key_digest(&context.participant_id, &principal.id)?
                    != *projection.actor_key_digest()
            {
                return Err(RuntimeError::TargetIdentity);
            }
            let wallets = WalletAssociations::parse(
                roles.get("wallet_bindings"),
                &context.participant_id,
                &context.privacy_domain_id,
                &principal.id,
            )
            .inspect_err(|error| {
                eprintln!(
                    "runtime_identity_actor actor={actor_index} stage=wallets reason={error:?}"
                )
            })?;
            let credentials = WorkloadCredentials::parse(
                roles.get("credentials"),
                &principal.id,
                &workload_id,
            )
            .inspect_err(|error| {
                eprintln!(
                    "runtime_identity_actor actor={actor_index} stage=credentials reason={error:?}"
                )
            })?;
            let raw_envelopes = source::canonical_json(content(
                artifacts,
                projection.participant_envelope_digest(),
            )?)?;
            let permissions = WorkloadPermissions::parse(
                raw_envelopes.as_array().ok_or(RuntimeError::InvalidInput)?,
                source::field(roles, "paths")?
                    .as_array()
                    .ok_or(RuntimeError::InvalidInput)?,
                source::field(roles, "revocations")?
                    .as_array()
                    .ok_or(RuntimeError::InvalidInput)?,
                &principal,
                &context.participant_id,
            )
            .inspect_err(|error| {
                eprintln!(
                    "runtime_identity_actor actor={actor_index} stage=permissions reason={error:?}"
                )
            })?;
            if workloads
                .insert(
                    workload_id,
                    Workload {
                        participant_epoch,
                        principal,
                        projection: projection.clone(),
                        permissions,
                        credentials,
                        wallets,
                        target_profile,
                    },
                )
                .is_some()
            {
                return Err(RuntimeError::InvalidInput);
            }
        }
        Ok(Self {
            context,
            profile_digest: *profile.profile_semantic_digest(),
            snapshot,
            workloads,
        })
    }

    pub fn authorize(
        &self,
        peer: &WorkloadPeer,
        request: &RuntimeAuthorityRequest<'_>,
        now_ns: u64,
    ) -> RuntimeResult<WorkloadAuthorization> {
        let credential_until = self
            .workload_for_peer(peer, now_ns)?
            .credentials
            .require_peer(peer, now_ns)?;
        let mut granted = self.authorize_permission(peer, now_ns, |p| {
            p.permits(
                &self.context.privacy_domain_id,
                request.action_intent_id,
                request.resource_id,
                request.risk_class,
                now_ns,
            )
        })?;
        granted.valid_until_ns = granted.valid_until_ns.min(credential_until);
        Ok(granted)
    }

    pub fn authorize_runtime(
        &self,
        peer: &WorkloadPeer,
        request: &RuntimeInvocationAuthorityRequest<'_>,
        now_ns: u64,
    ) -> RuntimeResult<WorkloadAuthorization> {
        let profile = self
            .workload_for_peer(peer, now_ns)?
            .target_profile
            .as_ref();
        self.authorize_permission(peer, now_ns, |p| match profile {
            Some(profile) => p.permits_runtime_for_profile(
                &self.context.privacy_domain_id,
                request.capability,
                request.resource_id,
                request.risk_class,
                now_ns,
                profile,
            ),
            None => p.permits_runtime(
                &self.context.privacy_domain_id,
                request.capability,
                request.resource_id,
                request.risk_class,
                now_ns,
            ),
        })
    }

    /// Resolve the recovered signer under the actual authenticated workload and
    /// installed context. Callers must separately enforce invocation permission,
    /// application/route binding, live authority, transaction policy and nonce custody.
    pub fn wallet_association_for_transaction(
        &self,
        peer: &WorkloadPeer,
        transaction: &openpc_multi_rpc::signed_transaction::SignedTransaction,
        now_ns: u64,
    ) -> RuntimeResult<WalletAssociation> {
        self.workload_for_peer(peer, now_ns)?
            .wallets
            .for_transaction(transaction)
    }

    /// A supplied call sender must belong to the currently authenticated
    /// workload. Matching a wallet is a constraint, never a capability grant.
    pub(crate) fn validate_call_sender(
        &self,
        peer: &WorkloadPeer,
        chain_id: u64,
        sender: &[u8; 20],
        now_ns: u64,
    ) -> RuntimeResult<()> {
        self.workload_for_peer(peer, now_ns)?
            .wallets
            .for_account(chain_id, sender)?;
        Ok(())
    }

    /// Submission requires both the exact recovered wallet association and an
    /// independent capability grant for the selected contract binding and risk.
    pub fn authorize_submission(
        &self,
        peer: &WorkloadPeer,
        transaction: &openpc_multi_rpc::signed_transaction::SignedTransaction,
        request: &RuntimeInvocationAuthorityRequest<'_>,
        now_ns: u64,
    ) -> RuntimeResult<WorkloadAuthorization> {
        if request.capability != InvocationCapability::SignedTransactionSubmission {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let wallet = self.wallet_association_for_transaction(peer, transaction, now_ns)?;
        let mut authorization = self.authorize_runtime(peer, request, now_ns)?;
        authorization.wallet = Some(wallet);
        Ok(authorization)
    }

    fn authorize_permission(
        &self,
        peer: &WorkloadPeer,
        now_ns: u64,
        permission: impl Fn(&Permission) -> bool,
    ) -> RuntimeResult<WorkloadAuthorization> {
        let actor = self.workload_for_peer(peer, now_ns)?;
        let selected = actor.permissions.select(&actor.principal, permission)?;
        let valid_until_ns = selected
            .valid_until_ns
            .min(self.snapshot.expires_at_ns())
            .min(peer.not_after_ms().saturating_mul(1_000_000));
        Ok(WorkloadAuthorization {
            participant_epoch: actor.participant_epoch,
            authorization: ValidatedInvocationAuthorization::try_new(InvocationAuthorization {
                participant_id: self.context.participant_id.clone(),
                privacy_domain_id: self.context.privacy_domain_id.clone(),
                workload_id: peer.workload_id().into(),
                actor_principal_id: actor.principal.id.clone(),
                roles: selected.roles.into_iter().collect(),
                approval: None,
                webauthn: None,
            })?,
            identity: self.identity_for_peer(peer, now_ns)?.0,
            valid_until_ns,
            wallet: None,
            authorized_at_ns: now_ns,
            groups: selected.groups,
        })
    }

    fn workload_for_peer(&self, peer: &WorkloadPeer, now_ns: u64) -> RuntimeResult<&Workload> {
        if peer.participant_id() != self.context.participant_id
            || now_ns >= self.snapshot.expires_at_ns()
        {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        let actor = self
            .workloads
            .get(peer.workload_id())
            .ok_or(RuntimeError::TargetIdentity)?;
        if !actor.principal.active || actor.permissions.is_revoked(&actor.principal.id) {
            return Err(RuntimeError::Denied);
        }
        let valid_until_ns = self
            .snapshot
            .expires_at_ns()
            .min(peer.not_after_ms().saturating_mul(1_000_000));
        if now_ns < peer.not_before_ms().saturating_mul(1_000_000) || now_ns >= valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        Ok(actor)
    }

    /// Current identity and principal scope for rechecking an externally signed
    /// assertion after I/O. This projection carries no invocation grant.
    pub fn identity_for_peer(
        &self,
        peer: &WorkloadPeer,
        now_ns: u64,
    ) -> RuntimeResult<(IdentityAssertionBindings, &str)> {
        let actor = self.workload_for_peer(peer, now_ns)?;
        let certificate = array_digest(peer.certificate_fingerprint())?;
        Ok((
            IdentityAssertionBindings {
                actor_kind: 1,
                sender_binding_kind: 2,
                actor_key_digest: *actor.projection.actor_key_digest(),
                participant_context_digest: self.context.participant_context_digest(),
                audience_digest: self.context.target_scope_digest(),
                assurance_profile_digest: self.profile_digest,
                authority_vector_digest: *actor.projection.authority_vector_digest(),
                authentication_evidence_digest: tuple_digest(vec![
                    Value::Text("TLS1.3".into()),
                    Value::Text(peer.uri_san().into()),
                    Value::Bytes(certificate.to_vec()),
                    Value::Bytes(array_digest(peer.public_key_digest())?.to_vec()),
                ]),
                sender_credential_binding_digest: certificate,
            },
            actor.principal.id.as_str(),
        ))
    }
}
