use super::*;
use ciborium::value::Value as Cbor;
use openpc_pds::{IdentityAssertionBindings, IdentitySnapshotTrust};
use pc_policy_core::{
    identity_context::{tuple_digest, workload_actor_key_digest},
    identity_permissions::{SelectedPermissions, WorkloadPermissions},
    identity_source::{self as source, Principal},
};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeMap;

pub(crate) struct VerifiedWorkloadSource {
    pub principal: Principal,
    pub permissions: SelectedPermissions,
    pub roles: Value,
    pub envelopes: Value,
    pub expires_at_ns: u64,
}

impl AuthenticatedFactWorkload {
    pub(crate) async fn verify_snapshot(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        trust: &FactIdentityTrust,
        resource: &str,
        now_ns: u64,
    ) -> Result<VerifiedWorkloadSource> {
        let publication = &self.publication;
        let target = Uuid::parse_str(&self.context.target_runtime_id)
            .map_err(|_| WorkloadAuthorityError::Authority)?;
        let privacy = Uuid::parse_str(&self.context.privacy_domain_id)
            .map_err(|_| WorkloadAuthorityError::Authority)?;
        let row = sqlx::query(
            "select manifest_digest,manifest_payload,manifest_cose,profile_payload,profile_cose,profile_digest,
              expires_at_ns::text from control.identity_runtime_snapshot
             where participant_id=$1 and privacy_domain_id=$2 and target_runtime_id=$3 and snapshot_id=$4
              and octet_length(manifest_payload)+octet_length(manifest_cose)<=262144
              and octet_length(profile_payload)+octet_length(profile_cose)<=65536",
        ).bind(self.reply.participant_id).bind(privacy).bind(target).bind(publication.snapshot_id)
            .fetch_optional(&mut **transaction).await?.ok_or(WorkloadAuthorityError::Authority)?;
        let manifest_digest = prefixed_digest(&publication.manifest_digest)?;
        let expires_at_ns: u64 = row
            .try_get::<String, _>("expires_at_ns")?
            .parse()
            .map_err(|_| WorkloadAuthorityError::Authority)?;
        if row.try_get::<Vec<u8>, _>("manifest_digest")? != manifest_digest
            || row.try_get::<Vec<u8>, _>("profile_digest")? != trust.profile_digest
            || publication.expires_at_ns.parse::<u64>().ok() != Some(expires_at_ns)
            || now_ns >= expires_at_ns
        {
            return Err(WorkloadAuthorityError::Expired);
        }
        let profile = trust
            .verifier
            .verify_runtime_authority_profile(
                &IdentityAssertionEvidence {
                    payload_cbor: row.try_get("profile_payload")?,
                    cose_sign1: row.try_get("profile_cose")?,
                },
                &trust.profile_digest,
                &trust.signer_id,
            )
            .map_err(|_| WorkloadAuthorityError::Authority)?;
        if profile.profile_id() != "pc.identity.r1.workload-mtls" || profile.profile_version() != 1
        {
            return Err(WorkloadAuthorityError::Authority);
        }
        let (count, total): (i64, i64) = sqlx::query_as(
            "select count(*),coalesce(sum(octet_length(payload)),0)::bigint
             from control.identity_runtime_snapshot_content
             where participant_id=$1 and privacy_domain_id=$2 and snapshot_id=$3",
        )
        .bind(self.reply.participant_id)
        .bind(privacy)
        .bind(publication.snapshot_id)
        .fetch_one(&mut **transaction)
        .await?;
        if !(1..=8192).contains(&count) || !(1..=4_194_304).contains(&total) {
            return Err(WorkloadAuthorityError::Authority);
        }
        let rows = sqlx::query("select content_digest,content_kind,payload from control.identity_runtime_snapshot_content
            where participant_id=$1 and privacy_domain_id=$2 and snapshot_id=$3 order by content_kind,ordinal")
            .bind(self.reply.participant_id).bind(privacy).bind(publication.snapshot_id)
            .fetch_all(&mut **transaction).await?;
        let mut shards = Vec::new();
        let mut content = BTreeMap::new();
        for row in rows {
            let payload: Vec<u8> = row.try_get("payload")?;
            let digest: Vec<u8> = row.try_get("content_digest")?;
            if digest != pc_facts_core::sha256(&payload) {
                return Err(WorkloadAuthorityError::Authority);
            }
            match row.try_get::<String, _>("content_kind")?.as_str() {
                "SHARD" => shards.push(payload),
                "ROLE_ASSIGNMENTS" | "PARTICIPANT_ENVELOPES" => {
                    if content.insert(digest, payload).is_some() {
                        return Err(WorkloadAuthorityError::Authority);
                    }
                }
                _ => return Err(WorkloadAuthorityError::Authority),
            }
        }
        let verified = trust
            .verifier
            .verify_snapshot(
                &IdentityAssertionEvidence {
                    payload_cbor: row.try_get("manifest_payload")?,
                    cose_sign1: row.try_get("manifest_cose")?,
                },
                &shards,
                &IdentitySnapshotTrust {
                    manifest_digest,
                    target_scope_digest: self.context.target_scope_digest(),
                    release_profile_registry_digest: trust.profile_digest,
                    signer_id: trust.signer_id.clone(),
                    profiles: vec![profile],
                    maximum_total_bytes: 4_456_448,
                },
                now_ns,
            )
            .map_err(|_| WorkloadAuthorityError::Authority)?;
        if verified.snapshot_id() != publication.snapshot_id.to_string()
            || verified.expires_at_ns() != expires_at_ns
        {
            return Err(WorkloadAuthorityError::Authority);
        }
        let actor_key = workload_actor_key_digest(
            &self.context.participant_id,
            &self.reply.principal_id.to_string(),
        )
        .map_err(|_| WorkloadAuthorityError::Authority)?;
        let actor = verified
            .actor(&actor_key)
            .ok_or(WorkloadAuthorityError::Authority)?;
        if actor.actor_kind() != 1
            || actor.participant_context_digest() != &self.context.participant_context_digest()
        {
            return Err(WorkloadAuthorityError::Authority);
        }
        let assertion = trust
            .verifier
            .verify(
                &self.assertion,
                &IdentityAssertionBindings {
                    actor_kind: 1,
                    sender_binding_kind: 2,
                    actor_key_digest: actor_key,
                    participant_context_digest: self.context.participant_context_digest(),
                    audience_digest: self.context.target_scope_digest(),
                    assurance_profile_digest: trust.profile_digest,
                    authority_vector_digest: *actor.authority_vector_digest(),
                    authentication_evidence_digest: tuple_digest(vec![
                        Cbor::Text("TLS1.3".into()),
                        Cbor::Text(self.reply.uri_san.clone()),
                        Cbor::Bytes(self.certificate_digest.to_vec()),
                        Cbor::Bytes(self.key_digest.to_vec()),
                    ]),
                    sender_credential_binding_digest: self.certificate_digest,
                },
                now_ns / 1_000_000,
            )
            .map_err(|_| WorkloadAuthorityError::Authority)?;
        let roles = read_content(&content, actor.role_assignment_set_digest())?;
        let envelopes = read_content(&content, actor.participant_envelope_digest())?;
        let parsed = parse_permissions(&roles, &envelopes, self, resource, now_ns)?;
        Ok(VerifiedWorkloadSource {
            principal: parsed.0,
            permissions: parsed.1,
            roles,
            envelopes,
            expires_at_ns: expires_at_ns.min(assertion.expires_at_ms().saturating_mul(1_000_000)),
        })
    }
}

fn read_content(content: &BTreeMap<Vec<u8>, Vec<u8>>, digest: &[u8; 32]) -> Result<Value> {
    source::canonical_json(
        content
            .get(digest.as_slice())
            .ok_or(WorkloadAuthorityError::Authority)?,
    )
    .map_err(|_| WorkloadAuthorityError::Authority)
}

fn parse_permissions(
    roles: &Value,
    envelopes: &Value,
    workload: &AuthenticatedFactWorkload,
    resource: &str,
    now: u64,
) -> Result<(Principal, SelectedPermissions)> {
    let parse = || -> pc_runtime_types::RuntimeResult<_> {
        let roles = source::object(roles)?;
        source::keys(
            roles,
            &[
                "participant_id",
                "participant",
                "privacy_domain_id",
                "principal_id",
                "workload_id",
                "principal",
                "credentials",
                "paths",
                "wallet_bindings",
                "revocations",
            ],
        )?;
        let participant = source::object(source::field(roles, "participant")?)?;
        source::keys(participant, &["id", "state", "epoch"])?;
        let principal = Principal::parse(source::field(roles, "principal")?)?;
        if source::string(roles, "participant_id")? != workload.context.participant_id
            || source::string(roles, "privacy_domain_id")? != workload.context.privacy_domain_id
            || source::string(roles, "principal_id")? != principal.id
            || source::string(roles, "workload_id")? != workload.reply.workload_id
            || principal.id != workload.reply.principal_id.to_string()
            || principal.participant != workload.context.participant_id
            || principal.kind != "WORKLOAD"
            || source::string(participant, "id")? != workload.context.participant_id
            || source::string(participant, "state")? != "ACTIVE"
            || source::unsigned(participant, "epoch")?.to_string()
                != workload.reply.participant_epoch
        {
            return Err(pc_runtime_types::RuntimeError::Denied);
        }
        let permissions = WorkloadPermissions::parse(
            envelopes
                .as_array()
                .ok_or(pc_runtime_types::RuntimeError::InvalidInput)?,
            source::field(roles, "paths")?
                .as_array()
                .ok_or(pc_runtime_types::RuntimeError::InvalidInput)?,
            source::field(roles, "revocations")?
                .as_array()
                .ok_or(pc_runtime_types::RuntimeError::InvalidInput)?,
            &principal,
            &workload.context.participant_id,
        )?;
        let selected = permissions.select(&principal, |p| {
            p.permits(
                &workload.context.privacy_domain_id,
                ACTION,
                resource,
                "STANDARD",
                now,
            )
        })?;
        Ok((principal, selected))
    };
    parse().map_err(|_| WorkloadAuthorityError::Authority)
}
