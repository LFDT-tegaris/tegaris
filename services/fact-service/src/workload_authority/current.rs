use super::*;
use pc_policy_core::identity_source::{self as source, Permission};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use std::collections::BTreeSet;

/// Provenance of one current, scoped authorization. It remains usable only
/// while its owning Control transaction and finite deadline are retained.
#[derive(serde::Serialize)]
pub struct FactWorkloadAdmission {
    pub(crate) participant_id: Uuid,
    pub(crate) privacy_domain_id: Uuid,
    pub(crate) principal_id: Uuid,
    pub(crate) credential_id: Uuid,
    pub(crate) resource_id: String,
    pub(crate) participant_epoch: String,
    pub(crate) principal_epoch: String,
    pub(crate) workload_epoch: String,
    pub(crate) platform_context_id: Uuid,
    pub(crate) platform_authority_epoch: String,
    pub(crate) participant_authority_envelope_id: Uuid,
    pub(crate) delegation_epoch: String,
    pub(crate) snapshot_id: Uuid,
    pub(crate) manifest_digest: String,
    pub(crate) permission_source_digest: [u8; 32],
    pub(crate) expires_at_ns: u64,
}

impl AuthenticatedFactWorkload {
    pub(crate) async fn authorize_in(
        self,
        transaction: &mut Transaction<'_, Postgres>,
        participant: Uuid,
        privacy: Uuid,
        resource: &str,
        trust: &FactIdentityTrust,
        now: u64,
    ) -> Result<FactWorkloadAdmission> {
        if self.reply.participant_id != participant
            || self.context.privacy_domain_id != privacy.to_string()
            || resource.is_empty()
            || resource.len() > 256
        {
            return Err(WorkloadAuthorityError::Authority);
        }
        // Caller holds the exclusive Participant fence before source/business
        // locks. Every supported authority mutation takes that same root fence.
        let deadline: Option<String> = sqlx::query_scalar(
            "select (extract(epoch from c.valid_until)*1000000000)::numeric(20,0)::text
             from control.credential c join control.principal p
              on p.participant_id=c.participant_id and p.principal_id=c.principal_id
             join control.participant root on root.participant_id=p.participant_id
             join control.privacy_domain d on d.participant_id=p.participant_id and d.privacy_domain_id=$2
             where c.participant_id=$1 and c.credential_id=$3 and c.principal_id=$4
              and c.kind='WORKLOAD_MTLS' and c.state='ACTIVE' and c.subject=$5 and c.audience=$6
              and c.public_key_digest=$7 and c.secret_fingerprint=$8 and c.credential_epoch::text=$9
              and c.valid_from=$10::text::timestamptz and c.valid_until=$11::text::timestamptz
              and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()
              and p.kind='WORKLOAD' and p.state='ACTIVE' and p.authority_epoch::text=$12
              and root.state='ACTIVE' and root.archived_at is null and root.authority_epoch::text=$13
              and d.state='ACTIVE'",
        ).bind(participant).bind(privacy).bind(self.reply.credential_id).bind(self.reply.principal_id)
            .bind(&self.reply.uri_san).bind(&self.reply.workload_id).bind(self.key_digest.as_slice())
            .bind(self.certificate_digest.as_slice()).bind(&self.reply.workload_epoch)
            .bind(&self.reply.not_before).bind(&self.reply.not_after).bind(&self.reply.principal_epoch)
            .bind(&self.reply.participant_epoch).fetch_optional(&mut **transaction).await?;
        let mut deadline = deadline
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or(WorkloadAuthorityError::Authority)?;
        let source = self
            .verify_snapshot(transaction, trust, resource, now)
            .await?;
        deadline = deadline
            .min(source.expires_at_ns)
            .min(source.permissions.valid_until_ns);
        let dependencies = &source.permissions.dependencies;
        let principal = source
            .roles
            .get("principal")
            .ok_or(WorkloadAuthorityError::Authority)?;
        version(
            transaction,
            participant,
            "principal",
            &source.principal.id,
            principal,
        )
        .await?;
        let mut verified = BTreeSet::from([source.principal.id.clone()]);
        let mut grant_epochs = BTreeSet::new();
        for path in source.roles["paths"]
            .as_array()
            .ok_or(WorkloadAuthorityError::Authority)?
        {
            for entry in path.as_array().ok_or(WorkloadAuthorityError::Authority)? {
                let grant = &entry["grant"];
                let permission =
                    Permission::parse(grant).map_err(|_| WorkloadAuthorityError::Authority)?;
                if !dependencies.contains(&permission.id) {
                    continue;
                }
                grant_epochs.insert(permission.epoch);
                let kind = if permission.parent.is_some() {
                    "delegation"
                } else {
                    "assignment"
                };
                version(transaction, participant, kind, &permission.id, grant).await?;
                version(
                    transaction,
                    participant,
                    "principal",
                    &permission.principal,
                    &entry["principal"],
                )
                .await?;
                if let Some(role) = &permission.role {
                    let valid: bool =
                        sqlx::query_scalar("select openpc.assignment_role_permits($1,$2,$3)")
                            .bind(participant)
                            .bind(role)
                            .bind(ACTION)
                            .fetch_one(&mut **transaction)
                            .await?;
                    if !valid {
                        return Err(WorkloadAuthorityError::Authority);
                    }
                }
                if kind == "assignment" {
                    let current: bool = sqlx::query_scalar("select openpc.assignment_group_permits(participant_id,authority_group_id,principal_id,valid_during)
                        from control.assignment where participant_id=$1 and assignment_id=$2::text::uuid")
                        .bind(participant).bind(&permission.id).fetch_one(&mut **transaction).await?;
                    if !current {
                        return Err(WorkloadAuthorityError::Authority);
                    }
                }
                verified.insert(permission.id);
                verified.insert(permission.principal);
            }
        }
        let mut selected_envelopes = Vec::new();
        for envelope in source
            .envelopes
            .as_array()
            .ok_or(WorkloadAuthorityError::Authority)?
        {
            let permission =
                Permission::parse(envelope).map_err(|_| WorkloadAuthorityError::Authority)?;
            if dependencies.contains(&permission.id) {
                version(
                    transaction,
                    participant,
                    "authority_envelope",
                    &permission.id,
                    envelope,
                )
                .await?;
                selected_envelopes.push((permission.id.clone(), permission.epoch));
                verified.insert(permission.id);
            }
        }
        if &verified != dependencies {
            return Err(WorkloadAuthorityError::Authority);
        }
        // A fact identifies one exact authorization envelope. Do not pick an
        // arbitrary member of a union of independently valid grant paths.
        let [(envelope_id, delegation_epoch)] = selected_envelopes.as_slice() else {
            return Err(WorkloadAuthorityError::Authority);
        };
        if grant_epochs != BTreeSet::from([*delegation_epoch]) {
            return Err(WorkloadAuthorityError::Authority);
        }
        let envelope_id =
            Uuid::parse_str(envelope_id).map_err(|_| WorkloadAuthorityError::Authority)?;
        let platform: Option<(Uuid, String, String)> = sqlx::query_as(
            "select platform_context_id,platform_authority_epoch,delegation_epoch
             from openpc.lock_authority_envelope_platform_context($1)",
        )
        .bind(envelope_id)
        .fetch_optional(&mut **transaction)
        .await?;
        let (platform_context_id, platform_authority_epoch, current_delegation_epoch) =
            platform.ok_or(WorkloadAuthorityError::Authority)?;
        if current_delegation_epoch != delegation_epoch.to_string()
            || platform_authority_epoch.parse::<u64>().is_err()
        {
            return Err(WorkloadAuthorityError::Authority);
        }
        verified.insert(self.reply.credential_id.to_string());
        for role in source.permissions.roles {
            verified.insert(
                role.strip_prefix("urn:openpc:role:")
                    .ok_or(WorkloadAuthorityError::Authority)?
                    .to_owned(),
            );
        }
        let targets = verified
            .into_iter()
            .map(|id| Uuid::parse_str(&id).map_err(|_| WorkloadAuthorityError::Authority))
            .collect::<Result<Vec<_>>>()?;
        let earliest: Option<String> = sqlx::query_scalar(
            "select (extract(epoch from min(effective_at))*1000000000)::numeric(20,0)::text
             from control.revocation where participant_id=$1 and target_id=any($2::uuid[])",
        )
        .bind(participant)
        .bind(targets)
        .fetch_one(&mut **transaction)
        .await?;
        if let Some(earliest) = earliest {
            deadline = deadline.min(
                earliest
                    .parse()
                    .map_err(|_| WorkloadAuthorityError::Authority)?,
            );
        }
        if now >= deadline {
            return Err(WorkloadAuthorityError::Expired);
        }
        let bytes = serde_json::to_vec(
            &serde_json::json!({"roles":source.roles,"envelopes":source.envelopes}),
        )
        .map_err(|_| WorkloadAuthorityError::Authority)?;
        Ok(FactWorkloadAdmission {
            participant_id: participant,
            privacy_domain_id: privacy,
            principal_id: self.reply.principal_id,
            credential_id: self.reply.credential_id,
            resource_id: resource.into(),
            participant_epoch: self.reply.participant_epoch,
            principal_epoch: self.reply.principal_epoch,
            workload_epoch: self.reply.workload_epoch,
            platform_context_id,
            platform_authority_epoch,
            participant_authority_envelope_id: envelope_id,
            delegation_epoch: current_delegation_epoch,
            snapshot_id: self.publication.snapshot_id,
            manifest_digest: self.publication.manifest_digest,
            permission_source_digest: pc_facts_core::sha256(&bytes),
            expires_at_ns: deadline,
        })
    }
}

async fn version(
    transaction: &mut Transaction<'_, Postgres>,
    participant: Uuid,
    kind: &str,
    id: &str,
    value: &Value,
) -> Result<()> {
    let row_version = source::unsigned(
        source::object(value).map_err(|_| WorkloadAuthorityError::Authority)?,
        "row_version",
    )
    .map_err(|_| WorkloadAuthorityError::Authority)?;
    let statement = match kind {
        "principal" => {
            "select exists(select 1 from control.principal where participant_id=$1 and principal_id=$2::text::uuid and row_version::text=$3 and state='ACTIVE')"
        }
        "assignment" => {
            "select exists(select 1 from control.assignment where participant_id=$1 and assignment_id=$2::text::uuid and row_version::text=$3 and state='ACTIVE')"
        }
        "delegation" => {
            "select exists(select 1 from control.delegation where participant_id=$1 and delegation_id=$2::text::uuid and row_version::text=$3 and state='ACTIVE')"
        }
        "authority_envelope" => {
            "select exists(select 1 from control.authority_envelope where participant_id=$1 and authority_envelope_id=$2::text::uuid and row_version::text=$3 and state='ACTIVE')"
        }
        _ => return Err(WorkloadAuthorityError::Authority),
    };
    let valid: bool = sqlx::query_scalar(statement)
        .bind(participant)
        .bind(id)
        .bind(row_version.to_string())
        .fetch_one(&mut **transaction)
        .await?;
    if !valid {
        return Err(WorkloadAuthorityError::Authority);
    }
    Ok(())
}
