//! Bootstrap custody binds actual activation work and current workload identity.
//! These read-only selectors never create a disposition or a serving grant.
use super::*;
use crate::runtime_target::TargetDispositionBootstrap;
use pc_runtime_types::target_disposition::{TargetDispositionIdentity, TargetDispositionSource};

impl TargetDispositionStore {
    pub(super) async fn bootstrap_identity(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        peer: &crate::TargetIdentity,
    ) -> Result<TargetDispositionIdentity> {
        let authority=sqlx::query("select credential_id::text,credential_epoch,principal_epoch from openpc.lock_runtime_discovery_authority($1::text::uuid,$2)")
            .bind(&peer.target_id)
            .bind(format!("sha256:{}", peer.certificate_fingerprint.as_str()))
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| unavailable())?;
        let credential: String = authority
            .try_get("credential_id")
            .map_err(|_| unavailable())?;
        let principal:String=sqlx::query_scalar("select principal_id::text from control.credential where participant_id=openpc.current_participant_id() and credential_id=$1::text::uuid")
            .bind(&credential).fetch_one(&mut **tx).await.map_err(|_| unavailable())?;
        let current_identity = pc_runtime_types::target_disposition::TargetDispositionIdentity {
            participant_id: self.participant.clone(),
            privacy_domain_id: self.privacy.clone(),
            target_id: peer.target_id.clone(),
            credential_id: credential,
            principal_id: principal,
            certificate_digest: peer.certificate_fingerprint.clone(),
            credential_epoch: u64::try_from(
                authority
                    .try_get::<i64, _>("credential_epoch")
                    .map_err(|_| unavailable())?,
            )
            .map_err(|_| unavailable())?,
            principal_epoch: u64::try_from(
                authority
                    .try_get::<i64, _>("principal_epoch")
                    .map_err(|_| unavailable())?,
            )
            .map_err(|_| unavailable())?,
        };
        current_identity.validate().map_err(|_| unavailable())?;
        Ok(current_identity)
    }

    /// Read-only composition for the pending observed denial. This cannot
    /// produce a serving bootstrap or authorize an ordinary source transition.
    pub(super) async fn expired_credential_binding_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        peer: &crate::TargetIdentity,
    ) -> Result<(TargetDispositionBootstrap, String)> {
        let row=sqlx::query("select binding,rotation_operation_id::text from openpc.expired_denial_credential_bootstrap($1::text::uuid,$2)")
            .bind(&peer.target_id).bind(format!("sha256:{}",peer.certificate_fingerprint.as_str()))
            .fetch_one(&mut **tx).await.map_err(database_error)?;
        let binding: TargetDispositionBootstrap =
            serde_json::from_value(row.try_get("binding").map_err(|_| unavailable())?)
                .map_err(|_| unavailable())?;
        let rotation: String = row
            .try_get("rotation_operation_id")
            .map_err(|_| unavailable())?;
        binding
            .validate_identity_lineage()
            .map_err(|_| unavailable())?;
        if binding.target.participant_id != self.participant
            || binding.target.privacy_domain_id != self.privacy
            || binding.target.target_id != peer.target_id
            || binding.target.certificate_digest != peer.certificate_fingerprint
            || binding.credential_predecessor.is_none()
        {
            return Err(unavailable());
        }
        Ok((binding, rotation))
    }

    pub(super) async fn bootstrap_for_expired_credential_denial(
        &self,
        peer: &crate::TargetIdentity,
        capsule: &openpc_runtime_agent::RuntimeCapsule,
        rotation: &str,
    ) -> Result<TargetDispositionBootstrap> {
        let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
        let result = async {
            self.context(&mut tx).await?;
            let (binding, operation) = self.expired_credential_binding_in(&mut tx, peer).await?;
            if operation != rotation
                || capsule.target_runtime_id != peer.target_id
                || binding.source.runtime_configuration_generation_id != capsule.capsule_id
                || binding.source.capsule_digest != capsule.digest().map_err(|_| unavailable())?
                || binding.source.predecessor_capsule_digest != capsule.previous_capsule_digest
            {
                return Err(unavailable());
            }
            Ok(binding)
        }
        .await;
        let released = tx.rollback().await;
        match result {
            Err(error) => Err(error),
            Ok(binding) => {
                released.map_err(|_| unavailable())?;
                Ok(binding)
            }
        }
    }

    pub async fn bootstrap_for_activation(
        &self,
        peer: &crate::TargetIdentity,
        capsule: &openpc_runtime_agent::RuntimeCapsule,
    ) -> Result<TargetDispositionBootstrap> {
        eprintln!(
            "{}",
            serde_json::json!({"boundary":"target_disposition_bootstrap","stage":"input","target_id":peer.target_id,"capsule_id":capsule.capsule_id,"has_predecessor":capsule.previous_capsule_digest.is_some()})
        );
        if capsule.target_runtime_id != peer.target_id {
            return Err(unavailable());
        }
        let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
        self.context(&mut tx).await?;
        eprintln!(
            "{}",
            serde_json::json!({"boundary":"target_disposition_bootstrap","stage":"context"})
        );
        let target = self.bootstrap_identity(&mut tx, peer).await?;
        eprintln!(
            "{}",
            serde_json::json!({"boundary":"target_disposition_bootstrap","stage":"identity"})
        );
        let rows = sqlx::query(r#"select jsonb_build_object(
          'runtime_configuration_input_id',i.runtime_configuration_input_id::text,
          'configuration_digest',encode(i.configuration_digest,'hex'),
          'module_installation_id',i.module_installation_id::text,
          'module_configuration_generation_id',i.module_configuration_generation_id::text,
          'runtime_configuration_generation_id',w.runtime_configuration_generation_id::text,
          'capsule_digest',$3::text,'xds_version_digest',substring(w.xds_version_digest from 8),
          'predecessor_capsule_digest',substring(w.predecessor_digest from 8),
          'original_work_id',w.configuration_work_id::text,'original_operation_id',w.operation_id::text,
          'original_execution_attempt_id',w.execution_attempt_id::text) as source
          from control.configuration_work w join control.runtime_configuration_input i
           on i.participant_id=w.participant_id and i.privacy_domain_id=w.privacy_domain_id
           and i.configuration_digest=decode(substring(w.configuration_digest from 8),'hex')
          where w.participant_id=openpc.current_participant_id() and w.privacy_domain_id=openpc.current_privacy_domain_id()
           and w.runtime_target_id=$1::text::uuid and w.runtime_configuration_generation_id=$2::text::uuid
           and w.work_kind='RUNTIME_ACTIVATION' and w.execution_started_at is not null and w.execution_attempt_id is not null
           and ((w.state='LEASED' and w.lease_until>clock_timestamp()) or (w.state in ('COMPLETED','RECONCILING') and exists(
             select 1 from control.runtime_activation_observation o where o.participant_id=w.participant_id
             and o.privacy_domain_id=w.privacy_domain_id and o.configuration_work_id=w.configuration_work_id
             and o.operation_id=w.operation_id and o.execution_attempt_id=w.execution_attempt_id
             and o.runtime_target_id=w.runtime_target_id and o.runtime_configuration_generation_id=w.runtime_configuration_generation_id
             and o.generation_digest=w.generation_digest and o.xds_version_digest=w.xds_version_digest
             and (w.state='RECONCILING' or o.activation_receipt_digest=w.result_receipt_digest) and o.capsule_digest='sha256:'||$3)))
          for share of w,i"#)
          .bind(&peer.target_id).bind(&capsule.capsule_id).bind(capsule.digest().map_err(|_| unavailable())?.as_str())
          .fetch_all(&mut *tx).await.map_err(database_error)?;
        eprintln!(
            "{}",
            serde_json::json!({"boundary":"target_disposition_bootstrap","stage":"source_rows","count":rows.len()})
        );
        if rows.len() != 1 {
            return Err(unavailable());
        }
        let source: TargetDispositionSource =
            serde_json::from_value(rows[0].try_get("source").map_err(|_| unavailable())?)
                .map_err(|_| unavailable())?;
        eprintln!(
            "{}",
            serde_json::json!({"boundary":"target_disposition_bootstrap","stage":"source_decoded"})
        );
        source.validate().map_err(|_| unavailable())?;
        eprintln!(
            "{}",
            serde_json::json!({"boundary":"target_disposition_bootstrap","stage":"source_validated"})
        );
        if source.predecessor_capsule_digest != capsule.previous_capsule_digest {
            eprintln!(
                "{}",
                serde_json::json!({"boundary":"target_disposition_bootstrap","stage":"predecessor_mismatch","source_has_predecessor":source.predecessor_capsule_digest.is_some(),"capsule_has_predecessor":capsule.previous_capsule_digest.is_some()})
            );
            return Err(unavailable());
        }
        eprintln!(
            "{}",
            serde_json::json!({"boundary":"target_disposition_bootstrap","stage":"credential_predecessor_lookup"})
        );
        let predecessor: Option<serde_json::Value> = sqlx::query_scalar(
            "select openpc.runtime_discovery_credential_predecessor($1::text::uuid,$2,$3)",
        )
        .bind(&peer.target_id)
        .bind(format!("sha256:{}", peer.certificate_fingerprint.as_str()))
        .bind(serde_json::to_value(&source).map_err(|_| unavailable())?)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| {
            eprintln!("{}", serde_json::json!({"boundary":"target_disposition_bootstrap","stage":"credential_predecessor_lookup_failed","error_class":database_error_class(&error),"sqlstate":error.as_database_error().and_then(|db|db.code()).filter(|code|safe_sqlstate(code)).map(|code|code.to_string())}));
            database_error(error)
        })?;
        let credential_predecessor: Option<TargetDispositionIdentity> = predecessor
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| unavailable())?;
        if let Some(previous) = &credential_predecessor {
            previous.validate().map_err(|_| unavailable())?;
        }
        tx.commit().await.map_err(|error| {
            eprintln!("{}", serde_json::json!({"boundary":"target_disposition_bootstrap","stage":"commit_failed","error_class":database_error_class(&error),"sqlstate":error.as_database_error().and_then(|db|db.code()).map(|code|code.to_string())}));
            unavailable()
        })?;
        eprintln!(
            "{}",
            serde_json::json!({"boundary":"target_disposition_bootstrap","stage":"complete"})
        );
        Ok(TargetDispositionBootstrap {
            target,
            source,
            credential_predecessor,
        })
    }
}
