//! Native use remains bound to the caller's actual scoped transaction and the
//! installed source. Negative history is persisted before any consumer effect.
use super::*;
use sqlx::{Postgres, Row, Transaction};

impl RuntimeArtifactSourceWorker {
    /// The caller's actual transaction owns the lifecycle/current-source fence.
    /// Recording use grants no authority beyond that existing admission.
    pub async fn record_consumer_use(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        original: SourceConsumerUse,
    ) -> SourceCustodyResult<()> {
        use crate::runtime_configuration_input::{
            RUNTIME_ARTIFACT_BUSY, runtime_artifact_new_use_allowed,
        };
        let allowed = runtime_artifact_new_use_allowed(
            tx,
            &self.participant,
            &self.privacy,
            &original.configuration_digest,
        )
        .await
        .map_err(|error| {
            if error == RUNTIME_ARTIFACT_BUSY {
                SourceCustodyError::Busy
            } else {
                RuntimeError::RuntimeUnavailable.into()
            }
        })?;
        if !allowed {
            return Err(RuntimeError::Denied.into());
        }
        self.record_observed_use(tx, original, true).await
    }

    /// Record custody before a restriction or original-result operation. This
    /// records possible prior consumption; it grants no signing, restoration or
    /// serving authority and must not require new-use permission to withdraw.
    pub async fn record_consumer_restriction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        original: SourceConsumerUse,
    ) -> SourceCustodyResult<()> {
        self.lock_consumer_scope(tx).await?;
        self.record_observed_use(tx, original, false).await
    }

    async fn record_observed_use(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        original: SourceConsumerUse,
        new_use: bool,
    ) -> SourceCustodyResult<()> {
        // V1 covers one exact installed source. A newly installed, missing or
        // additional source cannot use a stale legacy or single-source owner.
        let rows = sqlx::query("select source_owner_id::text,encode(source_file_binding,'hex') binding,source_public_key,database_role=session_user role_matches from control.runtime_artifact_source where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid")
            .bind(&self.participant).bind(&self.privacy).fetch_all(&mut **tx).await
            .map_err(super::control::unavailable)?;
        match &self.custody {
            None if rows.is_empty() => {
                Self::require_uninstalled_in(tx, &self.participant, &self.privacy).await
            }
            None => Err(RuntimeError::InvalidAuthorization.into()),
            Some(custody) => {
                let mut custody = custody.lock().await;
                custody.verify_installed_root(tx).await?;
                let row = rows
                    .first()
                    .filter(|_| rows.len() == 1)
                    .ok_or(RuntimeError::InvalidAuthorization)?;
                let source: String = row
                    .try_get("source_owner_id")
                    .map_err(super::control::unavailable)?;
                let binding: String = row
                    .try_get("binding")
                    .map_err(super::control::unavailable)?;
                let key: Vec<u8> = row
                    .try_get("source_public_key")
                    .map_err(super::control::unavailable)?;
                let role_matches: bool = row
                    .try_get("role_matches")
                    .map_err(super::control::unavailable)?;
                if !role_matches
                    || source != custody.installation.source_owner_id
                    || binding != custody.installation.source_file_binding.as_str()
                    || key != custody.signer.verifier().sec1_bytes()
                    || (new_use && custody.denies(&original.configuration_digest)?)
                {
                    return Err(RuntimeError::InvalidAuthorization.into());
                }
                custody
                    .record_observation(super::history::Observation::ConsumedOrUnknown(original))?;
                Ok(())
            }
        }
    }

    /// Acquire the shared producer's first fence before module/policy/row
    /// owners. Contention is a deferral, never a reason to reverse-wait.
    pub async fn lock_consumer_scope(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> SourceCustodyResult<()> {
        let row = sqlx::query("select openpc.assert_request_context(true),openpc.current_participant_id()=$1::text::uuid and openpc.current_privacy_domain_id()=$2::text::uuid scoped,pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1,0)) acquired")
            .bind(&self.participant).bind(&self.privacy).fetch_one(&mut **tx).await.map_err(super::control::unavailable)?;
        if !row
            .try_get::<bool, _>("scoped")
            .map_err(super::control::unavailable)?
        {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        if !row
            .try_get::<bool, _>("acquired")
            .map_err(super::control::unavailable)?
        {
            return Err(SourceCustodyError::Busy);
        }
        Ok(())
    }
    /// Legacy native custody has no source-history proof. It can retain its
    /// existing behavior only while the actual scope has no installed source.
    pub async fn require_legacy_consumer(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> SourceCustodyResult<()> {
        self.lock_consumer_scope(tx).await?;
        if self.custody.is_some() {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        Self::require_uninstalled_in(tx, &self.participant, &self.privacy).await
    }

    pub(crate) async fn require_uninstalled_in(
        tx: &mut Transaction<'_, Postgres>,
        participant: &str,
        privacy: &str,
    ) -> SourceCustodyResult<()> {
        let row = sqlx::query("select openpc.assert_request_context(true),openpc.current_participant_id()=$1::text::uuid and openpc.current_privacy_domain_id()=$2::text::uuid and not exists(select 1 from control.runtime_artifact_source where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid) allowed,pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1,0)) acquired")
            .bind(participant).bind(privacy).fetch_one(&mut **tx).await.map_err(super::control::unavailable)?;
        if !row
            .try_get::<bool, _>("acquired")
            .map_err(super::control::unavailable)?
        {
            return Err(SourceCustodyError::Busy);
        }
        if !row
            .try_get::<bool, _>("allowed")
            .map_err(super::control::unavailable)?
        {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        if super::installation::authenticate(tx, participant, privacy).await?
            != super::installation::Mode::LegacyUnproven
        {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        Ok(())
    }
}
