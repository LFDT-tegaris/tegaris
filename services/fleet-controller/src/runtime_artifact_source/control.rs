//! Continuing custody requires the exact committed Control admissions. A
//! restored database missing a journaled admission cannot start the source.
use super::*;
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::Generate;
use sha2::Sha256;
use sqlx::{PgPool, Postgres, Row, Transaction};

pub(super) fn unavailable(_: impl std::fmt::Debug) -> RuntimeError {
    RuntimeError::RuntimeUnavailable
}

pub(super) fn database_error(error: sqlx::Error) -> SourceCustodyError {
    use crate::runtime_configuration_input::{
        RUNTIME_ARTIFACT_BUSY, runtime_artifact_database_error,
    };
    if runtime_artifact_database_error(error) == RUNTIME_ARTIFACT_BUSY {
        SourceCustodyError::Busy
    } else {
        RuntimeError::RuntimeUnavailable.into()
    }
}

pub(super) fn nonce() -> RuntimeResult<[u8; 32]> {
    <[u8; 32]>::try_generate().map_err(unavailable)
}

pub(super) fn commit_mac(
    key: &[u8; 32],
    transaction: &str,
    wire: &[u8],
    nonce: &[u8],
) -> RuntimeResult<Vec<u8>> {
    if nonce.len() != 32 {
        return Err(RuntimeError::RuntimeUnavailable);
    }
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(unavailable)?;
    mac.update(b"OPENPC_RUNTIME_ARTIFACT_SOURCE_DENIAL_COMMIT_V1");
    mac.update(transaction.as_bytes());
    mac.update(Digest::of(wire).as_str().as_bytes());
    mac.update(nonce);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(super) async fn context(
    pool: &PgPool,
    participant: &str,
    privacy: &str,
) -> SourceCustodyResult<Transaction<'static, Postgres>> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',true),openpc.assert_request_context(true)")
        .bind(participant).bind(privacy).execute(&mut *tx).await.map_err(unavailable)?;
    // Classify only actual fence acquisition. Later inventory/capacity errors
    // can use the same SQL code and must not become silent deferrals.
    sqlx::query("select openpc.lock_runtime_artifact_source_custody()")
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    Ok(tx)
}

impl RuntimeArtifactSourceCustody {
    pub(super) async fn admissions(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> SourceCustodyResult<Vec<(SourceDispositionAdmission, Option<Vec<u8>>)>> {
        self.checked_state()?;
        let installed = canonical_bytes(&self.installation)?;
        // This owner authenticates the installed source identity/key and takes
        // lifecycle -> module -> policy fences before reading committed intent.
        // Missing SQL/grants/installation are failures, never an empty inventory.
        let rows = sqlx::query("select admission,signed_denial from openpc.read_runtime_artifact_source_admissions($1::jsonb,$2)")
            .bind(serde_json::from_slice::<serde_json::Value>(&installed).map_err(unavailable)?)
            .bind(self.signer.verifier().sec1_bytes())
            .fetch_all(&mut **tx).await.map_err(unavailable)?;
        self.verify_installed_root(tx).await?;
        if rows.len() > MAX_DENIALS {
            return Err(RuntimeError::RuntimeUnavailable.into());
        }
        let mut admissions = Vec::with_capacity(rows.len());
        for row in rows {
            let value: serde_json::Value = row.try_get("admission").map_err(unavailable)?;
            let admission: SourceDispositionAdmission =
                serde_json::from_value(value).map_err(unavailable)?;
            admission.validate()?;
            if admission.installation != self.installation {
                return Err(RuntimeError::InvalidAuthorization.into());
            }
            admissions.push((
                admission,
                row.try_get("signed_denial").map_err(unavailable)?,
            ));
        }
        self.require_control_custody(&admissions)?;
        Ok(admissions)
    }

    pub(super) async fn verify_installed_root(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> SourceCustodyResult<()> {
        match super::installation::authenticate(
            tx,
            &self.installation.participant_id,
            &self.installation.privacy_domain_id,
        )
        .await?
        {
            super::installation::Mode::Rooted(binding)
                if binding.installation == self.installation
                    && self.checked_state()?.retained_root.as_ref() == Some(&binding.root)
                    && binding.archive_custody.as_ref()
                        == self.archive.as_ref().map(|archive| &archive.binding)
                    && binding.source_public_key == self.signer.verifier().sec1_bytes() => {}
            super::installation::Mode::LegacyUnproven
                if self.checked_state()?.retained_root.is_none() => {}
            _ => return Err(RuntimeError::InvalidAuthorization.into()),
        }
        let installed: Option<serde_json::Value> = sqlx::query_scalar("select custody_root from control.runtime_artifact_source where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and source_owner_id=$3::text::uuid")
            .bind(&self.installation.participant_id).bind(&self.installation.privacy_domain_id)
            .bind(&self.installation.source_owner_id).fetch_one(&mut **tx).await.map_err(unavailable)?;
        let expected = self
            .checked_state()?
            .retained_root
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(unavailable)?;
        if installed != expected {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        if let Some(binding) = &self.checked_state()?.retained_root
            && binding.consumer_profile == retained_root::MATERIALIZATION_PROFILE
        {
            sqlx::query("select openpc.assert_runtime_artifact_materialization_boundary()")
                .execute(&mut **tx)
                .await
                .map_err(unavailable)?;
            let database: serde_json::Value =
                sqlx::query_scalar("select openpc.runtime_artifact_database_identity()")
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(unavailable)?;
            if database != serde_json::to_value(&binding.database).map_err(unavailable)? {
                return Err(RuntimeError::InvalidAuthorization.into());
            }
        }
        Ok(())
    }

    pub(super) fn require_control_custody(
        &self,
        admissions: &[(SourceDispositionAdmission, Option<Vec<u8>>)],
    ) -> RuntimeResult<()> {
        let entries = &self.checked_state()?.entries;
        let mut ids = BTreeSet::new();
        let mut digests = BTreeSet::new();
        for (admission, signed) in admissions {
            admission.validate()?;
            if admission.installation != self.installation
                || !ids.insert(&admission.disposition_id)
                || !digests.insert(&admission.configuration_digest)
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            if let Some(wire) = signed {
                // SQL cannot claim an effect whose exact signed original is
                // absent from this independent, authenticated native custody.
                if !entries.iter().any(|entry| {
                    entry.denial.admission == *admission
                        && entry.signed_denial.as_ref() == Some(wire)
                }) {
                    return Err(RuntimeError::InvalidAuthorization);
                }
            }
        }
        for entry in entries {
            if !admissions
                .iter()
                .any(|(admission, _)| *admission == entry.denial.admission)
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
        }
        Ok(())
    }

    /// The independent journal can survive an unknown SQL COMMIT. Reconcile
    /// only its exact original identity from real committed source bytes. An
    /// absent row remains pending; a substituted identity or corrupt payload
    /// fails closed. No source row, business outcome or first-issue permit is
    /// constructed here.
    async fn reconcile_pending_imports(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> SourceCustodyResult<()> {
        for observation in self.verify_import_readback(tx).await? {
            self.record_observation(observation)?;
        }
        Ok(())
    }

    pub(super) async fn verify_import_readback(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> SourceCustodyResult<Vec<super::history::Observation>> {
        let Some(history) = &self.checked_state()?.history else {
            return Ok(Vec::new());
        };
        let mut reconciled = Vec::new();
        let retirements = history.retirements(&self.history_signer)?;
        for (original, committed) in history.imports(&self.history_signer)? {
            let rows = sqlx::query("select runtime_configuration_input_id::text input_id,module_installation_id::text,module_configuration_generation_id::text,encode(configuration_digest,'hex') configuration_digest,(openpc.runtime_artifact_input_information(runtime_configuration_input_id)->>'bytesMatch')::boolean integrity from control.runtime_configuration_input where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and (runtime_configuration_input_id=$3::text::uuid or (module_configuration_generation_id=$4::text::uuid and configuration_digest=decode($5,'hex'))) limit 2")
                .bind(&self.installation.participant_id).bind(&self.installation.privacy_domain_id)
                .bind(&original.input_id).bind(&original.module_configuration_generation_id).bind(original.configuration_digest.as_str())
                .fetch_all(&mut **tx).await.map_err(unavailable)?;
            if rows.is_empty() {
                if committed {
                    // Only the exact independently committed physical receipt
                    // can explain absence. Persist its original identity in
                    // the existing native chain before further source use.
                    reconciled.push(super::history::Observation::RetirementCommitted(
                        self.read_retirement(tx, &original).await?,
                    ));
                }
                continue;
            }
            if rows.len() != 1
                || retirements.iter().any(|retirement| {
                    retirement.input.input_id == original.input_id
                        || retirement.input.configuration_digest == original.configuration_digest
                })
            {
                return Err(RuntimeError::InvalidAuthorization.into());
            }
            let row = &rows[0];
            let actual = super::history::ImportIdentity {
                input_id: row.try_get("input_id").map_err(unavailable)?,
                module_installation_id: row
                    .try_get("module_installation_id")
                    .map_err(unavailable)?,
                module_configuration_generation_id: row
                    .try_get("module_configuration_generation_id")
                    .map_err(unavailable)?,
                configuration_digest: Digest::parse(
                    &row.try_get::<String, _>("configuration_digest")
                        .map_err(unavailable)?,
                )?,
            };
            if actual != original || !row.try_get::<bool, _>("integrity").map_err(unavailable)? {
                return Err(RuntimeError::InvalidAuthorization.into());
            }
            if !committed {
                reconciled.push(super::history::Observation::ImportCommitted(original));
            }
        }
        Ok(reconciled)
    }

    /// Required before source or target startup, and during each reconciliation.
    /// A Control backup cannot erase an irreversible local denial. Recovery must
    /// preserve the actual governed admission; this method never recreates it.
    pub async fn verify_control_custody(&self, pool: &PgPool) -> SourceCustodyResult<()> {
        let mut tx = context(
            pool,
            &self.installation.participant_id,
            &self.installation.privacy_domain_id,
        )
        .await?;
        self.admissions(&mut tx).await?;
        self.verify_import_readback(&mut tx).await?;
        self.read_archives(&mut tx).await?;
        tx.commit().await.map_err(|error| unavailable(error).into())
    }

    /// Process one actual committed admission. The first native journal write
    /// burns issuance before signing. A retained signed result is republished
    /// byte-for-byte; an unsigned pending result remains unknown and denied.
    pub async fn reconcile_one(
        &mut self,
        pool: &PgPool,
        commit_key: &[u8; 32],
    ) -> SourceCustodyResult<bool> {
        if PurposeSigner::from_secret_bytes(PURPOSE, *commit_key)
            .is_ok_and(|key| key.verifier().sec1_bytes() == self.signer.verifier().sec1_bytes())
        {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        let mut tx = context(
            pool,
            &self.installation.participant_id,
            &self.installation.privacy_domain_id,
        )
        .await?;
        let admissions = self.admissions(&mut tx).await?;
        self.reconcile_pending_imports(&mut tx).await?;
        for archive in self.read_archives(&mut tx).await? {
            self.record_observation(history::Observation::ArchiveCustodyCommitted(archive))?;
        }
        let next = admissions.into_iter().find(|(_, wire)| wire.is_none());
        let Some((admission, _)) = next else {
            tx.commit().await.map_err(unavailable)?;
            return Ok(false);
        };
        let transaction: String = sqlx::query_scalar("select pg_current_xact_id()::text")
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        let nonce = nonce()?.to_vec();
        // Validate the installed publication key before consuming first issue.
        // This verifier has no write effect and grants no disposition intent.
        let challenge = canonical_bytes(&self.installation)?;
        sqlx::query("select openpc.verify_runtime_artifact_source_commit($1::text::uuid,$2,$3,$4)")
            .bind(&self.installation.source_owner_id)
            .bind(&challenge)
            .bind(&nonce)
            .bind(commit_mac(commit_key, &transaction, &challenge, &nonce)?)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let retained = self
            .checked_state()?
            .entries
            .iter()
            .find(|entry| entry.denial.admission == admission);
        let wire = match retained {
            Some(entry) => entry
                .signed_denial
                .clone()
                .ok_or(RuntimeError::RuntimeUnavailable)?,
            None => {
                let permit = self.begin_governed(admission.clone())?;
                self.finish(permit)?
            }
        };
        sqlx::query("select openpc.commit_runtime_artifact_source_denial($1::text::uuid,$2,$3,$4)")
            .bind(&admission.disposition_id)
            .bind(&wire)
            .bind(&nonce)
            .bind(commit_mac(commit_key, &transaction, &wire, &nonce)?)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(true)
    }
}
