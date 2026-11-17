//! A committed admission burns first-issue authority before signer invocation.
//! A pending row is never a source from which this capability is reconstructed.
use super::*;
use fact_custody::PreparedDispositionSource;
use openpc_fact_service::source_authority::retained::RetainedFactCommitFence;
use serde_json::Value;

// The production implementation remains the installed concrete crypto owner.
// This narrow internal boundary also lets regressions count real signer calls
// independently of database rows or deterministic signature bytes.
pub(super) trait DeliverySigner {
    fn sign_delivery(&self, claims: TargetDispositionDelivery) -> Result<Vec<u8>>;
}
impl DeliverySigner for PurposeSigner {
    fn sign_delivery(&self, claims: TargetDispositionDelivery) -> Result<Vec<u8>> {
        encode_target_disposition_delivery(&self.sign(claims).map_err(|_| unavailable())?)
            .map_err(|_| unavailable())
    }
}

pub(super) struct FirstIssuePermit {
    claims: TargetDispositionDelivery,
    operator_window: Option<(u64, u64)>,
}
impl FirstIssuePermit {
    /// Call only for the authoritative NEW INSERT result, never for readback.
    pub(super) async fn commit_new(
        tx: Transaction<'_, Postgres>,
        fence: Option<RetainedFactCommitFence>,
        claims: TargetDispositionDelivery,
    ) -> Result<Self> {
        // Fact remains fenced through the durable Control admission. A lost
        // commit response or failed post-commit fence yields no capability.
        tx.commit().await.map_err(|_| unavailable())?;
        fact_custody::finish_fact_commit(fence).await?;
        Ok(Self {
            claims,
            operator_window: None,
        })
    }

    pub(super) fn with_operator_window(mut self, issued_ms: u64, expires_ms: u64) -> Self {
        self.operator_window = Some((issued_ms, expires_ms));
        self
    }

    // Ownership is consumed before entering the signer, including error paths.
    // No Clone/serde/reference-taking signing API or retry closure is exposed.
    pub(super) fn sign(self, signer: &impl DeliverySigner) -> Result<Vec<u8>> {
        if let Some((issued, expires)) = self.operator_window {
            let now = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| unavailable())?
                    .as_millis(),
            )
            .map_err(|_| unavailable())?;
            if issued > now
                || now >= expires
                || expires
                    .checked_sub(issued)
                    .is_none_or(|n| n == 0 || n > 120_000)
            {
                return Err(unavailable());
            }
        }
        signer.sign_delivery(self.claims)
    }
}

#[cfg(test)]
#[path = "issuance_tests.rs"]
mod tests;

impl TargetDispositionStore {
    pub(super) async fn lock_issuance(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        claims: &TargetDispositionDelivery,
        worker: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "select openpc.lock_runtime_target_disposition_issuance($1::text::uuid,$2,$3,$4)",
        )
        .bind(&claims.target.target_id)
        .bind(i64::try_from(claims.revision).map_err(|_| unavailable())?)
        .bind(format!(
            "sha256:{}",
            claims.committed_admission_digest.as_str()
        ))
        .bind(worker)
        .execute(&mut **tx)
        .await
        .map_err(|error| withdrawal_database_error("issuance", error))?;
        if let Some(source) = &self.source_custody {
            let original = crate::runtime_artifact_source::SourceConsumerUse {
                configuration_digest: claims.source.configuration_digest.clone(),
                consumer_id: "target-disposition-issuance".into(),
                boundary: Some(crate::runtime_artifact_source::SourceConsumerBoundary::TargetDispositionIssuance),
                target_id: Some(claims.target.target_id.clone()),
                original_id: claims.source.original_work_id.clone(),
            };
            match claims.action {
                pc_runtime_types::target_disposition::TargetDispositionAction::Withdraw => {
                    source.record_consumer_restriction(tx, original).await
                }
                _ => source.record_consumer_use(tx, original).await,
            }
            .map_err(|error| match error {
                crate::runtime_artifact_source::SourceCustodyError::Busy => {
                    TARGET_DISPOSITION_BUSY.into()
                }
                _ => unavailable(),
            })?;
        } else {
            // Keep the actual caller's scope and fence. A second transaction
            // could race installation or contend with the caller's own locks.
            crate::runtime_artifact_source::RuntimeArtifactSourceWorker::require_uninstalled_in(
                tx,
                &self.participant,
                &self.privacy,
            )
            .await
            .map_err(|_| unavailable())?;
        }
        Ok(())
    }

    pub(super) async fn issue_prepared(
        &self,
        original: &OriginalTargetActivation<'_>,
        prepared: &PreparedDispositionSource<'_>,
        proof: &Value,
        permit: FirstIssuePermit,
    ) -> Result<bool> {
        // Keep the original in-memory capability while retrying a confirmed
        // pre-sign rollback. It is never reconstructed from an admission row.
        let mut permit = Some(permit);
        for attempt in 0..5 {
            let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
            let result = async {
                let claims = &permit.as_ref().ok_or_else(unavailable)?.claims;
                self.context(&mut tx).await?;
                let mut sources = prepared
                    .lock(self, &mut tx, &original.peer.target_id)
                    .await?;
                if self
                    .bootstrap_identity(sources.transaction(), original.peer)
                    .await?
                    != claims.target
                {
                    return Err(unavailable());
                }
                let operation = match claims.action {
                    pc_runtime_types::target_disposition::TargetDispositionAction::ConfirmActivation => {
                        "CONFIRM"
                    }
                    pc_runtime_types::target_disposition::TargetDispositionAction::Restore => "RESTORE",
                    _ => return Err(unavailable()),
                };
                // CIGL's native invalidation oracle remains required in this new
                // transaction; the relational helper cannot replace that owner.
                self.lock_current_sources(
                    sources.transaction(),
                    &original.peer.target_id,
                    &serde_json::to_value(&claims.source).map_err(|_| unavailable())?,
                    proof,
                    operation,
                )
                .await?;
                self.lock_issuance(sources.transaction(), claims, None)
                    .await?;
                let row = sqlx::query("select binding,activation_proof,restoration_proof from control.runtime_target_disposition_admission where participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id() and runtime_target_id=$1::text::uuid and revision=$2 and admission_digest=$3")
                    .bind(&original.peer.target_id)
                    .bind(i64::try_from(claims.revision).map_err(|_| unavailable())?)
                    .bind(format!("sha256:{}", claims.committed_admission_digest.as_str()))
                    .fetch_one(&mut **sources.transaction()).await.map_err(database_error)?;
                let column = match claims.action {
                    pc_runtime_types::target_disposition::TargetDispositionAction::ConfirmActivation => {
                        "activation_proof"
                    }
                    pc_runtime_types::target_disposition::TargetDispositionAction::Restore => {
                        "restoration_proof"
                    }
                    _ => return Err(unavailable()),
                };
                let stored: Value = row.try_get(column).map_err(|_| unavailable())?;
                let mut binding: Value = row.try_get("binding").map_err(|_| unavailable())?;
                binding.as_object_mut().ok_or_else(unavailable)?.insert(
                    "committed_admission_digest".into(),
                    serde_json::to_value(&claims.committed_admission_digest)
                        .map_err(|_| unavailable())?,
                );
                if stored != *proof
                    || serde_json::from_value::<TargetDispositionDelivery>(binding)
                        .map_err(|_| unavailable())?
                        != *claims
                {
                    return Err(unavailable());
                }
                sources.require_issuance_proof(proof, original)?;
                let mut live = sources.acquire().await?;
                live.revalidate().await?;
                let wire = permit.take().ok_or_else(unavailable)?.sign(&self.control_signer)?;
                self.commit_in_transaction(live.transaction(), "DELIVERY", &wire)
                    .await?;
                live.into_commit_fence().await
            }.await;
            match result {
                Ok(fence) => {
                    // Signing has consumed the permit. Neither this commit nor
                    // an uncertain delivery can enter the retry path.
                    tx.commit().await.map_err(|_| unavailable())?;
                    fact_custody::finish_fact_commit(fence).await?;
                    return Ok(false);
                }
                Err(error) => {
                    if !retry_unsigned_after_rollback(tx, &error, &permit, attempt).await? {
                        return Err(error);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10 * 3_u64.pow(attempt)))
                        .await;
                }
            }
        }
        Err(unavailable())
    }
}

// A Busy result alone is insufficient: the same unconsumed capability and a
// confirmed rollback are both required. No network/effect retry happens here.
async fn retry_unsigned_after_rollback(
    tx: Transaction<'_, Postgres>,
    error: &str,
    permit: &Option<FirstIssuePermit>,
    attempt: u32,
) -> Result<bool> {
    tx.rollback().await.map_err(|_| unavailable())?;
    Ok(error == TARGET_DISPOSITION_BUSY && permit.is_some() && attempt < 4)
}
