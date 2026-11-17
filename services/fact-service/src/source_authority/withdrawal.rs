//! Off-path verification of a durable source-manager removal occurrence. This
//! observes the current Control owners once per event, never a policy read or
//! the historical acquisition workload credential.
use super::*;
use crate::candidate_feed::withdrawal::SourceFence;

pub(crate) struct VerifiedSourceWithdrawal {
    pub fence: SourceFence,
    pub authority_digest: [u8; 32],
    transaction: Transaction<'static, Postgres>,
}

impl VerifiedSourceWithdrawal {
    pub async fn confirm(&mut self) -> Result<()> {
        sqlx::query("select 1")
            .execute(&mut *self.transaction)
            .await?;
        Ok(())
    }
}

impl FactSourceAuthority {
    pub(crate) async fn verify_withdrawal(
        &self,
        fence: SourceFence,
        operation: Uuid,
    ) -> Result<Option<VerifiedSourceWithdrawal>> {
        let text = |name| {
            fence
                .publication_text(name)
                .map_err(|_| SourceAuthorityError::Binding)
        };
        let plan = Uuid::parse_str(text("projectionPlanId")?)
            .map_err(|_| SourceAuthorityError::Binding)?;
        let indexer = Uuid::parse_str(text("indexerProfileId")?)
            .map_err(|_| SourceAuthorityError::Binding)?;
        if plan.get_version_num() != 7 || indexer.get_version_num() != 7 {
            return Err(SourceAuthorityError::Binding);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("set local statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("set local lock_timeout='3s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("set local idle_in_transaction_session_timeout='45s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',false)")
            .bind(fence.participant).bind(fence.privacy).bind(operation).execute(&mut *tx).await?;
        sqlx::query("select openpc.lock_fact_candidate_source($1)")
            .bind(plan)
            .execute(&mut *tx)
            .await?;
        let rows = control_source::load(
            &mut tx,
            &fence.participant.to_string(),
            &fence.privacy.to_string(),
            Some(&plan.to_string()),
            false,
        )
        .await
        .map_err(|_| SourceAuthorityError::Binding)?;
        if rows.len() > 1 {
            return Err(SourceAuthorityError::Binding);
        }
        let mut withdrawn = rows.is_empty();
        let mut current = serde_json::Value::Null;
        if let Some(row) = rows.first() {
            let fields = [
                (
                    "indexerProfileId",
                    row.try_get::<String, _>("indexer_profile_id")?,
                ),
                (
                    "sourceRevision",
                    row.try_get::<i64, _>("source_revision")?.to_string(),
                ),
                (
                    "projectionRevision",
                    row.try_get::<i64, _>("projection_revision")?.to_string(),
                ),
                (
                    "qualificationOperationId",
                    row.try_get::<String, _>("qualification_operation_id")?,
                ),
                (
                    "validationOperationId",
                    row.try_get::<String, _>("validation_operation_id")?,
                ),
            ];
            for (name, value) in &fields {
                withdrawn |= text(name)? != value;
            }
            let active = digest(row.try_get("active_configuration_digest")?)?;
            withdrawn |= digest(text("configurationDigest")?)? != active;
            let mut provider_quorum = None;
            if !withdrawn {
                let bytes: Vec<u8> = row.try_get("configuration_cbor")?;
                let config = decode_active_invocation_configuration(&bytes, &active)
                    .map_err(|_| SourceAuthorityError::Binding)?;
                let profile = config
                    .resource_artifacts
                    .iter()
                    .find(|a| {
                        a.artifact_kind == ConfigurationArtifactKind::ClientIndexerProfile
                            && a.artifact_id == indexer.to_string()
                    })
                    .ok_or(SourceAuthorityError::Binding)?;
                let profile = openpc_indexer_adapter::admit_scoped_client_indexer_profile(
                    &profile.payload_cbor,
                    &format!("sha256:{}", profile.artifact_digest.as_str()),
                    &fence.participant.to_string(),
                    &fence.privacy.to_string(),
                )
                .map_err(|_| SourceAuthorityError::Binding)?;
                let rule_bytes = load_active_configuration_artifact(
                    &bytes,
                    &active,
                    &indexer.to_string(),
                    ConfigurationArtifactKind::IndexerFinalityRule,
                    &digest(&profile.finality_rule_digest)?,
                )
                .map_err(|_| SourceAuthorityError::Binding)?;
                let rule = openpc_indexer_adapter::FinalityRule::resolve(&profile, &rule_bytes)
                    .map_err(|_| SourceAuthorityError::Binding)?;
                let mut qualified = 0usize;
                for expected in &rule.canonical_provider_digests {
                    let provider = config
                        .resource_artifacts
                        .iter()
                        .find(|a| {
                            a.artifact_kind == ConfigurationArtifactKind::ProviderProfile
                                && digest(expected).is_ok_and(|value| value == a.artifact_digest)
                        })
                        .ok_or(SourceAuthorityError::Binding)?;
                    let expiry: Option<i64> = sqlx::query_scalar(
                        "select openpc.lock_indexer_qualified_provider($1::text::uuid,$2)",
                    )
                    .bind(&provider.artifact_id)
                    .bind(expected)
                    .fetch_one(&mut *tx)
                    .await?;
                    qualified += usize::from(expiry.is_some());
                }
                withdrawn = qualified < usize::from(rule.required_observations);
                provider_quorum = Some(qualified);
            }
            current = serde_json::json!({"owners":fields,"configurationDigest":active,"qualifiedProviderCount":provider_quorum});
        }
        if !withdrawn {
            tx.rollback().await?;
            return Ok(None);
        }
        let evidence=crate::state_value::canonical(&serde_json::json!({
            "purpose":"openpc:fact-source-withdrawal:v1","participantId":fence.participant,"privacyDomainId":fence.privacy,
            "eventId":fence.event_id,"eventDigest":crate::signing::shard::digest_text(&pc_facts_core::sha256(&fence.payload)),
            "publicationDigest":crate::signing::shard::digest_text(&fence.publication_digest),"currentControl":current,
        })).map_err(|_|SourceAuthorityError::Binding)?;
        Ok(Some(VerifiedSourceWithdrawal {
            fence,
            authority_digest: pc_facts_core::sha256(&evidence),
            transaction: tx,
        }))
    }
}
