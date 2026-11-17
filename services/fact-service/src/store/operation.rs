//! A public admission operation is a binding on the committed feed receipt.
//! It is not another fact lifecycle or an assertion of shard readiness.
use super::*;
use uuid::Uuid;

pub(crate) const UPDATE_ACTION: &str = "ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1";
pub(crate) const UPDATE_DIGEST: &str =
    "sha256:1e0f1ff216ab9a4d35b7467f767710e05e827dc8e40943aa35d6719298c5ac2a";

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactOperationBinding {
    pub operation_id: Uuid,
    pub principal_id: Uuid,
    pub candidate_id: Uuid,
    pub idempotency_key: String,
    pub input_digest: String,
    pub expected_revision: String,
}

impl FactOperationBinding {
    pub(crate) fn valid(&self) -> bool {
        [self.operation_id, self.principal_id, self.candidate_id]
            .iter()
            .all(|id| id.get_version_num() == 7)
            && (16..=128).contains(&self.idempotency_key.len())
            && self
                .idempotency_key
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._~-".contains(&c))
            && self.input_digest.len() == 71
            && self.input_digest.starts_with("sha256:")
            && self.input_digest[7..]
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            && self
                .expected_revision
                .parse::<u64>()
                .is_ok_and(|v| v > 0 && v.to_string() == self.expected_revision)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FactOperation {
    pub operation_id: Uuid,
    pub resource_ref: String,
    pub action_intent_id: &'static str,
    pub intent_digest: &'static str,
    pub idempotency_key: String,
    pub state: &'static str,
    pub truth_state: &'static str,
    pub revision: String,
    pub created_at: String,
    pub updated_at: String,
}

impl FactStore {
    pub(crate) async fn bind_feed_operation_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        participant: &str,
        privacy: &str,
        binding: &FactOperationBinding,
        outcome: DurableAdmissionOutcome,
    ) -> Result<(), FactStoreError> {
        if !binding.valid() {
            return Err(FactStoreError::Feed);
        }
        let document = serde_json::to_string(binding).map_err(|_| FactStoreError::Feed)?;
        let outcome = if outcome == DurableAdmissionOutcome::Conflicting {
            "CONFLICTING"
        } else {
            "ADMITTED"
        };
        let mut bytes = Vec::new();
        for (index, field) in [
            participant,
            privacy,
            document.as_str(),
            outcome,
            "FACT_ARTIFACT_OPERATION",
        ]
        .iter()
        .enumerate()
        {
            bytes.extend_from_slice(&((index + 1) as u16).to_be_bytes());
            bytes.push(1);
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        let capability = self.capabilities.lineage(&pc_facts_core::sha256(&bytes));
        sqlx::query("select facts.bind_admission_operation($1,$2,$3,$4,$5,$6)")
            .bind(participant)
            .bind(privacy)
            .bind(document)
            .bind(outcome)
            .bind(capability.nonce.as_slice())
            .bind(capability.mac.as_slice())
            .execute(&mut **tx)
            .await
            .map_err(map_database_error)?;
        Ok(())
    }

    pub(crate) async fn bind_feed_operation(
        &self,
        participant: &str,
        privacy: &str,
        binding: &FactOperationBinding,
    ) -> Result<(), FactStoreError> {
        let mut tx = self.pool.begin().await?;
        set_context(&mut tx, participant, privacy).await?;
        // Existing admission effects may predate their first public command.
        // Binding never inserts a fact or changes readiness.
        let conflicting: bool = sqlx::query_scalar("select exists(select 1 from facts.semantic_occurrence s join facts.occurrence_conflict c using(participant_id,privacy_domain_id,occurrence_digest) where s.participant_id=$1 and s.privacy_domain_id=$2 and s.candidate_id=$3)")
            .bind(participant).bind(privacy).bind(binding.candidate_id.to_string()).fetch_one(&mut *tx).await?;
        self.bind_feed_operation_in(
            &mut tx,
            participant,
            privacy,
            binding,
            if conflicting {
                DurableAdmissionOutcome::Conflicting
            } else {
                DurableAdmissionOutcome::IdempotentReplay
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn admission_operation(
        &self,
        participant: &str,
        privacy: &str,
        principal: Uuid,
        operation: Option<Uuid>,
        key: Option<&str>,
        expected: Option<&FactOperationBinding>,
    ) -> Result<Option<FactOperation>, FactStoreError> {
        if operation.is_some() == key.is_some() {
            return Err(FactStoreError::Feed);
        }
        let mut tx = self.pool.begin().await?;
        set_context(&mut tx, participant, privacy).await?;
        let row = sqlx::query("select candidate_id,operation_binding,operation_outcome,
          to_char(operation_bound_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') bound_at
          from facts.candidate_feed_receipt where participant_id=$1 and privacy_domain_id=$2
          and operation_binding->>'principalId'=$3
          and (($4::text is not null and operation_binding->>'operationId'=$4)
            or ($5::text is not null and operation_binding->>'idempotencyKey'=$5))")
            .bind(participant).bind(privacy).bind(principal.to_string())
            .bind(operation.map(|v| v.to_string())).bind(key).fetch_optional(&mut *tx).await?;
        let result = row
            .map(|row| -> Result<_, FactStoreError> {
                let saved: FactOperationBinding =
                    serde_json::from_value(row.try_get("operation_binding")?)
                        .map_err(|_| FactStoreError::Feed)?;
                if let Some(expected) = expected
                    && (saved.candidate_id != expected.candidate_id
                        || saved.input_digest != expected.input_digest
                        || saved.expected_revision != expected.expected_revision
                        || saved.idempotency_key != expected.idempotency_key)
                {
                    return Err(FactStoreError::ReplayDigestMismatch);
                }
                let failed = row.try_get::<String, _>("operation_outcome")? == "CONFLICTING";
                let bound_at: String = row.try_get("bound_at")?;
                Ok(FactOperation {
                    operation_id: saved.operation_id,
                    resource_ref: format!("urn:openpc:resource:{}", saved.candidate_id),
                    action_intent_id: UPDATE_ACTION,
                    intent_digest: UPDATE_DIGEST,
                    idempotency_key: saved.idempotency_key,
                    state: if failed { "FAILED" } else { "SUCCEEDED" },
                    truth_state: if failed { "FAILED" } else { "SUCCESS" },
                    revision: "1".into(),
                    created_at: bound_at.clone(),
                    updated_at: bound_at,
                })
            })
            .transpose()?;
        tx.commit().await?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
