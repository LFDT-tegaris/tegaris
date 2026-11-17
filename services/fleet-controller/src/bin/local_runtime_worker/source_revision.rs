//! The accepted public operation owns one source revision. Matching bytes after
//! an A -> B -> A update do not let old work qualify or quarantine the new row.
use super::{ClaimedWork, Postgres, Transaction, WorkerResult};
use sqlx::Row;

pub(super) const SUPERSEDED: &str = "source work revision superseded";

#[cfg(test)]
#[path = "source_revision_tests.rs"]
mod database_tests;

pub(super) struct SourceRevision {
    accepted: i64,
    pub(super) current: bool,
}

/// Lock the resource before work/result locks on both completion and failure.
/// The operation's accepted revision is durable across leases and restarts.
pub(super) async fn lock(
    transaction: &mut Transaction<'_, Postgres>,
    work: &ClaimedWork,
) -> WorkerResult<Option<SourceRevision>> {
    let query = match work.work_kind.as_str() {
        "INDEXER_ADMISSION" => {
            "select revision::bigint,method_profile_digest as digest,state='SHADOW' as pending from control.indexer_profile where indexer_profile_id=$1::text::uuid and participant_id=$2::text::uuid and privacy_domain_id=$3::text::uuid for update"
        }
        "PROJECTION_VALIDATION" => {
            "select revision::bigint,plan_digest as digest,state='DRAFT' and readiness='UNKNOWN' as pending from control.projection_plan where projection_plan_id=$1::text::uuid and participant_id=$2::text::uuid and privacy_domain_id=$3::text::uuid for update"
        }
        _ => return Ok(None),
    };
    let resource = sqlx::query(query)
        .bind(&work.resource_id)
        .bind(&work.participant_id)
        .bind(&work.privacy_domain_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| "source revision unavailable".to_owned())?;
    let accepted: i64 = sqlx::query_scalar(
        "select result.result_aggregate_version::bigint from control.configuration_work work join control.idempotency_record result on result.participant_id=work.participant_id and result.privacy_domain_id=work.privacy_domain_id and result.operation_id=work.operation_id where work.configuration_work_id=$1::text::uuid and work.operation_id=$2::text::uuid and work.participant_id=$3::text::uuid and work.privacy_domain_id=$4::text::uuid and work.resource_id=$5::text::uuid and work.work_kind=$6 and work.input_digest=$7 and result.terminal_state='COMMITTED' and result.result_payload->>'state'='ACCEPTED' and result.result_payload->>'truthState'='UNKNOWN' and result.result_payload->>'resourceRef'='urn:openpc:resource:'||work.resource_id::text",
    )
    .bind(&work.work_id)
    .bind(&work.operation_id)
    .bind(&work.participant_id)
    .bind(&work.privacy_domain_id)
    .bind(&work.resource_id)
    .bind(&work.work_kind)
    .bind(&work.input_digest)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| "accepted source revision unavailable".to_owned())?;
    let current = resource.is_some_and(|row| {
        row.get::<i64, _>("revision") == accepted
            && row.get::<String, _>("digest") == work.input_digest
            && row.get::<bool, _>("pending")
    });
    Ok(Some(SourceRevision { accepted, current }))
}

impl SourceRevision {
    pub(super) fn require_current(&self) -> WorkerResult<()> {
        if self.current {
            Ok(())
        } else {
            Err(SUPERSEDED.into())
        }
    }

    pub(super) async fn finish(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        work: &ClaimedWork,
        success: bool,
    ) -> WorkerResult<i64> {
        if success {
            self.require_current()?;
        } else if !self.current {
            // Report the failed old operation at its own accepted revision;
            // never claim a transition or quarantine on the replacement row.
            return Ok(self.accepted);
        }
        let query = match work.work_kind.as_str() {
            "INDEXER_ADMISSION" => {
                "update control.indexer_profile set state=$5,revision=revision+1,updated_at=clock_timestamp() where indexer_profile_id=$1::text::uuid and participant_id=$2::text::uuid and privacy_domain_id=$3::text::uuid and revision=$4 and state='SHADOW' and method_profile_digest=$6 returning revision::bigint"
            }
            "PROJECTION_VALIDATION" => {
                "update control.projection_plan set state=case when $5='QUALIFIED' then 'VALIDATED' else 'DRAFT' end,readiness=case when $5='QUALIFIED' then 'READY' else 'NOT_READY' end,revision=revision+1,updated_at=clock_timestamp() where projection_plan_id=$1::text::uuid and participant_id=$2::text::uuid and privacy_domain_id=$3::text::uuid and revision=$4 and state='DRAFT' and readiness='UNKNOWN' and plan_digest=$6 returning revision::bigint"
            }
            _ => return Err("source work kind rejected".into()),
        };
        sqlx::query_scalar(query)
            .bind(&work.resource_id)
            .bind(&work.participant_id)
            .bind(&work.privacy_domain_id)
            .bind(self.accepted)
            .bind(if success { "QUALIFIED" } else { "QUARANTINED" })
            .bind(&work.input_digest)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| "source result compare-and-set rejected".to_owned())
    }
}
