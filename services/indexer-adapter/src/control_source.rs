//! One exact qualified source selection for manager publication and dispatch.
//! The caller chooses its lock owner; these rows alone grant no source authority.
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};

pub async fn load(
    tx: &mut Transaction<'_, Postgres>,
    participant: &str,
    privacy: &str,
    plan_id: Option<&str>,
    lock: bool,
) -> Result<Vec<PgRow>, String> {
    const QUERY: &str = r#"
          select p.projection_plan_id::text,p.revision as projection_revision,p.plan_digest,
            i.indexer_profile_id::text,i.revision as source_revision,i.method_profile_digest,
            qualification.operation_id::text as qualification_operation_id,
            validation.operation_id::text as validation_operation_id,
            validation.configuration_digest,validation.result_receipt,
            qualification.result_receipt as qualification_receipt,
            configuration.configuration_cbor,
            encode(configuration.configuration_digest,'hex') as active_configuration_digest
          from control.projection_plan p
          join control.indexer_profile i on i.indexer_profile_id=p.indexer_profile_id
            and i.participant_id=p.participant_id and i.privacy_domain_id=p.privacy_domain_id
          join control.configuration_work validation on validation.resource_id=p.projection_plan_id
            and validation.participant_id=p.participant_id and validation.privacy_domain_id=p.privacy_domain_id
            and validation.work_kind='PROJECTION_VALIDATION' and validation.state='COMPLETED'
            and validation.input_digest=p.plan_digest
          join control.idempotency_record validated on validated.operation_id=validation.operation_id
            and validated.participant_id=p.participant_id and validated.privacy_domain_id=p.privacy_domain_id
            and validated.terminal_state='COMMITTED' and validated.result_payload->>'state'='SUCCEEDED'
            and validated.result_aggregate_version=p.revision
          join control.configuration_work qualification on qualification.resource_id=i.indexer_profile_id
            and qualification.participant_id=i.participant_id and qualification.privacy_domain_id=i.privacy_domain_id
            and qualification.work_kind='INDEXER_ADMISSION' and qualification.state='COMPLETED'
            and qualification.input_digest=i.method_profile_digest
            and qualification.operation_id::text=validation.result_receipt->>'profileQualificationOperationId'
          join control.idempotency_record qualified on qualified.operation_id=qualification.operation_id
            and qualified.participant_id=i.participant_id and qualified.privacy_domain_id=i.privacy_domain_id
            and qualified.terminal_state='COMMITTED' and qualified.result_payload->>'state'='SUCCEEDED'
            and qualified.result_aggregate_version=i.revision
          join control.module_installation installation on installation.participant_id=p.participant_id
            and installation.privacy_domain_id=p.privacy_domain_id and installation.state='ENABLED'
          join control.module_version version on version.module_version_id=installation.module_version_id
            and version.module_id='pc.config.assets'
          join control.runtime_configuration_input_current configuration
            on configuration.module_installation_id=installation.module_installation_id and configuration.active
          where p.participant_id=$1::text::uuid and p.privacy_domain_id=$2::text::uuid
            and ($3::text is null or p.projection_plan_id::text=$3)
            and p.state='VALIDATED' and p.readiness='READY' and i.state in ('QUALIFIED','ACTIVE')
            and validation.result_receipt->>'profileQualificationRevision'=i.revision::text
            and validation.result_receipt->>'profileResourceId'=i.indexer_profile_id::text
            and validation.result_receipt->>'profileArtifactDigest'=i.method_profile_digest
          order by p.projection_plan_id
        "#;
    // Resolve eligible owners without releasing payloads first. The final query
    // retains every qualification predicate and the caller's original locks.
    let metadata = QUERY
        .replace(
            "configuration.configuration_cbor,",
            "configuration.runtime_configuration_input_id::text input_id,",
        )
        .replace(
            "control.runtime_configuration_input_current",
            "control.runtime_configuration_input_current_metadata",
        );
    let mut query = sqlx::QueryBuilder::<Postgres>::new(metadata);
    if lock {
        query.push(" for share of p,i");
    }
    let rows = query
        .build()
        .bind(participant)
        .bind(privacy)
        .bind(plan_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(|_| "current indexer source metadata unavailable")?;
    let mut inputs = std::collections::BTreeSet::new();
    for row in rows {
        inputs.insert(
            row.try_get::<String, _>("input_id")
                .map_err(|_| "current source identity rejected")?,
        );
    }
    if inputs.is_empty() {
        return Ok(Vec::new());
    }
    for input in inputs {
        crate::control_materialization::authorize_input(tx, &input).await?;
    }
    let mut query = sqlx::QueryBuilder::<Postgres>::new(QUERY);
    if lock {
        query.push(" for share of p,i");
    }
    query
        .build()
        .bind(participant)
        .bind(privacy)
        .bind(plan_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(|_| "current indexer publication owners unavailable".into())
}
