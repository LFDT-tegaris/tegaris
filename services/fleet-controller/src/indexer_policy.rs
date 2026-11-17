//! Resolve dedicated source restrictions from the current Control owners.
//! Compilation authenticates immutable inputs; it is not source qualification,
//! workload authorization, activation or permission to contact a provider.
use pc_policy_core::{
    indexer_policy::{IndexerCompilationInput, compile_indexer_sources},
    semantics::PolicySemanticDocument,
};
use pc_runtime_types::Digest;
use sqlx::PgConnection;
use std::collections::BTreeSet;

pub async fn load_indexer_policy_inputs(
    connection: &mut PgConnection,
    document: &PolicySemanticDocument,
    expected_configuration_digest: &Digest,
) -> Result<Vec<IndexerCompilationInput>, String> {
    if document.indexer_policies.is_empty() {
        return Ok(Vec::new());
    }
    document.validate()?;
    let ids = document
        .indexer_policies
        .iter()
        .map(|policy| policy.projection_plan_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        r#"select plan.projection_plan_id::text,profile.indexer_profile_id::text,
                  plan.plan_digest,profile.method_profile_digest
             from control.projection_plan plan
             join control.indexer_profile profile
               on profile.participant_id=plan.participant_id
              and profile.privacy_domain_id=plan.privacy_domain_id
              and profile.indexer_profile_id=plan.indexer_profile_id
            where plan.participant_id=$1::text::uuid
              and plan.privacy_domain_id=$2::text::uuid
              and plan.projection_plan_id::text=any($3::text[])
              and plan.state<>'RETIRED' and profile.state<>'RETIRED'
            order by plan.projection_plan_id for share of plan,profile"#,
    )
    .bind(&document.participant_id)
    .bind(&document.privacy_domain_id)
    .bind(&ids)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| "policy source references unavailable")?;
    if rows.len() != ids.len()
        || document.indexer_policies.iter().any(|policy| {
            !rows
                .iter()
                .any(|(plan, profile, plan_digest, profile_digest)| {
                    plan == &policy.projection_plan_id
                        && profile == &policy.indexer_profile_id
                        && plan_digest == &policy.plan_artifact_digest
                        && profile_digest == &policy.profile_artifact_digest
                })
        })
    {
        return Err("policy source references rejected".into());
    }
    // Fleet has SELECT-only access to module records. This snapshot is pinned
    // to the claimed configuration; it is not a lease on module activation.
    // Do not require UPDATE merely to take a row lock on immutable versions.
    let configurations: Vec<(String, String)> = sqlx::query_as(
        r#"select current.runtime_configuration_input_id::text,encode(current.configuration_digest,'hex')
             from control.runtime_configuration_input_current_metadata current
             join control.module_installation installation
               on installation.module_installation_id=current.module_installation_id
              and installation.participant_id=current.participant_id
              and installation.privacy_domain_id=current.privacy_domain_id
              and installation.state='ENABLED'
             join control.module_version version
               on version.module_version_id=installation.module_version_id
              and version.module_id='pc.config.assets'
            where current.participant_id=$1::text::uuid
              and current.privacy_domain_id=$2::text::uuid and current.active"#,
    )
    .bind(&document.participant_id)
    .bind(&document.privacy_domain_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| "current policy source bytes unavailable")?;
    let [(input_id, stored_digest)] = configurations.as_slice() else {
        return Err("current policy source configuration ambiguous or unavailable".into());
    };
    openpc_indexer_adapter::control_materialization::authorize_input(connection, input_id).await?;
    let bytes: Vec<u8> =
        sqlx::query_scalar("select openpc.runtime_artifact_input_payload($1::text::uuid)")
            .bind(input_id)
            .fetch_one(connection)
            .await
            .map_err(|_| "current policy source materialization unavailable")?;
    let actual = Digest::of(&bytes);
    if &actual != expected_configuration_digest || stored_digest != actual.as_str() {
        return Err("policy source configuration changed or substituted".into());
    }
    let inputs = vec![IndexerCompilationInput {
        configuration_cbor: bytes.clone(),
        configuration_digest: actual,
    }];
    // Recheck bytes, exact profile/plan/acquisition and workload bounds before
    // releasing the source-row locks. The compiler selects no caller payload.
    compile_indexer_sources(&document.indexer_policies, &inputs)?;
    Ok(inputs)
}

#[cfg(test)]
mod tests;
