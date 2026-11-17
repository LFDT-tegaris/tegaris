//! Exact governed source dependency of projection validation. A prior receipt
//! cannot qualify replacement bytes, another scope, or a retired source.
use super::{
    ClaimedWork, ConfigurationArtifactKind, Digest, Postgres, Transaction, Value, WorkerResult,
    admit_scoped_client_indexer_profile, load_active_configuration_artifact, parse_digest,
    receipt_bytes, validate_projection_admission,
};

#[cfg(test)]
#[path = "projection_admission_tests.rs"]
mod database_tests;

fn field<'a>(receipt: &'a Value, key: &str) -> WorkerResult<&'a str> {
    receipt
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| "qualified indexer receipt rejected".into())
}

pub(super) fn receipt(work: &ClaimedWork, plan_cbor: Vec<u8>) -> WorkerResult<Value> {
    let source = work
        .related_profile_receipt
        .as_ref()
        .ok_or_else(|| "qualified indexer profile unavailable".to_owned())?;
    if field(source, "workKind")? != "INDEXER_ADMISSION"
        || field(source, "consumer")? != "LS-INDEXER-MANAGER/LS-INDEXER-ADAPTER"
    {
        return Err("qualified indexer receipt rejected".into());
    }
    let resource_id = field(source, "resourceId")?;
    let artifact_digest = field(source, "artifactDigest")?;
    let profile_cbor = receipt_bytes(source, "artifactCbor")?;
    let profile = admit_scoped_client_indexer_profile(
        &profile_cbor,
        artifact_digest,
        &work.participant_id,
        &work.privacy_domain_id,
    )
    .map_err(|_| "qualified indexer scope or artifact rejected")?;
    let configured = load_active_configuration_artifact(
        &work.configuration_cbor,
        &work.configuration_digest,
        resource_id,
        ConfigurationArtifactKind::ClientIndexerProfile,
        &parse_digest(artifact_digest.to_owned())?,
    )
    .map_err(|_| "qualified indexer configuration rejected")?;
    if configured != profile_cbor
        || field(source, "profileId")? != profile.profile_id
        || field(source, "profileVersion")? != profile.profile_version
    {
        return Err("qualified indexer receipt rejected".into());
    }
    let plan = validate_projection_admission(&profile_cbor, &plan_cbor, &work.input_digest)
        .map_err(|_| "projection admission rejected")?;
    Ok(serde_json::json!({
        "artifactCbor": plan_cbor,
        "artifactDigest": work.input_digest,
        "consumer": "LS-INDEXER-MANAGER/LS-INDEXER-ADAPTER",
        "planDigest": plan.plan_digest,
        "profileArtifactCbor": profile_cbor,
        "profileArtifactDigest": artifact_digest,
        "profileResourceId": resource_id,
        "profileQualificationOperationId": field(source, "qualificationOperationId")?,
        "profileQualificationRevision": field(source, "qualificationRevision")?,
        "profileId": plan.profile_id,
        "resourceId": work.resource_id,
        "workKind": work.work_kind,
    }))
}

/// Retain the source row lock until the projection/result/evidence transaction
/// commits. Updating or retiring the source cannot race this final revalidation.
pub(super) async fn assert_current(
    transaction: &mut Transaction<'_, Postgres>,
    work: &ClaimedWork,
    receipt: &Value,
) -> WorkerResult<()> {
    let profile_digest = format!(
        "sha256:{}",
        Digest::of(receipt_bytes(receipt, "profileArtifactCbor")?).as_str()
    );
    if field(receipt, "profileArtifactDigest")? != profile_digest {
        return Err("projection source digest rejected".into());
    }
    let current = sqlx::query_scalar::<_, String>(r#"
      select i.indexer_profile_id::text
        from control.projection_plan p
        join control.indexer_profile i on i.indexer_profile_id=p.indexer_profile_id
          and i.participant_id=p.participant_id and i.privacy_domain_id=p.privacy_domain_id
       where p.projection_plan_id=$1::text::uuid and p.participant_id=$2::text::uuid
         and p.privacy_domain_id=$3::text::uuid and p.plan_digest=$4
         and p.state='DRAFT' and p.readiness='UNKNOWN'
         and i.indexer_profile_id=$5::text::uuid and i.method_profile_digest=$6
         and i.revision::text=$8
         and i.state in ('QUALIFIED','ACTIVE')
         and exists (select 1 from control.configuration_work prior
           where prior.participant_id=i.participant_id and prior.privacy_domain_id=i.privacy_domain_id
             and prior.resource_id=i.indexer_profile_id and prior.work_kind='INDEXER_ADMISSION'
             and prior.state='COMPLETED' and prior.input_digest=i.method_profile_digest
             and prior.operation_id::text=$9
             and exists (select 1 from control.idempotency_record result
               where result.participant_id=prior.participant_id and result.operation_id=prior.operation_id
                 and result.terminal_state='COMMITTED' and result.result_payload->>'state'='SUCCEEDED'
                 and result.result_aggregate_version=i.revision))
         and exists (select 1 from control.runtime_configuration_input_current_metadata configuration
           join control.module_installation installation
             on installation.module_installation_id=configuration.module_installation_id
            and installation.participant_id=p.participant_id
            and installation.privacy_domain_id=p.privacy_domain_id and installation.state='ENABLED'
           join control.module_version version on version.module_version_id=installation.module_version_id
             and version.module_id='pc.config.assets'
           where configuration.active and encode(configuration.configuration_digest,'hex')=$7)
       for share of i
    "#)
        .bind(&work.resource_id).bind(&work.participant_id).bind(&work.privacy_domain_id)
        .bind(&work.input_digest).bind(field(receipt, "profileResourceId")?).bind(profile_digest)
        .bind(work.configuration_digest.as_str())
        .bind(field(receipt, "profileQualificationRevision")?)
        .bind(field(receipt, "profileQualificationOperationId")?)
        .fetch_optional(&mut **transaction).await
        .map_err(|_| "projection source revalidation unavailable".to_owned())?;
    if current.is_none() {
        return Err(crate::source_revision::SUPERSEDED.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generic_receipt,
        tests::{indexer_profile, invocation_asset, projection_plan, work},
    };
    use pc_policy_core::invocation::{
        ActiveInvocationConfigurationV1, ConfigurationArtifactV1,
        encode_active_invocation_configuration,
    };
    use pc_provider_api::{
        ClientIndexerProfileV1, encode_client_indexer_profile_pc_cbor,
        encode_projection_plan_pc_cbor,
    };

    fn fixture(change: impl FnOnce(&mut ClientIndexerProfileV1)) -> ClaimedWork {
        let mut work = work();
        let mut profile = indexer_profile();
        profile.participant_binding = work.participant_id.clone();
        profile.privacy_binding = work.privacy_domain_id.clone();
        change(&mut profile);
        let profile_cbor = encode_client_indexer_profile_pc_cbor(&profile).unwrap();
        let profile_digest = Digest::of(&profile_cbor);
        let plan_cbor = encode_projection_plan_pc_cbor(&projection_plan(&profile)).unwrap();
        let plan_digest = Digest::of(&plan_cbor);
        let profile_id = "018f0000-0000-7000-8000-000000000406";
        let configuration = ActiveInvocationConfigurationV1 {
            workload_scope: None,
            visibility_resources: Vec::new(),
            schema_version: "1.0".into(),
            assets: vec![invocation_asset()],
            deployment_policies: Vec::new(),
            resource_artifacts: vec![
                ConfigurationArtifactV1 {
                    artifact_id: profile_id.into(),
                    artifact_kind: ConfigurationArtifactKind::ClientIndexerProfile,
                    artifact_digest: profile_digest.clone(),
                    payload_cbor: profile_cbor.clone(),
                },
                ConfigurationArtifactV1 {
                    artifact_id: work.resource_id.clone(),
                    artifact_kind: ConfigurationArtifactKind::ProjectionPlan,
                    artifact_digest: plan_digest.clone(),
                    payload_cbor: plan_cbor,
                },
            ],
        };
        work.configuration_cbor = encode_active_invocation_configuration(&configuration).unwrap();
        work.configuration_digest = Digest::of(&work.configuration_cbor);
        work.work_kind = "PROJECTION_VALIDATION".into();
        work.input_digest = format!("sha256:{}", plan_digest.as_str());
        work.related_profile_receipt = Some(serde_json::json!({
            "resourceId": profile_id, "artifactCbor": profile_cbor,
            "artifactDigest": format!("sha256:{}", profile_digest.as_str()),
            "workKind": "INDEXER_ADMISSION", "consumer": "LS-INDEXER-MANAGER/LS-INDEXER-ADAPTER",
            "profileId": profile.profile_id, "profileVersion": profile.profile_version,
            "qualificationOperationId": "018f0000-0000-7000-8000-000000000408",
            "qualificationRevision": "3",
        }));
        work
    }

    #[test]
    fn projection_retains_exact_source_dependency() {
        let work = fixture(|_| {});
        let receipt = generic_receipt(&work).unwrap();
        let source = work.related_profile_receipt.unwrap();
        assert_eq!(receipt["profileResourceId"], source["resourceId"]);
        assert_eq!(receipt["profileArtifactDigest"], source["artifactDigest"]);
        assert_eq!(receipt["profileArtifactCbor"], source["artifactCbor"]);
        assert_eq!(
            receipt["profileQualificationOperationId"],
            source["qualificationOperationId"]
        );
        assert_eq!(
            receipt["profileQualificationRevision"],
            source["qualificationRevision"]
        );
    }

    #[test]
    fn valid_artifact_in_another_scope_cannot_qualify_projection() {
        for change in [
            (|p: &mut ClientIndexerProfileV1| {
                p.participant_binding = "018f0000-0000-7000-8000-000000000999".into()
            }) as fn(&mut ClientIndexerProfileV1),
            |p: &mut ClientIndexerProfileV1| {
                p.privacy_binding = "018f0000-0000-7000-8000-000000000999".into()
            },
        ] {
            assert!(generic_receipt(&fixture(change)).is_err());
        }
    }

    #[test]
    fn historical_or_substituted_receipt_is_not_current_source_admission() {
        for (key, changed) in [
            (
                "resourceId",
                "018f0000-0000-7000-8000-000000000499".to_owned(),
            ),
            (
                "artifactDigest",
                format!("sha256:{}", Digest::of("replacement").as_str()),
            ),
            ("profileId", "another-profile".into()),
            ("profileVersion", "2.0.0".into()),
            ("workKind", "PROJECTION_VALIDATION".into()),
            ("consumer", "LS-MULTI-RPC".into()),
        ] {
            let mut work = fixture(|_| {});
            work.related_profile_receipt.as_mut().unwrap()[key] = Value::String(changed);
            assert!(generic_receipt(&work).is_err(), "{key}");
        }
        let mut work = fixture(|_| {});
        let mut configuration = crate::decode_active_invocation_configuration(
            &work.configuration_cbor,
            &work.configuration_digest,
        )
        .unwrap();
        configuration.resource_artifacts.retain(|artifact| {
            artifact.artifact_kind != ConfigurationArtifactKind::ClientIndexerProfile
        });
        work.configuration_cbor = encode_active_invocation_configuration(&configuration).unwrap();
        work.configuration_digest = Digest::of(&work.configuration_cbor);
        assert!(generic_receipt(&work).is_err());
    }
}
