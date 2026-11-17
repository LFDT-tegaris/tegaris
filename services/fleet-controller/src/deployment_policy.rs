//! Re-resolve exact governed deployment publications at Fleet installation.
use pc_policy_core::{
    deployment_policy::AdmittedDeploymentPolicy, semantics::PolicySemanticDocument,
};
use pc_runtime_types::Digest;
use serde_json::Value;
use sqlx::PgConnection;

pub async fn load_deployment_policy_inputs(
    connection: &mut PgConnection,
    document: &PolicySemanticDocument,
) -> Result<Vec<AdmittedDeploymentPolicy>, String> {
    if document.deployment_policies.is_empty() {
        return Ok(Vec::new());
    }
    let ids = document
        .deployment_policies
        .iter()
        .map(|reference| reference.deployment_policy_id.clone())
        .collect::<Vec<_>>();
    let rows = sqlx::query_as::<_, (Value, Value)>(r#"
      select jsonb_build_object('deploymentPolicyId',policy.deployment_policy_id::text,
        'participantId',policy.participant_id::text,'privacyDomainId',policy.privacy_domain_id::text,
        'definition',policy.definition,'definitionDigest',policy.definition_digest,'artifactDigest',policy.artifact_digest,
        'initCodeHash',policy.init_code_hash,'abiDigest',policy.abi_digest,
        'publicationOperationId',policy.publication_operation_id::text,'publicationAuthorityDigest',policy.publication_authority_digest,
        'factoryBinding',(select jsonb_build_object('runtimeBindingId',factory.runtime_binding_id::text,
          'chainId',factory.chain_id,'networkId',factory.network_id,'genesisDigest',factory.genesis_digest,
          'contractAddress',factory.contract_address,'codeDigest',factory.code_digest,
          'abiDigest',factory_abi.abi_digest,'canonicalAbi',factory_abi.canonical_abi)
         from control.contract_runtime_binding factory join control.abi_artifact factory_abi
          on factory_abi.participant_id=factory.participant_id and factory_abi.privacy_domain_id=factory.privacy_domain_id
          and factory_abi.abi_artifact_id=factory.abi_artifact_id
         where factory.participant_id=policy.participant_id and factory.privacy_domain_id=policy.privacy_domain_id
          and factory.runtime_binding_id=policy.factory_runtime_binding_id and factory.state='BOUND'
          and factory.chain_id=policy.definition->>'chainId' and factory.network_id=policy.definition->>'networkId'
          and factory.genesis_digest=policy.definition->>'genesisDigest' and factory.proxy_address is null
          and factory.implementation_address is null and factory.implementation_code_digest is null
         for share of factory,factory_abi)),abi.canonical_abi
      from control.deployment_policy policy join control.abi_artifact abi
       on abi.participant_id=policy.participant_id and abi.privacy_domain_id=policy.privacy_domain_id
       and abi.abi_artifact_id=policy.abi_artifact_id and abi.abi_digest=policy.abi_digest
      where policy.participant_id=$1::text::uuid and policy.privacy_domain_id=$2::text::uuid
       and policy.deployment_policy_id::text=any($3::text[])
       and (policy.definition->>'expiresAt')::timestamptz>clock_timestamp()
      order by policy.deployment_policy_id for share of policy,abi
    "#).bind(&document.participant_id).bind(&document.privacy_domain_id).bind(ids)
        .fetch_all(connection).await.map_err(|_| "deployment publication read failed".to_owned())?;
    if rows.len() != document.deployment_policies.len() {
        return Err("deployment publication unavailable".into());
    }
    rows.into_iter()
        .map(|(row, canonical_abi)| {
            let policy: AdmittedDeploymentPolicy =
                serde_json::from_value(row).map_err(|_| "deployment publication rejected")?;
            policy.validate()?;
            if !canonical_abi.is_array()
                || policy.abi_digest
                    != format!(
                        "sha256:{}",
                        Digest::of(
                            serde_json::to_vec(&canonical_abi)
                                .map_err(|_| "deployment ABI rejected")?
                        )
                        .as_str()
                    )
            {
                return Err("deployment ABI identity rejected".into());
            }
            if !document.deployment_policies.iter().any(|reference| {
                reference.deployment_policy_id == policy.deployment_policy_id
                    && reference.definition_digest == policy.definition_digest
            }) {
                return Err("deployment publication substitution rejected".into());
            }
            Ok(policy)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_policy_core::{
        contract_simulation::compile_document_with_deployments,
        deployment_policy::ValidatedDeploymentPolicy, invocation::ActiveInvocationScope,
    };
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct PublishedFixture {
        document: PolicySemanticDocument,
        admitted: Vec<AdmittedDeploymentPolicy>,
        workload_id: String,
    }

    #[tokio::test]
    #[ignore = "requires the real governed deployment-publication PostgreSQL producer"]
    async fn postgres_published_deployment_compiles_for_the_installed_scope() {
        let input: PublishedFixture = serde_json::from_slice(
            &std::fs::read(std::env::var("OPENPC_ASTRA08_DEPLOYMENT_PUBLICATION_FIXTURE").unwrap())
                .unwrap(),
        )
        .unwrap();
        let pool = sqlx::PgPool::connect(
            &std::env::var("OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL").unwrap(),
        )
        .await
        .unwrap();
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,$3::text::uuid,'ACT-DEPLOYMENT_POLICIES_READ_RESOURCE-V1',false)")
            .bind(&input.document.participant_id).bind(&input.document.privacy_domain_id)
            .bind("018f0000-0000-7000-8000-000000000998").execute(&mut *transaction).await.unwrap();
        let actual = load_deployment_policy_inputs(&mut transaction, &input.document)
            .await
            .unwrap();
        assert_eq!(actual, input.admitted);
        let generation = input.document.digest().unwrap();
        let compiled = compile_document_with_deployments(
            &input.document,
            &[],
            &actual,
            &input.workload_id,
            &generation,
        )
        .unwrap();
        let scope = ActiveInvocationScope {
            policy_generation_digest: &generation,
            tenant_id: &input.document.participant_id,
            privacy_domain_id: &input.document.privacy_domain_id,
            workload_id: &input.workload_id,
        };
        let installed = ValidatedDeploymentPolicy::load_active(
            &compiled.configuration_cbor,
            &compiled.configuration_digest,
            &compiled.policy_cbor,
            &compiled.policy_digest,
            &scope,
        )
        .unwrap();
        assert_eq!(installed.len(), 2);
        assert!(compiled.policies.is_empty());
        for (installed, published) in installed.iter().zip(&input.admitted) {
            assert_eq!(installed.publication(), published);
            assert_eq!(installed.policy_generation_digest(), &generation);
        }
        let mut wrong_reference = input.document.clone();
        wrong_reference.deployment_policies[0].definition_digest =
            format!("sha256:{}", "99".repeat(32));
        assert!(
            load_deployment_policy_inputs(&mut transaction, &wrong_reference)
                .await
                .is_err()
        );
        let mut wrong_scope = input.document;
        wrong_scope.privacy_domain_id = "018f0000-0000-7000-8000-000000000999".into();
        assert!(
            load_deployment_policy_inputs(&mut transaction, &wrong_scope)
                .await
                .is_err()
        );
        transaction.rollback().await.unwrap();
        pool.close().await;
    }
}
