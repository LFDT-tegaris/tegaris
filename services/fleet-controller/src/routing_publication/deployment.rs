//! Deployment routes resolve immutable governed definitions and the exact
//! qualified provider artifact. Observation has its own purpose; sharing a
//! connection never permits another submission or a provider switch.
use super::GovernedRoutingPublicationInput;
use pc_provider_api::{IdempotencyClass, ProviderProfileV1, RoutePlanDraftV1};
use sqlx::Row;

/// An irreversible handoff keeps its observation identity across policy renewal.
/// These are not current deployment grants: the target independently pins the
/// provider artifact/instance and transaction from its authenticated journal.
pub(super) async fn observation_bindings(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    target: &str,
    participant: &str,
    privacy: &str,
    chain_environment: &str,
) -> Result<Vec<String>, String> {
    let bindings: Vec<String> = sqlx::query_scalar(
        r#"select distinct i.deployment_policy_id::text
        from control.deployment_address_reservation r
        join control.deployment_intent i
          on i.participant_id=r.participant_id and i.privacy_domain_id=r.privacy_domain_id
          and i.preparation_digest=r.prepared_record_digest and i.intent_digest=r.intent_digest
          and r.target_runtime_id='urn:openpc:resource:'||i.runtime_target_id::text
        join control.deployment_policy p
          on p.deployment_policy_id=i.deployment_policy_id
          and p.participant_id=i.participant_id and p.privacy_domain_id=i.privacy_domain_id
        join control.mutation_candidate c
          on c.participant_id=r.participant_id and c.privacy_domain_id=r.privacy_domain_id
          and c.consumed_operation_id=r.command_id and c.resource_id=r.attempt_id
          and c.state='CONSUMED' and c.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'
          and c.maker_principal_id=i.actor_principal_id
          and c.candidate_document->>'deploymentIntentId'='urn:openpc:resource:'||i.deployment_intent_id::text
        join control.idempotency_record operation
          on operation.participant_id=c.participant_id and operation.privacy_domain_id=c.privacy_domain_id
          and operation.operation_id=c.consumed_operation_id and operation.input_digest=c.candidate_digest
          and operation.catalog_operation_id=c.catalog_operation_id and operation.terminal_state='COMMITTED'
        where r.participant_id=$1::text::uuid and r.privacy_domain_id=$2::text::uuid
          and i.runtime_target_id=$3::text::uuid and r.state='HANDOFF'
          and r.chain_id=p.definition->>'chainId' and r.genesis_digest=p.definition->>'genesisDigest'
          and concat_ws(':',p.definition->>'chainId',p.definition->>'networkId',p.definition->>'genesisDigest')=$4
        order by i.deployment_policy_id::text limit 257"#,
    )
    .bind(participant)
    .bind(privacy)
    .bind(target)
    .bind(chain_environment)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| "deployment observation custody unavailable")?;
    if bindings.len() > 256 {
        return Err("deployment observation capacity rejected".into());
    }
    Ok(bindings)
}

pub(super) fn validate_profile(profile: &ProviderProfileV1) -> Result<(), String> {
    let methods = [
        ("eth_sendRawTransaction", "transaction"),
        ("eth_chainId", "CHAIN_METADATA"),
        ("eth_getBlockByNumber", "BLOCK_HEADER"),
        ("eth_getTransactionByHash", "TRANSACTION"),
        ("eth_getTransactionReceipt", "RECEIPT"),
        ("debug_traceTransaction", "TRANSACTION"),
    ];
    if profile.idempotency != IdempotencyClass::GovernedWrite
        || profile.route_plan != RoutePlanDraftV1::SingleExact
        || profile.read_retry_budget != 0
        || methods.iter().any(|(method, class)| {
            !profile
                .method_data_classes
                .iter()
                .any(|pair| pair.method == *method && pair.data_class == *class)
        })
        || [
            "eth_getTransactionCount",
            "eth_getBalance",
            "eth_getCode",
            "debug_traceCall",
        ]
        .iter()
        .any(|method| {
            !profile
                .method_data_classes
                .iter()
                .any(|pair| pair.method == *method)
        })
    {
        return Err("qualified deployment provider methods unavailable".into());
    }
    Ok(())
}

pub(super) async fn validate_bindings(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: &GovernedRoutingPublicationInput,
    profile: &ProviderProfileV1,
    participant: &str,
    privacy: &str,
) -> Result<String, String> {
    for reference in &input.deployment_policies {
        let row = sqlx::query(
            r#"select definition
            from control.deployment_policy
            where deployment_policy_id=$1::text::uuid and participant_id=$2::text::uuid
              and privacy_domain_id=$3::text::uuid and definition_digest=$4
              and (definition->>'expiresAt')::timestamptz>clock_timestamp()
            for share"#,
        )
        .bind(&reference.deployment_policy_id)
        .bind(participant)
        .bind(privacy)
        .bind(&reference.definition_digest)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| "governed deployment route policy unavailable")?;
        let definition: serde_json::Value = row
            .try_get("definition")
            .map_err(|_| "governed deployment route definition invalid")?;
        if definition["chainId"] != profile.chain_id
            || definition["networkId"] != profile.network_id
            || definition["genesisDigest"] != profile.genesis_hash
        {
            return Err("governed deployment route chain mismatch".into());
        }
    }
    Ok(format!(
        "{}:{}:{}",
        profile.chain_id, profile.network_id, profile.genesis_hash
    ))
}
