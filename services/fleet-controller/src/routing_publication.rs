//! Durable Fleet publication of target routing and provider certification.
//! The publisher derives route fields from the currently leased activation,
//! approved contract bindings and reviewed provider observation. A target still
//! verifies the signed sources, capsule generation and live connection lease.

use openpc_multi_rpc::{
    provider_connection::{ConnectionRecord, ConnectionStatus},
    qualify_provider_profile,
    runtime_profile::MrpcRuntimeProfile,
};
use openpc_runtime_agent::{
    RuntimeWireSigner, RuntimeWireVerifier,
    authority_artifact::AuthorityArtifact,
    routing_custody::{
        ProviderCertification, ProviderCertificationSource, RoutingAssignment,
        RoutingSnapshotSource,
    },
};
use pc_policy_core::{pc_cbor_1, runtime_wire::Signer as ProfileSigner, semantics::FactReference};
use pc_runtime_types::{Digest, RuntimeError};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::collections::BTreeSet;

mod deployment;

pub const ROUTING_ARTIFACT_ID: &str = "openpc.routing.snapshot";
pub const CERTIFICATION_ARTIFACT_ID: &str = "openpc.provider.certification";
pub const ROUTING_DEFINITION: &[u8] = b"openpc.routing.snapshot-source.v1";
pub const CERTIFICATION_DEFINITION: &[u8] = b"openpc.provider-certification.source.v1";

#[derive(Clone, Debug)]
pub struct GovernedRoutingPublicationInput {
    pub configuration_work_id: String,
    pub runtime_configuration_generation_id: String,
    pub runtime_target_id: String,
    pub runtime_generation: u64,
    pub generation_digest: Digest,
    pub policy_generation_digest: Digest,
    pub read_runtime_binding_ids: Vec<String>,
    pub visibility_resources: Vec<pc_policy_core::visibility_policy::AdmittedVisibilityResource>,
    pub write_runtime_binding_ids: Vec<String>,
    pub deployment_policies: Vec<pc_policy_core::deployment_policy::DeploymentPolicyReference>,
    pub required_facts: Vec<FactReference>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedRoutingArtifacts {
    pub publication_id: String,
    pub mrpc_runtime_profile: Vec<u8>,
    pub mrpc_runtime_profile_content_digest: Digest,
    pub mrpc_runtime_profile_digest: Digest,
    pub routing_source: Vec<u8>,
    pub routing_source_digest: Digest,
    pub routing_authority: Vec<u8>,
    pub routing_authority_content_digest: Digest,
    pub routing_authority_digest: Digest,
    pub certification_source: Vec<u8>,
    pub certification_source_digest: Digest,
    pub certification_authority: Vec<u8>,
    pub certification_authority_content_digest: Digest,
    pub certification_authority_digest: Digest,
}

pub struct RoutingPublicationRepository {
    pool: PgPool,
    participant_id: String,
    privacy_domain_id: String,
    worker_id: String,
    signer: RuntimeWireSigner,
    profile_signer: ProfileSigner,
}

struct CurrentOwner {
    provider_profile_id: String,
    provider_chain_id: String,
    provider_revision: i64,
    observation_id: String,
    observation_digest: String,
    observation_valid_until_ms: u64,
    provider_artifact_digest: String,
    provider_artifact_cbor: Vec<u8>,
    connection: ConnectionRecord,
    risk_class: String,
    governed_write: bool,
}

impl RoutingPublicationRepository {
    pub fn new(
        pool: PgPool,
        participant_id: String,
        privacy_domain_id: String,
        worker_id: String,
        signing_key: [u8; 32],
    ) -> Result<Self, String> {
        for value in [&participant_id, &privacy_domain_id, &worker_id] {
            if value.is_empty()
                || value.len() > 160
                || !value.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err("routing publisher identity rejected".into());
            }
        }
        Ok(Self {
            pool,
            participant_id,
            privacy_domain_id,
            worker_id,
            signer: RuntimeWireSigner::from_secret_bytes(signing_key)
                .map_err(|_| "routing publisher signer rejected")?,
            profile_signer: ProfileSigner::from_secret_bytes(signing_key)
                .map_err(|_| "routing profile signer rejected")?,
        })
    }

    pub async fn publish(
        &self,
        input: &GovernedRoutingPublicationInput,
        now_ns: u64,
    ) -> Result<PublishedRoutingArtifacts, String> {
        validate_input(input, now_ns)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| "routing publication transaction unavailable")?;
        self.set_context(&mut transaction).await?;
        let owner = self.current_owner(&mut transaction, input, now_ns).await?;
        let chain_environment_id = self
            .validate_bindings(&mut transaction, input, &owner)
            .await?;
        let observation_bindings = if owner.governed_write {
            deployment::observation_bindings(
                &mut transaction,
                &input.runtime_target_id,
                &self.participant_id,
                &self.privacy_domain_id,
                &chain_environment_id,
            )
            .await?
        } else {
            Vec::new()
        };
        let selected_routes = observation_assignments(
            selected_assignments(input, owner.governed_write),
            &observation_bindings,
        )?;
        let valid_until_ns = owner
            .observation_valid_until_ms
            .checked_mul(1_000_000)
            .ok_or_else(|| "routing publication validity overflow".to_owned())?;
        if now_ns >= valid_until_ns {
            return Err("routing publication observation expired".into());
        }
        let mrpc_profile = governed_mrpc_profile(&self.worker_id, owner.governed_write)?;
        let mrpc_runtime_profile_digest = mrpc_profile.semantic_digest().map_err(runtime_error)?;
        let mrpc_runtime_profile = mrpc_profile
            .sign(&self.profile_signer)
            .map_err(runtime_error)?;
        let coherence_group_digest = Digest::of(
            serde_json::to_vec(&(
                &owner.provider_profile_id,
                &owner.connection.endpoint_id,
                &owner.connection.configuration_digest,
                &input.generation_digest,
                &mrpc_runtime_profile_digest,
            ))
            .map_err(|_| "routing publication coherence rejected")?,
        );
        let assignments = selected_routes
            .iter()
            .map(|(binding, method, role, purpose)| RoutingAssignment {
                runtime_binding_id: binding.clone(),
                method: (*method).into(),
                risk_class: owner.risk_class.clone(),
                provider_profile_id: owner.provider_profile_id.clone(),
                endpoint_id: owner.connection.endpoint_id.clone(),
                endpoint_role: *role,
                purpose: *purpose,
                chain_environment_id: chain_environment_id.clone(),
                canonical_generation: input.runtime_generation,
                invalidation_generation: input.runtime_generation,
                coherence_group_digest: coherence_group_digest.clone(),
                valid_until_ns,
                required_facts: input.required_facts.clone(),
            })
            .collect();
        let routing = RoutingSnapshotSource {
            version: 1,
            participant_id: self.participant_id.clone(),
            privacy_domain_id: self.privacy_domain_id.clone(),
            target_id: input.runtime_target_id.clone(),
            runtime_generation: input.runtime_generation,
            policy_generation_digest: input.policy_generation_digest.clone(),
            mrpc_runtime_profile_digest: mrpc_runtime_profile_digest.clone(),
            assignments,
        };
        let certification = ProviderCertificationSource {
            version: 1,
            participant_id: self.participant_id.clone(),
            privacy_domain_id: self.privacy_domain_id.clone(),
            target_id: input.runtime_target_id.clone(),
            runtime_generation: input.runtime_generation,
            policy_generation_digest: input.policy_generation_digest.clone(),
            mrpc_runtime_profile_digest: mrpc_runtime_profile_digest.clone(),
            certifications: vec![ProviderCertification {
                provider_profile_id: owner.provider_profile_id.clone(),
                provider_artifact_digest: parse_stored_digest(&owner.provider_artifact_digest)?,
                provider_profile_cbor: owner.provider_artifact_cbor.clone(),
                endpoint_id: owner.connection.endpoint_id.clone(),
                connection_configuration_digest: owner.connection.configuration_digest.clone(),
                valid_from_ns: now_ns,
                valid_until_ns,
                required_facts: input.required_facts.clone(),
            }],
        };
        let mut built = build_publication(
            &self.signer,
            &self.worker_id,
            routing,
            certification,
            mrpc_runtime_profile,
            mrpc_runtime_profile_digest.clone(),
            now_ns,
        )?;
        let inserted = sqlx::query(
            r#"insert into control.runtime_route_publication(
              participant_id,privacy_domain_id,configuration_work_id,
              runtime_configuration_generation_id,runtime_target_id,provider_profile_id,
              qualification_observation_id,generation_digest,policy_generation_digest,
              provider_revision,qualification_observation_digest,mrpc_runtime_profile_cose,
              mrpc_runtime_profile_content_digest,mrpc_runtime_profile_digest,
              routing_source_cbor,routing_source_digest,routing_authority_cose,
              routing_authority_content_digest,routing_authority_digest,
              certification_source_cbor,certification_source_digest,certification_authority_cose,
              certification_authority_content_digest,certification_authority_digest,valid_until)
            values($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,
              $6::text::uuid,$7::text::uuid,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
              $21,$22,$23,$24,to_timestamp($25::double precision/1000.0))
            on conflict(runtime_configuration_generation_id) do nothing"#,
        )
        .bind(&self.participant_id)
        .bind(&self.privacy_domain_id)
        .bind(&input.configuration_work_id)
        .bind(&input.runtime_configuration_generation_id)
        .bind(&input.runtime_target_id)
        .bind(&owner.provider_profile_id)
        .bind(&owner.observation_id)
        .bind(stored_digest(&input.generation_digest))
        .bind(stored_digest(&input.policy_generation_digest))
        .bind(owner.provider_revision)
        .bind(&owner.observation_digest)
        .bind(&built.mrpc_runtime_profile)
        .bind(stored_digest(&built.mrpc_runtime_profile_content_digest))
        .bind(stored_digest(&built.mrpc_runtime_profile_digest))
        .bind(&built.routing_source)
        .bind(stored_digest(&built.routing_source_digest))
        .bind(&built.routing_authority)
        .bind(stored_digest(&built.routing_authority_content_digest))
        .bind(stored_digest(&built.routing_authority_digest))
        .bind(&built.certification_source)
        .bind(stored_digest(&built.certification_source_digest))
        .bind(&built.certification_authority)
        .bind(stored_digest(&built.certification_authority_content_digest))
        .bind(stored_digest(&built.certification_authority_digest))
        .bind(owner.observation_valid_until_ms as f64)
        .execute(&mut *transaction)
        .await
        .map_err(|_| "routing publication insert rejected")?;
        let selected = read_in_transaction(
            &mut transaction,
            &input.runtime_configuration_generation_id,
            &self.signer.verifier(),
            &self.profile_signer.verifier(),
            now_ns,
        )
        .await?;
        built.publication_id = selected.publication_id.clone();
        if inserted.rows_affected() == 0 {
            validate_replayed_publication(
                &selected,
                input,
                &owner,
                &chain_environment_id,
                &selected_routes,
                self,
                now_ns,
            )?;
        } else if selected != built {
            return Err("routing publication replay substitution rejected".into());
        }
        transaction
            .commit()
            .await
            .map_err(|_| "routing publication commit failed")?;
        Ok(selected)
    }

    pub async fn read_current(
        &self,
        runtime_configuration_generation_id: &str,
        now_ns: u64,
    ) -> Result<PublishedRoutingArtifacts, String> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| "routing publication read unavailable")?;
        self.set_context(&mut transaction).await?;
        let result = read_in_transaction(
            &mut transaction,
            runtime_configuration_generation_id,
            &self.signer.verifier(),
            &self.profile_signer.verifier(),
            now_ns,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| "routing publication read commit failed")?;
        Ok(result)
    }

    async fn set_context(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<(), String> {
        sqlx::query(
            "select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true),openpc.assert_request_context(true)",
        )
        .bind(&self.participant_id)
        .bind(&self.privacy_domain_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| "routing publication context rejected")?;
        Ok(())
    }

    async fn current_owner(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        input: &GovernedRoutingPublicationInput,
        now_ns: u64,
    ) -> Result<CurrentOwner, String> {
        let row = sqlx::query(
            r#"select g.provider_profile_id::text,p.chain_id provider_chain_id,
              p.revision::bigint provider_revision,
              o.observation_id::text,o.observation_digest,
              floor(extract(epoch from o.valid_until)*1000)::bigint observation_valid_until_ms,
              o.observation,q.result_receipt,
              (select risk_class from control.action_intent
                where action_intent_id='ACT-RUNTIME_READ_RPC-V1'
                  and resource_type='runtime-rpc' and operation_class='READ'
                  and risk_class='LOW' and maker_checker_required=false
                  and step_up_required=false and idempotency_required=false
                  and existence_disclosure='NONE'
                  and payload_disclosure='AUTHORIZED_MINIMAL'
                  and evidence_class='READ_RUNTIME_RPC') risk_class,
              (select risk_class from control.action_intent
                where action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
                  and resource_type='deployment-submission' and operation_class='CREATE'
                  and risk_class='HIGH' and maker_checker_required=true
                  and step_up_required=true and idempotency_required=true
                  and evidence_class='DEPLOYMENT_SUBMISSION') deployment_risk_class
            from control.runtime_configuration_generation g
            join control.configuration_work w
              on w.runtime_configuration_generation_id=g.runtime_configuration_generation_id
             and w.participant_id=g.participant_id and w.privacy_domain_id=g.privacy_domain_id
            join control.runtime_target t on t.runtime_target_id=g.runtime_target_id
             and t.participant_id=g.participant_id and t.privacy_domain_id=g.privacy_domain_id
            join control.provider_profile p on p.provider_profile_id=g.provider_profile_id
             and p.participant_id=g.participant_id and p.privacy_domain_id=g.privacy_domain_id
            join control.provider_probe_observation o on o.observation_id=p.qualification_observation_id
             and o.provider_profile_id=p.provider_profile_id and o.participant_id=p.participant_id
             and o.privacy_domain_id=p.privacy_domain_id
            join control.configuration_work q on q.resource_id=p.provider_profile_id
             and q.participant_id=p.participant_id and q.privacy_domain_id=p.privacy_domain_id
             and q.work_kind='PROVIDER_QUALIFICATION' and q.state='COMPLETED'
            where g.runtime_configuration_generation_id=$1::text::uuid
              and g.runtime_target_id=$2::text::uuid and g.participant_id=$3::text::uuid
              and g.privacy_domain_id=$4::text::uuid and g.state in ('ACTIVATING','ACTIVE')
              and g.generation_digest=$5 and g.policy_generation_digest=$6
              and w.configuration_work_id=$7::text::uuid and w.work_kind='RUNTIME_ACTIVATION'
              and w.state in ('LEASED','RECONCILING','COMPLETED')
              and (w.state<>'LEASED' or w.lease_owner=$8)
              and p.state in ('QUALIFIED','ACTIVE') and p.revision=o.observed_revision+2
              and o.state='OBSERVED' and o.input_digest=p.behavior_fingerprint
              and o.observation_id::text=q.result_receipt->>'liveObservationId'
              and o.observation_digest=q.result_receipt->>'liveObservationDigest'
              and o.observation=q.result_receipt->'liveObservation'
              and q.result_receipt->>'artifactDigest'=p.behavior_fingerprint
              and o.valid_until>to_timestamp($9::double precision/1000000000.0)
              and (t.desired_generation_digest=g.generation_digest
                or t.active_generation_digest=g.generation_digest)
            for share of g,w,t,p,o,q"#,
        )
        .bind(&input.runtime_configuration_generation_id)
        .bind(&input.runtime_target_id)
        .bind(&self.participant_id)
        .bind(&self.privacy_domain_id)
        .bind(stored_digest(&input.generation_digest))
        .bind(stored_digest(&input.policy_generation_digest))
        .bind(&input.configuration_work_id)
        .bind(&self.worker_id)
        .bind(now_ns as f64)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| "current routing owners unavailable")?;
        let observation: Value = row
            .try_get("observation")
            .map_err(|_| "provider observation invalid")?;
        let receipt: Value = row
            .try_get("result_receipt")
            .map_err(|_| "provider qualification receipt invalid")?;
        let connection: ConnectionRecord = serde_json::from_value(
            observation
                .get("connection")
                .cloned()
                .ok_or_else(|| "provider connection observation missing".to_owned())?,
        )
        .map_err(|_| "provider connection observation invalid")?;
        let provider_profile_id: String = row
            .try_get("provider_profile_id")
            .map_err(|_| "provider identity invalid")?;
        if connection.provider_id != provider_profile_id
            || connection.status != ConnectionStatus::Prepared
        {
            return Err("provider connection observation stale".into());
        }
        let provider_artifact_cbor = receipt_bytes(&receipt, "artifactCbor")?;
        let provider_artifact_digest = receipt
            .get("artifactDigest")
            .and_then(Value::as_str)
            .ok_or_else(|| "provider artifact digest missing".to_owned())?
            .to_owned();
        let profile = qualify_provider_profile(&provider_artifact_cbor, &provider_artifact_digest)
            .map_err(|_| "provider qualification artifact rejected")?;
        let provider_chain_id: String = row
            .try_get("provider_chain_id")
            .map_err(|_| "provider chain identity invalid")?;
        if profile.provider_instance_id.is_empty() {
            return Err("provider route instance unsupported".into());
        }
        if profile.chain_id != provider_chain_id {
            return Err("provider route chain unsupported".into());
        }
        if profile.route_plan != pc_provider_api::RoutePlanDraftV1::SingleExact {
            return Err("provider route plan unsupported".into());
        }
        if profile.read_retry_budget != 0 {
            return Err("provider route retry unsupported".into());
        }
        let governed_write =
            profile.idempotency == pc_provider_api::IdempotencyClass::GovernedWrite;
        if governed_write {
            deployment::validate_profile(&profile)?;
            if input.deployment_policies.is_empty() && input.write_runtime_binding_ids.is_empty() {
                return Err("governed write routing selection missing".into());
            }
        } else if profile.idempotency != pc_provider_api::IdempotencyClass::IdempotentRead
            || (input.read_runtime_binding_ids.is_empty() && input.visibility_resources.is_empty())
        {
            return Err("read routing selection missing".into());
        }
        if !governed_write
            && !input.read_runtime_binding_ids.is_empty()
            && !profile
                .method_data_classes
                .iter()
                .any(|item| item.method == "eth_call" && item.data_class == "STATE_CALL")
        {
            return Err("provider route data class unsupported".into());
        }
        if !governed_write {
            for (_, method, _, _) in visibility_assignments(input) {
                let class = match method {
                    "eth_getLogs" => "EVENT_LOG",
                    "eth_getTransactionByHash" => "TRANSACTION",
                    _ => "RECEIPT",
                };
                if !profile
                    .method_data_classes
                    .iter()
                    .any(|entry| entry.method == method && entry.data_class == class)
                {
                    return Err("provider visibility data class unsupported".into());
                }
            }
        }
        if !governed_write
            && profile.response_schema_digest
                != openpc_runtime_agent::provider_response::call_result_response_schema_digest()
        {
            return Err("provider route response schema unsupported".into());
        }
        if !governed_write
            && profile.normalization_rule_digest
                != openpc_runtime_agent::provider_response::call_result_normalization_rule_digest()
        {
            return Err("provider route normalization unsupported".into());
        }
        let valid_until_ms: i64 = row
            .try_get("observation_valid_until_ms")
            .map_err(|_| "provider observation validity invalid")?;
        Ok(CurrentOwner {
            provider_profile_id,
            provider_chain_id,
            provider_revision: row
                .try_get("provider_revision")
                .map_err(|_| "provider revision invalid")?,
            observation_id: row
                .try_get("observation_id")
                .map_err(|_| "provider observation identity invalid")?,
            observation_digest: row
                .try_get("observation_digest")
                .map_err(|_| "provider observation digest invalid")?,
            observation_valid_until_ms: u64::try_from(valid_until_ms)
                .map_err(|_| "provider observation validity invalid")?,
            provider_artifact_digest,
            provider_artifact_cbor,
            connection,
            risk_class: row
                .try_get(if governed_write {
                    "deployment_risk_class"
                } else {
                    "risk_class"
                })
                .map_err(|_| "runtime route risk class unavailable")?,
            governed_write,
        })
    }

    async fn validate_bindings(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        input: &GovernedRoutingPublicationInput,
        owner: &CurrentOwner,
    ) -> Result<String, String> {
        let profile = qualify_provider_profile(
            &owner.provider_artifact_cbor,
            &owner.provider_artifact_digest,
        )
        .map_err(|_| "provider route profile rejected")?;
        if profile.chain_id != owner.provider_chain_id {
            return Err("provider route profile chain substituted".into());
        }
        if owner.governed_write {
            deployment::validate_bindings(
                transaction,
                input,
                &profile,
                &self.participant_id,
                &self.privacy_domain_id,
            )
            .await?;
        }
        let mut environment = None;
        if !owner.governed_write {
            for resource in &input.visibility_resources {
                use pc_policy_core::visibility_policy::VisibilitySelector;
                let (id, revision) = match &resource.selector {
                    VisibilitySelector::Event {
                        runtime_binding_id,
                        binding_revision,
                        ..
                    }
                    | VisibilitySelector::Transaction {
                        runtime_binding_id,
                        binding_revision,
                    }
                    | VisibilitySelector::Receipt {
                        runtime_binding_id,
                        binding_revision,
                    } => (runtime_binding_id, binding_revision),
                    _ => return Err("visibility route selector rejected".into()),
                };
                let expected = resource
                    .contract_binding
                    .as_ref()
                    .ok_or("visibility route binding absent")?;
                if resource.participant_id != self.participant_id
                    || resource.privacy_domain_id != self.privacy_domain_id
                    || expected.chain_id != profile.chain_id
                    || expected.network_id != profile.network_id
                    || expected.genesis_digest != profile.genesis_hash
                {
                    return Err("visibility route scope rejected".into());
                }
                let current: (Value,) = sqlx::query_as(r#"select jsonb_build_object(
                    'chainId',b.chain_id,'networkId',b.network_id,'genesisDigest',b.genesis_digest,
                    'contractAddress',b.contract_address,'codeDigest',b.code_digest,'abiDigest',a.abi_digest,'canonicalAbi',a.canonical_abi)
                    from control.contract_runtime_binding b join control.abi_artifact a
                      on a.abi_artifact_id=b.abi_artifact_id and a.participant_id=b.participant_id and a.privacy_domain_id=b.privacy_domain_id
                    where b.runtime_binding_id=$1::text::uuid and b.revision=$2::text::bigint and b.state='BOUND'
                      and b.participant_id=$3::text::uuid and b.privacy_domain_id=$4::text::uuid for share of b,a"#)
                    .bind(id).bind(revision).bind(&self.participant_id).bind(&self.privacy_domain_id)
                    .fetch_one(&mut **transaction).await.map_err(|_|"visibility route binding unavailable")?;
                if current.0
                    != serde_json::to_value(expected)
                        .map_err(|_| "visibility route binding invalid")?
                {
                    return Err("visibility route binding changed".into());
                }
                environment = Some(format!(
                    "{}:{}:{}",
                    profile.chain_id, profile.network_id, profile.genesis_hash
                ));
            }
        }
        let (bindings, effect) = if owner.governed_write {
            (&input.write_runtime_binding_ids, "WRITE")
        } else {
            (&input.read_runtime_binding_ids, "READ")
        };
        for binding in bindings {
            let row = sqlx::query(
                r#"select b.chain_id,b.network_id,b.genesis_digest
                  from control.contract_runtime_binding b
                  where b.runtime_binding_id=$1::text::uuid and b.participant_id=$2::text::uuid
                    and b.privacy_domain_id=$3::text::uuid and b.state='BOUND'
                    and exists(select 1 from control.contract_method_policy m
                      where m.runtime_binding_id=b.runtime_binding_id
                        and m.participant_id=b.participant_id and m.privacy_domain_id=b.privacy_domain_id
                        and m.abi_artifact_id=b.abi_artifact_id and m.effect=$4
                        and m.state='ACTIVE' and 'LOCAL'=any(m.environments))"#,
            )
            .bind(binding)
            .bind(&self.participant_id)
            .bind(&self.privacy_domain_id)
            .bind(effect)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| "governed contract binding unavailable")?;
            let chain_id: String = row.try_get("chain_id").map_err(|_| "chain id invalid")?;
            let network_id: String = row
                .try_get("network_id")
                .map_err(|_| "network id invalid")?;
            let genesis_digest: String = row
                .try_get("genesis_digest")
                .map_err(|_| "genesis digest invalid")?;
            if chain_id != profile.chain_id
                || network_id != profile.network_id
                || genesis_digest != profile.genesis_hash
            {
                return Err("governed contract binding chain mismatch".into());
            }
            let current = format!("{chain_id}:{network_id}:{genesis_digest}");
            if environment
                .replace(current.clone())
                .is_some_and(|old| old != current)
            {
                return Err("cross-chain route publication rejected".into());
            }
        }
        if owner.governed_write && !input.deployment_policies.is_empty() {
            Ok(format!(
                "{}:{}:{}",
                profile.chain_id, profile.network_id, profile.genesis_hash
            ))
        } else {
            environment.ok_or_else(|| "governed contract binding set empty".into())
        }
    }
}

fn validate_replayed_publication(
    selected: &PublishedRoutingArtifacts,
    input: &GovernedRoutingPublicationInput,
    owner: &CurrentOwner,
    chain_environment_id: &str,
    expected_assignments: &[(String, &'static str, u64, u64)],
    repository: &RoutingPublicationRepository,
    now_ns: u64,
) -> Result<(), String> {
    let mrpc_runtime_profile_digest =
        &governed_mrpc_profile(&repository.worker_id, owner.governed_write)?
            .semantic_digest()
            .map_err(runtime_error)?;
    let routing = decode_canonical::<RoutingSnapshotSource>(&selected.routing_source)?;
    let certification =
        decode_canonical::<ProviderCertificationSource>(&selected.certification_source)?;
    let valid_until_ns = owner
        .observation_valid_until_ms
        .checked_mul(1_000_000)
        .ok_or_else(|| "routing publication validity overflow".to_owned())?;
    let coherence_group_digest = Digest::of(
        serde_json::to_vec(&(
            &owner.provider_profile_id,
            &owner.connection.endpoint_id,
            &owner.connection.configuration_digest,
            &input.generation_digest,
            mrpc_runtime_profile_digest,
        ))
        .map_err(|_| "routing publication coherence rejected")?,
    );
    let common_matches = routing.version == 1
        && certification.version == 1
        && routing.participant_id == certification.participant_id
        && routing.participant_id == repository.participant_id
        && routing.privacy_domain_id == certification.privacy_domain_id
        && routing.privacy_domain_id == repository.privacy_domain_id
        && routing.target_id == input.runtime_target_id
        && certification.target_id == input.runtime_target_id
        && routing.runtime_generation == input.runtime_generation
        && certification.runtime_generation == input.runtime_generation
        && routing.policy_generation_digest == input.policy_generation_digest
        && certification.policy_generation_digest == input.policy_generation_digest
        && routing.mrpc_runtime_profile_digest == *mrpc_runtime_profile_digest
        && certification.mrpc_runtime_profile_digest == *mrpc_runtime_profile_digest;
    let assignments_match = routing.assignments.len() == expected_assignments.len()
        && routing.assignments.iter().zip(expected_assignments).all(
            |(assignment, (binding, method, role, purpose))| {
                assignment.runtime_binding_id == *binding
                    && assignment.method == *method
                    && assignment.risk_class == owner.risk_class
                    && assignment.provider_profile_id == owner.provider_profile_id
                    && assignment.endpoint_id == owner.connection.endpoint_id
                    && assignment.endpoint_role == *role
                    && assignment.purpose == *purpose
                    && assignment.chain_environment_id == chain_environment_id
                    && assignment.canonical_generation == input.runtime_generation
                    && assignment.invalidation_generation == input.runtime_generation
                    && assignment.coherence_group_digest == coherence_group_digest
                    && assignment.valid_until_ns == valid_until_ns
                    && assignment.required_facts == input.required_facts
            },
        );
    let certification_matches = match certification.certifications.as_slice() {
        [item] => {
            item.provider_profile_id == owner.provider_profile_id
                && item.provider_artifact_digest
                    == parse_stored_digest(&owner.provider_artifact_digest)?
                && item.provider_profile_cbor == owner.provider_artifact_cbor
                && item.endpoint_id == owner.connection.endpoint_id
                && item.connection_configuration_digest == owner.connection.configuration_digest
                && item.valid_from_ns > 0
                && item.valid_from_ns <= now_ns
                && item.valid_until_ns == valid_until_ns
                && item.required_facts == input.required_facts
        }
        _ => false,
    };
    if !common_matches || !assignments_match || !certification_matches {
        return Err("routing publication replay substitution rejected".into());
    }
    Ok(())
}

fn validate_input(input: &GovernedRoutingPublicationInput, now_ns: u64) -> Result<(), String> {
    if now_ns == 0
        || input.runtime_generation == 0
        || (input.read_runtime_binding_ids.is_empty()
            && input.visibility_resources.is_empty()
            && input.write_runtime_binding_ids.is_empty()
            && input.deployment_policies.is_empty())
        || input.read_runtime_binding_ids.len()
            + input.visibility_resources.len()
            + 2 * (input.write_runtime_binding_ids.len() + input.deployment_policies.len())
            > 256
    {
        return Err("routing publication input rejected".into());
    }
    let ids = input
        .read_runtime_binding_ids
        .iter()
        .collect::<BTreeSet<_>>();
    for resource in &input.visibility_resources {
        resource
            .contract_binding
            .as_ref()
            .ok_or("visibility route binding absent")?
            .digest()
            .map_err(runtime_error)?;
    }
    if ids.len() != input.read_runtime_binding_ids.len()
        || input
            .write_runtime_binding_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != input.write_runtime_binding_ids.len()
        || input
            .deployment_policies
            .iter()
            .any(|p| p.validate().is_err())
        || input
            .deployment_policies
            .iter()
            .map(|p| &p.deployment_policy_id)
            .collect::<BTreeSet<_>>()
            .len()
            != input.deployment_policies.len()
        || input.deployment_policies.iter().any(|p| {
            ids.contains(&p.deployment_policy_id)
                || input
                    .write_runtime_binding_ids
                    .contains(&p.deployment_policy_id)
        })
        || input
            .required_facts
            .iter()
            .map(|fact| &fact.candidate_id)
            .collect::<BTreeSet<_>>()
            .len()
            != input.required_facts.len()
    {
        return Err("routing publication input duplicates".into());
    }
    if input.required_facts.is_empty() {
        Ok(())
    } else {
        pc_policy_core::semantics::validate_fact_references(&input.required_facts)
            .map_err(|_| "routing publication facts rejected".to_owned())
    }
}

fn build_publication(
    signer: &RuntimeWireSigner,
    signer_id: &str,
    routing: RoutingSnapshotSource,
    certification: ProviderCertificationSource,
    mrpc_runtime_profile: Vec<u8>,
    mrpc_runtime_profile_digest: Digest,
    now_ns: u64,
) -> Result<PublishedRoutingArtifacts, String> {
    let routing_source = pc_cbor_1(&routing);
    let certification_source = pc_cbor_1(&certification);
    let routing_header = AuthorityArtifact {
        artifact_id: ROUTING_ARTIFACT_ID.into(),
        artifact_version: routing.runtime_generation,
        artifact_class: 1,
        source_media_type: "application/cbor".into(),
        source_content_sha256: Digest::of(&routing_source),
        definition_digest: Digest::of(ROUTING_DEFINITION),
        issued_at_ns: now_ns,
        signer_id: signer_id.into(),
    };
    let certification_header = AuthorityArtifact {
        artifact_id: CERTIFICATION_ARTIFACT_ID.into(),
        artifact_version: certification.runtime_generation,
        artifact_class: 1,
        source_media_type: "application/cbor".into(),
        source_content_sha256: Digest::of(&certification_source),
        definition_digest: Digest::of(CERTIFICATION_DEFINITION),
        issued_at_ns: now_ns,
        signer_id: signer_id.into(),
    };
    let routing_authority = signer
        .sign_authority_artifact(&routing_header)
        .map_err(runtime_error)?;
    let certification_authority = signer
        .sign_authority_artifact(&certification_header)
        .map_err(runtime_error)?;
    Ok(PublishedRoutingArtifacts {
        publication_id: String::new(),
        mrpc_runtime_profile_content_digest: Digest::of(&mrpc_runtime_profile),
        mrpc_runtime_profile_digest,
        mrpc_runtime_profile,
        routing_source_digest: routing_header.source_content_sha256.clone(),
        routing_authority_content_digest: Digest::of(&routing_authority),
        routing_authority_digest: routing_header.semantic_digest().map_err(runtime_error)?,
        routing_source,
        routing_authority,
        certification_source_digest: certification_header.source_content_sha256.clone(),
        certification_authority_content_digest: Digest::of(&certification_authority),
        certification_authority_digest: certification_header
            .semantic_digest()
            .map_err(runtime_error)?,
        certification_source,
        certification_authority,
    })
}

async fn read_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    generation_id: &str,
    verifier: &RuntimeWireVerifier,
    profile_verifier: &pc_policy_core::runtime_wire::Verifier,
    now_ns: u64,
) -> Result<PublishedRoutingArtifacts, String> {
    let row = sqlx::query(
        r#"select p.runtime_route_publication_id::text,p.mrpc_runtime_profile_cose,
          p.mrpc_runtime_profile_content_digest,p.mrpc_runtime_profile_digest,p.routing_source_cbor,
          p.routing_source_digest,p.routing_authority_cose,p.routing_authority_content_digest,
          p.routing_authority_digest,p.certification_source_cbor,p.certification_source_digest,
          p.certification_authority_cose,p.certification_authority_content_digest,
          p.certification_authority_digest
        from control.runtime_route_publication p
        join control.runtime_configuration_generation g
          on g.runtime_configuration_generation_id=p.runtime_configuration_generation_id
         and g.participant_id=p.participant_id and g.privacy_domain_id=p.privacy_domain_id
         and g.runtime_target_id=p.runtime_target_id and g.provider_profile_id=p.provider_profile_id
         and g.generation_digest=p.generation_digest
         and g.policy_generation_digest=p.policy_generation_digest
        join control.runtime_target t on t.runtime_target_id=p.runtime_target_id
         and t.participant_id=p.participant_id and t.privacy_domain_id=p.privacy_domain_id
        join control.provider_profile provider on provider.provider_profile_id=p.provider_profile_id
         and provider.participant_id=p.participant_id and provider.privacy_domain_id=p.privacy_domain_id
         and provider.revision=p.provider_revision and provider.state in ('QUALIFIED','ACTIVE')
        join control.provider_probe_observation o
          on o.observation_id=p.qualification_observation_id
         and o.provider_profile_id=p.provider_profile_id and o.participant_id=p.participant_id
         and o.privacy_domain_id=p.privacy_domain_id
         and o.observation_digest=p.qualification_observation_digest and o.state='OBSERVED'
        left join control.runtime_activation_observation activation
          on activation.configuration_work_id=p.configuration_work_id
         and activation.runtime_configuration_generation_id=p.runtime_configuration_generation_id
         and activation.runtime_target_id=p.runtime_target_id
         and activation.generation_digest=p.generation_digest
        where p.runtime_configuration_generation_id=$1::text::uuid
          and p.valid_until>to_timestamp($2::double precision/1000000000.0)
          and o.valid_until>to_timestamp($2::double precision/1000000000.0)
          and ((g.state='ACTIVATING' and t.desired_generation_digest=g.generation_digest)
            or (g.state='ACTIVE' and activation.capsule_digest=t.active_generation_digest))"#,
    )
    .bind(generation_id)
    .bind(now_ns as f64)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| "current routing publication unavailable")?;
    let result = PublishedRoutingArtifacts {
        publication_id: row
            .try_get("runtime_route_publication_id")
            .map_err(row_error)?,
        mrpc_runtime_profile: row
            .try_get("mrpc_runtime_profile_cose")
            .map_err(row_error)?,
        mrpc_runtime_profile_content_digest: parse_stored_digest(
            &row.try_get::<String, _>("mrpc_runtime_profile_content_digest")
                .map_err(row_error)?,
        )?,
        mrpc_runtime_profile_digest: parse_stored_digest(
            &row.try_get::<String, _>("mrpc_runtime_profile_digest")
                .map_err(row_error)?,
        )?,
        routing_source: row.try_get("routing_source_cbor").map_err(row_error)?,
        routing_source_digest: parse_stored_digest(
            &row.try_get::<String, _>("routing_source_digest")
                .map_err(row_error)?,
        )?,
        routing_authority: row.try_get("routing_authority_cose").map_err(row_error)?,
        routing_authority_content_digest: parse_stored_digest(
            &row.try_get::<String, _>("routing_authority_content_digest")
                .map_err(row_error)?,
        )?,
        routing_authority_digest: parse_stored_digest(
            &row.try_get::<String, _>("routing_authority_digest")
                .map_err(row_error)?,
        )?,
        certification_source: row
            .try_get("certification_source_cbor")
            .map_err(row_error)?,
        certification_source_digest: parse_stored_digest(
            &row.try_get::<String, _>("certification_source_digest")
                .map_err(row_error)?,
        )?,
        certification_authority: row
            .try_get("certification_authority_cose")
            .map_err(row_error)?,
        certification_authority_content_digest: parse_stored_digest(
            &row.try_get::<String, _>("certification_authority_content_digest")
                .map_err(row_error)?,
        )?,
        certification_authority_digest: parse_stored_digest(
            &row.try_get::<String, _>("certification_authority_digest")
                .map_err(row_error)?,
        )?,
    };
    verify_readback(&result, verifier, profile_verifier)?;
    Ok(result)
}

fn verify_readback(
    result: &PublishedRoutingArtifacts,
    verifier: &RuntimeWireVerifier,
    profile_verifier: &pc_policy_core::runtime_wire::Verifier,
) -> Result<(), String> {
    if Digest::of(&result.mrpc_runtime_profile) != result.mrpc_runtime_profile_content_digest
        || Digest::of(&result.routing_source) != result.routing_source_digest
        || Digest::of(&result.routing_authority) != result.routing_authority_content_digest
        || Digest::of(&result.certification_source) != result.certification_source_digest
        || Digest::of(&result.certification_authority)
            != result.certification_authority_content_digest
    {
        return Err("routing publication content digest rejected".into());
    }
    let mrpc_profile = MrpcRuntimeProfile::verify(profile_verifier, &result.mrpc_runtime_profile)
        .map_err(runtime_error)?;
    if mrpc_profile.semantic_digest().map_err(runtime_error)? != result.mrpc_runtime_profile_digest
        || mrpc_profile.capability_registry_digest
            != openpc_runtime_agent::provider_response::call_result_disclosure_policy_digest()
    {
        return Err("routing publication runtime profile rejected".into());
    }
    let routing = verifier
        .verify_authority_artifact(&result.routing_authority)
        .map_err(runtime_error)?;
    let certification = verifier
        .verify_authority_artifact(&result.certification_authority)
        .map_err(runtime_error)?;
    if routing.artifact_id != ROUTING_ARTIFACT_ID
        || routing.source_content_sha256 != result.routing_source_digest
        || routing.definition_digest != Digest::of(ROUTING_DEFINITION)
        || routing.semantic_digest().map_err(runtime_error)? != result.routing_authority_digest
        || certification.artifact_id != CERTIFICATION_ARTIFACT_ID
        || certification.source_content_sha256 != result.certification_source_digest
        || certification.definition_digest != Digest::of(CERTIFICATION_DEFINITION)
        || certification.semantic_digest().map_err(runtime_error)?
            != result.certification_authority_digest
    {
        return Err("routing publication authority rejected".into());
    }
    let routing = decode_canonical::<RoutingSnapshotSource>(&result.routing_source)?;
    let certification =
        decode_canonical::<ProviderCertificationSource>(&result.certification_source)?;
    if routing.mrpc_runtime_profile_digest != result.mrpc_runtime_profile_digest
        || certification.mrpc_runtime_profile_digest != result.mrpc_runtime_profile_digest
    {
        return Err("routing publication runtime profile substitution rejected".into());
    }
    Ok(())
}

fn observation_assignments(
    mut assignments: Vec<(String, &'static str, u64, u64)>,
    historical_bindings: &[String],
) -> Result<Vec<(String, &'static str, u64, u64)>, String> {
    for binding in historical_bindings {
        let route = (binding.clone(), "eth_getTransactionReceipt", 4, 4);
        if !assignments.contains(&route) {
            assignments.push(route);
        }
    }
    if assignments.len() > 256 {
        return Err("routing publication assignment capacity rejected".into());
    }
    Ok(assignments)
}

fn selected_assignments(
    input: &GovernedRoutingPublicationInput,
    governed_write: bool,
) -> Vec<(String, &'static str, u64, u64)> {
    if governed_write {
        input
            .write_runtime_binding_ids
            .iter()
            .chain(
                input
                    .deployment_policies
                    .iter()
                    .map(|p| &p.deployment_policy_id),
            )
            .flat_map(|binding| {
                [
                    (binding.clone(), "eth_sendRawTransaction", 4, 3),
                    (binding.clone(), "eth_getTransactionReceipt", 4, 4),
                ]
            })
            .collect()
    } else {
        input
            .read_runtime_binding_ids
            .iter()
            .map(|id| (id.clone(), "eth_call", 1, 1))
            .chain(visibility_assignments(input))
            .collect()
    }
}

fn visibility_assignments(
    input: &GovernedRoutingPublicationInput,
) -> Vec<(String, &'static str, u64, u64)> {
    use pc_policy_core::visibility_policy::VisibilitySelector;
    input
        .visibility_resources
        .iter()
        .filter_map(|resource| {
            let method = match resource.selector {
                VisibilitySelector::Event { .. } => "eth_getLogs",
                VisibilitySelector::Transaction { .. } => "eth_getTransactionByHash",
                VisibilitySelector::Receipt { .. } => "eth_getTransactionReceipt",
                _ => return None,
            };
            Some((resource.selector.resource_id().into(), method, 1, 1))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn governed_mrpc_profile(signer_id: &str, deployment: bool) -> Result<MrpcRuntimeProfile, String> {
    if signer_id.is_empty() || signer_id.len() > 160 {
        return Err("routing runtime profile signer rejected".into());
    }
    Ok(MrpcRuntimeProfile {
        profile_id: if deployment {
            "openpc-r1-single-exact-deployment"
        } else {
            "openpc-r1-single-exact-state-call"
        }
        .into(),
        capability_registry_digest:
            openpc_runtime_agent::provider_response::call_result_disclosure_policy_digest(),
        endpoint_role_rules_digest: Digest::of(b"openpc.mrpc.endpoint-role.single-exact.v1"),
        coherence_rules_digest: if deployment {
            Digest::of(b"openpc.mrpc.coherence.hash-pinned-deployment.v1")
        } else {
            Digest::of(b"openpc.mrpc.coherence.hash-pinned-state-call.v1")
        },
        signer_id: signer_id.into(),
    })
}

fn decode_canonical<T: serde::de::DeserializeOwned + serde::Serialize>(
    bytes: &[u8],
) -> Result<T, String> {
    let value: T = ciborium::de::from_reader(bytes)
        .map_err(|_| "routing publication source invalid".to_owned())?;
    if pc_cbor_1(&value) != bytes {
        return Err("routing publication source noncanonical".into());
    }
    Ok(value)
}

fn receipt_bytes(receipt: &Value, field: &str) -> Result<Vec<u8>, String> {
    receipt
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("provider receipt {field} missing"))?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|byte| u8::try_from(byte).ok())
                .ok_or_else(|| format!("provider receipt {field} invalid"))
        })
        .collect()
}

fn stored_digest(value: &Digest) -> String {
    format!("sha256:{}", value.as_str())
}

fn parse_stored_digest(value: &str) -> Result<Digest, String> {
    Digest::parse(
        value
            .strip_prefix("sha256:")
            .ok_or_else(|| "stored routing digest invalid".to_owned())?,
    )
    .map_err(runtime_error)
}

fn runtime_error(_: RuntimeError) -> String {
    "routing publication cryptographic validation failed".into()
}

fn row_error(_: sqlx::Error) -> String {
    "routing publication row invalid".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handed_off_policy_retains_observation_without_renewing_submission() {
        let current = vec![
            ("renewed".into(), "eth_sendRawTransaction", 4, 3),
            ("renewed".into(), "eth_getTransactionReceipt", 4, 4),
        ];
        let routes = observation_assignments(
            current,
            &["expired".into(), "renewed".into(), "expired".into()],
        )
        .unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(
            routes[2],
            ("expired".into(), "eth_getTransactionReceipt", 4, 4)
        );
        assert!(!routes.iter().any(|r| r.0 == "expired" && r.3 == 3));
        assert!(observation_assignments(routes.clone(), &[]) == Ok(routes));
        let overflow = (0..257).map(|i| format!("old-{i}")).collect::<Vec<_>>();
        assert!(observation_assignments(Vec::new(), &overflow).is_err());
    }

    #[test]
    fn signed_publication_rejects_substituted_source_authority_and_key() {
        let signer = RuntimeWireSigner::from_secret_bytes([21; 32]).unwrap();
        let profile_signer = ProfileSigner::from_secret_bytes([21; 32]).unwrap();
        let profile = governed_mrpc_profile("publisher", false).unwrap();
        let profile_digest = profile.semantic_digest().unwrap();
        let signed_profile = profile.sign(&profile_signer).unwrap();
        let facts = vec![FactReference {
            candidate_id: "candidate".into(),
            generation_id: "generation".into(),
            fact_digest: format!("sha256:{}", Digest::of(b"fact").as_str()),
        }];
        let routing = RoutingSnapshotSource {
            version: 1,
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            target_id: "target".into(),
            runtime_generation: 7,
            policy_generation_digest: Digest::of(b"policy"),
            mrpc_runtime_profile_digest: profile_digest.clone(),
            assignments: vec![RoutingAssignment {
                runtime_binding_id: "018f0000-0000-7000-8000-000000000101".into(),
                method: "eth_call".into(),
                risk_class: "LOW".into(),
                provider_profile_id: "provider".into(),
                endpoint_id: "endpoint".into(),
                endpoint_role: 1,
                purpose: 1,
                chain_environment_id: "chain".into(),
                canonical_generation: 7,
                invalidation_generation: 7,
                coherence_group_digest: Digest::of(b"coherence"),
                valid_until_ns: 20,
                required_facts: facts.clone(),
            }],
        };
        let certification = ProviderCertificationSource {
            version: 1,
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            target_id: "target".into(),
            runtime_generation: 7,
            policy_generation_digest: Digest::of(b"policy"),
            mrpc_runtime_profile_digest: profile_digest.clone(),
            certifications: vec![ProviderCertification {
                provider_profile_id: "provider".into(),
                provider_artifact_digest: Digest::of(b"profile"),
                provider_profile_cbor: vec![1],
                endpoint_id: "endpoint".into(),
                connection_configuration_digest: Digest::of(b"connection"),
                valid_from_ns: 1,
                valid_until_ns: 20,
                required_facts: facts,
            }],
        };
        let publication = build_publication(
            &signer,
            "publisher",
            routing,
            certification,
            signed_profile,
            profile_digest,
            1,
        )
        .unwrap();
        verify_readback(&publication, &signer.verifier(), &profile_signer.verifier()).unwrap();
        for changed in 0..3 {
            let mut altered = publication.clone();
            match changed {
                0 => altered.routing_source.push(0),
                1 => altered.certification_authority.push(0),
                _ => {
                    assert!(
                        verify_readback(
                            &altered,
                            &RuntimeWireSigner::from_secret_bytes([22; 32])
                                .unwrap()
                                .verifier(),
                            &profile_signer.verifier(),
                        )
                        .is_err()
                    );
                    continue;
                }
            }
            assert!(
                verify_readback(&altered, &signer.verifier(), &profile_signer.verifier()).is_err()
            );
        }
    }

    #[test]
    fn publication_input_rejects_partial_duplicate_and_unsupported_sets() {
        let baseline = GovernedRoutingPublicationInput {
            visibility_resources: Vec::new(),
            configuration_work_id: "work".into(),
            runtime_configuration_generation_id: "generation".into(),
            runtime_target_id: "target".into(),
            runtime_generation: 1,
            generation_digest: Digest::of(b"generation"),
            policy_generation_digest: Digest::of(b"policy"),
            read_runtime_binding_ids: vec!["binding".into()],
            write_runtime_binding_ids: Vec::new(),
            deployment_policies: Vec::new(),
            required_facts: vec![FactReference {
                candidate_id: "candidate".into(),
                generation_id: "generation".into(),
                fact_digest: format!("sha256:{}", Digest::of(b"fact").as_str()),
            }],
        };
        assert!(validate_input(&baseline, 1).is_ok());
        for changed in 0..3 {
            let mut input = baseline.clone();
            match changed {
                0 => input.runtime_generation = 0,
                1 => input.read_runtime_binding_ids.clear(),
                2 => input.read_runtime_binding_ids.push("binding".into()),
                _ => unreachable!(),
            }
            assert!(validate_input(&input, 1).is_err());
        }
        let mut factless = baseline.clone();
        factless.required_facts.clear();
        assert!(validate_input(&factless, 1).is_ok());
        let mut malformed_fact = baseline.clone();
        malformed_fact.required_facts[0].fact_digest = "not-a-digest".into();
        assert!(validate_input(&malformed_fact, 1).is_err());
        let mut write = baseline.clone();
        write.read_runtime_binding_ids.clear();
        write.write_runtime_binding_ids.push("binding".into());
        assert!(validate_input(&write, 1).is_ok());
        assert_eq!(
            selected_assignments(&write, true),
            vec![
                ("binding".into(), "eth_sendRawTransaction", 4, 3),
                ("binding".into(), "eth_getTransactionReceipt", 4, 4),
            ]
        );
        // A read-only provider cannot acquire a write route merely because its
        // capsule contains that method. Observation remains a separate purpose.
        assert!(selected_assignments(&write, false).is_empty());
        write.read_runtime_binding_ids.push("binding".into());
        assert!(validate_input(&write, 1).is_ok());
        assert_eq!(
            selected_assignments(&write, false),
            vec![("binding".into(), "eth_call", 1, 1),]
        );
        assert_eq!(selected_assignments(&write, true).len(), 2);
        write.write_runtime_binding_ids.push("binding".into());
        assert!(validate_input(&write, 1).is_err());

        // Standalone response policies need real read routes without inventing
        // an invocation policy or granting the submission/observation purposes.
        let mut visibility = baseline.clone();
        visibility.read_runtime_binding_ids.clear();
        visibility.visibility_resources.push(serde_json::from_value(serde_json::json!({
            "participantId":"participant","privacyDomainId":"privacy",
            "selector":{"kind":"RECEIPT","runtimeBindingId":"018f0000-0000-7000-8000-000000000191","bindingRevision":"1"},
            "availableFields":[],"contractBinding":{
                "chainId":"1","networkId":"test","genesisDigest":format!("sha256:{}",Digest::of("genesis").as_str()),
                "contractAddress":format!("0x{}","11".repeat(20)),"codeDigest":format!("sha256:{}",Digest::of("code").as_str()),
                "abiDigest":format!("sha256:{}",Digest::of("abi").as_str()),"canonicalAbi":[]
            }
        })).unwrap());
        assert!(validate_input(&visibility, 1).is_ok());
        assert_eq!(
            selected_assignments(&visibility, false),
            vec![(
                "018f0000-0000-7000-8000-000000000191".into(),
                "eth_getTransactionReceipt",
                1,
                1
            )]
        );
        assert!(selected_assignments(&visibility, true).is_empty());
        visibility.visibility_resources[0].contract_binding = None;
        assert!(validate_input(&visibility, 1).is_err());
    }
}
