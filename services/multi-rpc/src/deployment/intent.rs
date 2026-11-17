//! DeploymentIntentV1 for direct creation and the closed factory extension.
//! Direct artifacts retain their frozen schema and canonical bytes. The record binds intent, not
//! authority: preflight, approval, reservation and the final fence remain owners
//! of their own transitions. The contract-only pc_prepareTransaction is unchanged.
use super::{
    BoundDeployment, DeploymentConstraints, DeploymentRoute, FactoryMechanism, bind_publication,
};
use crate::signed_transaction::{SignedTransaction, UnsignedTransaction};
use pc_policy_core::deployment_policy::{AdmittedDeploymentPolicy, DeploymentRouteDefinition};
use pc_policy_core::native_value::{
    NativeValueAuthorizationV1, NativeValueScope, decimal_uint256, intersect_creation_endowment,
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const MAX_PREPARATION_LIFETIME_MS: u64 = 300_000;

/// Resolved inside the owning authenticated transaction, never accepted as
/// client readiness/authority fields. Retention permits exact later rebinding;
/// deserializing this metadata does not establish that any owner is current.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparationContext {
    pub intent_id: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    #[serde(with = "decimal_u64")]
    pub participant_epoch: u64,
    pub actor_subject_id: String,
    pub workload_binding_id: Option<String>,
    pub wallet_binding_id: String,
    #[serde(with = "decimal_u64")]
    pub wallet_binding_epoch: u64,
    pub sender: [u8; 20],
    pub chain_environment_id: String,
    pub target_runtime_id: String,
    pub policy_generation_digest: Digest,
    pub authority_digest: Digest,
    pub policy_decision_digest: Digest,
    pub entitlement_envelope_digest: Digest,
    pub routing_constraint_digest: Digest,
    pub approval_set_digest: Digest,
    /// Exact immutable issuance from Native Value governance. Bytes alone grant
    /// nothing: the protected preparation and signed global handoff own provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_value_authorization_bytes: Option<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeploymentIntentDocument {
    // Present only for factory artifacts, which must never masquerade as the
    // frozen direct-only DeploymentIntentV1 contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    schema_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    factory_constraints: Option<DeploymentConstraints>,
    intent_id: String,
    participant_id: String,
    participant_epoch: u64,
    actor_subject_id: String,
    workload_binding_id: Option<String>,
    chain_environment_id: String,
    chain_id: String,
    genesis_hash: Digest,
    sender: String,
    nonce: String,
    transaction_type: u8,
    destination: Option<String>,
    gas_limit: String,
    value_wei: String,
    init_code: String,
    expected_contract_address: Option<String>,
    artifact_mode: String,
    routing_constraint_digest: Digest,
    policy_decision_digest: Digest,
    approval_set_digest: Digest,
    entitlement_envelope_digest: Digest,
    native_value_authorization_digest: Option<Digest>,
    expires_at: String,
    semantic_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredPreparation {
    schema_version: String,
    context: PreparationContext,
    deployment_policy_id: String,
    publication_digest: Digest,
    signing_payload: String,
    signing_hash: String,
    intent: DeploymentIntentDocument,
}

/// Only constructor/restore validation produces this value. It contains no
/// signing key, one-use grant or provider handle and cannot perform a send.
#[derive(Clone, Debug)]
pub struct PreparedDeploymentIntent {
    stored: StoredPreparation,
    unsigned: UnsignedTransaction,
}

impl PreparedDeploymentIntent {
    pub fn prepare_direct(
        publication: &AdmittedDeploymentPolicy,
        unsigned: UnsignedTransaction,
        context: PreparationContext,
        now_ms: u64,
    ) -> RuntimeResult<Self> {
        if !matches!(
            publication.definition.route,
            DeploymentRouteDefinition::TransactionCreate
        ) {
            return Err(RuntimeError::Denied);
        }
        Self::prepare(publication, unsigned, context, now_ms)
    }

    pub fn prepare(
        publication: &AdmittedDeploymentPolicy,
        unsigned: UnsignedTransaction,
        context: PreparationContext,
        now_ms: u64,
    ) -> RuntimeResult<Self> {
        publication
            .validate()
            .map_err(|_| RuntimeError::InvalidInput)?;
        let definition = &publication.definition;
        if context.participant_id != publication.participant_id
            || context.privacy_domain_id != publication.privacy_domain_id
            || definition.chain_id != unsigned.chain_id().to_string()
            || !definition.allowed_senders.contains(&hex(&context.sender))
            || definition
                .expires_at_ms()
                .map_err(|_| RuntimeError::InvalidInput)?
                < context.expires_at_ms
        {
            return Err(RuntimeError::Denied);
        }
        context.validate(now_ms)?;
        let native_value = context.native_value_authorization()?;
        let native_value = intersect_creation_endowment(
            native_value.as_ref(),
            &NativeValueScope {
                participant_id: &context.participant_id,
                participant_epoch: context.participant_epoch,
                actor_subject_id: &context.actor_subject_id,
                chain_environment_id: &context.chain_environment_id,
                chain_id: &definition.chain_id,
                genesis_hash: &tagged(&definition.genesis_digest)?,
            },
            unsigned.value(),
            &definition.transaction_policy.maximum_value,
            now_ms,
        )?;
        if let Some(grant) = native_value
            && grant.valid_until_ns()? < i128::from(context.expires_at_ms) * 1_000_000
        {
            return Err(RuntimeError::Denied);
        }
        let constraints = super::publication::prepare_publication(
            publication,
            &unsigned,
            &context.sender,
            now_ms,
        )?;
        let expected_contract_address = match &constraints.route {
            DeploymentRoute::DirectCreate { expected_address } => Some(hex(expected_address)),
            DeploymentRoute::Factory(factory) => match &factory.mechanism {
                FactoryMechanism::Create => None,
                FactoryMechanism::Create2 {
                    expected_address, ..
                }
                | FactoryMechanism::Create3 {
                    expected_address, ..
                } => Some(hex(expected_address)),
            },
        };
        let factory = matches!(constraints.route, DeploymentRoute::Factory(_));
        let mut intent = DeploymentIntentDocument {
            schema_version: factory.then(|| "PC-FACTORY-DEPLOYMENT-INTENT-1".into()),
            factory_constraints: factory.then_some(constraints),
            intent_id: context.intent_id.clone(),
            participant_id: context.participant_id.clone(),
            participant_epoch: context.participant_epoch,
            actor_subject_id: context.actor_subject_id.clone(),
            workload_binding_id: context.workload_binding_id.clone(),
            chain_environment_id: context.chain_environment_id.clone(),
            chain_id: unsigned.chain_id().to_string(),
            genesis_hash: tagged(&definition.genesis_digest)?,
            sender: hex(&context.sender),
            nonce: unsigned.nonce().to_string(),
            transaction_type: unsigned.kind(),
            destination: unsigned.destination().map(|address| hex(address)),
            gas_limit: unsigned.gas_limit().to_string(),
            value_wei: decimal_uint256(unsigned.value()),
            init_code: definition.artifact.init_code.clone(),
            expected_contract_address,
            artifact_mode: "FULL_INIT_CODE_V1".into(),
            routing_constraint_digest: context.routing_constraint_digest.clone(),
            policy_decision_digest: context.policy_decision_digest.clone(),
            approval_set_digest: context.approval_set_digest.clone(),
            entitlement_envelope_digest: context.entitlement_envelope_digest.clone(),
            native_value_authorization_digest: native_value
                .map(|grant| grant.semantic_digest.clone()),
            expires_at: OffsetDateTime::from_unix_timestamp_nanos(
                i128::from(context.expires_at_ms) * 1_000_000,
            )
            .map_err(|_| RuntimeError::InvalidInput)?
            .format(&Rfc3339)
            .map_err(|_| RuntimeError::InvalidInput)?,
            semantic_digest: Digest::of([]),
        };
        let mut value = serde_json::to_value(&intent).map_err(|_| RuntimeError::InvalidInput)?;
        value
            .as_object_mut()
            .ok_or(RuntimeError::InvalidInput)?
            .remove("semanticDigest");
        intent.semantic_digest = Digest::of(canonical_bytes(&value)?);
        Ok(Self {
            stored: StoredPreparation {
                schema_version: "PC-DEPLOYMENT-PREPARATION-1".into(),
                context,
                deployment_policy_id: publication.deployment_policy_id.clone(),
                publication_digest: Digest::of(canonical_bytes(
                    &serde_json::to_value(publication).map_err(|_| RuntimeError::InvalidInput)?,
                )?),
                signing_payload: hex(unsigned.bytes()),
                signing_hash: hex(unsigned.signing_hash()),
                intent,
            },
            unsigned,
        })
    }

    /// Validate retained bytes against their publication and historical issue
    /// time. Expired records remain readable; use requires a fresh rebind.
    pub fn restore(bytes: &[u8], publication: &AdmittedDeploymentPolicy) -> RuntimeResult<Self> {
        if bytes.len() > 1024 * 1024 {
            return Err(RuntimeError::InvalidInput);
        }
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidInput)?;
        let stored: StoredPreparation =
            serde_json::from_value(value.clone()).map_err(|_| RuntimeError::InvalidInput)?;
        let payload = decode(&stored.signing_payload)?;
        let unsigned =
            UnsignedTransaction::decode(&payload).map_err(|_| RuntimeError::InvalidInput)?;
        let rebuilt = Self::prepare(
            publication,
            unsigned,
            stored.context.clone(),
            stored.context.issued_at_ms,
        )?;
        if rebuilt.stored != stored
            || serde_json::to_value(&rebuilt.stored).map_err(|_| RuntimeError::InvalidInput)?
                != value
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(rebuilt)
    }

    pub fn record_bytes(&self) -> RuntimeResult<Vec<u8>> {
        canonical_bytes(&self.stored)
    }
    pub fn record_digest(&self) -> RuntimeResult<Digest> {
        Ok(Digest::of(self.record_bytes()?))
    }
    pub fn intent_bytes(&self) -> RuntimeResult<Vec<u8>> {
        canonical_bytes(&self.stored.intent)
    }
    pub fn intent_digest(&self) -> &Digest {
        &self.stored.intent.semantic_digest
    }
    pub fn native_value_authorization_digest(&self) -> Option<&Digest> {
        self.stored
            .intent
            .native_value_authorization_digest
            .as_ref()
    }
    pub fn context(&self) -> &PreparationContext {
        &self.stored.context
    }
    pub fn genesis_digest(&self) -> &Digest {
        &self.stored.intent.genesis_hash
    }
    pub fn unsigned(&self) -> &UnsignedTransaction {
        &self.unsigned
    }
    pub fn expected_contract_address(&self) -> Option<&str> {
        self.stored.intent.expected_contract_address.as_deref()
    }

    /// Preparation may name an executor only from the exact activated target
    /// configuration. This checks scope, not TLS identity or a runtime grant.
    pub fn validate_workload_configuration(&self, bytes: &[u8], digest: &str) -> RuntimeResult<()> {
        let context = self.context();
        let expected = context
            .workload_binding_id
            .as_ref()
            .ok_or(RuntimeError::Denied)?;
        let installed = pc_policy_core::invocation::active_invocation_workload(
            bytes,
            &Digest::parse(digest)?,
            &context.participant_id,
            &context.privacy_domain_id,
        )?;
        if &installed != expected {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }

    /// Produce the existing global coordinator's exact deployment claim.
    /// IDs belong to the deployment owner before reservation; this derives all
    /// address/chain/artifact/intent fields from retained inputs. The result is
    /// not a reservation, a handoff, live authorization or permission to send.
    pub fn reservation_binding(
        &self,
        publication: &AdmittedDeploymentPolicy,
        signed: &SignedTransaction,
        command_id: &str,
        attempt_id: &str,
        now_ms: u64,
    ) -> RuntimeResult<serde_json::Value> {
        let context = self.context();
        for id in [command_id, attempt_id, &context.target_runtime_id] {
            if !uuid::Uuid::try_parse(id)
                .is_ok_and(|parsed| parsed.get_version_num() == 7 && parsed.to_string() == id)
            {
                return Err(RuntimeError::InvalidInput);
            }
        }
        let bound = self.rebind_signed(publication, context, signed, now_ms)?;
        let mechanism = match bound.mechanism {
            super::CreationMechanism::TransactionCreate => "TRANSACTION_CREATE",
            super::CreationMechanism::Create => "CREATE",
            super::CreationMechanism::Create2 => "CREATE2",
            super::CreationMechanism::Create3 => "CREATE3",
        };
        let namespace = match &publication.definition.route {
            DeploymentRouteDefinition::Create2 {
                salt_namespace_digest,
                ..
            }
            | DeploymentRouteDefinition::Create3 {
                salt_namespace_digest,
                ..
            } => Some(salt_namespace_digest),
            _ => None,
        };
        let expires_at = OffsetDateTime::from_unix_timestamp_nanos(
            i128::from(context.expires_at_ms) * 1_000_000,
        )
        .map_err(|_| RuntimeError::InvalidInput)?
        .format(
            &time::format_description::parse_borrowed::<2>(
                "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z",
            )
            .map_err(|_| RuntimeError::InvalidInput)?,
        )
        .map_err(|_| RuntimeError::InvalidInput)?;
        let mut binding = serde_json::json!({
            "attemptId": attempt_id,
            "commandId": command_id,
            "participantId": context.participant_id,
            "privacyDomainId": context.privacy_domain_id,
            "targetRuntimeId": format!("urn:openpc:resource:{}", context.target_runtime_id),
            "chainId": signed.chain_id().to_string(),
            "genesisDigest": publication.definition.genesis_digest,
            "contractAddress": bound.predicted_address.map(|address| hex(&address)),
            "senderAddress": hex(signed.signer()),
            "creatorAddress": hex(&bound.creator),
            "mechanism": mechanism,
            "saltNamespaceDigest": namespace,
            "effectiveSalt": bound.salt.map(|salt| hex(&salt)),
            "artifactDigest": publication.artifact_digest,
            "initCodeHash": publication.init_code_hash,
            "intentDigest": format!("sha256:{}", self.intent_digest().as_str()),
            "profileDigest": publication.definition_digest,
            "generationDigest": format!("sha256:{}", context.policy_generation_digest.as_str()),
            "transactionHash": hex(signed.hash()),
            "preparedRecordDigest": format!("sha256:{}", self.record_digest()?.as_str()),
            "expiresAt": expires_at,
        });
        if bound.mechanism == super::CreationMechanism::Create3 {
            let (helper, _) = super::solady_create3_addresses(
                &bound.creator,
                &bound.salt.ok_or(RuntimeError::InvalidAuthorization)?,
            )?;
            binding["helperAddress"] = serde_json::json!(hex(&helper));
        }
        if let Some(digest) = &self.stored.intent.native_value_authorization_digest {
            let grant = context
                .native_value_authorization()?
                .ok_or(RuntimeError::InvalidAuthorization)?;
            let id = grant
                .authorization_id
                .strip_prefix("urn:openpc:resource:")
                .filter(|id| {
                    uuid::Uuid::try_parse(id).is_ok_and(|parsed| {
                        parsed.get_version_num() == 7 && parsed.to_string() == *id
                    })
                })
                .ok_or(RuntimeError::InvalidAuthorization)?;
            binding["nativeValueAuthorizationId"] = serde_json::json!(id);
            binding["nativeValueAuthorizationDigest"] =
                serde_json::json!(format!("sha256:{}", digest.as_str()));
        }
        Ok(binding)
    }

    /// Exact identity rebinding only. Callers must resolve current_context from
    /// the live owners and still obtain final preflight/PDS/Broker authority.
    pub fn rebind_signed(
        &self,
        publication: &AdmittedDeploymentPolicy,
        current_context: &PreparationContext,
        signed: &SignedTransaction,
        now_ms: u64,
    ) -> RuntimeResult<BoundDeployment> {
        current_context.validate(now_ms)?;
        if &self.stored.context != current_context
            || !self
                .unsigned
                .matches_signed(&current_context.sender, signed)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let current = Self::prepare(
            publication,
            self.unsigned.clone(),
            current_context.clone(),
            now_ms,
        )?;
        if self.stored != current.stored {
            return Err(RuntimeError::GenerationMismatch);
        }
        bind_publication(publication, signed, now_ms).map(|(_, bound)| bound)
    }

    /// Compare an independently approved fresh preparation to retained original
    /// custody. The old preparation grants no authority and need not be renewed.
    pub fn validate_fee_bump_from(
        &self,
        predecessor: &Self,
        signed: &SignedTransaction,
    ) -> RuntimeResult<()> {
        let a = predecessor.context();
        let b = self.context();
        if a.participant_id != b.participant_id
            || a.privacy_domain_id != b.privacy_domain_id
            || a.participant_epoch != b.participant_epoch
            || a.actor_subject_id != b.actor_subject_id
            || a.workload_binding_id != b.workload_binding_id
            || a.wallet_binding_id != b.wallet_binding_id
            || a.wallet_binding_epoch != b.wallet_binding_epoch
            || a.sender != b.sender
            || a.chain_environment_id != b.chain_environment_id
            || a.target_runtime_id != b.target_runtime_id
            || a.policy_generation_digest != b.policy_generation_digest
            || a.entitlement_envelope_digest != b.entitlement_envelope_digest
            || a.routing_constraint_digest != b.routing_constraint_digest
            || a.native_value_authorization_bytes != b.native_value_authorization_bytes
            || self.genesis_digest() != predecessor.genesis_digest()
            || !self.unsigned().matches_signed(&b.sender, signed)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        predecessor
            .unsigned()
            .validate_fee_bump(&a.sender, signed)
            .map_err(|_| RuntimeError::InvalidAuthorization)
    }
}

impl PreparationContext {
    fn native_value_authorization(&self) -> RuntimeResult<Option<NativeValueAuthorizationV1>> {
        self.native_value_authorization_bytes
            .as_ref()
            .map(|encoded| {
                if encoded.len() > 8194 {
                    return Err(RuntimeError::BudgetExhausted);
                }
                let bytes = decode(encoded)?;
                let grant = NativeValueAuthorizationV1::decode(&bytes)?;
                if grant.document_bytes()? != bytes {
                    return Err(RuntimeError::InvalidAuthorization);
                }
                Ok(grant)
            })
            .transpose()
    }

    fn validate(&self, now_ms: u64) -> RuntimeResult<()> {
        let identifiers = [
            &self.intent_id,
            &self.participant_id,
            &self.privacy_domain_id,
            &self.actor_subject_id,
            &self.wallet_binding_id,
            &self.chain_environment_id,
            &self.target_runtime_id,
        ];
        if identifiers
            .into_iter()
            .chain(self.workload_binding_id.iter())
            .any(|v| !identifier(v))
            || self.participant_epoch == 0
            || self.wallet_binding_epoch == 0
            || self.issued_at_ms == 0
            || now_ms < self.issued_at_ms
            || now_ms >= self.expires_at_ms
            || self
                .expires_at_ms
                .checked_sub(self.issued_at_ms)
                .is_none_or(|v| v == 0 || v > MAX_PREPARATION_LIFETIME_MS)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        for digest in [
            &self.policy_generation_digest,
            &self.authority_digest,
            &self.policy_decision_digest,
            &self.entitlement_envelope_digest,
            &self.routing_constraint_digest,
            &self.approval_set_digest,
        ] {
            super::valid_digest(digest)?;
        }
        Ok(())
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"._:-".contains(&v))
}
fn tagged(value: &str) -> RuntimeResult<Digest> {
    Digest::parse(
        value
            .strip_prefix("sha256:")
            .ok_or(RuntimeError::InvalidInput)?,
    )
}
fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
fn decode(value: &str) -> RuntimeResult<Vec<u8>> {
    let value = value
        .strip_prefix("0x")
        .filter(|v| {
            v.len().is_multiple_of(2)
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or(RuntimeError::InvalidInput)?;
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| RuntimeError::InvalidInput)?,
                16,
            )
            .map_err(|_| RuntimeError::InvalidInput)
        })
        .collect()
}

// Context crosses a JavaScript owner; uint64 epochs use lossless decimal text.
// The canonical intent document retains its specified integer field.
mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        let parsed = value.parse::<u64>().map_err(D::Error::custom)?;
        if parsed.to_string() != value {
            return Err(D::Error::custom("noncanonical uint64"));
        }
        Ok(parsed)
    }
}
