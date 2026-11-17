use super::*;
use crate::candidate_feed::CandidateMaterial;
use openpc_indexer_adapter::{
    AcquisitionRequest, FinalityMode,
    acquisition::{state_result_extractor, state_result_schema},
};
use openpc_multi_rpc::fact_observation::FactStateQuery;
use pc_policy_core::{
    contract_policy::read_method_types,
    invocation::{AbiType, ArgumentValue, decode_canonical_abi},
};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

mod admission;
mod external;
mod relationship;
pub(crate) use admission::ObservedStateAdmission;
#[cfg(test)]
pub(crate) use admission::StateFactRecordSource;
mod observation;
pub use observation::BoundFactObservation;

/// Borrows the current source lease so code/ABI custody cannot be detached from
/// the Control transaction while source observations and projection are used.
pub struct CurrentFactContract<'a> {
    source: &'a mut CurrentFactSource,
    query: FactStateQuery,
    event_signature: Option<Digest>,
    external_request: Option<openpc_multi_rpc::external_decision::ExternalDecisionRequestV1>,
    binding_id: Uuid,
    binding_revision: i64,
    abi_digest: Digest,
    signature: String,
    input_values: Vec<ArgumentValue>,
    output_types: Vec<AbiType>,
    candidate_id: Option<Uuid>,
    payload_digest: Option<Digest>,
    admission_profile: pc_policy_core::fact_profile::StateFactProfile,
}

/// Typed data only. Source permission, mapping/privacy admission, completeness,
/// freshness, conflict handling, signing and readiness remain with FactBridge.
#[derive(Serialize)]
pub struct TypedStateProjection {
    runtime_binding_id: Uuid,
    binding_revision: i64,
    abi_digest: Digest,
    canonical_signature: String,
    arguments: Vec<ArgumentValue>,
    result: Vec<ArgumentValue>,
    observation_digest: Digest,
    specialization: Option<(pc_facts_core::FactSubject, pc_facts_core::FactObject)>,
}

impl CurrentFactSource {
    pub async fn contract<'a>(
        &'a mut self,
        material: &CandidateMaterial,
    ) -> Result<CurrentFactContract<'a>> {
        self.contract_at(
            &material.source,
            material.block_number,
            &material.block_hash,
            material.range_end,
            Some(material),
        )
        .await
    }
    pub(crate) async fn contract_at<'a>(
        &'a mut self,
        source: &CandidateSourceMaterial,
        block_number: u64,
        block_hash: &[u8],
        range_end: u64,
        material: Option<&CandidateMaterial>,
    ) -> Result<CurrentFactContract<'a>> {
        self.confirm_live().await?;
        let (target_address, calldata, event_signature, expected_schema, expected_extractor) =
            match &source.inputs.acquisition().request {
                AcquisitionRequest::StateCall {
                    target_address,
                    calldata,
                } => (
                    target_address,
                    decode_hex(calldata)?,
                    None,
                    state_result_schema(),
                    state_result_extractor(),
                ),
                AcquisitionRequest::ExternalDecision {
                    target_address,
                    calldata,
                    ..
                } => (
                    target_address,
                    decode_hex(calldata)?,
                    None,
                    openpc_indexer_adapter::acquisition::external_schema(),
                    openpc_indexer_adapter::acquisition::external_extractor(),
                ),
                AcquisitionRequest::EventLogs {
                    contract_address,
                    event_name,
                    event_signature,
                } => {
                    if event_name != openpc_indexer_adapter::acquisition::RGRA_EVENT_NAME
                        || event_signature
                            != openpc_indexer_adapter::acquisition::RGRA_EVENT_SIGNATURE
                    {
                        return Err(SourceAuthorityError::Binding);
                    }
                    (
                        contract_address,
                        Vec::new(),
                        Some(digest(event_signature)?),
                        openpc_indexer_adapter::acquisition::relationship_schema(),
                        openpc_indexer_adapter::acquisition::relationship_extractor(),
                    )
                }
            };
        let external_request = if matches!(
            source.inputs.acquisition().request,
            AcquisitionRequest::ExternalDecision { .. }
        ) {
            Some(
                source
                    .inputs
                    .acquisition()
                    .external_request(source.inputs.profile(), block_number, &hex(block_hash))
                    .map_err(|_| SourceAuthorityError::Binding)?,
            )
        } else {
            None
        };
        if self.publication_digest != source.inputs.published().publication_digest
            || source.inputs.plan().candidate_schema_digests != [expected_schema.clone()]
            || source.inputs.plan().extractor_digests != [expected_extractor]
            || (material.is_none() && event_signature.is_none())
            || material.is_some_and(|m| {
                m.record_kind
                    != if event_signature.is_some() {
                        "EVENT_LOG"
                    } else if external_request.is_some() {
                        "EXTERNAL_OBSERVATION"
                    } else {
                        "STATE_CALL"
                    }
                    || m.schema_digest.len() != 32
                    || format!("sha256:{}", hex(&m.schema_digest)) != expected_schema.digest
            })
        {
            return Err(SourceAuthorityError::Binding);
        }
        let target: [u8; 20] = decode_hex(target_address)?
            .try_into()
            .map_err(|_| SourceAuthorityError::Binding)?;
        let selector: Option<[u8; 4]> = if event_signature.is_none() {
            Some(
                calldata
                    .get(..4)
                    .ok_or(SourceAuthorityError::Binding)?
                    .try_into()
                    .map_err(|_| SourceAuthorityError::Binding)?,
            )
        } else {
            None
        };
        let profile = source.inputs.profile();
        let admission_profile = pc_policy_core::fact_profile::StateFactProfile::resolve(
            &self.configuration,
            &source.inputs.source().projection_plan_id.to_string(),
        )
        .map_err(|_| SourceAuthorityError::Binding)?;
        if admission_profile.source_profile_id
            != source.inputs.source().indexer_profile_id.to_string()
        {
            return Err(SourceAuthorityError::Binding);
        }
        let assets: Vec<_> = self
            .configuration
            .assets
            .iter()
            .filter(|asset| {
                asset.contract_address == target
                    && selector.is_none_or(|selector| asset.selector == selector)
                    && asset.tenant_id == profile.participant_binding
                    && asset.privacy_domain_id == profile.privacy_binding
                    && asset.chain_id == profile.chain_id
                    && asset.network_id == profile.network_id
            })
            .collect();
        if assets.is_empty()
            || (event_signature.is_none() && assets.len() != 1)
            || assets.iter().any(|asset| {
                asset.runtime_binding_id != assets[0].runtime_binding_id
                    || asset.code_digest != assets[0].code_digest
                    || asset.abi_digest != assets[0].abi_digest
            })
        {
            return Err(SourceAuthorityError::Binding);
        }
        let asset = assets[0];
        if event_signature.is_some()
            != matches!(
                &admission_profile.mapping,
                pc_policy_core::fact_profile::StateFactMapping::RgraEventRelationshipV1 { .. }
            )
        {
            return Err(SourceAuthorityError::Binding);
        }
        match (&external_request, &admission_profile.mapping) {
            (
                Some(request),
                pc_policy_core::fact_profile::StateFactMapping::ExternalDecisionAdapterV1 {
                    provider_id,
                    provider_version,
                    provider_configuration_digest,
                    condition,
                },
            ) if &request.provider_id == provider_id
                && &request.provider_version == provider_version
                && &request.provider_configuration_digest == provider_configuration_digest
                && &request.condition == condition => {}
            (
                None,
                pc_policy_core::fact_profile::StateFactMapping::ExternalDecisionAdapterV1 {
                    ..
                },
            )
            | (Some(_), _) => return Err(SourceAuthorityError::Binding),
            _ => (),
        }
        let binding_id = asset
            .runtime_binding_id
            .as_deref()
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or(SourceAuthorityError::Binding)?;
        if binding_id.get_version_num() != 7
            || asset.genesis_digest != digest(&profile.genesis_hash)?
            || asset.proxy_address.is_some()
            || asset.implementation_address.is_some()
            || asset.implementation_code_digest.is_some()
            || material.is_some_and(|m| {
                (event_signature.is_some()
                    && (m.contract_address.as_deref() != Some(target.as_slice())
                        || m.event_signature.as_deref().map(hex).as_deref()
                            != event_signature.as_ref().map(|v| v.as_str())
                        || m.transaction_hash.as_ref().is_none_or(|v| v.len() != 32)
                        || m.transaction_index.is_none()
                        || m.log_index.is_none()))
                    || (event_signature.is_none()
                        && (m.target_address.as_deref() != Some(target.as_slice())
                            || m.call_parameter_digest
                                .as_deref()
                                .map(|value| format!("sha256:{}", hex(value)))
                                != if let Some(request) = &external_request {
                                    Some(format!(
                                        "sha256:{}",
                                        request
                                            .digest()
                                            .map(|d| d.as_str().to_owned())
                                            .unwrap_or_default()
                                    ))
                                } else {
                                    source
                                        .inputs
                                        .acquisition()
                                        .state_call_parameter_digest(block_number)
                                        .ok()
                                }))
            })
        {
            return Err(SourceAuthorityError::Binding);
        }
        let row = sqlx::query("select * from openpc.lock_fact_contract_binding($1)")
            .bind(binding_id)
            .fetch_one(&mut *self.transaction)
            .await?;
        let abi_bytes: Vec<u8> = row.try_get("canonical_abi_bytes")?;
        if row.try_get::<String, _>("chain_id")? != profile.chain_id
            || row.try_get::<String, _>("network_id")? != profile.network_id
            || digest(row.try_get("genesis_digest")?)? != asset.genesis_digest
            || decode_hex(row.try_get("contract_address")?)? != target
            || digest(row.try_get("code_digest")?)? != asset.code_digest
            || digest(row.try_get("abi_digest")?)? != asset.abi_digest
            || Digest::of(&abi_bytes) != asset.abi_digest
            || row.try_get::<Option<String>, _>("proxy_address")?.is_some()
            || row
                .try_get::<Option<String>, _>("implementation_address")?
                .is_some()
            || row
                .try_get::<Option<String>, _>("implementation_code_digest")?
                .is_some()
        {
            return Err(SourceAuthorityError::Binding);
        }
        let abi: Value =
            serde_json::from_slice(&abi_bytes).map_err(|_| SourceAuthorityError::Binding)?;
        let (input_values, output_types) = if let Some(selector) = selector {
            let (input_types, output_types) =
                read_method_types(&abi, &asset.canonical_signature, &selector)
                    .map_err(|_| SourceAuthorityError::Binding)?;
            if input_types != asset.input_types {
                return Err(SourceAuthorityError::Binding);
            }
            (
                decode_canonical_abi(&input_types, &calldata[4..])
                    .map_err(|_| SourceAuthorityError::Binding)?,
                output_types,
            )
        } else {
            relationship::validate_abi(&abi)?;
            (Vec::new(), Vec::new())
        };
        let FinalityMode::Confirmations { count } = source.inputs.finality_rule().mode else {
            return Err(SourceAuthorityError::Binding);
        };
        let query = FactStateQuery {
            chain_id: profile
                .chain_id
                .parse()
                .map_err(|_| SourceAuthorityError::Binding)?,
            genesis_hash: asset.genesis_digest.clone(),
            block_number,
            block_hash: Digest::parse(hex(block_hash))
                .map_err(|_| SourceAuthorityError::Binding)?,
            target,
            calldata,
            code_digest: asset.code_digest.clone(),
            // Every member binds the candidate batch's same confirmation
            // horizon; earlier members independently verify the extra headers.
            confirmations: range_end
                .checked_sub(block_number)
                .and_then(|distance| distance.checked_add(u64::from(count)))
                .and_then(|confirmations| u32::try_from(confirmations).ok())
                .filter(|confirmations| (1..=64).contains(confirmations))
                .ok_or(SourceAuthorityError::Binding)?,
        };
        // Confirmation depth verifies this observation. Retained reorg depth
        // independently decides whether replacement needs RecoverGap.
        let abi_digest = asset.abi_digest.clone();
        let signature = if event_signature.is_some() {
            "RelationshipChanged(bytes32,bytes32,uint8,uint64,uint64)".into()
        } else {
            asset.canonical_signature.clone()
        };
        Ok(CurrentFactContract {
            source: self,
            query,
            event_signature,
            external_request,
            binding_id,
            binding_revision: row.try_get("binding_revision")?,
            abi_digest,
            signature,
            input_values,
            output_types,
            candidate_id: material.map(|m| m.candidate_id),
            payload_digest: material.map(|m| Digest::of(&m.payload_cbor)),
            admission_profile,
        })
    }
}
impl CurrentFactContract<'_> {
    pub fn providers(&self) -> &[CurrentFactProvider] {
        self.source.providers()
    }
    pub fn assert_fresh(&self) -> Result<()> {
        self.source.assert_fresh()
    }
    pub async fn confirm_live(&mut self) -> Result<()> {
        self.source.confirm_live().await
    }
    pub fn project(
        &self,
        material: &CandidateMaterial,
        bound: &BoundFactObservation,
    ) -> Result<TypedStateProjection> {
        self.assert_fresh()?;
        let observation = &bound.observation;
        if Some(material.candidate_id) != self.candidate_id
            || Some(Digest::of(&material.payload_cbor)) != self.payload_digest
            || material.source.inputs.published().publication_digest
                != self.source.publication_digest
            || bound.publication_digest != self.source.publication_digest
            || !self.providers().iter().any(|provider| {
                provider.provider_id == observation.connection().provider_id
                    && provider.artifact_digest == bound.provider_artifact_digest
            })
            || material.block_number != self.query.block_number
            || hex(&material.block_hash) != self.query.block_hash.as_str()
        {
            return Err(SourceAuthorityError::Binding);
        }
        if let Some(request) = &self.external_request {
            return self.project_external(material, bound, request);
        }
        if self.event_signature.is_some() {
            return self.project_relationship(material, bound);
        }
        observation
            .validate(&self.query, observation.connection(), now_ns()? / 1_000_000)
            .map_err(|_| SourceAuthorityError::Binding)?;
        let payload: Value = ciborium::de::from_reader(material.payload_cbor.as_slice())
            .map_err(|_| SourceAuthorityError::Binding)?;
        if payload.as_object().is_none_or(|value| value.len() != 1)
            || decode_hex(
                payload["result"]
                    .as_str()
                    .ok_or(SourceAuthorityError::Binding)?,
            )? != observation.result()
        {
            return Err(SourceAuthorityError::Binding);
        }
        let result = decode_canonical_abi(&self.output_types, observation.result())
            .map_err(|_| SourceAuthorityError::Binding)?;
        Ok(TypedStateProjection {
            runtime_binding_id: self.binding_id,
            binding_revision: self.binding_revision,
            abi_digest: self.abi_digest.clone(),
            canonical_signature: self.signature.clone(),
            arguments: self.input_values.clone(),
            result,
            observation_digest: observation
                .digest()
                .map_err(|_| SourceAuthorityError::Binding)?,
            specialization: None,
        })
    }
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let value = value
        .strip_prefix("0x")
        .ok_or(SourceAuthorityError::Binding)?;
    if !value.len().is_multiple_of(2)
        || value.len() > 65536
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SourceAuthorityError::Binding);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| SourceAuthorityError::Binding)?;
            u8::from_str_radix(text, 16).map_err(|_| SourceAuthorityError::Binding)
        })
        .collect()
}
