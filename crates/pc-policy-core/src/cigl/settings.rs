//! UF-CIGL-001 configuration meaning. A staged definition supplies no runtime
//! permission, trace certification, fallback readiness or profile activation.
use super::TraceLimits;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::{Deserialize, Serialize};

/// An immutable public source record carried in configuration. Its shape and
/// digest are not governance proof: Fleet must join the exact protected row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfiguredCiglSettings {
    pub settings_id: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub publication_operation_id: String,
    pub publication_authority_digest: Digest,
    pub definition_digest: Digest,
    pub definition: CiglSettingsDefinition,
}
impl ConfiguredCiglSettings {
    pub fn validate(&self) -> RuntimeResult<()> {
        if [
            &self.settings_id,
            &self.participant_id,
            &self.privacy_domain_id,
            &self.publication_operation_id,
        ]
        .into_iter()
        .any(|id| !crate::semantics::uuid_v7(id))
            || self.publication_authority_digest == Digest::of([])
            || self.definition.digest()? != self.definition_digest
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }
    pub fn to_cbor(&self) -> RuntimeResult<Vec<u8>> {
        self.validate()?;
        crate::invocation::encode_exact(self)
    }
    pub fn from_cbor(bytes: &[u8]) -> RuntimeResult<Self> {
        let value: Self = crate::invocation::decode_exact(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug)]
pub struct InstalledCiglSettings {
    sources: Vec<ConfiguredCiglSettings>,
}
impl InstalledCiglSettings {
    pub fn load(
        configuration_bytes: &[u8],
        configuration_digest: &Digest,
        participant: &str,
        privacy: &str,
    ) -> RuntimeResult<Self> {
        use crate::invocation::{
            ConfigurationArtifactKind, decode_active_invocation_configuration,
        };
        let configuration =
            decode_active_invocation_configuration(configuration_bytes, configuration_digest)?;
        let mut scopes = std::collections::BTreeSet::new();
        let mut sources = Vec::new();
        for artifact in &configuration.resource_artifacts {
            if artifact.artifact_kind != ConfigurationArtifactKind::CiglSettings {
                continue;
            }
            let source = ConfiguredCiglSettings::from_cbor(&artifact.payload_cbor)?;
            if artifact.artifact_id != source.settings_id
                || source.participant_id != participant
                || source.privacy_domain_id != privacy
                || !scopes.insert(canonical_bytes(&source.definition.scope)?)
            {
                return Err(RuntimeError::GenerationMismatch);
            }
            sources.push(source);
        }
        Ok(Self { sources })
    }
    pub fn for_method(
        &self,
        method: &crate::invocation::ValidatedInvocationPolicy,
    ) -> RuntimeResult<Option<&ConfiguredCiglSettings>> {
        let policy = method.artifact();
        self.for_environment(
            &policy.tenant_id,
            &policy.privacy_domain_id,
            &policy.chain_id,
            &policy.network_id,
            &policy.genesis_digest,
        )
    }
    pub fn for_environment(
        &self,
        participant: &str,
        privacy: &str,
        chain: &str,
        network: &str,
        genesis: &Digest,
    ) -> RuntimeResult<Option<&ConfiguredCiglSettings>> {
        let mut global = None;
        let mut selected = None;
        for source in &self.sources {
            if source.participant_id != participant || source.privacy_domain_id != privacy {
                return Err(RuntimeError::GenerationMismatch);
            }
            match &source.definition.scope {
                SettingsScope::AllChains {} => global = Some(source),
                SettingsScope::Chain {
                    chain_id,
                    network_id,
                    genesis_digest,
                } if chain_id == chain
                    && network_id == network
                    && genesis_digest.strip_prefix("sha256:") == Some(genesis.as_str()) =>
                {
                    selected = Some(source)
                }
                _ => {}
            }
        }
        Ok(selected.or(global))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceMode {
    HybridStrict,
    Off,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraceProvider {
    DebugTraceCall,
    TraceCall,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadinessScope {
    Method,
    Contract,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SettingsScope {
    AllChains {},
    #[serde(rename_all = "camelCase")]
    Chain {
        chain_id: String,
        network_id: String,
        genesis_digest: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnforcementSettings {
    pub eth_call: bool,
    pub eth_estimate_gas: bool,
    pub prepare_write: bool,
    pub raw_submission: bool,
    pub deployment_constructors: bool,
    pub runtime_trace_for_writes: bool,
    pub reviewed_schema_subset: bool,
    pub fail_closed: bool,
    pub reject_external_state_overrides: bool,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostMineSettings {
    pub enabled: bool,
    pub freeze_on_divergence: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CiglSettingsDefinition {
    pub schema_version: String,
    pub scope: SettingsScope,
    pub mode: GovernanceMode,
    pub enforcement: EnforcementSettings,
    pub trace_limits: TraceLimits,
    pub trace_provider: TraceProvider,
    pub readiness_scope: ReadinessScope,
    pub schema_fallback_enabled: bool,
    pub precompile_allowlist: Vec<String>,
    pub system_contract_allowlist: Vec<String>,
    pub post_mine: PostMineSettings,
}
impl CiglSettingsDefinition {
    pub fn validate(&self) -> RuntimeResult<()> {
        self.trace_limits.validate()?;
        if self.schema_version != "1.0"
            || (self.post_mine.freeze_on_divergence && !self.post_mine.enabled)
            || (self.mode == GovernanceMode::HybridStrict
                && (!self.enforcement.fail_closed
                    || !self.enforcement.reject_external_state_overrides))
        {
            return Err(RuntimeError::InvalidInput);
        }
        if let SettingsScope::Chain {
            chain_id,
            network_id,
            genesis_digest,
        } = &self.scope
        {
            let chain = chain_id
                .parse::<u64>()
                .map_err(|_| RuntimeError::InvalidInput)?;
            if chain == 0
                || chain.to_string() != *chain_id
                || network_id.is_empty()
                || network_id.len() > 192
                || !network_id.as_bytes()[0].is_ascii_alphabetic()
                || !network_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:@/-".contains(&b))
            {
                return Err(RuntimeError::InvalidInput);
            }
            Digest::parse(
                genesis_digest
                    .strip_prefix("sha256:")
                    .ok_or(RuntimeError::InvalidInput)?,
            )?;
        }
        for addresses in [&self.precompile_allowlist, &self.system_contract_allowlist] {
            if addresses.len() > 256
                || addresses.windows(2).any(|pair| pair[0] >= pair[1])
                || addresses.iter().any(|address| {
                    address.len() != 42
                        || !address.starts_with("0x")
                        || !address.as_bytes()[2..]
                            .iter()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
                })
            {
                return Err(RuntimeError::InvalidInput);
            }
        }
        if self.precompile_allowlist.iter().any(|address| {
            self.system_contract_allowlist
                .binary_search(address)
                .is_ok()
        }) {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(())
    }
    pub fn digest(&self) -> RuntimeResult<Digest> {
        self.validate()?;
        canonical_bytes(&serde_json::to_value(self).map_err(|_| RuntimeError::InvalidInput)?)
            .map(Digest::of)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn definition() -> CiglSettingsDefinition {
        CiglSettingsDefinition {
            schema_version: "1.0".into(),
            scope: SettingsScope::AllChains {},
            mode: GovernanceMode::HybridStrict,
            enforcement: EnforcementSettings {
                eth_call: true,
                eth_estimate_gas: true,
                prepare_write: true,
                raw_submission: true,
                deployment_constructors: true,
                runtime_trace_for_writes: true,
                reviewed_schema_subset: true,
                fail_closed: true,
                reject_external_state_overrides: true,
            },
            trace_limits: TraceLimits {
                max_depth: 128,
                max_frames: 2048,
                max_response_bytes: 20_000_000,
                timeout_ms: 30_000,
            },
            trace_provider: TraceProvider::DebugTraceCall,
            readiness_scope: ReadinessScope::Method,
            schema_fallback_enabled: false,
            precompile_allowlist: vec![],
            system_contract_allowlist: vec![],
            post_mine: PostMineSettings {
                enabled: true,
                freeze_on_divergence: true,
            },
        }
    }
    #[test]
    fn settings_keep_exact_chain_scope_and_closed_c17_choices_and_bounds() {
        let valid = definition();
        assert!(valid.validate().is_ok());
        let mut chain = valid.clone();
        chain.scope = SettingsScope::Chain {
            chain_id: "18446744073709551615".into(),
            network_id: "devnet".into(),
            genesis_digest: format!("sha256:{}", Digest::of("chain").as_str()),
        };
        assert!(chain.validate().is_ok());
        assert_ne!(chain.digest().unwrap(), valid.digest().unwrap());
        for chain_id in ["0", "01", "-1", "18446744073709551616"] {
            let mut changed = chain.clone();
            if let SettingsScope::Chain {
                chain_id: value, ..
            } = &mut changed.scope
            {
                *value = chain_id.into();
            }
            assert!(changed.validate().is_err());
        }
        for mode in [
            "SCHEMA_ONLY",
            "TRACE_REQUIRED",
            "TRACE_PREFERRED_SCHEMA_FALLBACK",
        ] {
            let mut value = serde_json::to_value(&valid).unwrap();
            value["mode"] = mode.into();
            assert!(serde_json::from_value::<CiglSettingsDefinition>(value).is_err());
        }
        let mut changed = valid.clone();
        changed.trace_limits.max_frames = 2049;
        assert!(changed.validate().is_err());
        changed = valid.clone();
        changed.enforcement.fail_closed = false;
        assert!(changed.validate().is_err());
        changed = valid.clone();
        changed.enforcement.reject_external_state_overrides = false;
        assert!(changed.validate().is_err());
        changed = valid.clone();
        changed.post_mine.enabled = false;
        assert!(changed.validate().is_err());
        changed = valid.clone();
        changed.precompile_allowlist = vec!["0x0000000000000000000000000000000000000001".into()];
        assert!(changed.validate().is_ok());
        changed.system_contract_allowlist = changed.precompile_allowlist.clone();
        assert!(changed.validate().is_err());
        changed.system_contract_allowlist.clear();
        changed
            .precompile_allowlist
            .push(changed.precompile_allowlist[0].clone());
        assert!(changed.validate().is_err());
        changed = valid.clone();
        changed.system_contract_allowlist =
            vec!["0x000000000000000000000000000000000000000A".into()];
        assert!(changed.validate().is_err());
    }
}
