//! Resolve deployment-supplied data against real public resource owners.
//! This owner cannot install modules, qualify providers or activate targets.
use crate::runtime_artifact_source::{RuntimeArtifactSourceWorker, SourceCustodyError};
use pc_policy_core::invocation::{
    ConfigurationArtifactKind, active_invocation_workload, decode_active_invocation_configuration,
};
use pc_runtime_types::Digest;
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;

/// A retryable database fence conflict, never an authorization grant.
pub const RUNTIME_ARTIFACT_BUSY: &str = "runtime artifact retirement fence busy";

pub fn runtime_artifact_database_error(error: sqlx::Error) -> String {
    if error.as_database_error().is_some_and(|error| {
        matches!(error.code().as_deref(), Some("P0001" | "40001"))
            && error.message() == "PC-DATA-6007"
    }) {
        RUNTIME_ARTIFACT_BUSY.into()
    } else {
        "runtime artifact retirement enforcement unavailable".into()
    }
}

/// Observe retirement on the actual caller transaction before reference locks.
/// The server checks scope, READ COMMITTED, role/RLS, installed enforcement and
/// takes the lifecycle fence until commit/rollback. True only means that these
/// bytes are not retired; all ordinary source and authorization checks remain.
/// This must never be called to admit original STARTED/UNKNOWN result lookup.
pub async fn runtime_artifact_new_use_allowed(
    tx: &mut Transaction<'_, Postgres>,
    participant: &str,
    privacy: &str,
    digest: &Digest,
) -> Result<bool, String> {
    // Digest's serde representation can bypass Digest::parse; validate before
    // decode so the server always receives exactly the original 32 bytes.
    let digest = Digest::parse(digest.as_str())
        .map_err(|_| "runtime artifact configuration digest rejected")?;
    let allowed: Option<bool> = sqlx::query_scalar(
        "select openpc.runtime_artifact_new_use_allowed($1::text::uuid,$2::text::uuid,decode($3,'hex'))",
    )
    .bind(participant)
    .bind(privacy)
    .bind(digest.as_str())
    .fetch_one(&mut **tx)
    .await
    .map_err(runtime_artifact_database_error)?;
    allowed.ok_or_else(|| "runtime artifact retirement enforcement unavailable".into())
}

pub struct RuntimeConfigurationInputSource {
    path: PathBuf,
}

fn validate(bytes: &[u8], participant: &str, privacy: &str) -> Result<Value, String> {
    let digest = Digest::of(bytes);
    let configuration = decode_active_invocation_configuration(bytes, &digest)
        .map_err(|_| "runtime input configuration rejected")?;
    active_invocation_workload(bytes, &digest, participant, privacy)
        .map_err(|_| "runtime input scope rejected")?;
    if configuration.resource_artifacts.is_empty()
        || configuration.resource_artifacts.len() > 1024
        || !configuration.deployment_policies.is_empty()
    {
        return Err("runtime input resource boundary rejected".into());
    }
    let mut bindings = Vec::new();
    for artifact in &configuration.resource_artifacts {
        let expected = format!("sha256:{}", artifact.artifact_digest.as_str());
        let mut binding =
            json!({"id": artifact.artifact_id, "kind": artifact.artifact_kind, "digest": expected});
        match artifact.artifact_kind {
            ConfigurationArtifactKind::ProviderProfile => {
                let profile =
                    openpc_multi_rpc::qualify_provider_profile(&artifact.payload_cbor, &expected)
                        .map_err(|_| "runtime provider input rejected")?;
                binding["chainId"] = json!(profile.chain_id);
            }
            ConfigurationArtifactKind::ClientIndexerProfile => {
                let profile = openpc_indexer_adapter::admit_scoped_client_indexer_profile(
                    &artifact.payload_cbor,
                    &expected,
                    participant,
                    privacy,
                )
                .map_err(|_| "runtime indexer input rejected")?;
                binding["engineVersion"] = json!(profile.engine_version);
            }
            ConfigurationArtifactKind::ProjectionPlan => {
                pc_provider_api::decode_projection_plan_pc_cbor(&artifact.payload_cbor)
                    .map_err(|_| "runtime projection input rejected")?;
            }
            ConfigurationArtifactKind::IndexerFinalityRule
            | ConfigurationArtifactKind::IndexerAcquisitionConfiguration => {
                // The approved indexer artifact already binds the exact rule
                // digest. Its existing public resource binding also governs
                // this resolved content; an unrelated configuration entry
                // cannot replace it or manufacture a qualification receipt.
                let source = configuration
                    .resource_artifacts
                    .iter()
                    .find(|source| {
                        source.artifact_kind == ConfigurationArtifactKind::ClientIndexerProfile
                            && source.artifact_id == artifact.artifact_id
                    })
                    .ok_or_else(|| "runtime finality source missing".to_owned())?;
                let profile = openpc_indexer_adapter::admit_scoped_client_indexer_profile(
                    &source.payload_cbor,
                    &format!("sha256:{}", source.artifact_digest.as_str()),
                    participant,
                    privacy,
                )
                .map_err(|_| "runtime finality source rejected")?;
                if artifact.artifact_kind
                    == ConfigurationArtifactKind::IndexerAcquisitionConfiguration
                {
                    openpc_indexer_adapter::AcquisitionConfiguration::resolve(
                        &profile,
                        &artifact.payload_cbor,
                    )
                    .map_err(|_| "runtime acquisition configuration rejected")?;
                    continue;
                }
                let rule =
                    openpc_indexer_adapter::FinalityRule::resolve(&profile, &artifact.payload_cbor)
                        .map_err(|_| "runtime finality rule rejected")?;
                if rule.canonical_provider_digests.iter().any(|expected| {
                    !configuration.resource_artifacts.iter().any(|provider| {
                        provider.artifact_kind == ConfigurationArtifactKind::ProviderProfile
                            && *expected == format!("sha256:{}", provider.artifact_digest.as_str())
                    })
                }) {
                    return Err("runtime finality provider missing".into());
                }
                continue;
            }
            ConfigurationArtifactKind::CiglSettings => {
                let source = pc_policy_core::cigl::settings::ConfiguredCiglSettings::from_cbor(
                    &artifact.payload_cbor,
                )
                .map_err(|_| "runtime CIGL settings input rejected")?;
                if source.settings_id != artifact.artifact_id {
                    return Err("runtime CIGL settings identity rejected".into());
                }
            }
            ConfigurationArtifactKind::CiglProfile => {
                return Err("runtime input cannot publish CIGL profiles".into());
            }
            ConfigurationArtifactKind::FactAdmissionProfile => {
                let profile = pc_policy_core::fact_profile::StateFactProfile::resolve(
                    &configuration,
                    &artifact.artifact_id,
                )
                .map_err(|_| "runtime fact profile input rejected")?;
                if profile.participant_id != participant || profile.privacy_domain_id != privacy {
                    return Err("runtime fact profile scope rejected".into());
                }
                // Meaning and bounds are governed by the enclosing configuration
                // digest. Its exact source and plan already have public bindings.
                continue;
            }
        }
        bindings.push(binding);
    }
    Ok(Value::Array(bindings))
}

impl RuntimeConfigurationInputSource {
    pub fn from_environment() -> Result<Option<Self>, String> {
        let Some(path) = std::env::var_os("OPENPC_RUNTIME_CONFIGURATION_INPUT_FILE") else {
            return Ok(None);
        };
        Self::new(PathBuf::from(path)).map(Some)
    }

    pub fn new(path: PathBuf) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("runtime input path must be absolute".into());
        }
        Ok(Self { path })
    }

    pub async fn refresh(
        &self,
        pool: &PgPool,
        participant: &str,
        privacy: &str,
    ) -> Result<(), String> {
        self.refresh_inner(pool, participant, privacy, None).await
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn refresh_guarded(
        &self,
        pool: &PgPool,
        participant: &str,
        privacy: &str,
        custody: &RuntimeArtifactSourceWorker,
    ) -> Result<(), String> {
        self.refresh_inner(pool, participant, privacy, Some(custody))
            .await
    }

    async fn refresh_inner(
        &self,
        pool: &PgPool,
        participant: &str,
        privacy: &str,
        custody: Option<&RuntimeArtifactSourceWorker>,
    ) -> Result<(), String> {
        if custody.is_none() {
            RuntimeArtifactSourceWorker::require_uninstalled(pool, participant, privacy)
                .await
                .map_err(|_| "runtime input source custody unavailable")?;
        }
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err("runtime input source unavailable".into()),
        };
        let mut bytes = Vec::new();
        file.take(MAX_INPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "runtime input source unreadable")?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_INPUT_BYTES {
            return Err("runtime input source size rejected".into());
        }
        let digest = Digest::of(&bytes);
        if let Some(custody) = custody {
            match custody
                .source_allowed(pool, participant, privacy, &self.path, &digest)
                .await
            {
                Ok(true) => {}
                Ok(false) | Err(SourceCustodyError::Busy) => return Ok(()),
                Err(_) => return Err("runtime input source custody unavailable".into()),
            }
        }
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| "runtime input transaction unavailable")?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true),openpc.assert_request_context(true)")
            .bind(participant).bind(privacy).execute(&mut *tx).await
            .map_err(|_| "runtime input context rejected")?;
        match runtime_artifact_new_use_allowed(&mut tx, participant, privacy, &digest).await {
            Ok(true) => {}
            Ok(false) => return Ok(()), // Do not deselect a valid successor.
            Err(error) if error == RUNTIME_ARTIFACT_BUSY => return Ok(()),
            Err(error) => return Err(error),
        }
        let existing: bool = sqlx::query_scalar("select exists(select 1 from control.runtime_configuration_input_current_metadata where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and encode(configuration_digest,'hex')=$3)")
            .bind(participant).bind(privacy).bind(digest.as_str()).fetch_one(&mut *tx).await
            .map_err(|_| "runtime input readback unavailable")?;
        if existing {
            tx.commit()
                .await
                .map_err(|_| "runtime input readback commit failed")?;
            return Ok(());
        }
        let bindings = validate(&bytes, participant, privacy)?;
        let current: bool = sqlx::query_scalar("select openpc.runtime_configuration_bindings_current($1::text::uuid,$2::text::uuid,$3::jsonb)")
            .bind(participant).bind(privacy).bind(&bindings).fetch_one(&mut *tx).await
            .map_err(|_| "runtime input references rejected")?;
        if !current {
            // Resources can arrive through their public owners after source
            // delivery. Missing or changed references grant no readiness.
            tx.rollback()
                .await
                .map_err(|_| "runtime input rollback failed")?;
            return Ok(());
        }
        sqlx::query("select pg_advisory_xact_lock_shared(hashtextextended($1,0))")
            .bind(format!("module-admission:{participant}:{privacy}"))
            .execute(&mut *tx)
            .await
            .map_err(|_| "runtime input module fence unavailable")?;
        let generations = sqlx::query(r#"select c.generation_id::text,i.module_installation_id::text
            from control.module_installation i
            join control.module_version v on v.module_version_id=i.module_version_id and v.module_id='pc.config.assets'
            join control.module_configuration_generation c on c.module_installation_id=i.module_installation_id
              and c.participant_id=i.participant_id and c.privacy_domain_id=i.privacy_domain_id and c.active
            where i.participant_id=$1::text::uuid and i.privacy_domain_id=$2::text::uuid
              and i.state='ENABLED' and i.lifecycle_operation_id is not null"#)
            .bind(participant).bind(privacy).fetch_all(&mut *tx).await
            .map_err(|_| "runtime input module generation unavailable")?;
        if generations.len() != 1 {
            tx.rollback()
                .await
                .map_err(|_| "runtime input rollback failed")?;
            return Ok(());
        }
        let generation: String = generations[0]
            .try_get("generation_id")
            .map_err(|_| "runtime input generation rejected")?;
        let installation: String = generations[0]
            .try_get("module_installation_id")
            .map_err(|_| "runtime input installation rejected")?;
        // A retained mount can lag a newer selected input. Re-observing known
        // old bytes is not a new delivery and cannot deselect that successor.
        // The lifecycle/module fences serialize this read with selection.
        let stale: bool = sqlx::query_scalar(
            r#"select
          exists(select 1 from control.runtime_configuration_input
            where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid
             and configuration_digest=decode($3,'hex'))
          and exists(select 1 from control.runtime_configuration_input_current_metadata
            where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid
             and configuration_digest<>decode($3,'hex'))"#,
        )
        .bind(participant)
        .bind(privacy)
        .bind(digest.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| "runtime input successor readback unavailable")?;
        if stale {
            return Ok(());
        }
        // The identity is fixed before either the independent journal or SQL
        // publication. A failed/ambiguous commit retains the original pending
        // import; a fresh UUID is never used to disguise the same source intent.
        let prior_id: Option<String> = sqlx::query_scalar(
            "select runtime_configuration_input_id::text from control.runtime_configuration_input where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and module_configuration_generation_id=$3::text::uuid and configuration_digest=decode($4,'hex')",
        ).bind(participant).bind(privacy).bind(&generation).bind(digest.as_str())
            .fetch_optional(&mut *tx).await.map_err(|_| "runtime input original unavailable")?;
        let imported = crate::runtime_artifact_source::ImportIdentity {
            input_id: prior_id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::now_v7().to_string()),
            module_installation_id: installation.clone(),
            module_configuration_generation_id: generation.clone(),
            configuration_digest: digest,
        };
        if let Some(custody) = custody {
            custody
                .bind_import(&mut tx, imported.clone(), prior_id.is_none())
                .await
                .map_err(|_| "runtime input original custody unavailable")?;
        }
        sqlx::query("update control.runtime_configuration_input set selected=false where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and selected")
            .bind(participant).bind(privacy).execute(&mut *tx).await
            .map_err(|_| "runtime input selection unavailable")?;
        sqlx::query(r#"insert into control.runtime_configuration_input
            (participant_id,privacy_domain_id,module_installation_id,module_configuration_generation_id,
             configuration_cbor,configuration_digest,resource_bindings,selected,runtime_configuration_input_id)
            values ($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5,sha256($5),$6,true,$7::text::uuid)
            on conflict (participant_id,privacy_domain_id,module_configuration_generation_id,configuration_digest)
            do update set selected=true"#)
            .bind(participant).bind(privacy).bind(installation).bind(generation).bind(bytes).bind(bindings).bind(&imported.input_id)
            .execute(&mut *tx).await.map_err(|_| "runtime input persistence rejected")?;
        tx.commit()
            .await
            .map_err(|_| "runtime input commit failed")?;
        if prior_id.is_none()
            && let Some(custody) = custody
        {
            custody
                .record_import_committed(imported)
                .await
                .map_err(|_| "runtime input committed custody unavailable")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_policy_core::invocation::{
        ActiveInvocationConfigurationV1, encode_active_invocation_configuration,
    };

    const PARTICIPANT: &str = "018f0000-0000-7000-8000-000000000101";
    const PRIVACY: &str = "018f0000-0000-7000-8000-000000000201";

    fn fixture() -> Vec<u8> {
        let fixture = crate::local_fixture::build_local_configuration_fixture(
            Some("018f0000-0000-7000-8000-000000000801"),
            Some("018f0000-0000-7000-8000-000000000802"),
            Some("018f0000-0000-7000-8000-000000000803"),
            Some("urn:openpc:workload:018f0000-0000-7000-8000-000000000191"),
        )
        .unwrap();
        fixture
            .configuration_cbor_hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn fact_profile_binds_governed_source_mapping_and_required_bounds() {
        use pc_policy_core::fact_profile::{StateFactMapping, StateFactProfile};
        let bytes = fixture();
        let mut configuration =
            decode_active_invocation_configuration(&bytes, &Digest::of(&bytes)).unwrap();
        let source = configuration
            .resource_artifacts
            .iter()
            .find(|a| a.artifact_kind == ConfigurationArtifactKind::ClientIndexerProfile)
            .unwrap();
        let plan = configuration
            .resource_artifacts
            .iter()
            .find(|a| a.artifact_kind == ConfigurationArtifactKind::ProjectionPlan)
            .unwrap();
        let profile = StateFactProfile {
            schema_version: "1.0.0".into(),
            fact_profile_id: "018f0000-0000-7000-8000-000000000501".into(),
            fact_semantic_version: "1.0.0".into(),
            admission_policy_version: "1.0.0".into(),
            participant_id: PARTICIPANT.into(),
            privacy_domain_id: PRIVACY.into(),
            source_profile_id: source.artifact_id.clone(),
            projection_plan_id: plan.artifact_id.clone(),
            projection_plan_digest: plan.artifact_digest.clone(),
            mapping: StateFactMapping::AbiStateResultV1,
            maximum_staleness_ms: 60_000,
            reorg_retained_tail_blocks: 64,
            shard_entry_limit: 1_000_000,
        };
        let profile_artifact = profile.artifact().unwrap();
        let source = configuration
            .resource_artifacts
            .iter_mut()
            .find(|a| a.artifact_kind == ConfigurationArtifactKind::ClientIndexerProfile)
            .unwrap();
        let mut decoded =
            pc_provider_api::decode_client_indexer_profile_pc_cbor(&source.payload_cbor).unwrap();
        decoded
            .artifact_digests
            .push(pc_provider_api::NamedDigestV1 {
                name: "fact-admission-profile".into(),
                digest: format!("sha256:{}", profile_artifact.artifact_digest.as_str()),
            });
        decoded.artifact_digests.sort_by(|a, b| a.name.cmp(&b.name));
        source.payload_cbor =
            pc_provider_api::encode_client_indexer_profile_pc_cbor(&decoded).unwrap();
        source.artifact_digest = Digest::of(&source.payload_cbor);
        configuration.resource_artifacts.push(profile_artifact);
        let encode = |value: &ActiveInvocationConfigurationV1| {
            encode_active_invocation_configuration(value).unwrap()
        };
        assert_eq!(
            validate(&encode(&configuration), PARTICIPANT, PRIVACY)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            3
        );
        for field in 0..4 {
            let mut changed = profile.clone();
            match field {
                0 => changed.maximum_staleness_ms *= 2,
                1 => changed.projection_plan_digest = Digest::of(b"other mapping"),
                2 => changed.participant_id = "018f0000-0000-7000-8000-000000000999".into(),
                _ => changed.privacy_domain_id = "018f0000-0000-7000-8000-000000000999".into(),
            }
            let mut altered = configuration.clone();
            *altered.resource_artifacts.last_mut().unwrap() = changed.artifact().unwrap();
            assert!(validate(&encode(&altered), PARTICIPANT, PRIVACY).is_err());
        }
        configuration
            .resource_artifacts
            .push(profile.artifact().unwrap());
        assert!(validate(&encode(&configuration), PARTICIPANT, PRIVACY).is_err());
    }

    #[test]
    fn input_validation_pins_resource_bytes_and_scope_without_minting_authority() {
        let bytes = fixture();
        let bindings = validate(&bytes, PARTICIPANT, PRIVACY).unwrap();
        assert_eq!(bindings.as_array().unwrap().len(), 3);
        assert!(validate(&bytes, "foreign", PRIVACY).is_err());
        assert!(validate(&bytes, PARTICIPANT, "foreign").is_err());
        let original = decode_active_invocation_configuration(&bytes, &Digest::of(&bytes)).unwrap();
        let mut changed = original.clone();
        changed.resource_artifacts[0].payload_cbor.push(0);
        assert!(
            validate(
                &encode_active_invocation_configuration(&changed).unwrap(),
                PARTICIPANT,
                PRIVACY
            )
            .is_err()
        );
        let mut changed = original.clone();
        changed
            .resource_artifacts
            .push(changed.resource_artifacts[0].clone());
        assert!(
            validate(
                &encode_active_invocation_configuration(&changed).unwrap(),
                PARTICIPANT,
                PRIVACY
            )
            .is_err()
        );
        let mut changed = original;
        changed.resource_artifacts[0].artifact_kind = ConfigurationArtifactKind::CiglProfile;
        assert!(
            validate(
                &encode_active_invocation_configuration(&changed).unwrap(),
                PARTICIPANT,
                PRIVACY
            )
            .is_err()
        );
    }

    #[test]
    fn acquisition_configuration_requires_the_exact_governed_parent_and_method() {
        use openpc_indexer_adapter::{AcquisitionConfiguration, AcquisitionRequest};
        let acquisition = AcquisitionConfiguration {
            rate_limit: Some(openpc_indexer_adapter::AcquisitionRateLimit {
                window_ms: 1_000,
                maximum_requests: 8,
            }),
            runtime_target_id: "018f0000-0000-7000-8000-000000000820".into(),
            request: AcquisitionRequest::StateCall {
                target_address: format!("0x{}", "11".repeat(20)),
                calldata: "0x11223344".into(),
            },
        };
        let prepared = crate::local_fixture::indexer::acquisition_input(
            &fixture(),
            "018f0000-0000-7000-8000-000000000802",
            "018f0000-0000-7000-8000-000000000803",
            "018f0000-0000-7000-8000-000000000801",
            acquisition.clone(),
            crate::local_fixture::indexer::AcquisitionFixtureOptions {
                generation: 2,
                confirmation_count: 12,
                state_candidates: true,
            },
        )
        .unwrap();
        let bytes = prepared["configurationCborHex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            validate(&bytes, PARTICIPANT, PRIVACY)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            3
        );
        let configuration =
            decode_active_invocation_configuration(&bytes, &Digest::of(&bytes)).unwrap();
        for change in ["parent", "parameters", "method"] {
            let mut modified = configuration.clone();
            if change == "parent" {
                modified.resource_artifacts.retain(|artifact| {
                    artifact.artifact_kind != ConfigurationArtifactKind::ClientIndexerProfile
                });
            } else if change == "parameters" {
                let artifact = modified
                    .resource_artifacts
                    .iter_mut()
                    .find(|artifact| {
                        artifact.artifact_kind
                            == ConfigurationArtifactKind::IndexerAcquisitionConfiguration
                    })
                    .unwrap();
                let mut other = acquisition.clone();
                other.runtime_target_id = "018f0000-0000-7000-8000-000000000821".into();
                artifact.payload_cbor = other.encode().unwrap();
                artifact.artifact_digest = Digest::of(&artifact.payload_cbor);
            } else {
                let source = modified
                    .resource_artifacts
                    .iter_mut()
                    .find(|artifact| {
                        artifact.artifact_kind == ConfigurationArtifactKind::ClientIndexerProfile
                    })
                    .unwrap();
                let mut profile =
                    pc_provider_api::decode_client_indexer_profile_pc_cbor(&source.payload_cbor)
                        .unwrap();
                profile.method_data_classes[0].method = "eth_getLogs".into();
                source.payload_cbor =
                    pc_provider_api::encode_client_indexer_profile_pc_cbor(&profile).unwrap();
                source.artifact_digest = Digest::of(&source.payload_cbor);
            }
            assert!(
                validate(
                    &encode_active_invocation_configuration(&modified).unwrap(),
                    PARTICIPANT,
                    PRIVACY
                )
                .is_err(),
                "{change}"
            );
        }
    }

    #[test]
    fn finality_configuration_is_exactly_bound_by_the_governed_source() {
        use openpc_indexer_adapter::{FinalityMode, FinalityRule};
        use pc_policy_core::invocation::ConfigurationArtifactV1;
        use pc_provider_api::{
            decode_client_indexer_profile_pc_cbor, encode_client_indexer_profile_pc_cbor,
        };
        let bytes = fixture();
        let mut configured =
            decode_active_invocation_configuration(&bytes, &Digest::of(&bytes)).unwrap();
        let provider = configured
            .resource_artifacts
            .iter()
            .find(|artifact| artifact.artifact_kind == ConfigurationArtifactKind::ProviderProfile)
            .unwrap();
        let rule = FinalityRule {
            rule_id: "urn:openpc:finality-rule:018f0000-0000-7000-8000-000000000910".into(),
            receipt_digest: format!("sha256:{}", Digest::of("unadmitted-test-receipt").as_str()),
            mode: FinalityMode::Confirmations { count: 12 },
            canonical_provider_digests: vec![format!(
                "sha256:{}",
                provider.artifact_digest.as_str()
            )],
            required_observations: 1,
        };
        let rule_bytes = rule.encode().unwrap();
        let source = configured
            .resource_artifacts
            .iter_mut()
            .find(|artifact| {
                artifact.artifact_kind == ConfigurationArtifactKind::ClientIndexerProfile
            })
            .unwrap();
        let mut profile = decode_client_indexer_profile_pc_cbor(&source.payload_cbor).unwrap();
        assert!(FinalityRule::resolve(&profile, &rule_bytes).is_err());
        profile.finality_rule_digest = format!("sha256:{}", Digest::of(&rule_bytes).as_str());
        source.payload_cbor = encode_client_indexer_profile_pc_cbor(&profile).unwrap();
        source.artifact_digest = Digest::of(&source.payload_cbor);
        let id = source.artifact_id.clone();
        configured.resource_artifacts.push(ConfigurationArtifactV1 {
            artifact_id: id,
            artifact_kind: ConfigurationArtifactKind::IndexerFinalityRule,
            artifact_digest: Digest::of(&rule_bytes),
            payload_cbor: rule_bytes.clone(),
        });
        let bindings = validate(
            &encode_active_invocation_configuration(&configured).unwrap(),
            PARTICIPANT,
            PRIVACY,
        )
        .unwrap();
        assert_eq!(
            bindings.as_array().unwrap().len(),
            3,
            "the existing source approval binds the rule digest; configuration does not mint another resource"
        );
        assert_eq!(
            FinalityRule::resolve(&profile, &rule_bytes)
                .unwrap()
                .database_mode(),
            ("CONFIRMATIONS", Some(12))
        );
        for invalid in [
            FinalityRule {
                mode: FinalityMode::Confirmations { count: 0 },
                ..rule.clone()
            },
            FinalityRule {
                required_observations: 0,
                ..rule.clone()
            },
            FinalityRule {
                required_observations: 2,
                ..rule.clone()
            },
            FinalityRule {
                canonical_provider_digests: vec![],
                ..rule.clone()
            },
            FinalityRule {
                rule_id: "default-finality".into(),
                ..rule.clone()
            },
        ] {
            assert!(invalid.encode().is_err());
        }
        let mut substituted = configured.clone();
        substituted
            .resource_artifacts
            .last_mut()
            .unwrap()
            .artifact_id = "another-source".into();
        assert!(
            validate(
                &encode_active_invocation_configuration(&substituted).unwrap(),
                PARTICIPANT,
                PRIVACY
            )
            .is_err()
        );
        configured.resource_artifacts.retain(|artifact| {
            artifact.artifact_kind != ConfigurationArtifactKind::ProviderProfile
        });
        assert!(
            validate(
                &encode_active_invocation_configuration(&configured).unwrap(),
                PARTICIPANT,
                PRIVACY
            )
            .is_err()
        );
    }
}
