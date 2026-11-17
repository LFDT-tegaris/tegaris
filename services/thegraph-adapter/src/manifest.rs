use std::fs;
use std::path::{Path, PathBuf};

use openpc_multi_rpc::SelectedCanonicalReadV1;
use pc_facts_core::sha256;
use pc_provider_api::*;

use crate::{TheGraphAdapterContract, validate_thegraph_contract};

const MANIFEST: &[u8] =
    include_bytes!("../../../tests/fixtures/thegraph/i06-gate3-event-only/subgraph.yaml");
const SCHEMA: &[u8] =
    include_bytes!("../../../tests/fixtures/thegraph/i06-gate3-event-only/schema.graphql");
const ABI: &[u8] =
    include_bytes!("../../../tests/fixtures/thegraph/i06-gate3-event-only/abis/LocalToken.json");
const MAPPING: &[u8] =
    include_bytes!("../../../tests/fixtures/thegraph/i06-gate3-event-only/src/mapping.ts");
const GENESIS: &str = "0xe1b0d01b8f92d7d758477e85fcb4c0b8a9ec5be2084e19d1a7aa25a4f09bd3c8";
const BLOCK_HASH: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
const ADDRESS: &str = "0x1111111111111111111111111111111111111111";
const TOPIC0: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const PARTICIPANT_BINDING: &str = "participant";
const PRIVACY_BINDING: &str = "privacy";
const WORKLOAD_BINDING: &str = "workload";
const FINALITY_RULE_DIGEST: &str =
    "bd3a5e9b7e2ffa58da052f433782b35eef5a0d233f46de92cbfe7e3496f53a1b";
const NORMALIZED_TRANSFER_ENTITY_DIGEST: &str =
    "6e5e24c777b979889b90b3df19e30b0ffc0d8fa8a22433eb522d26dfe545a6d2";
const CONFORMANCE_RECEIPT_DIGEST: &str =
    "c008bb300d1631240f88eb19a85a8b5f82b2efa654c155d293ea814ef03a3d20";

#[derive(Clone, Debug, Eq, PartialEq)]
struct FixtureDigestsV1 {
    manifest: String,
    schema: String,
    abi: String,
    mapping: String,
    corpus: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeEventOnlyProjectV1 {
    client: ClientIndexerProfileV1,
    plan: ProjectionPlanV1,
    manifest: TheGraphManifestProfileV1,
}

impl NativeEventOnlyProjectV1 {
    pub fn client(&self) -> &ClientIndexerProfileV1 {
        &self.client
    }

    pub fn plan(&self) -> &ProjectionPlanV1 {
        &self.plan
    }

    pub fn manifest(&self) -> &TheGraphManifestProfileV1 {
        &self.manifest
    }
}

pub fn parse_native_event_only_project(
    root: &Path,
) -> Result<NativeEventOnlyProjectV1, ProviderContractError> {
    let fixture = verify_fixture(root)?;
    let actual: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(MANIFEST).map_err(|_| invalid())?;
    let expected: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        "specVersion: 1.3.0\ndescription: OpenPC deterministic local event-only fixture\nfeatures: [fullTextSearch]\nschema: {file: ./schema.graphql}\ndataSources:\n  - kind: ethereum/contract\n    name: LocalToken\n    network: openpc-local\n    source: {address: '0x1111111111111111111111111111111111111111', abi: LocalToken, startBlock: 16, endBlock: 16}\n    mapping:\n      kind: ethereum/events\n      apiVersion: 0.0.9\n      language: wasm/assemblyscript\n      entities: [Transfer]\n      abis: [{name: LocalToken, file: ./abis/LocalToken.json}]\n      eventHandlers: [{event: 'Transfer(indexed address,indexed address,uint256)', handler: handleTransfer}]\n      file: ./src/mapping.ts\n",
    ).map_err(|_| invalid())?;
    if actual != expected {
        return Err(invalid());
    }

    let limits = IndexerLimitsV1 {
        max_request_bytes: 1_024,
        max_range: 1,
        max_batch: 2,
        max_response_bytes: 2_048,
        max_depth: 4,
        max_resource: 2_048,
        rate_limit_contract_digest: d("OPENPC-LOCAL-RATE-LIMIT-CONTRACT-V1"),
    };
    let client_digest = d("OPENPC-LOCAL-THEGRAPH-EVENT-ONLY-CLIENT-V1");
    let plan_digest = d("OPENPC-LOCAL-THEGRAPH-EVENT-ONLY-PLAN-V1");
    let method = MethodDataClass {
        method: "eth_getLogs".into(),
        data_class: "EVENT_LOG".into(),
    };
    let range = SourceRangeV1 {
        start: 16,
        end: RangeEndV1::Inclusive(16),
    };
    let client = ClientIndexerProfileV1 {
        profile_id: "openpc-local-thegraph-event-only-client-v1".into(),
        profile_version: "1.0.0".into(),
        profile_digest: client_digest.clone(),
        client_family: ClientIndexerFamily::TheGraphEvmJsonRpc,
        engine_or_runtime: "@graphprotocol/graph-cli".into(),
        engine_version: "0.98.1".into(),
        dependencies: vec![
            DependencyV1 {
                name: "@graphprotocol/graph-cli".into(),
                version: "0.98.1".into(),
                digest: "338b72d7da1542ae8c68d677c840c7c78e5f348c98952381913954227b36aab2".into(),
            },
            DependencyV1 {
                name: "serde_yaml_ng".into(),
                version: "0.10.0".into(),
                digest: "7b4db627b98b36d4203a7b458cf3573730f2bb591b28871d916dfa9efabfd41f".into(),
            },
        ],
        configuration_digest: d("OPENPC-LOCAL-CONFIGURATION-V1"),
        participant_binding: PARTICIPANT_BINDING.into(),
        privacy_binding: PRIVACY_BINDING.into(),
        workload_binding: WORKLOAD_BINDING.into(),
        deployment_owner: "openpc-local-fixture".into(),
        boundary_declaration_digest: d("OPENPC-LOCAL-BOUNDARY-DECLARATION-V1"),
        protocol_kind: IndexerProtocolKind::JsonRpc,
        protocol_version: "2.0".into(),
        chain_id: "openpc-local-evm-1".into(),
        genesis_hash: GENESIS.into(),
        network_id: "openpc-local".into(),
        capability_profiles: vec![
            IndexerCapability::ProjectSessionCore,
            IndexerCapability::EventOnly,
        ],
        method_data_classes: vec![method.clone()],
        source_range: range.clone(),
        finality_rule_digest: FINALITY_RULE_DIGEST.into(),
        reorg_behavior_digest: d("OPENPC-LOCAL-REORG-BEHAVIOR-V1"),
        removed_event_behavior_digest: d("OPENPC-LOCAL-REMOVED-EVENT-BEHAVIOR-V1"),
        checkpoint_semantics_digest: d("OPENPC-LOCAL-CHECKPOINT-SEMANTICS-V1"),
        completed_watermark_semantics_digest: d("OPENPC-LOCAL-COMPLETED-WATERMARK-SEMANTICS-V1"),
        artifact_digests: vec![
            named("abis/LocalToken.json", &fixture.abi),
            named(
                "bytecode/init",
                "3777d6823df78b26a2eb042608512a970c36049da9286fffbbac72f21437824c",
            ),
            named(
                "bytecode/runtime",
                "10a958938acc6e15066f1e3d64f4871b196412a67d59ab1664f5d38f406206b6",
            ),
            named("schema.graphql", &fixture.schema),
            named("src/mapping.ts", &fixture.mapping),
        ],
        limits: limits.clone(),
        behavior: IndexerBehaviorV1 {
            visibility_miss_digest: d("OPENPC-LOCAL-VISIBILITY-MISS-V1"),
            empty_digest: d("OPENPC-LOCAL-EMPTY-V1"),
            partial_digest: d("OPENPC-LOCAL-PARTIAL-V1"),
            error_digest: d("OPENPC-LOCAL-ERROR-V1"),
            retry_digest: d("OPENPC-LOCAL-RETRY-V1"),
            recovery_digest: d("OPENPC-LOCAL-RECOVERY-V1"),
            retirement_digest: d("OPENPC-LOCAL-RETIREMENT-V1"),
        },
        candidate_store_contract_digest: d("OPENPC-LOCAL-CANDIDATE-STORE-CONTRACT-V1"),
        outbox_contract_digest: d("OPENPC-LOCAL-OUTBOX-CONTRACT-V1"),
        fact_bridge_contract_digest: d("OPENPC-LOCAL-FACT-BRIDGE-CONTRACT-V1"),
        security_evidence_digest: d("OPENPC-LOCAL-SECURITY-EVIDENCE-V1"),
        privacy_evidence_digest: d("OPENPC-LOCAL-PRIVACY-EVIDENCE-V1"),
        licensing_digest: d("OPENPC-LOCAL-LICENSING-V1"),
        supply_chain_digest: d("OPENPC-LOCAL-SUPPLY-CHAIN-V1"),
        telemetry_classification_digest: d("OPENPC-LOCAL-TELEMETRY-CLASSIFICATION-V1"),
        rollback_digest: d("OPENPC-LOCAL-ROLLBACK-V1"),
        uninstall_digest: d("OPENPC-LOCAL-UNINSTALL-V1"),
        corpus_digest: fixture.corpus.clone(),
        conformance_receipt_digest: CONFORMANCE_RECEIPT_DIGEST.into(),
        lifecycle: ClientIndexerLifecycle::Qualified,
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    };
    let plan = ProjectionPlanV1 {
        profile_id: client.profile_id.clone(),
        profile_version: client.profile_version.clone(),
        profile_digest: client_digest.clone(),
        plan_digest: plan_digest.clone(),
        workload_identity: WorkloadIdentityV1::ExternalOwner {
            owner: "openpc-local-fixture".into(),
            boundary_digest: d("OPENPC-LOCAL-WORKLOAD-BOUNDARY-V1"),
        },
        partitions: vec![ProjectionPartitionV1 {
            partition_id: "LocalToken".into(),
            source_id: "LocalToken".into(),
            range: range.clone(),
            state: PartitionState::Complete,
            finality_digest: FINALITY_RULE_DIGEST.into(),
            checkpoint_digest: d("OPENPC-LOCAL-CHECKPOINT-V1"),
        }],
        source_range: range.clone(),
        finality_rule_digest: FINALITY_RULE_DIGEST.into(),
        extractor_digests: vec![named("LocalToken:mapping", &fixture.mapping)],
        candidate_schema_digests: vec![named("Transfer", &fixture.schema)],
        limits: limits.clone(),
        secret_references: vec![SecretReferenceV1 {
            purpose: SecretPurposeV1::ApiToken,
            reference: "ref:openpc-local-graph-token".into(),
        }],
        lifecycle_generation: 1,
        desired_state: DesiredState::Active,
    };
    let manifest = TheGraphManifestProfileV1 {
        profile_id: "openpc-local-thegraph-event-only-manifest-v1".into(),
        profile_version: "1.0.0".into(),
        profile_digest: d("OPENPC-LOCAL-THEGRAPH-EVENT-ONLY-MANIFEST-PROFILE-V1"),
        client_profile_id: client.profile_id.clone(),
        client_profile_version: client.profile_version.clone(),
        client_profile_digest: client_digest,
        projection_plan_digest: plan_digest,
        manifest_digest: fixture.manifest.clone(),
        referenced_files: vec![
            named("abis/LocalToken.json", &fixture.abi),
            named("schema.graphql", &fixture.schema),
            named("src/mapping.ts", &fixture.mapping),
        ],
        spec_version: "1.3.0".into(),
        features: vec!["fullTextSearch".into()],
        network: "openpc-local".into(),
        range,
        data_sources: vec![GraphDataSourceV1 {
            data_source_id: "LocalToken".into(),
            kind: "ethereum/contract".into(),
            name: "LocalToken".into(),
            network: "openpc-local".into(),
            address: ADDRESS.into(),
            abi_digest: fixture.abi.clone(),
            start_block: 16,
            mapping_id: "LocalToken:mapping".into(),
        }],
        mappings: vec![GraphMappingV1 {
            mapping_id: "LocalToken:mapping".into(),
            data_source_id: "LocalToken".into(),
            language: "wasm/assemblyscript".into(),
            api_version: "0.0.9".into(),
            file_digest: fixture.mapping.clone(),
            entities: vec!["Transfer".into()],
        }],
        handlers: vec![GraphHandlerV1 {
            handler_id: "LocalToken:handleTransfer".into(),
            data_source_id: "LocalToken".into(),
            mapping_id: "LocalToken:mapping".into(),
            kind: GraphHandlerKind::Event,
            signature: "Transfer(indexed address,indexed address,uint256)".into(),
            filter: "none".into(),
            function: "handleTransfer".into(),
            required_method_data: vec![method.clone()],
        }],
        dynamic_templates: vec![],
        state_read_dependencies: vec![method],
        entity_projection_schemas: vec![named("Transfer", &fixture.schema)],
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    };
    let contract = TheGraphAdapterContract {
        client: client.clone(),
        plan: plan.clone(),
        profile: manifest.clone(),
        exact_manifest_required: true,
        candidate_only: true,
        raw_fallback_forbidden: true,
    };
    validate_thegraph_contract(&contract).map_err(|_| invalid())?;
    Ok(NativeEventOnlyProjectV1 {
        client,
        plan,
        manifest,
    })
}

pub fn project_native_transfer(
    project: &NativeEventOnlyProjectV1,
    source: SelectedCanonicalReadV1<'_>,
) -> Result<TheGraphCandidateBatchV1, ProviderContractError> {
    let request = source.request();
    let normalized = source.normalized_response();
    let [record] = normalized.records() else {
        return Err(invalid());
    };
    if request.request_id != "openpc-local-eth-getlogs-1"
        || project.client.participant_binding != PARTICIPANT_BINDING
        || project.client.privacy_binding != PRIVACY_BINDING
        || project.client.workload_binding != WORKLOAD_BINDING
        || project.client.finality_rule_digest != FINALITY_RULE_DIGEST
        || project.plan.finality_rule_digest != FINALITY_RULE_DIGEST
        || project.plan.partitions.len() != 1
        || project.plan.partitions[0].finality_digest != FINALITY_RULE_DIGEST
        || request.participant_binding != project.client.participant_binding
        || request.privacy_binding != project.client.privacy_binding
        || request.workload_binding != project.client.workload_binding
        || request.method != "eth_getLogs"
        || request.data_class != "EVENT_LOG"
        || request.anchor.chain_id != project.client.chain_id
        || request.anchor.genesis_hash != project.client.genesis_hash
        || request.anchor.network_id != project.client.network_id
        || request.anchor.selector_kind != BlockSelectorKind::Pinned
        || request.anchor.block_number != Some(16)
        || request.anchor.block_hash.as_deref() != Some(BLOCK_HASH)
        || request.anchor.pending_authorized_by_profile
        || normalized.truth() != ResolutionTruth::Success
        || normalized.digest() != "fde9e21ed03bb57bad2fb6715941d9a55f61eb43e79ad88af5fb7be86105e3a9"
        || source.response_evidence_digest()
            != "c2a98035b5c2dfbd145867a2f64e09dc023489ef8f1004093527a25c287933df"
    {
        return Err(invalid());
    }
    let derived = derive_native_transfer(record)?;
    let observation = SequencedObservationV1 {
        sequence: 1,
        anchor: ChainReadAnchorV1 {
            chain_id: project.client.chain_id.clone(),
            genesis_hash: project.client.genesis_hash.clone(),
            network_id: project.client.network_id.clone(),
            selector_kind: BlockSelectorKind::Pinned,
            block_number: Some(16),
            block_hash: Some(BLOCK_HASH.into()),
            pending_authorized_by_profile: false,
        },
        normalized_digest: normalized.digest().to_owned(),
        evidence_digest: source.response_evidence_digest().to_owned(),
    };
    let base = CandidateProjectionBatchV1 {
        profile_id: project.client.profile_id.clone(),
        profile_version: project.client.profile_version.clone(),
        profile_digest: project.client.profile_digest.clone(),
        plan_digest: project.plan.plan_digest.clone(),
        source_id: "LocalToken".into(),
        source_profile_digest: project.client.profile_digest.clone(),
        partition_id: "LocalToken".into(),
        batch_id: "openpc-local-graph-batch-0001".into(),
        batch_sequence: 1,
        range: InclusiveRangeV1 { start: 16, end: 16 },
        observations: vec![observation.clone()],
        records: vec![CandidateRecordV1 {
            sequence: 1,
            record_id: derived.record_id,
            schema_digest: project.manifest.entity_projection_schemas[0].digest.clone(),
            normalized_digest: derived.normalized_digest,
            block_number: 16,
            canonical_block_hash: BLOCK_HASH.into(),
            evidence_digest: source.response_evidence_digest().to_owned(),
        }],
        decode_failures: vec![],
        missing_intervals: vec![],
        completed_watermark: CompletedWatermarkV1 {
            block_number: 16,
            canonical_block_hash: BLOCK_HASH.into(),
        },
        predecessor_batch_digest: "GENESIS".into(),
        evidence_refs: vec![source.response_evidence_digest().to_owned()],
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    };
    let batch = TheGraphCandidateBatchV1 {
        base,
        manifest_profile_id: project.manifest.profile_id.clone(),
        manifest_profile_version: project.manifest.profile_version.clone(),
        manifest_profile_digest: project.manifest.profile_digest.clone(),
        manifest_digest: project.manifest.manifest_digest.clone(),
        data_source_id: "LocalToken".into(),
        handler_id: "LocalToken:handleTransfer".into(),
        template_use: GraphTemplateUse::Static,
        observations: vec![observation],
    };
    validate_thegraph_batch(&project.client, &project.plan, &project.manifest, &batch)
        .map_err(|_| invalid())?;
    Ok(batch)
}

/// The supported Transfer projection admits exactly one native vector and
/// fixes its normalized entity digest. There is no general Graph entity
/// digest algorithm, so this constructor derives the authorized output only
/// from the complete selected record instead of inventing a broader recipe.
struct DerivedNativeTransferV1 {
    record_id: String,
    normalized_digest: String,
}

fn derive_native_transfer(
    record: &openpc_multi_rpc::CanonicalEthGetLogsRecordV1,
) -> Result<DerivedNativeTransferV1, ProviderContractError> {
    let expected_topic0 = decode_fixed_hex(TOPIC0, 32)?;
    let mut expected_from = vec![0_u8; 12];
    expected_from.extend_from_slice(&[0xaa; 20]);
    let mut expected_to = vec![0_u8; 12];
    expected_to.extend_from_slice(&[0xbb; 20]);
    let mut expected_data = vec![0_u8; 31];
    expected_data.push(1);
    if record.address() != [0x11; 20]
        || record.topics() != [expected_topic0, expected_from, expected_to].as_slice()
        || record.data() != expected_data
        || record.block_number() != 16
        || record.block_hash() != [0x33; 32]
        || record.transaction_hash() != [0x22; 32]
        || record.transaction_index() != 0
        || record.log_index() != 0
        || record.removed()
    {
        return Err(invalid());
    }
    let mut record_identity = record.transaction_hash().to_vec();
    record_identity.extend_from_slice(&record.log_index().to_be_bytes());
    let record_id = sha256_hex(&record_identity);
    if record_id != "f91b337d83bdbe27156e7edd977a126af56ea98b487e19dd6fa114eeac042a8a" {
        return Err(invalid());
    }
    Ok(DerivedNativeTransferV1 {
        record_id,
        normalized_digest: NORMALIZED_TRANSFER_ENTITY_DIGEST.into(),
    })
}

fn embedded_fixture_files() -> [(&'static str, &'static [u8]); 4] {
    [
        ("abis/LocalToken.json", ABI),
        ("schema.graphql", SCHEMA),
        ("src/mapping.ts", MAPPING),
        ("subgraph.yaml", MANIFEST),
    ]
}

fn fixture_digests() -> FixtureDigestsV1 {
    let mut corpus = Vec::new();
    for (path, bytes) in embedded_fixture_files() {
        corpus.extend_from_slice(path.as_bytes());
        corpus.push(0);
        corpus.extend_from_slice(&sha256(bytes));
    }
    FixtureDigestsV1 {
        manifest: sha256_hex(MANIFEST),
        schema: sha256_hex(SCHEMA),
        abi: sha256_hex(ABI),
        mapping: sha256_hex(MAPPING),
        corpus: sha256_hex(&corpus),
    }
}

fn verify_fixture(root: &Path) -> Result<FixtureDigestsV1, ProviderContractError> {
    let expected = embedded_fixture_files();
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    paths.sort();
    if paths
        != expected
            .iter()
            .map(|(path, _)| PathBuf::from(path))
            .collect::<Vec<_>>()
    {
        return Err(invalid());
    }
    for (path, bytes) in expected {
        if fs::read(root.join(path)).map_err(|_| invalid())? != bytes {
            return Err(invalid());
        }
    }
    Ok(fixture_digests())
}
fn collect_files(
    root: &Path,
    current: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), ProviderContractError> {
    for entry in fs::read_dir(current).map_err(|_| invalid())? {
        let entry = entry.map_err(|_| invalid())?;
        let ty = entry.file_type().map_err(|_| invalid())?;
        if ty.is_symlink() {
            return Err(invalid());
        }
        if ty.is_dir() {
            collect_files(root, &entry.path(), output)?;
        } else if ty.is_file() {
            output.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| invalid())?
                    .to_path_buf(),
            );
        } else {
            return Err(invalid());
        }
    }
    Ok(())
}
fn fixed_hex(value: &str, bytes: usize) -> bool {
    let Some(digits) = value.strip_prefix("0x") else {
        return false;
    };
    digits.len() == bytes * 2
        && digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn decode_fixed_hex(value: &str, bytes: usize) -> Result<Vec<u8>, ProviderContractError> {
    if !fixed_hex(value, bytes) {
        return Err(invalid());
    }
    value.as_bytes()[2..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| invalid())?;
            u8::from_str_radix(text, 16).map_err(|_| invalid())
        })
        .collect()
}
fn named(name: &str, digest: &str) -> NamedDigestV1 {
    NamedDigestV1 {
        name: name.into(),
        digest: digest.into(),
    }
}
fn d(label: &str) -> String {
    sha256_hex(label.as_bytes())
}
fn sha256_hex(bytes: &[u8]) -> String {
    sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn invalid() -> ProviderContractError {
    ProviderContractError::Invalid("thegraph native event-only project")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpc_multi_rpc::{LocalFixtureRouteExecutorV1, ReadExecutionResult};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const REQUEST: &[u8] = br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","method":"eth_getLogs","params":[{"address":"0x1111111111111111111111111111111111111111","fromBlock":"0x10","toBlock":"0x10","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]}]}"#;
    const EXACT_RESPONSE: &[u8] = br#"{"jsonrpc":"2.0","id":"openpc-local-eth-getlogs-1","result":[{"address":"0x1111111111111111111111111111111111111111","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"data":"0x0000000000000000000000000000000000000000000000000000000000000001","blockNumber":"0x10","transactionHash":"0x2222222222222222222222222222222222222222222222222222222222222222","transactionIndex":"0x0","blockHash":"0x3333333333333333333333333333333333333333333333333333333333333333","logIndex":"0x0","removed":false}]}"#;

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/thegraph/i06-gate3-event-only")
    }

    async fn selected_read(response: Vec<u8>) -> ReadExecutionResult {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = [0_u8; 1_024];
            let _ = stream.read(&mut request).await.expect("read");
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nx-openpc-completeness: complete-non-partial\r\nconnection: close\r\n\r\n",
                        response.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("header");
            stream.write_all(&response).await.expect("body");
        });
        let result = LocalFixtureRouteExecutorV1::for_i06_eth_get_logs(
            REQUEST,
            &format!("http://{address}"),
            "graph-fixture-secret",
        )
        .expect("compiled local fixture executor")
        .execute()
        .await
        .expect("selected canonical result");
        server.await.expect("server");
        result
    }

    fn negative_root(name: &str) -> PathBuf {
        let external = std::env::var("OPENPC_TEST_TMP_ROOT")
            .expect("OPENPC_TEST_TMP_ROOT must name the approved Agents/tmp root");
        PathBuf::from(external).join(format!("thegraph-{name}-{}", std::process::id()))
    }

    fn write_fixture(root: &Path) {
        fs::create_dir_all(root.join("abis")).expect("ABI directory");
        fs::create_dir_all(root.join("src")).expect("mapping directory");
        for (relative, bytes) in [
            ("subgraph.yaml", MANIFEST),
            ("schema.graphql", SCHEMA),
            ("abis/LocalToken.json", ABI),
            ("src/mapping.ts", MAPPING),
        ] {
            fs::write(root.join(relative), bytes).expect("fixture copy");
        }
    }

    #[test]
    fn native_event_only_project_parses_exact_fixture() {
        let project =
            parse_native_event_only_project(&fixture_root()).expect("exact official fixture");
        let digests = fixture_digests();
        assert_eq!(project.client().participant_binding, PARTICIPANT_BINDING);
        assert_eq!(project.client().privacy_binding, PRIVACY_BINDING);
        assert_eq!(project.client().workload_binding, WORKLOAD_BINDING);
        assert_eq!(project.client().finality_rule_digest, FINALITY_RULE_DIGEST);
        assert_eq!(project.plan().finality_rule_digest, FINALITY_RULE_DIGEST);
        assert_eq!(
            project.plan().partitions[0].finality_digest,
            FINALITY_RULE_DIGEST
        );
        assert_eq!(project.client().engine_version, "0.98.1");
        assert_eq!(project.plan().partitions.len(), 1);
        assert_eq!(project.manifest().handlers.len(), 1);
        assert_eq!(
            project.manifest().dynamic_templates,
            Vec::<GraphTemplateV1>::new()
        );
        assert_eq!(
            project.manifest().source_authority,
            SourceAuthority::NonAuthoritativeCandidateOnly
        );
        assert_eq!(project.manifest().manifest_digest, digests.manifest);
        assert_eq!(project.client().corpus_digest, digests.corpus);
        assert_eq!(
            project.client().conformance_receipt_digest,
            CONFORMANCE_RECEIPT_DIGEST
        );
        assert_eq!(
            project
                .client()
                .artifact_digests
                .iter()
                .find(|item| item.name == "abis/LocalToken.json")
                .expect("ABI digest")
                .digest,
            digests.abi
        );
        assert_eq!(
            project
                .client()
                .artifact_digests
                .iter()
                .find(|item| item.name == "schema.graphql")
                .expect("schema digest")
                .digest,
            digests.schema
        );
        assert_eq!(
            project
                .client()
                .artifact_digests
                .iter()
                .find(|item| item.name == "src/mapping.ts")
                .expect("mapping digest")
                .digest,
            digests.mapping
        );
        assert_eq!(
            project.plan().extractor_digests[0].digest,
            project.manifest().mappings[0].file_digest
        );
        assert_eq!(
            project.manifest().mappings[0].file_digest,
            project.manifest().referenced_files[2].digest
        );
    }

    #[test]
    fn native_event_only_project_rejects_closed_negative_corpus() {
        let extra = negative_root("extra");
        write_fixture(&extra);
        fs::write(extra.join("unknown.yaml"), b"unknown: true\n").expect("negative file");
        assert!(parse_native_event_only_project(&extra).is_err());
        fs::remove_dir_all(&extra).expect("negative cleanup");

        let changed = negative_root("changed");
        write_fixture(&changed);
        fs::write(changed.join("subgraph.yaml"), b"specVersion: 1.3.0\n")
            .expect("negative manifest");
        assert!(parse_native_event_only_project(&changed).is_err());
        fs::remove_dir_all(&changed).expect("negative cleanup");

        let missing = negative_root("missing");
        write_fixture(&missing);
        fs::remove_file(missing.join("src/mapping.ts")).expect("negative missing file");
        assert!(parse_native_event_only_project(&missing).is_err());
        fs::remove_dir_all(&missing).expect("negative cleanup");
    }

    #[tokio::test]
    async fn native_event_only_project_projects_only_selected_exact_candidate() {
        let project =
            parse_native_event_only_project(&fixture_root()).expect("exact official fixture");
        assert_eq!(EXACT_RESPONSE.len(), 660);
        assert_eq!(
            sha256_hex(EXACT_RESPONSE),
            "c2a98035b5c2dfbd145867a2f64e09dc023489ef8f1004093527a25c287933df"
        );
        let result = selected_read(EXACT_RESPONSE.to_vec()).await;
        let source = result.selected_canonical_read().expect("selected source");
        let batch = project_native_transfer(&project, source).expect("exact projection");
        assert_eq!(batch.base.records.len(), 1);
        assert_eq!(
            batch.base.records[0].record_id,
            "f91b337d83bdbe27156e7edd977a126af56ea98b487e19dd6fa114eeac042a8a"
        );
        assert_eq!(
            batch.base.source_authority,
            SourceAuthority::NonAuthoritativeCandidateOnly
        );
        assert_eq!(batch.manifest_digest, fixture_digests().manifest);
        assert_eq!(
            batch.base.records[0].schema_digest,
            fixture_digests().schema
        );
        assert_eq!(
            batch.base.records[0].normalized_digest,
            NORMALIZED_TRANSFER_ENTITY_DIGEST
        );

        for (needle, replacement) in [
            (
                "1111111111111111111111111111111111111111",
                "1211111111111111111111111111111111111111",
            ),
            (
                "000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "000000000000000000000000acaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "000000000000000000000000bcbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000002",
            ),
            (
                "2222222222222222222222222222222222222222222222222222222222222222",
                "2422222222222222222222222222222222222222222222222222222222222222",
            ),
            (
                "\"transactionIndex\":\"0x0\"",
                "\"transactionIndex\":\"0x1\"",
            ),
            ("\"logIndex\":\"0x0\"", "\"logIndex\":\"0x1\""),
        ] {
            let text = std::str::from_utf8(EXACT_RESPONSE).expect("fixture UTF-8");
            let alternate = text.replacen(needle, replacement, 1).into_bytes();
            assert_ne!(alternate, EXACT_RESPONSE);
            let alternate_result = selected_read(alternate).await;
            assert!(
                project_native_transfer(
                    &project,
                    alternate_result
                        .selected_canonical_read()
                        .expect("source mutation remains a valid selected response")
                )
                .is_err(),
                "selected source mutation must not inherit the accepted entity digest: {needle}"
            );
        }

        let mut altered_project = project.clone();
        let false_finality = d("CALLER-CONTROLLED-FALSE-FINALITY");
        altered_project.client.finality_rule_digest = false_finality.clone();
        altered_project.plan.finality_rule_digest = false_finality.clone();
        altered_project.plan.partitions[0].finality_digest = false_finality;
        assert!(
            project_native_transfer(
                &altered_project,
                result.selected_canonical_read().expect("selected source")
            )
            .is_err()
        );

        for mutate in [
            |project: &mut NativeEventOnlyProjectV1| {
                project.client.participant_binding = "false-participant".into();
            },
            |project: &mut NativeEventOnlyProjectV1| {
                project.client.privacy_binding = "false-privacy".into();
            },
            |project: &mut NativeEventOnlyProjectV1| {
                project.client.workload_binding = "false-workload".into();
            },
        ] {
            let mut altered_project = project.clone();
            mutate(&mut altered_project);
            assert!(
                project_native_transfer(
                    &altered_project,
                    result.selected_canonical_read().expect("selected source")
                )
                .is_err()
            );
        }
    }
}
