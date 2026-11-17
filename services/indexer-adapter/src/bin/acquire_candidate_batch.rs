//! One bounded service job. Deployment owns its target connection and secret
//! paths; the CandidateStore and target own publication and current authority.
use openpc_indexer_adapter::{
    CandidatePersistenceBinding, CandidateStore, PersistenceOutcome,
    acquisition::{AcquisitionBatch, acquire_batch},
};
use openpc_multi_rpc::provider_connection::{
    DestinationPolicy, EndpointDescriptor, LocalTlsMaterial, NetworkRange, ProviderConnection,
    Resolution,
};
use pc_provider_api::InclusiveRangeV1;
use pc_runtime_types::Digest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use std::{
    env,
    fs::File,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

type Result<T> = std::result::Result<T, &'static str>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    participant_id: Uuid,
    privacy_domain_id: Uuid,
    projection_generation_id: Uuid,
    operation_id: Uuid,
    correlation_id: Uuid,
    source_id: String,
    partition_id: String,
    batch_id: String,
    sequence: u64,
    predecessor_digest: String,
    range: InclusiveRangeV1,
    runtime_target_id: String,
    candidate_database_url_file: PathBuf,
    endpoint: EndpointDescriptor,
    allowed_ranges: Vec<String>,
    private_network_ranges: Vec<String>,
    allow_ip_endpoint: bool,
    addresses: Vec<IpAddr>,
    roots_der_files: Vec<PathBuf>,
    client_chain_der_files: Vec<PathBuf>,
    client_key_pkcs8_file: PathBuf,
    server_certificate_digest: String,
}
fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err("configuration path rejected");
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "configuration unavailable")?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "configuration unreadable")?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err("configuration size rejected");
    }
    Ok(bytes)
}
fn certificates(paths: &[PathBuf]) -> Result<Vec<CertificateDer<'static>>> {
    if paths.is_empty() || paths.len() > 8 {
        return Err("certificate chain bound rejected");
    }
    paths
        .iter()
        .map(|path| read(path, 65_536).map(CertificateDer::from))
        .collect()
}
async fn run() -> Result<()> {
    let path = env::var_os("OPENPC_ACQUISITION_CONFIG_FILE").ok_or("configuration missing")?;
    let config: Config = serde_json::from_slice(&read(Path::new(&path), 131_072)?)
        .map_err(|_| "configuration structure rejected")?;
    if config.endpoint.endpoint_id != config.runtime_target_id
        || config.allowed_ranges.len() > 64
        || config.private_network_ranges.len() > 64
        || config.addresses.is_empty()
        || config.addresses.len() > 64
    {
        return Err("target binding rejected");
    }
    let binding = CandidatePersistenceBinding::try_new(
        config.participant_id,
        config.privacy_domain_id,
        config.projection_generation_id,
        config.operation_id,
        config.correlation_id,
    )
    .map_err(|_| "job scope rejected")?;
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock unavailable")?
        .as_millis()
        .try_into()
        .map_err(|_| "clock rejected")?;
    let ranges = |items: &[String]| {
        items
            .iter()
            .map(|item| NetworkRange::parse(item).map_err(|_| "egress bound rejected"))
            .collect::<Result<Vec<_>>>()
    };
    let endpoint = config
        .endpoint
        .prepare(
            &DestinationPolicy {
                allowed_ranges: ranges(&config.allowed_ranges)?,
                private_network_ranges: ranges(&config.private_network_ranges)?,
                allow_ip_endpoint: config.allow_ip_endpoint,
            },
            Resolution {
                addresses: config.addresses,
                resolved_at_ms: now,
                valid_until_ms: now.checked_add(60_000).ok_or("clock rejected")?,
                generation: 1,
            },
        )
        .map_err(|_| "target endpoint rejected")?;
    let connection = ProviderConnection::prepare(
        endpoint,
        LocalTlsMaterial {
            roots: certificates(&config.roots_der_files)?,
            client_chain: certificates(&config.client_chain_der_files)?,
            client_key: PrivateKeyDer::try_from(read(&config.client_key_pkcs8_file, 16_384)?)
                .map_err(|_| "workload key rejected")?,
            expected_server_certificate: Digest::parse(&config.server_certificate_digest)
                .map_err(|_| "target certificate binding rejected")?,
        },
        131_072,
        131_072,
    )
    .map_err(|_| "target TLS configuration rejected")?;
    let database = String::from_utf8(read(&config.candidate_database_url_file, 8192)?)
        .map_err(|_| "candidate database configuration rejected")?;
    let store = CandidateStore::connect(database.trim())
        .await
        .map_err(|_| "candidate writer unavailable")?;
    let result = acquire_batch(
        &store,
        &connection,
        &config.runtime_target_id,
        &AcquisitionBatch {
            binding,
            source_id: config.source_id,
            partition_id: config.partition_id,
            batch_id: config.batch_id,
            sequence: config.sequence,
            predecessor_digest: config.predecessor_digest,
            range: config.range,
        },
    )
    .await
    .map_err(|error| {
        // CandidateStoreError's Display is a closed code; it deliberately omits
        // database messages, source payloads, endpoint details and credentials.
        eprintln!(
            "{}",
            serde_json::json!({"event":"candidate_acquisition_rejected","code":error.to_string()})
        );
        "source acquisition rejected"
    });
    store.close().await;
    let outcome = match result? {
        PersistenceOutcome::Committed => "COMMITTED_CANDIDATE",
        PersistenceOutcome::ReplayedSameDigest => "REPLAYED_CANDIDATE",
        PersistenceOutcome::ReorgInvalidated => "REORG_INVALIDATED",
        _ => return Err("candidate checkpoint not committed"),
    };
    println!(
        "{}",
        serde_json::json!({"outcome":outcome,"authority":"NON_AUTHORITATIVE"})
    );
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(classification) = run().await {
        eprintln!(
            "{}",
            serde_json::json!({"event":"candidate_acquisition_stopped","classification":classification})
        );
        std::process::exit(1);
    }
}
