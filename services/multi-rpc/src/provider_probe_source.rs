//! Restricted deployment inputs for the live provider observation worker.
//! Files supply data, not qualification: their exact bytes are pinned by the
//! provider artifact in the governed active configuration.
use crate::{
    provider_connection::{
        DestinationPolicy, EndpointDescriptor, LocalTlsMaterial, NetworkRange, ProviderConnection,
        ProviderTlsMaterial, Resolution, ServerTlsMaterial,
    },
    provider_probe::HashPinnedCallProbePlan,
};
use pc_provider_api::ProviderProfileV1;
use pc_runtime_types::Digest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    net::IpAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Default, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TlsAuthentication {
    #[default]
    Mutual,
    Server,
}
#[derive(Default, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AdmissionScope {
    #[default]
    FullCorpus,
    BoundedQa,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    version: u32,
    participant_id: String,
    privacy_domain_id: String,
    endpoint: EndpointDescriptor,
    allowed_ranges: Vec<String>,
    private_network_ranges: Vec<String>,
    allow_ip_endpoint: bool,
    addresses: Vec<IpAddr>,
    connection_validity_ms: u64,
    roots_der: Vec<Vec<u8>>,
    #[serde(default)]
    client_chain_der: Vec<Vec<u8>>,
    #[serde(default)]
    tls_authentication: TlsAuthentication,
    #[serde(default)]
    admission_scope: AdmissionScope,
    server_certificate_digest: Digest,
    #[serde(default)]
    server_certificate_overlap_digest: Option<Digest>,
    probe: HashPinnedCallProbePlan,
}

pub struct PreparedProbe {
    pub endpoint_id: String,
    pub connection: ProviderConnection,
    pub plan: HashPinnedCallProbePlan,
    pub valid_until_ms: u64,
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "provider source unavailable")?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "provider source unreadable")?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err("provider source size rejected".into());
    }
    Ok(bytes)
}

fn secret_id(reference: &str) -> Result<&str, String> {
    let id = reference
        .strip_prefix("urn:openpc:secret:")
        .ok_or("provider secret reference rejected")?;
    if id.len() != 36
        || id.bytes().enumerate().any(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b != b'-'
            } else {
                !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b)
            }
        })
        || id.as_bytes()[14] != b'7'
        || !b"89ab".contains(&id.as_bytes()[19])
    {
        return Err("provider secret reference rejected".into());
    }
    Ok(id)
}

pub fn now_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| d.as_millis().try_into().ok())
        .ok_or_else(|| "provider clock unavailable".into())
}

pub fn prepare(
    directory: &Path,
    endpoint_secret_ref: &str,
    profile: &ProviderProfileV1,
    participant_id: &str,
    privacy_domain_id: &str,
    resolution_generation: u64,
) -> Result<PreparedProbe, String> {
    let id = secret_id(endpoint_secret_ref)?;
    let bytes = read_bounded(&directory.join(format!("{id}.json")), 2 * 1024 * 1024)?;
    if format!("sha256:{}", Digest::of(&bytes).as_str()) != profile.configuration_digest {
        return Err("provider source commitment rejected".into());
    }
    let source: Source =
        serde_json::from_slice(&bytes).map_err(|_| "provider source structure rejected")?;
    if source.participant_id != participant_id || source.privacy_domain_id != privacy_domain_id {
        return Err("provider source authority scope rejected".into());
    }
    if source.version != 1
        || !(30_000..=3_600_000).contains(&source.connection_validity_ms)
        || source.probe.chain_id.to_string() != profile.chain_id
        || format!("sha256:{}", source.probe.genesis_hash.as_str()) != profile.genesis_hash
        || format!("sha256:{}", source.probe.corpus_digest.as_str()) != profile.corpus_digest
        || source.endpoint.credential_ref != profile.tls_credential_identity
        || source.allowed_ranges.len() > 64
        || source.private_network_ranges.len() > 64
    {
        return Err("provider source profile mismatch".into());
    }
    // This opt-in pins the entire governed source: endpoint, scope, chain,
    // corpus, trust material, capabilities and explicit QA limitation. Unset
    // deployments retain full-corpus admission; runtime reads recheck it too.
    if source.admission_scope == AdmissionScope::BoundedQa {
        if profile.lifecycle != pc_provider_api::ProfileLifecycle::BoundedQa
            || std::env::var("OPENPC_PROVIDER_BOUNDED_QA_SOURCE_DIGEST")
                .ok()
                .as_deref()
                != Some(profile.configuration_digest.as_str())
            || source.probe.noncanonical_block_hash.is_some()
        {
            return Err("provider bounded QA admission rejected".into());
        }
    } else if source.probe.noncanonical_block_hash.is_none()
        || profile.lifecycle == pc_provider_api::ProfileLifecycle::BoundedQa
    {
        return Err("provider full corpus missing historical reorg case".into());
    }
    let roots = source
        .roots_der
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let tls: ProviderTlsMaterial = match source.tls_authentication {
        TlsAuthentication::Mutual => {
            if source.server_certificate_overlap_digest.is_some()
                || source.client_chain_der.first().is_none_or(|cert| {
                    format!("sha256:{}", Digest::of(cert).as_str())
                        != profile.tls_credential_fingerprint
                })
            {
                return Err("provider client identity mismatch".into());
            }
            let key_id = secret_id(&source.endpoint.credential_ref)?;
            let key = read_bounded(&directory.join(format!("{key_id}.pk8")), 16 * 1024)?;
            LocalTlsMaterial {
                roots,
                client_chain: source
                    .client_chain_der
                    .into_iter()
                    .map(CertificateDer::from)
                    .collect(),
                client_key: PrivateKeyDer::try_from(key).map_err(|_| "provider key rejected")?,
                expected_server_certificate: source.server_certificate_digest,
            }
            .into()
        }
        TlsAuthentication::Server => {
            if !source.client_chain_der.is_empty()
                || profile.tls_credential_fingerprint
                    != format!("sha256:{}", source.server_certificate_digest.as_str())
                || source.server_certificate_overlap_digest.as_ref()
                    == Some(&source.server_certificate_digest)
            {
                return Err("provider server identity mismatch".into());
            }
            ServerTlsMaterial {
                roots,
                expected_server_certificate: source.server_certificate_digest,
                server_certificate_overlap: source.server_certificate_overlap_digest,
            }
            .into()
        }
    };
    let now = now_ms()?;
    let valid_until_ms = now
        .checked_add(source.connection_validity_ms)
        .ok_or("provider source validity rejected")?;
    let parse_ranges = |values: &[String]| {
        values
            .iter()
            .map(|v| NetworkRange::parse(v))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "provider source egress rejected".to_owned())
    };
    let endpoint_id = source.endpoint.endpoint_id.clone();
    let endpoint = source
        .endpoint
        .prepare(
            &DestinationPolicy {
                allowed_ranges: parse_ranges(&source.allowed_ranges)?,
                private_network_ranges: parse_ranges(&source.private_network_ranges)?,
                allow_ip_endpoint: source.allow_ip_endpoint,
            },
            Resolution {
                addresses: source.addresses,
                resolved_at_ms: now,
                valid_until_ms,
                generation: resolution_generation,
            },
        )
        .map_err(|_| "provider endpoint preparation rejected")?;
    let connection = ProviderConnection::prepare(
        endpoint,
        tls,
        profile
            .limits
            .max_request_bytes
            .try_into()
            .map_err(|_| "provider request bound rejected")?,
        profile
            .limits
            .max_response_bytes
            .try_into()
            .map_err(|_| "provider response bound rejected")?,
    )
    .map_err(|_| "provider transport preparation rejected")?;
    Ok(PreparedProbe {
        endpoint_id,
        connection,
        plan: source.probe,
        valid_until_ms,
    })
}

pub fn prepare_matching_profile(
    directory: &Path,
    profile: &ProviderProfileV1,
    participant_id: &str,
    privacy_domain_id: &str,
    resolution_generation: u64,
) -> Result<PreparedProbe, String> {
    let mut matches = Vec::new();
    for (index, entry) in std::fs::read_dir(directory)
        .map_err(|_| "provider source directory unavailable")?
        .enumerate()
    {
        if index >= 128 {
            return Err("provider source directory capacity rejected".into());
        }
        let entry = entry.map_err(|_| "provider source directory unreadable")?;
        if !entry
            .file_type()
            .map_err(|_| "provider source metadata unavailable")?
            .is_file()
        {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "provider source name rejected")?;
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
        if secret_id(&format!("urn:openpc:secret:{id}")).is_err() {
            continue;
        }
        let bytes = read_bounded(&entry.path(), 2 * 1024 * 1024)?;
        if format!("sha256:{}", Digest::of(&bytes).as_str()) == profile.configuration_digest {
            matches.push(format!("urn:openpc:secret:{id}"));
        }
    }
    let [reference] = matches.as_slice() else {
        return Err("unique committed provider source unavailable".into());
    };
    prepare(
        directory,
        reference,
        profile,
        participant_id,
        privacy_domain_id,
        resolution_generation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };

    #[tokio::test]
    async fn scoped_source_and_actual_key_are_required_before_preparation() {
        for deployment in ["0", "1"] {
            let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            let scratch = std::env::var_os("OPENPC_TEST_TMP_ROOT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| repository.join("../Agents/tmp"));
            let directory = scratch.join(format!(
                "provider-source-{}-{}",
                std::process::id(),
                now_ms().unwrap()
            ));
            fs::create_dir_all(&directory).unwrap();
            let bootstrap =
                repository.join("tests/integration/local-runtime/rpc-provider-bootstrap.mjs");
            for mode in ["bootstrap", "source"] {
                let mut command = Command::new("node");
                command.env("OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY", deployment);
                command.arg(&bootstrap).arg(mode).arg(&directory);
                if mode == "source" {
                    command.arg("127.0.0.1");
                }
                assert!(
                    command
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .unwrap()
                        .success()
                );
            }
            let sources = directory.join("provider-probe-source");
            let profile: ProviderProfileV1 =
                serde_json::from_slice(&fs::read(sources.join("profile.json")).unwrap()).unwrap();
            pc_provider_api::validate_provider_profile(&profile).unwrap();
            let participant = "018f0000-0000-7000-8000-000000000101";
            let privacy = "018f0000-0000-7000-8000-000000000201";
            let reference = "urn:openpc:secret:018f0000-0000-7000-8000-000000000930";
            let result = prepare(&sources, reference, &profile, participant, privacy, 1);
            assert!(result.is_ok());
            for (participant, privacy) in [(privacy, privacy), (participant, participant)] {
                assert_eq!(
                    prepare(&sources, reference, &profile, participant, privacy, 2)
                        .err()
                        .unwrap(),
                    "provider source authority scope rejected"
                );
            }
            assert!(
                prepare(
                    &sources,
                    "urn:openpc:secret:../../credential",
                    &profile,
                    participant,
                    privacy,
                    2
                )
                .is_err()
            );
            let source = sources.join("018f0000-0000-7000-8000-000000000930.json");
            let mut bytes = fs::read(&source).unwrap();
            bytes.push(b' ');
            fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&source, bytes).unwrap();
            assert_eq!(
                prepare(&sources, reference, &profile, participant, privacy, 2)
                    .err()
                    .unwrap(),
                "provider source commitment rejected"
            );
            fs::remove_dir_all(directory).unwrap();
        }
    }
}
