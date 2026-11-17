//! TLS 1.3 mutual authentication precedes target identity and ADS processing.
use crate::{FleetController, TargetIdentity};
use futures::Stream;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::sync::Arc;
use tokio::{
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tonic::{
    Status,
    transport::server::{TcpConnectInfo, TlsConnectInfo},
};
use x509_parser::{extensions::GeneralName, prelude::*};

pub fn target_identity_from_pem(certificate_pem: &[u8]) -> RuntimeResult<TargetIdentity> {
    let certificate = CertificateDer::pem_slice_iter(certificate_pem)
        .next()
        .ok_or(RuntimeError::TargetIdentity)?
        .map_err(|_| RuntimeError::TargetIdentity)?;
    target_identity_from_der(certificate.as_ref())
}

/// The public issuer identifies a target workload by its registered target UUID.
/// The database discovery owner also binds the signed Participant and current
/// credential. Retained SPIFFE targets keep their existing transport identity.
pub(crate) fn target_id_from_uri_san(uri: &str) -> Option<&str> {
    if let Some(target) = uri.strip_prefix("spiffe://openpc.local/runtime-target/") {
        return (!target.is_empty()).then_some(target);
    }
    let (participant, target) = uri
        .strip_prefix("urn:openpc:participant:")?
        .split_once(":workload:")?;
    for value in [participant, target] {
        let id = uuid::Uuid::parse_str(value).ok()?;
        if id.get_version_num() != 7
            || id.get_variant() != uuid::Variant::RFC4122
            || id.hyphenated().to_string() != value
        {
            return None;
        }
    }
    Some(target)
}

fn target_identity_from_der(certificate: &[u8]) -> RuntimeResult<TargetIdentity> {
    let (remaining, parsed) =
        X509Certificate::from_der(certificate).map_err(|_| RuntimeError::TargetIdentity)?;
    if !remaining.is_empty() {
        return Err(RuntimeError::TargetIdentity);
    }
    let san = parsed
        .subject_alternative_name()
        .map_err(|_| RuntimeError::TargetIdentity)?
        .ok_or(RuntimeError::TargetIdentity)?;
    let uris: Vec<_> = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        })
        .collect();
    let [uri_san] = uris.as_slice() else {
        return Err(RuntimeError::TargetIdentity);
    };
    let target_id = target_id_from_uri_san(uri_san).ok_or(RuntimeError::TargetIdentity)?;
    Ok(TargetIdentity {
        target_id: target_id.to_owned(),
        uri_san: (*uri_san).to_owned(),
        certificate_fingerprint: Digest::of(certificate),
        workload_epoch: 1,
    })
}

pub fn server_config(
    certificate_pem: &[u8],
    key_pem: &[u8],
    client_ca_pem: &[u8],
) -> RuntimeResult<Arc<ServerConfig>> {
    let certs = CertificateDer::pem_slice_iter(certificate_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RuntimeError::TargetIdentity)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| RuntimeError::TargetIdentity)?;
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(client_ca_pem) {
        roots
            .add(cert.map_err(|_| RuntimeError::TargetIdentity)?)
            .map_err(|_| RuntimeError::TargetIdentity)?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    .build()
    .map_err(|_| RuntimeError::TargetIdentity)?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| RuntimeError::TargetIdentity)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|_| RuntimeError::TargetIdentity)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}
pub(crate) fn incoming(
    listener: TcpListener,
    config: Arc<ServerConfig>,
) -> impl Stream<Item = Result<TlsStream<TcpStream>, std::io::Error>> {
    let acceptor = TlsAcceptor::from(config);
    futures::stream::unfold((listener, acceptor), |(listener, acceptor)| async move {
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => return Some((Err(e), (listener, acceptor))),
            };
            match timeout(Duration::from_secs(2), acceptor.accept(socket)).await {
                Ok(Ok(tls))
                    if tls.get_ref().1.protocol_version()
                        == Some(rustls::ProtocolVersion::TLSv1_3)
                        && tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) =>
                {
                    return Some((Ok(tls), (listener, acceptor)));
                }
                _ => continue,
            }
        }
    })
}
pub(crate) fn authenticated_target(
    extensions: &http::Extensions,
    fleet: &FleetController,
) -> Result<(TargetIdentity, u64), Status> {
    let info = extensions
        .get::<TlsConnectInfo<TcpConnectInfo>>()
        .ok_or_else(|| Status::unauthenticated("verified TLS peer required"))?;
    let certificates = info
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
    let certificate = certificates
        .first()
        .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
    let presented = target_identity_from_der(certificate.as_ref())
        .map_err(|_| Status::unauthenticated("invalid client identity"))?;
    let (_, parsed) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|_| Status::unauthenticated("invalid client certificate"))?;
    let certificate_until_ms = u64::try_from(parsed.validity().not_after.timestamp())
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .ok_or_else(|| Status::unauthenticated("invalid client certificate validity"))?;
    let targets = fleet
        .targets
        .lock()
        .map_err(|_| Status::unavailable("Fleet identity owner unavailable"))?;
    let mut matches = targets.values().filter(|t| {
        t.identity.certificate_fingerprint == presented.certificate_fingerprint
            && t.identity.uri_san == presented.uri_san
            && t.identity.target_id == presented.target_id
            && t.identity.workload_epoch > 0
    });
    let identity = matches
        .next()
        .ok_or_else(|| Status::permission_denied("unregistered target peer"))?
        .identity
        .clone();
    if matches.next().is_some() {
        return Err(Status::permission_denied("ambiguous target peer"));
    }
    Ok((identity, certificate_until_ms))
}
