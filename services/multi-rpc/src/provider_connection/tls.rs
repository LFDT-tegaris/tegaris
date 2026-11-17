use super::ConnectionError;
use pc_runtime_types::Digest;
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use std::sync::Arc;

/// Material from local credential distribution. The key is never serialized or
/// printed. No remote secret fetch or trust-store discovery occurs at dispatch.
pub struct LocalTlsMaterial {
    pub roots: Vec<CertificateDer<'static>>,
    pub client_chain: Vec<CertificateDer<'static>>,
    pub client_key: PrivateKeyDer<'static>,
    pub expected_server_certificate: Digest,
}
/// Explicit server-authenticated HTTPS; no client identity is fabricated.
pub struct ServerTlsMaterial {
    pub roots: Vec<CertificateDer<'static>>,
    pub expected_server_certificate: Digest,
    /// One exact concurrently served leaf during a governed certificate rotation.
    pub server_certificate_overlap: Option<Digest>,
}

pub enum ProviderTlsMaterial {
    Mutual(LocalTlsMaterial),
    Server(ServerTlsMaterial),
}
impl From<LocalTlsMaterial> for ProviderTlsMaterial {
    fn from(value: LocalTlsMaterial) -> Self {
        Self::Mutual(value)
    }
}
impl From<ServerTlsMaterial> for ProviderTlsMaterial {
    fn from(value: ServerTlsMaterial) -> Self {
        Self::Server(value)
    }
}
impl ProviderTlsMaterial {
    fn roots(&self) -> &[CertificateDer<'static>] {
        match self {
            Self::Mutual(v) => &v.roots,
            Self::Server(v) => &v.roots,
        }
    }
    fn client_chain(&self) -> &[CertificateDer<'static>] {
        match self {
            Self::Mutual(v) => &v.client_chain,
            Self::Server(_) => &[],
        }
    }
    fn expected_server_certificate(&self) -> &Digest {
        match self {
            Self::Mutual(v) => &v.expected_server_certificate,
            Self::Server(v) => &v.expected_server_certificate,
        }
    }
    fn server_certificate_overlap(&self) -> Option<&Digest> {
        match self {
            Self::Mutual(_) => None,
            Self::Server(v) => v.server_certificate_overlap.as_ref(),
        }
    }
    pub(super) fn validate_size(&self) -> Result<(), ConnectionError> {
        if self.roots().is_empty()
            || self.roots().len() > 16
            || matches!(self, Self::Mutual(v) if v.client_chain.is_empty() || v.client_chain.len() > 8 || v.client_key.secret_der().len() > 16_384)
            || self
                .roots()
                .iter()
                .chain(self.client_chain())
                .any(|c| c.len() > 65_536)
            || self
                .server_certificate_overlap()
                .is_some_and(|alternate| alternate == self.expected_server_certificate())
        {
            return Err(ConnectionError::Tls);
        }
        Ok(())
    }
    pub(super) fn configuration_value(&self) -> ciborium::value::Value {
        use ciborium::value::Value;
        Value::Array(vec![
            Value::Text(
                match self {
                    Self::Mutual(_) => {
                        "TLS1.3;webpki-SAN;certificate-pin;mutual-auth;no-resumption;no-early-data"
                    }
                    Self::Server(_) => {
                        "TLS1.3;webpki-SAN;certificate-pin;server-auth;no-resumption;no-early-data"
                    }
                }
                .into(),
            ),
            Value::Array(
                self.roots()
                    .iter()
                    .map(|c| Value::Bytes(c.as_ref().to_vec()))
                    .collect(),
            ),
            Value::Array(
                self.client_chain()
                    .iter()
                    .map(|c| Value::Bytes(c.as_ref().to_vec()))
                    .collect(),
            ),
            match self.server_certificate_overlap() {
                None => Value::Text(self.expected_server_certificate().as_str().into()),
                Some(alternate) => Value::Array(vec![
                    Value::Text("openpc:provider-certificate-overlap:v1".into()),
                    Value::Text(self.expected_server_certificate().as_str().into()),
                    Value::Text(alternate.as_str().into()),
                ]),
            },
        ])
    }
    pub(super) fn into_config(self) -> Result<ClientConfig, ConnectionError> {
        self.validate_size()?;
        let mut roots = RootCertStore::empty();
        for root in self.roots() {
            roots.add(root.clone()).map_err(|_| ConnectionError::Tls)?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|_| ConnectionError::Tls)?;
        let verifier = Arc::new(PinnedCertificate {
            webpki,
            expected: self.expected_server_certificate().clone(),
            overlap: self.server_certificate_overlap().cloned(),
        });
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ConnectionError::Tls)?
            .dangerous()
            .with_custom_certificate_verifier(verifier);
        let mut config = match self {
            Self::Mutual(v) => builder
                .with_client_auth_cert(v.client_chain, v.client_key)
                .map_err(|_| ConnectionError::Tls)?,
            Self::Server(_) => builder.with_no_client_auth(),
        };
        // Every connection revalidates identity. A resumed session must not
        // bypass a changed certificate or a new dispatcher generation.
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        Ok(config)
    }
}

struct PinnedCertificate {
    webpki: Arc<WebPkiServerVerifier>,
    expected: Digest,
    overlap: Option<Digest>,
}
impl std::fmt::Debug for PinnedCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinnedCertificate")
    }
}
impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified = self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let observed = Digest::of(end_entity.as_ref());
        if observed != self.expected && self.overlap.as_ref() != Some(&observed) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}
