//! Certificate metadata from the authenticated Envoy UDS connection. Envoy owns
//! chain verification and SANITIZE_SET; the local identity owner must additionally
//! require an exact current credential in the admitted identity snapshot.
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::collections::BTreeMap;
use x509_parser::{extensions::GeneralName, prelude::*};

#[derive(Clone, Debug)]
pub struct WorkloadPeer {
    participant_id: String,
    workload_id: String,
    uri_san: String,
    certificate_fingerprint: Digest,
    public_key_digest: Digest,
    not_before_ms: u64,
    not_after_ms: u64,
}
impl WorkloadPeer {
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }
    pub fn uri_san(&self) -> &str {
        &self.uri_san
    }
    pub fn certificate_fingerprint(&self) -> &Digest {
        &self.certificate_fingerprint
    }
    pub fn public_key_digest(&self) -> &Digest {
        &self.public_key_digest
    }
    pub fn not_before_ms(&self) -> u64 {
        self.not_before_ms
    }
    pub fn not_after_ms(&self) -> u64 {
        self.not_after_ms
    }

    /// A recovery binding to the exact authenticated original credential, not
    /// an actor grant. Only the verified private Envoy path creates this peer.
    pub(crate) fn submission_binding_digest(&self) -> RuntimeResult<Digest> {
        pc_runtime_types::canonical_bytes(&(
            "openpc:submission-workload-peer:v1",
            &self.participant_id,
            &self.workload_id,
            &self.uri_san,
            &self.certificate_fingerprint,
            &self.public_key_digest,
        ))
        .map(Digest::of)
    }

    pub(crate) fn from_envoy_headers(
        headers: &[(String, Vec<u8>)],
        now_ms: u64,
    ) -> RuntimeResult<Self> {
        let mut matching = headers
            .iter()
            .filter(|(name, _)| name == "x-forwarded-client-cert");
        let value = matching.next().ok_or(RuntimeError::TargetIdentity)?;
        if matching.next().is_some() {
            return Err(RuntimeError::TargetIdentity);
        }
        let value = std::str::from_utf8(&value.1).map_err(|_| RuntimeError::TargetIdentity)?;
        let fields = fields(value)?;
        let encoded = fields.get("Cert").ok_or(RuntimeError::TargetIdentity)?;
        let pem_bytes = percent_decode(encoded)?;
        let (remaining, pem) =
            parse_x509_pem(&pem_bytes).map_err(|_| RuntimeError::TargetIdentity)?;
        if !remaining.iter().all(u8::is_ascii_whitespace) || pem.label != "CERTIFICATE" {
            return Err(RuntimeError::TargetIdentity);
        }
        let (remaining, certificate) =
            X509Certificate::from_der(&pem.contents).map_err(|_| RuntimeError::TargetIdentity)?;
        if !remaining.is_empty() {
            return Err(RuntimeError::TargetIdentity);
        }
        let fingerprint = Digest::of(&pem.contents);
        let hash = fields.get("Hash").ok_or(RuntimeError::TargetIdentity)?;
        if *hash != fingerprint.as_str() {
            return Err(RuntimeError::TargetIdentity);
        }
        let san = certificate
            .subject_alternative_name()
            .map_err(|_| RuntimeError::TargetIdentity)?
            .ok_or(RuntimeError::TargetIdentity)?;
        let uris: Vec<_> = san
            .value
            .general_names
            .iter()
            .filter_map(|name| {
                if let GeneralName::URI(uri) = name {
                    Some(*uri)
                } else {
                    None
                }
            })
            .collect();
        if uris.len() != 1 || fields.get("URI").copied() != Some(uris[0]) {
            return Err(RuntimeError::TargetIdentity);
        }
        let parts: Vec<_> = uris[0].split(':').collect();
        if parts.len() != 6
            || parts[..3] != ["urn", "openpc", "participant"]
            || parts[4] != "workload"
            || !uuid_v7(parts[3])
            || !uuid_v7(parts[5])
        {
            return Err(RuntimeError::TargetIdentity);
        }
        let milliseconds = |seconds: i64| {
            u64::try_from(seconds)
                .ok()
                .and_then(|v| v.checked_mul(1000))
                .ok_or(RuntimeError::TargetIdentity)
        };
        let not_before_ms = milliseconds(certificate.validity().not_before.timestamp())?;
        let not_after_ms = milliseconds(certificate.validity().not_after.timestamp())?;
        if now_ms < not_before_ms || now_ms >= not_after_ms {
            return Err(RuntimeError::TargetIdentity);
        }
        Ok(Self {
            participant_id: parts[3].into(),
            workload_id: format!("urn:openpc:workload:{}", parts[5]),
            uri_san: uris[0].into(),
            certificate_fingerprint: fingerprint,
            public_key_digest: Digest::of(certificate.public_key().raw),
            not_before_ms,
            not_after_ms,
        })
    }
}
fn uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes[14] == b'7'
        && b"89ab".contains(&bytes[19])
        && bytes.iter().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(b)
            }
        })
}
fn fields(value: &str) -> RuntimeResult<BTreeMap<&str, &str>> {
    if value.is_empty() || value.len() > 32 * 1024 {
        return Err(RuntimeError::TargetIdentity);
    }
    let mut result = BTreeMap::new();
    // Envoy percent-encodes the certificate. URI values in this profile contain
    // no separators; multiple hops, escaped quotes and chains are rejected.
    for entry in value.split(';') {
        let (key, value) = entry.split_once('=').ok_or(RuntimeError::TargetIdentity)?;
        if !["By", "Hash", "Cert", "URI"].contains(&key) {
            return Err(RuntimeError::TargetIdentity);
        }
        let value = if let Some(value) = value.strip_prefix('"') {
            value
                .strip_suffix('"')
                .ok_or(RuntimeError::TargetIdentity)?
        } else {
            value
        };
        if value
            .bytes()
            .any(|b| b == b',' || b == b'"' || b == b'\\' || b.is_ascii_control())
            || result.insert(key, value).is_some()
        {
            return Err(RuntimeError::TargetIdentity);
        }
    }
    Ok(result)
}
fn percent_decode(value: &str) -> RuntimeResult<Vec<u8>> {
    let mut result = Vec::new();
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let digit = |b: u8| (b as char).to_digit(16).ok_or(RuntimeError::TargetIdentity);
            let high = digit(bytes.next().ok_or(RuntimeError::TargetIdentity)?)?;
            let low = digit(bytes.next().ok_or(RuntimeError::TargetIdentity)?)?;
            result.push((high * 16 + low) as u8);
        } else {
            result.push(byte);
        }
    }
    Ok(result)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{fs, os::unix::fs::DirBuilderExt, process::Command, sync::OnceLock};
    pub(crate) fn forwarded() -> String {
        static VALUE: OnceLock<String> = OnceLock::new();
        VALUE.get_or_init(|| {
            let root = std::env::temp_dir()
                .join(format!("wc-{:016x}", uuid::Uuid::now_v7().as_u128() as u64));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let uri = "urn:openpc:participant:019936ed-0000-7000-8000-000000000001:workload:019936ed-0000-7000-8000-000000000002";
            let output = Command::new("openssl").args(["req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=runtime-component", "-addext", &format!("subjectAltName=URI:{uri}"), "-keyout"]).arg(root.join("key.pem")).arg("-out").arg(root.join("cert.pem")).output().unwrap();
            assert!(output.status.success());
            let cert = fs::read(root.join("cert.pem")).unwrap();
            let (_, pem) = parse_x509_pem(&cert).unwrap();
            let hash = Digest::of(pem.contents);
            let encoded: String = cert.iter().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(b) {(*b as char).to_string()} else {format!("%{b:02X}")}).collect();
            fs::remove_dir_all(root).unwrap();
            format!("Hash={};Cert=\"{encoded}\";URI={uri}", hash.as_str())
        }).clone()
    }
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
    #[test]
    fn exact_certificate_hash_uri_and_time_bind_transport_identity() {
        let headers = vec![("x-forwarded-client-cert".into(), forwarded().into_bytes())];
        let peer = WorkloadPeer::from_envoy_headers(&headers, now()).unwrap();
        assert_eq!(
            peer.participant_id(),
            "019936ed-0000-7000-8000-000000000001"
        );
        assert_eq!(
            peer.workload_id(),
            "urn:openpc:workload:019936ed-0000-7000-8000-000000000002"
        );
        assert!(WorkloadPeer::from_envoy_headers(&headers, peer.not_after_ms()).is_err());
        assert!(WorkloadPeer::from_envoy_headers(&headers, peer.not_before_ms() - 1).is_err());
        for bad in [
            format!("{},{}", forwarded(), forwarded()),
            forwarded().replace("Hash=", "Hash=f"),
            forwarded().replace(";URI=urn:", ";URI=bad:"),
            format!("{};URI=duplicate", forwarded()),
            forwarded().replace("%20", "%GG"),
        ] {
            assert!(
                WorkloadPeer::from_envoy_headers(
                    &[("x-forwarded-client-cert".into(), bad.into_bytes())],
                    now()
                )
                .is_err()
            );
        }
        assert!(
            WorkloadPeer::from_envoy_headers(&[headers[0].clone(), headers[0].clone()], now())
                .is_err()
        );
        assert!(WorkloadPeer::from_envoy_headers(&[], now()).is_err());
    }
}
