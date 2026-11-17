//! Current credential bindings authenticated by the signed actor content. A
//! CA-valid certificate alone cannot replace the Identity credential owner.
use crate::{WorkloadPeer, identity_source as source};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde_json::Value;
use std::collections::BTreeSet;

struct CredentialBinding {
    fingerprint: Digest,
    public_key: Digest,
    subject: String,
    active: bool,
    start: u64,
    end: u64,
}
pub(super) struct WorkloadCredentials(Vec<CredentialBinding>);
impl WorkloadCredentials {
    pub fn parse(raw: Option<&Value>, principal: &str, workload: &str) -> RuntimeResult<Self> {
        // Earlier immutable actor projections can still be used by the separate
        // assertion-verifying invocation owner. They grant no source dispatch.
        let Some(raw) = raw else {
            return Ok(Self(vec![]));
        };
        let rows = raw
            .as_array()
            .filter(|rows| rows.len() <= 4096)
            .ok_or(RuntimeError::InvalidInput)?;
        let mut ids = BTreeSet::new();
        let mut bindings = Vec::new();
        for row in rows {
            let row = source::object(row)?;
            source::keys(
                row,
                &[
                    "credential_id",
                    "principal_id",
                    "issuer",
                    "subject",
                    "audience",
                    "state",
                    "epoch",
                    "public_key_digest",
                    "fingerprint",
                    "valid_from",
                    "valid_until",
                    "valid_from_ns",
                    "valid_until_ns",
                    "valid_now",
                ],
            )?;
            if source::string(row, "principal_id")? != principal
                || source::string(row, "audience")? != workload
                || !ids.insert(source::string(row, "credential_id")?.to_owned())
                || source::unsigned(row, "epoch")? == 0
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            source::string(row, "issuer")?;
            let start = source::unsigned(row, "valid_from_ns")?;
            let end = source::unsigned(row, "valid_until_ns")?;
            if start >= end {
                return Err(RuntimeError::InvalidInput);
            }
            bindings.push(CredentialBinding {
                fingerprint: Digest::parse(source::string(row, "fingerprint")?)?,
                public_key: Digest::parse(source::string(row, "public_key_digest")?)?,
                subject: source::string(row, "subject")?.to_owned(),
                active: source::string(row, "state")? == "ACTIVE"
                    && source::boolean(row, "valid_now")?,
                start,
                end,
            });
        }
        Ok(Self(bindings))
    }
    pub fn require_peer(&self, peer: &WorkloadPeer, now: u64) -> RuntimeResult<u64> {
        self.current_until(
            peer.uri_san(),
            peer.certificate_fingerprint(),
            peer.public_key_digest(),
            now,
        )
    }
    fn current_until(
        &self,
        subject: &str,
        certificate: &Digest,
        key: &Digest,
        now: u64,
    ) -> RuntimeResult<u64> {
        self.0
            .iter()
            .filter(|binding| {
                binding.active
                    && binding.start <= now
                    && now < binding.end
                    && binding.subject == subject
                    && &binding.fingerprint == certificate
                    && &binding.public_key == key
            })
            .map(|binding| binding.end)
            .max()
            .ok_or(RuntimeError::Denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn source_requires_the_exact_current_certificate_key_and_subject() {
        let cert = Digest::of(b"current certificate");
        let key = Digest::of(b"current public key");
        let row = json!({"credential_id":"credential", "principal_id":"principal", "issuer":"trusted-ca",
            "subject":"spiffe://workload", "audience":"workload", "state":"ACTIVE", "epoch":"2",
            "public_key_digest":key.as_str(), "fingerprint":cert.as_str(), "valid_from":"time", "valid_until":"time",
            "valid_from_ns":"100", "valid_until_ns":"200", "valid_now":true});
        let raw = json!([row]);
        let bindings = WorkloadCredentials::parse(Some(&raw), "principal", "workload").unwrap();
        assert_eq!(
            bindings
                .current_until("spiffe://workload", &cert, &key, 150)
                .unwrap(),
            200
        );
        for (subject, cert, key, now) in [
            ("spiffe://other", cert.clone(), key.clone(), 150),
            (
                "spiffe://workload",
                Digest::of(b"old certificate"),
                key.clone(),
                150,
            ),
            (
                "spiffe://workload",
                cert.clone(),
                Digest::of(b"other key"),
                150,
            ),
            ("spiffe://workload", cert.clone(), key.clone(), 99),
            ("spiffe://workload", cert.clone(), key.clone(), 200),
        ] {
            assert!(bindings.current_until(subject, &cert, &key, now).is_err());
        }
        let mut revoked = raw.clone();
        revoked[0]["state"] = json!("REVOKED");
        assert!(
            WorkloadCredentials::parse(Some(&revoked), "principal", "workload")
                .unwrap()
                .current_until("spiffe://workload", &cert, &key, 150)
                .is_err()
        );
        assert!(
            WorkloadCredentials::parse(None, "principal", "workload")
                .unwrap()
                .current_until("spiffe://workload", &cert, &key, 150)
                .is_err()
        );
        assert!(WorkloadCredentials::parse(Some(&raw), "other principal", "workload").is_err());
        assert!(WorkloadCredentials::parse(Some(&raw), "principal", "other workload").is_err());
    }
}
