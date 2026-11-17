//! Primary 1010 source-content binding. Its signature establishes custody, not
//! policy authority: the owning schema must also admit the referenced source.
use crate::{
    ArtifactComponent, RuntimeCapsule, RuntimeWireSigner, RuntimeWireVerifier,
    capsule::{digest, field, fields, map, number, read_digest, string, text, uint},
    cose::{self, Profile},
};
use pc_policy_core::pc_cbor_1;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityArtifact {
    pub artifact_id: String,
    pub artifact_version: u64,
    /// Exact primary wire class code. A consumer pins its allowed class through
    /// its release definition; this codec assigns no invented class aliases.
    pub artifact_class: u64,
    pub source_media_type: String,
    pub source_content_sha256: Digest,
    pub definition_digest: Digest,
    pub issued_at_ns: u64,
    pub signer_id: String,
}
impl AuthorityArtifact {
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        if self.artifact_version == 0 || !(1..=5).contains(&self.artifact_class) {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(pc_cbor_1(&map(vec![
            (0, text(&self.artifact_id, 160)?),
            (1, uint(self.artifact_version)),
            (2, uint(self.artifact_class)),
            (3, text(&self.source_media_type, 128)?),
            (4, digest(&self.source_content_sha256)?),
            (5, digest(&self.definition_digest)?),
            (6, uint(self.issued_at_ns)),
            (7, text(&self.signer_id, 160)?),
        ])))
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let value = cose::decode(bytes, 262_144)?;
        let f = fields(&value, &[0, 1, 2, 3, 4, 5, 6, 7])?;
        let result = Self {
            artifact_id: string(field(&f, 0)?)?,
            artifact_version: number(field(&f, 1)?)?,
            artifact_class: number(field(&f, 2)?)?,
            source_media_type: string(field(&f, 3)?)?,
            source_content_sha256: read_digest(field(&f, 4)?)?,
            definition_digest: read_digest(field(&f, 5)?)?,
            issued_at_ns: number(field(&f, 6)?)?,
            signer_id: string(field(&f, 7)?)?,
        };
        if result.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(result)
    }
    pub fn semantic_digest(&self) -> RuntimeResult<Digest> {
        cose::semantic_digest(Profile::AuthorityArtifact, &self.encode()?)
    }
}
impl RuntimeWireSigner {
    pub fn sign_authority_artifact(&self, artifact: &AuthorityArtifact) -> RuntimeResult<Vec<u8>> {
        self.sign(Profile::AuthorityArtifact, &artifact.encode()?)
    }
}
impl RuntimeWireVerifier {
    pub fn verify_authority_artifact(&self, signed: &[u8]) -> RuntimeResult<AuthorityArtifact> {
        AuthorityArtifact::decode(&self.verify(Profile::AuthorityArtifact, signed, 262_144)?)
    }
}

/// Immutable binding installed by the source's release-profile owner. These
/// values are not inferred from the received header or an RPC argument.
pub struct AuthoritySourceBinding {
    pub artifact_id: String,
    pub artifact_class: u64,
    pub source_media_type: String,
    pub definition_digest: Digest,
    pub signer_id: String,
    pub maximum_source_bytes: usize,
}
impl AuthoritySourceBinding {
    pub fn in_capsule<'a>(
        &self,
        verifier: &RuntimeWireVerifier,
        capsule: &'a RuntimeCapsule,
        artifacts: &'a BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<(&'a ArtifactComponent, AuthorityArtifact, &'a [u8])> {
        // Component IDs and authority artifact IDs refer to the same installed
        // source binding. No media/class/schema is selected from request input.
        let mut matches = capsule
            .artifact_components
            .iter()
            .filter(|c| c.component_id == self.artifact_id);
        let component = matches.next().ok_or(RuntimeError::InvalidInput)?;
        if matches.next().is_some()
            || component.schema_id != 1010
            || component.schema_version != 1
            || !component.required
        {
            return Err(RuntimeError::InvalidInput);
        }
        let signed = artifacts
            .get(&component.content_digest)
            .ok_or(RuntimeError::InvalidInput)?;
        if Digest::of(signed) != component.content_digest
            || signed.len() as u64 != component.size_bytes
        {
            return Err(RuntimeError::InvalidDigest);
        }
        let header = verifier.verify_authority_artifact(signed)?;
        let source = artifacts
            .get(&header.source_content_sha256)
            .ok_or(RuntimeError::InvalidInput)?;
        let header = self.verify(
            verifier,
            signed,
            source,
            &component.semantic_digest,
            capsule.issued_at_ns,
        )?;
        Ok((component, header, source))
    }
    pub fn verify(
        &self,
        verifier: &RuntimeWireVerifier,
        signed: &[u8],
        source: &[u8],
        expected_semantic_digest: &Digest,
        admitted_at_ns: u64,
    ) -> RuntimeResult<AuthorityArtifact> {
        if self.maximum_source_bytes == 0
            || source.is_empty()
            || source.len() > self.maximum_source_bytes
        {
            return Err(RuntimeError::BudgetExhausted);
        }
        let artifact = verifier.verify_authority_artifact(signed)?;
        if artifact.artifact_id != self.artifact_id
            || artifact.artifact_class != self.artifact_class
            || artifact.source_media_type != self.source_media_type
            || artifact.definition_digest != self.definition_digest
            || artifact.signer_id != self.signer_id
            || artifact.issued_at_ns > admitted_at_ns
        {
            eprintln!(
                "runtime_authority_binding component={} stage=header_constraints id={} class={} media={} definition={} signer={} time={}",
                self.artifact_id,
                artifact.artifact_id == self.artifact_id,
                artifact.artifact_class == self.artifact_class,
                artifact.source_media_type == self.source_media_type,
                artifact.definition_digest == self.definition_digest,
                artifact.signer_id == self.signer_id,
                artifact.issued_at_ns <= admitted_at_ns,
            );
            return Err(RuntimeError::InvalidAuthorization);
        }
        if artifact.semantic_digest()? != *expected_semantic_digest
            || Digest::of(source) != artifact.source_content_sha256
        {
            return Err(RuntimeError::InvalidDigest);
        }
        Ok(artifact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_source_is_bound_to_owner_definition_class_bytes_and_time() {
        let signer = RuntimeWireSigner::from_secret_bytes([34; 32]).unwrap();
        let source = b"source bytes requiring their own schema admission";
        let artifact = AuthorityArtifact {
            artifact_id: "test-source".into(),
            artifact_version: 1,
            artifact_class: 1,
            source_media_type: "application/octet-stream".into(),
            source_content_sha256: Digest::of(source),
            definition_digest: Digest::of(b"test-only source definition"),
            issued_at_ns: 10,
            signer_id: "test-source-owner".into(),
        };
        let binding = AuthoritySourceBinding {
            artifact_id: artifact.artifact_id.clone(),
            artifact_class: 1,
            source_media_type: artifact.source_media_type.clone(),
            definition_digest: artifact.definition_digest.clone(),
            signer_id: artifact.signer_id.clone(),
            maximum_source_bytes: 1024,
        };
        let signed = signer.sign_authority_artifact(&artifact).unwrap();
        let digest = artifact.semantic_digest().unwrap();
        assert_eq!(
            binding
                .verify(&signer.verifier(), &signed, source, &digest, 10)
                .unwrap(),
            artifact
        );
        assert!(signer.verifier().verify_capsule(&signed).is_err());
        assert!(
            binding
                .verify(&signer.verifier(), &signed, source, &digest, 9)
                .is_err()
        );
        assert!(
            binding
                .verify(&signer.verifier(), &signed, b"substitute", &digest, 10)
                .is_err()
        );
        assert!(
            binding
                .verify(
                    &signer.verifier(),
                    &signed,
                    source,
                    &Digest::of(b"wrong"),
                    10
                )
                .is_err()
        );
        assert!(
            binding
                .verify(
                    &RuntimeWireSigner::from_secret_bytes([35; 32])
                        .unwrap()
                        .verifier(),
                    &signed,
                    source,
                    &digest,
                    10
                )
                .is_err()
        );
        for change in 0..4 {
            let mut altered = artifact.clone();
            match change {
                0 => altered.artifact_id = "another".into(),
                1 => altered.artifact_class = 2,
                2 => altered.source_media_type = "application/cbor".into(),
                _ => altered.definition_digest = Digest::of(b"another definition"),
            }
            assert!(
                binding
                    .verify(
                        &signer.verifier(),
                        &signer.sign_authority_artifact(&altered).unwrap(),
                        source,
                        &altered.semantic_digest().unwrap(),
                        10
                    )
                    .is_err()
            );
        }
    }
}
