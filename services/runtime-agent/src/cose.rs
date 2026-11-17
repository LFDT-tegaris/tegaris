//! Runtime Agent compatibility surface over the shared primary wire owner.
pub(crate) use pc_policy_core::runtime_wire::{Profile, decode, semantic_digest};
use pc_policy_core::{
    decision_input::DecisionInputVector, decision_material::EffectivePolicyDecisionMaterial,
    runtime_wire,
};
use pc_runtime_types::{Digest, RuntimeResult};

#[derive(Clone)]
pub struct RuntimeWireSigner(runtime_wire::Signer);
impl RuntimeWireSigner {
    pub fn from_secret_bytes(bytes: [u8; 32]) -> RuntimeResult<Self> {
        Ok(Self(runtime_wire::Signer::from_secret_bytes(bytes)?))
    }
    pub fn verifier(&self) -> RuntimeWireVerifier {
        RuntimeWireVerifier(self.0.verifier())
    }
    pub(crate) fn sign(&self, profile: Profile, payload: &[u8]) -> RuntimeResult<Vec<u8>> {
        self.0.sign(profile, payload)
    }
    pub fn sign_capsule(&self, capsule: &crate::RuntimeCapsule) -> RuntimeResult<Vec<u8>> {
        self.sign(Profile::Capsule, &capsule.encode()?)
    }
    pub fn sign_decision_input(&self, vector: &DecisionInputVector) -> RuntimeResult<Vec<u8>> {
        self.0.sign_decision_input(vector)
    }
    pub fn sign_decision_material(
        &self,
        material: &EffectivePolicyDecisionMaterial,
    ) -> RuntimeResult<Vec<u8>> {
        self.0.sign_decision_material(material)
    }
}
#[derive(Clone)]
pub struct RuntimeWireVerifier(runtime_wire::Verifier);
impl RuntimeWireVerifier {
    pub fn from_public_key_bytes(bytes: &[u8]) -> RuntimeResult<Self> {
        Ok(Self(runtime_wire::Verifier::from_public_key_bytes(bytes)?))
    }
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0.public_key_bytes()
    }
    pub(crate) fn verify(
        &self,
        profile: Profile,
        signed: &[u8],
        maximum: usize,
    ) -> RuntimeResult<Vec<u8>> {
        self.0.verify(profile, signed, maximum)
    }
    pub fn verify_capsule(&self, signed: &[u8]) -> RuntimeResult<crate::RuntimeCapsule> {
        crate::RuntimeCapsule::decode(&self.verify(Profile::Capsule, signed, 1_048_576)?)
    }
    pub fn verify_decision_input(&self, signed: &[u8]) -> RuntimeResult<DecisionInputVector> {
        self.0.verify_decision_input(signed)
    }
    pub fn verify_decision_material(
        &self,
        signed: &[u8],
    ) -> RuntimeResult<EffectivePolicyDecisionMaterial> {
        self.0.verify_decision_material(signed)
    }
    pub fn verify_bound_decision_material(
        &self,
        signed_input: &[u8],
        signed_material: &[u8],
        active_capsule: &Digest,
        request_semantic: &Digest,
    ) -> RuntimeResult<(DecisionInputVector, EffectivePolicyDecisionMaterial)> {
        self.0.verify_bound_decision_material(
            signed_input,
            signed_material,
            active_capsule,
            request_semantic,
        )
    }
}
