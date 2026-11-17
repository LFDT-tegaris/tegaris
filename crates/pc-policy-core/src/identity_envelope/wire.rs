use super::{generated, scalar::*};
use crate::{
    pc_cbor_1,
    runtime_wire::{
        self,
        fields::{field, fields, map, uint},
    },
};
use ciborium::value::Value;
use pc_runtime_types::{RuntimeError, RuntimeResult};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub trait Wire: Sized {
    fn encode_value(&self) -> RuntimeResult<Value>;
    fn decode_value(value: &Value) -> RuntimeResult<Self>;
}
macro_rules! record {
    ($name:ident, $root:expr, $($field:ident : $ty:ty => $key:literal),+ $(,)?) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(rename_all="camelCase", deny_unknown_fields)]
        pub struct $name {$(pub $field: $ty),+}
        impl Wire for $name {
            fn encode_value(&self)->RuntimeResult<Value> {
                self.validate()?;
                let mut values=Vec::new();
                if $root {values.push((0,Hash32(generated::DEFINITION_DIGEST.to_owned()).encode_value()?));}
                $(values.push(($key,self.$field.encode_value()?));)+
                Ok(map(values))
            }
            fn decode_value(value:&Value)->RuntimeResult<Self> {
                let mut allowed=vec![$($key),+]; if $root {allowed.insert(0,0);}
                let f=fields(value,&allowed)?;
                if f.len()!=allowed.len() {return invalid();}
                if $root && Hash32::decode_value(field(&f,0)?)?.0!=generated::DEFINITION_DIGEST {return invalid();}
                let out=Self {$($field: <$ty>::decode_value(field(&f,$key)?)?),+};
                out.validate()?; Ok(out)
            }
        }
    };
}
record!(Administration,false,
    participant_ids:FiniteSet<DomainUuid> =>1, privacy_domain_ids:FiniteSet<DomainUuid> =>2,
    resource_ids:FiniteSet<Identifier> =>3,data_classes:FiniteSet<Identifier> =>4,
    target_profile_ids:FiniteSet<Identifier> =>5,risk_classes:FiniteSet<Risk> =>6,
    action_intent_ids:FiniteSet<ActionIntent> =>7);
record!(Runtime,false,
    participant_ids:FiniteSet<DomainUuid> =>1,privacy_domain_ids:FiniteSet<DomainUuid> =>2,
    resource_ids:FiniteSet<Identifier> =>3,data_classes:FiniteSet<Identifier> =>4,
    target_profile_ids:FiniteSet<Identifier> =>5,risk_classes:FiniteSet<Risk> =>6,
    capability_ids:FiniteSet<RuntimeCapability> =>7);
record!(Scope,false,administration:Administration=>1,runtime:Runtime=>2,valid_from_ns:Nanos=>3,
    valid_until_ns:Nanos=>4,maker_checker_required:Flag=>5,step_up_required:Flag=>6,onward_delegation_depth:Depth=>7);
record!(Parent,false,envelope_id:DomainUuid=>1,active_version:Positive=>2,semantic_revision:Positive=>3,
    artifact_digest:Hash32=>4,authority_epoch:Unsigned=>5,delegation_epoch:Unsigned=>6);
record!(Authority,false,participant_id:DomainUuid=>1,participant_epoch:Unsigned=>2,principal_id:DomainUuid=>3,
    principal_epoch:Unsigned=>4,session_id:DomainUuid=>5,session_epoch:Unsigned=>6,assignment_id:DomainUuid=>7,
    assignment_version:Positive=>8,authority_envelope_id:DomainUuid=>9,authority_epoch:Unsigned=>10,
    delegation_epoch:Unsigned=>11,role_id:Identifier=>12,role_version:Positive=>13,role_digest:Hash32=>14,authority_digest:Hash32=>15);
record!(Actor,false,authority:Authority=>1,step_up_challenge_id:DomainUuid=>2,step_up_evidence_digest:Hash32=>3,
    signer_credential_id:DomainUuid=>4,signer_credential_epoch:Unsigned=>5);
record!(Issuer,false,kind:IssuerKind=>1,authority:Authority=>2,platform_context_id:DomainUuid=>3,
    platform_authority_epoch:Unsigned=>4,platform_authority_digest:Hash32=>5,parent:OptionalParent=>6);
record!(Proposal,true,envelope_id:DomainUuid=>1,semantic_revision:Positive=>2,participant_id:DomainUuid=>3,
    participant_epoch:Unsigned=>4,authority_epoch:Unsigned=>5,delegation_epoch:Unsigned=>6,issuance:Issuance=>7,
    usable:Scope=>8,grantable:Scope=>9,issuer:Issuer=>10);
record!(Submission,false,operation_id:DomainUuid=>1,candidate_id:DomainUuid=>2,candidate_digest:Hash32=>3,
    approval_request_id:DomainUuid=>4,approval_digest:Hash32=>5,submitted_version:Positive=>6,
    approved_version:Positive=>7,maker:Actor=>8,checker:Actor=>9);
record!(Activation,false,operation_id:DomainUuid=>1,candidate_id:DomainUuid=>2,candidate_digest:Hash32=>3,
    approval_request_id:DomainUuid=>4,approval_digest:Hash32=>5,expected_approved_version:Positive=>6,
    active_version:Positive=>7,idempotency_binding_digest:Hash32=>8,action_intent_id:ActivateAction=>9,
    catalog_operation_id:ActivateOperation=>10,maker:Actor=>11,checker:Actor=>12);
record!(Signer,false,environment_id:Identifier=>1,participant_id:DomainUuid=>2,privacy_domain_id:DomainUuid=>3,
    profile_id:Identifier=>4,profile_version:Positive=>5,profile_digest:Hash32=>6,key_id:Hash32=>7,
    key_version:Identifier=>8,workload_credential_id:DomainUuid=>9,workload_credential_epoch:Unsigned=>10,trust_context_digest:Hash32=>11);
record!(Envelope,true,proposal_bytes:ProposalBytes=>1,proposal_digest:Hash32=>2,submission:Submission=>3,
    activation:Activation=>4,signer:Signer=>5,issued_at_ns:Nanos=>6);

macro_rules! no_relations {($($name:ident),+)=>{$(impl $name {fn validate(&self)->RuntimeResult<()>{Ok(())}})+};}
no_relations!(
    Administration,
    Runtime,
    Parent,
    Authority,
    Actor,
    Issuer,
    Submission,
    Activation,
    Signer
);
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OptionalParent(pub Option<Parent>);
impl Wire for OptionalParent {
    fn encode_value(&self) -> RuntimeResult<Value> {
        self.0
            .as_ref()
            .map_or_else(|| Ok(map(vec![])), Wire::encode_value)
    }
    fn decode_value(v: &Value) -> RuntimeResult<Self> {
        if v.as_map().is_some_and(Vec::is_empty) {
            Ok(Self(None))
        } else {
            Ok(Self(Some(Parent::decode_value(v)?)))
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProposalBytes(pub Vec<u8>);
impl Wire for ProposalBytes {
    fn encode_value(&self) -> RuntimeResult<Value> {
        Proposal::decode(&self.0)?;
        Ok(Value::Bytes(self.0.clone()))
    }
    fn decode_value(v: &Value) -> RuntimeResult<Self> {
        let out = Self(v.as_bytes().ok_or(RuntimeError::InvalidInput)?.clone());
        out.encode_value()?;
        Ok(out)
    }
}
fn successor(previous: &Positive, next: &Positive) -> RuntimeResult<()> {
    if previous.value()?.checked_add(1) != Some(next.value()?) {
        return invalid();
    }
    Ok(())
}
impl Scope {
    fn validate(&self) -> RuntimeResult<()> {
        if self.valid_until_ns.value()? <= self.valid_from_ns.value()? {
            return invalid();
        }
        Ok(())
    }
    /// Structural subset only, never current authorization.
    pub fn assert_narrower(&self, child: &Self) -> RuntimeResult<bool> {
        self.encode_value()?;
        child.encode_value()?;
        fn subset<T: Ord>(a: &FiniteSet<T>, b: &FiniteSet<T>) -> RuntimeResult<()> {
            if b.0.iter().any(|v| a.0.binary_search(v).is_err()) {
                return invalid();
            }
            Ok(())
        }
        macro_rules! dimension {($kind:ident,$($field:ident),+)=>{$(subset(&self.$kind.$field,&child.$kind.$field)?;)+};}
        dimension!(
            administration,
            participant_ids,
            privacy_domain_ids,
            resource_ids,
            data_classes,
            target_profile_ids,
            risk_classes,
            action_intent_ids
        );
        dimension!(
            runtime,
            participant_ids,
            privacy_domain_ids,
            resource_ids,
            data_classes,
            target_profile_ids,
            risk_classes,
            capability_ids
        );
        if child.valid_from_ns.value()? < self.valid_from_ns.value()?
            || child.valid_until_ns.value()? > self.valid_until_ns.value()?
            || (self.maker_checker_required.0 && !child.maker_checker_required.0)
            || (self.step_up_required.0 && !child.step_up_required.0)
            || child.onward_delegation_depth.0 > self.onward_delegation_depth.0
        {
            return invalid();
        }
        Ok(self != child)
    }
}
impl Proposal {
    fn validate(&self) -> RuntimeResult<()> {
        self.usable.validate()?;
        self.grantable.validate()?;
        match (&self.issuance, &self.issuer.parent.0) {
            (Issuance::PlatformRoot, None)
                if self.issuer.kind == IssuerKind::Platform
                    && self.semantic_revision.value()? == 1 => {}
            (Issuance::Child | Issuance::Rotation, Some(parent)) => {
                if parent.envelope_id != self.issuer.authority.authority_envelope_id
                    || parent.authority_epoch != self.issuer.authority.authority_epoch
                    || parent.delegation_epoch != self.issuer.authority.delegation_epoch
                {
                    return invalid();
                }
                if self.issuance == Issuance::Child {
                    if parent.envelope_id == self.envelope_id
                        || self.semantic_revision.value()? != 1
                    {
                        return invalid();
                    }
                } else {
                    if parent.envelope_id != self.envelope_id {
                        return invalid();
                    }
                    successor(&parent.semantic_revision, &self.semantic_revision)?;
                }
            }
            _ => return invalid(),
        }
        Ok(())
    }
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        bounded_encode(self)
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        decode(bytes)
    }
}
impl Envelope {
    fn validate(&self) -> RuntimeResult<()> {
        let proposal = Proposal::decode(&self.proposal_bytes.0)?;
        let s = &self.submission;
        let a = &self.activation;
        if self.proposal_digest != digest(&self.proposal_bytes.0)
            || self.signer.participant_id != proposal.participant_id
            || s.candidate_id == a.candidate_id
            || s.operation_id == a.operation_id
            || s.approval_request_id == a.approval_request_id
            || a.expected_approved_version != s.approved_version
            || proposal.issuer.authority != s.maker.authority
        {
            return invalid();
        }
        successor(&s.submitted_version, &s.approved_version)?;
        successor(&a.expected_approved_version, &a.active_version)?;
        for (maker, checker) in [(&s.maker, &s.checker), (&a.maker, &a.checker)] {
            if maker.authority.principal_id == checker.authority.principal_id
                || maker.authority.participant_id != checker.authority.participant_id
                || maker.authority.participant_id != proposal.issuer.authority.participant_id
                || maker.step_up_challenge_id == checker.step_up_challenge_id
                || maker.signer_credential_id == checker.signer_credential_id
            {
                return invalid();
            }
        }
        let challenges = [
            &s.maker.step_up_challenge_id,
            &s.checker.step_up_challenge_id,
            &a.maker.step_up_challenge_id,
            &a.checker.step_up_challenge_id,
        ];
        if challenges
            .iter()
            .enumerate()
            .any(|(i, v)| challenges[..i].contains(v))
        {
            return invalid();
        }
        Ok(())
    }
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        bounded_encode(self)
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        decode(bytes)
    }
    /// Historical typed content plus cryptographic signature only.
    pub fn verify_cose(payload: &[u8], spki: &[u8], cose: &[u8]) -> RuntimeResult<Self> {
        let envelope = Self::decode(payload)?;
        const PREFIX: &[u8] = &[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        if spki.len() != 91
            || !spki.starts_with(PREFIX)
            || envelope.signer.key_id != digest(spki)
            || cose.first() != Some(&0xd2)
            || cose.len() > 66560
        {
            return invalid();
        }
        let value = runtime_wire::decode(&cose[1..], 66560)?;
        let parts = value
            .as_array()
            .filter(|v| v.len() == 4)
            .ok_or(RuntimeError::InvalidInput)?;
        let header = pc_cbor_1(&map(vec![
            (1, Value::Integer((-7).into())),
            (2, Value::Array([100, 101, 102, 103].map(uint).to_vec())),
            (3, Value::Text("application/pc+cbor".to_owned())),
            (4, Value::Bytes(digest(spki).0.into_bytes())),
            (100, uint(generated::SCHEMA_ID)),
            (101, uint(1)),
            (102, uint(generated::PURPOSE_CODE)),
            (103, uint(2)),
        ]));
        if parts[0].as_bytes() != Some(&header)
            || !parts[1].as_map().is_some_and(Vec::is_empty)
            || parts[2].as_bytes().map(Vec::as_slice) != Some(payload)
        {
            return invalid();
        }
        let signature = parts[3]
            .as_bytes()
            .filter(|s| s.len() == 64)
            .ok_or(RuntimeError::InvalidInput)?;
        let structure = pc_cbor_1(&Value::Array(vec![
            Value::Text("Signature1".to_owned()),
            Value::Bytes(header),
            Value::Bytes(b"pcplane:cose-sign1:v2\0".to_vec()),
            Value::Bytes(payload.to_vec()),
        ]));
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &spki[26..])
            .verify(&structure, signature)
            .map_err(|_| RuntimeError::InvalidInput)?;
        Ok(envelope)
    }
    pub fn assert_child(&self, child: &Proposal) -> RuntimeResult<()> {
        let original = Proposal::decode(&self.proposal_bytes.0)?;
        child.encode()?;
        let parent = child
            .issuer
            .parent
            .0
            .as_ref()
            .ok_or(RuntimeError::InvalidInput)?;
        if parent.envelope_id != original.envelope_id
            || parent.active_version != self.activation.active_version
            || parent.semantic_revision != original.semantic_revision
            || parent.artifact_digest != digest(&self.encode()?)
            || parent.authority_epoch != original.authority_epoch
            || parent.delegation_epoch != original.delegation_epoch
        {
            return invalid();
        }
        match child.issuance {
            Issuance::Rotation => {
                if child.participant_id != original.participant_id {
                    return invalid();
                }
                original.usable.assert_narrower(&child.usable)?;
                original.grantable.assert_narrower(&child.grantable)?;
            }
            Issuance::Child => {
                let u = original.grantable.assert_narrower(&child.usable)?;
                let g = original.grantable.assert_narrower(&child.grantable)?;
                if (!u && !g)
                    || child.usable.onward_delegation_depth.0
                        >= original.grantable.onward_delegation_depth.0
                    || child.grantable.onward_delegation_depth.0
                        >= original.grantable.onward_delegation_depth.0
                {
                    return invalid();
                }
            }
            _ => return invalid(),
        }
        Ok(())
    }
}
pub fn digest(bytes: &[u8]) -> Hash32 {
    Hash32(format!("sha256:{}", hex(&Sha256::digest(bytes))))
}
fn bounded_encode<T: Wire>(value: &T) -> RuntimeResult<Vec<u8>> {
    let bytes = pc_cbor_1(&value.encode_value()?);
    if bytes.len() > 65536 {
        return invalid();
    }
    Ok(bytes)
}
fn decode<T: Wire>(bytes: &[u8]) -> RuntimeResult<T> {
    let value = runtime_wire::decode(bytes, 65536)?;
    let out = T::decode_value(&value)?;
    if bounded_encode(&out)? != bytes {
        return invalid();
    }
    Ok(out)
}
