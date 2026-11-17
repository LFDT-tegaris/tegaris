//! Deployment identity under owner-resolved intent/profile data. Matching these
//! constraints is not approval, provider qualification or permission to send.
//! The deployment profile requires complete creation evidence as well as
//! this signed-byte binding; neither a selector nor an address formula is proof
//! that a factory actually performs the expected creation.
use crate::signed_transaction::{SignedTransaction, UnsignedTransaction, create2_address};
use pc_policy_core::deployment_policy::CREATE3_HELPER_INIT_CODE;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Keccak256};

const MAX_INIT_CODE_BYTES: usize = pc_policy_core::transaction_policy::MAX_CALLDATA_BYTES;

mod trace;
pub use trace::CreationInspection;
mod mined;
pub(crate) use mined::MinedCreationEvidence;
mod dispatch;
pub use dispatch::DeploymentDispatchBinding;
mod observer;
pub mod occurrence;
pub mod projection;
pub mod rejection;
pub use observer::{DeploymentPreflight, observe_preflight};
mod publication;
pub use publication::bind_publication;
pub mod custody;
pub mod intent;
pub mod simulation;

/// The approval owner binds the complete unsigned signing preimage, including
/// fee model, gas, value and access list. The recovered signer is checked
/// separately. This is internal owner data, not a public request/grant schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConstraints {
    pub chain_id: u64,
    pub sender: [u8; 20],
    pub signing_hash: [u8; 32],
    pub profile_digest: Digest,
    pub artifact: DeploymentArtifact,
    pub route: DeploymentRoute,
}

/// Exact raw EVM bytes are identified with Keccak-256. Normalized compiler
/// metadata cannot substitute for either init-code or mined runtime identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentArtifact {
    pub init_code_hash: [u8; 32],
    pub runtime_code_hash: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DeploymentRoute {
    DirectCreate { expected_address: [u8; 20] },
    Factory(Box<FactoryDeployment>),
}

/// Closed adapter data supplied by the admitted, certified factory profile.
/// The runtime never loads arbitrary adapter code or caller-supplied scripts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryDeployment {
    pub address: [u8; 20],
    pub code_hash: [u8; 32],
    pub code_digest: Digest,
    pub abi_digest: Digest,
    pub adapter_digest: Digest,
    pub selector: [u8; 4],
    pub mechanism: FactoryMechanism,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum FactoryMechanism {
    /// The mined occurrence supplies the actual factory nonce by default.
    /// No exact pre-mine CREATE address or serialization claim is inferred.
    Create,
    Create2 {
        arguments: Create2Arguments,
        salt: [u8; 32],
        salt_namespace_digest: Digest,
        salt_transform: SaltTransform,
        expected_address: [u8; 20],
    },
    /// Only the named Solady v0.1.26 helper protocol, never generic CREATE3.
    Create3 {
        arguments: Create2Arguments,
        salt: [u8; 32],
        salt_namespace_digest: Digest,
        salt_transform: SaltTransform,
        expected_helper_address: [u8; 20],
        expected_address: [u8; 20],
    },
}

/// Supported canonical ABI shapes, not a general argument extraction language.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Create2Arguments {
    InitCodeSalt,
    SaltInitCode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SaltTransform {
    Identity,
    KeccakSenderSalt,
}
impl SaltTransform {
    fn apply(self, sender: &[u8; 20], salt: &[u8; 32]) -> [u8; 32] {
        match self {
            Self::Identity => *salt,
            Self::KeccakSenderSalt => {
                let mut bytes = [0; 52];
                bytes[..20].copy_from_slice(sender);
                bytes[20..].copy_from_slice(salt);
                keccak(&bytes)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CreationMechanism {
    TransactionCreate,
    Create,
    Create2,
    Create3,
}

/// Predict the exact named helper/final pair. Address derivation neither proves
/// chain availability nor authorizes either creation.
pub fn solady_create3_addresses(
    factory: &[u8; 20],
    effective_salt: &[u8; 32],
) -> RuntimeResult<([u8; 20], [u8; 20])> {
    let helper = create2_address(factory, effective_salt, &CREATE3_HELPER_INIT_CODE)
        .map_err(|_| RuntimeError::InvalidInput)?;
    Ok((
        helper,
        crate::signed_transaction::create_address(&helper, 1),
    ))
}

/// A minimized identity derived from the actual signed transaction. Private
/// fields and no Deserialize prevent a request from asserting it was checked.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundDeployment {
    intent_digest: Digest,
    profile_digest: Digest,
    transaction_hash: [u8; 32],
    sender: [u8; 20],
    transaction_value: [u8; 32],
    calldata_hash: [u8; 32],
    gas_limit: u64,
    creator: [u8; 20],
    mechanism: CreationMechanism,
    predicted_address: Option<[u8; 20]>,
    init_code_hash: [u8; 32],
    runtime_code_hash: [u8; 32],
    factory_code_hash: Option<[u8; 32]>,
    salt: Option<[u8; 32]>,
}

impl DeploymentConstraints {
    pub fn bind(&self, transaction: &SignedTransaction) -> RuntimeResult<BoundDeployment> {
        let (creator, mechanism, predicted_address, factory_code_hash, salt) =
            self.bind_unsigned(transaction.unsigned(), transaction.signer())?;
        Ok(BoundDeployment {
            intent_digest: self.digest()?,
            profile_digest: self.profile_digest.clone(),
            transaction_hash: *transaction.hash(),
            sender: *transaction.signer(),
            transaction_value: *transaction.value(),
            calldata_hash: keccak(transaction.data()),
            gas_limit: transaction.gas_limit(),
            creator,
            mechanism,
            predicted_address,
            init_code_hash: self.artifact.init_code_hash,
            runtime_code_hash: self.artifact.runtime_code_hash,
            factory_code_hash,
            salt,
        })
    }

    pub(super) fn validate_unsigned(
        &self,
        transaction: &UnsignedTransaction,
        sender: &[u8; 20],
    ) -> RuntimeResult<()> {
        self.bind_unsigned(transaction, sender).map(|_| ())
    }

    #[allow(clippy::type_complexity)]
    fn bind_unsigned(
        &self,
        transaction: &UnsignedTransaction,
        sender: &[u8; 20],
    ) -> RuntimeResult<(
        [u8; 20],
        CreationMechanism,
        Option<[u8; 20]>,
        Option<[u8; 32]>,
        Option<[u8; 32]>,
    )> {
        valid_digest(&self.profile_digest)?;
        if self.chain_id == 0
            || self.chain_id != transaction.chain_id()
            || &self.sender != sender
            || &self.signing_hash != transaction.signing_hash()
            || self.artifact.init_code_hash == keccak(&[])
            || self.artifact.runtime_code_hash == keccak(&[])
        {
            return Err(RuntimeError::Denied);
        }
        let (creator, mechanism, predicted_address, init_code, factory_code_hash, salt) =
            match &self.route {
                DeploymentRoute::DirectCreate { expected_address } => {
                    let address = transaction
                        .creation_address(sender)
                        .map_err(|_| RuntimeError::Denied)?;
                    if &address != expected_address {
                        return Err(RuntimeError::Denied);
                    }
                    (
                        self.sender,
                        CreationMechanism::TransactionCreate,
                        Some(address),
                        transaction.data(),
                        None,
                        None,
                    )
                }
                DeploymentRoute::Factory(factory) => {
                    valid_digest(&factory.code_digest)?;
                    valid_digest(&factory.abi_digest)?;
                    valid_digest(&factory.adapter_digest)?;
                    if transaction.destination() != Some(&factory.address)
                        || factory.code_hash == keccak(&[])
                        || transaction.data().get(..4) != Some(factory.selector.as_slice())
                    {
                        return Err(RuntimeError::Denied);
                    }
                    let arguments = &transaction.data()[4..];
                    let (mechanism, address, init_code, salt) = match &factory.mechanism {
                        FactoryMechanism::Create => (
                            CreationMechanism::Create,
                            None,
                            exact_bytes_argument(arguments, 1, 0)?,
                            None,
                        ),
                        FactoryMechanism::Create2 {
                            arguments: layout,
                            salt,
                            salt_namespace_digest,
                            salt_transform,
                            expected_address,
                        }
                        | FactoryMechanism::Create3 {
                            arguments: layout,
                            salt,
                            salt_namespace_digest,
                            salt_transform,
                            expected_address,
                            ..
                        } => {
                            valid_digest(salt_namespace_digest)?;
                            let bytes_index =
                                usize::from(*layout == Create2Arguments::SaltInitCode);
                            let salt_index = 1 - bytes_index;
                            if arguments.get(salt_index * 32..(salt_index + 1) * 32)
                                != Some(salt.as_slice())
                            {
                                return Err(RuntimeError::Denied);
                            }
                            let init_code = exact_bytes_argument(arguments, 2, bytes_index)?;
                            let effective_salt = salt_transform.apply(sender, salt);
                            let (mechanism, address) = if let FactoryMechanism::Create3 {
                                expected_helper_address,
                                ..
                            } = &factory.mechanism
                            {
                                let (helper, address) =
                                    solady_create3_addresses(&factory.address, &effective_salt)?;
                                if &helper != expected_helper_address {
                                    return Err(RuntimeError::Denied);
                                }
                                (CreationMechanism::Create3, address)
                            } else {
                                (
                                    CreationMechanism::Create2,
                                    create2_address(&factory.address, &effective_salt, init_code)
                                        .map_err(|_| RuntimeError::Denied)?,
                                )
                            };
                            if &address != expected_address {
                                return Err(RuntimeError::Denied);
                            }
                            (mechanism, Some(address), init_code, Some(effective_salt))
                        }
                    };
                    (
                        factory.address,
                        mechanism,
                        address,
                        init_code,
                        Some(factory.code_hash),
                        salt,
                    )
                }
            };
        if init_code.is_empty()
            || init_code.len() > MAX_INIT_CODE_BYTES
            || keccak(init_code) != self.artifact.init_code_hash
        {
            return Err(RuntimeError::Denied);
        }
        Ok((
            creator,
            mechanism,
            predicted_address,
            factory_code_hash,
            salt,
        ))
    }

    pub fn digest(&self) -> RuntimeResult<Digest> {
        canonical_bytes(&("openpc:deployment-intent-binding:v1", self)).map(Digest::of)
    }
}

impl BoundDeployment {
    /// Restore only the minimized observation identity retained by the real
    /// signed admission owner. This cannot prepare or authorize a submission.
    pub(crate) fn for_observation(
        constraints: &DeploymentConstraints,
        transaction_hash: [u8; 32],
        transaction: &crate::submission_operation::DeploymentTransactionIdentity,
    ) -> RuntimeResult<Self> {
        let (creator, mechanism, predicted_address, factory_code_hash, salt) =
            match &constraints.route {
                DeploymentRoute::DirectCreate { expected_address } => (
                    constraints.sender,
                    CreationMechanism::TransactionCreate,
                    Some(*expected_address),
                    None,
                    None,
                ),
                DeploymentRoute::Factory(factory) => {
                    valid_digest(&factory.code_digest)?;
                    let (mechanism, address, salt) = match &factory.mechanism {
                        FactoryMechanism::Create => (CreationMechanism::Create, None, None),
                        FactoryMechanism::Create2 {
                            salt,
                            salt_transform,
                            expected_address,
                            ..
                        } => (
                            CreationMechanism::Create2,
                            Some(*expected_address),
                            Some(salt_transform.apply(&constraints.sender, salt)),
                        ),
                        FactoryMechanism::Create3 {
                            salt,
                            salt_transform,
                            expected_helper_address,
                            expected_address,
                            ..
                        } => {
                            let salt = salt_transform.apply(&constraints.sender, salt);
                            if solady_create3_addresses(&factory.address, &salt)?
                                != (*expected_helper_address, *expected_address)
                            {
                                return Err(RuntimeError::InvalidAuthorization);
                            }
                            (
                                CreationMechanism::Create3,
                                Some(*expected_address),
                                Some(salt),
                            )
                        }
                    };
                    (
                        factory.address,
                        mechanism,
                        address,
                        Some(factory.code_hash),
                        salt,
                    )
                }
            };
        if transaction.gas_limit == 0
            || (transaction.value != [0; 32] && mechanism != CreationMechanism::TransactionCreate)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(Self {
            intent_digest: constraints.digest()?,
            profile_digest: constraints.profile_digest.clone(),
            transaction_hash,
            sender: constraints.sender,
            transaction_value: transaction.value,
            calldata_hash: transaction.calldata_hash,
            gas_limit: transaction.gas_limit,
            creator,
            mechanism,
            predicted_address,
            factory_code_hash,
            salt,
            init_code_hash: constraints.artifact.init_code_hash,
            runtime_code_hash: constraints.artifact.runtime_code_hash,
        })
    }

    pub fn digest(&self) -> RuntimeResult<Digest> {
        canonical_bytes(&("openpc:bound-deployment:v1", self)).map(Digest::of)
    }
    pub fn transaction_hash(&self) -> &[u8; 32] {
        &self.transaction_hash
    }
    pub fn predicted_address(&self) -> Option<&[u8; 20]> {
        self.predicted_address.as_ref()
    }
    pub fn mechanism(&self) -> CreationMechanism {
        self.mechanism
    }
}

fn valid_digest(digest: &Digest) -> RuntimeResult<()> {
    if Digest::parse(digest.as_str()).is_err() || *digest == Digest::of([]) {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}

pub(super) fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// A single dynamic bytes tail with zero padding and no gaps, aliases, trailing
/// data or alternate offsets. This is the complete grammar of these adapters.
fn exact_bytes_argument(
    data: &[u8],
    head_words: usize,
    bytes_index: usize,
) -> RuntimeResult<&[u8]> {
    let head = head_words * 32;
    if bounded_word(data, bytes_index * 32)? != head {
        return Err(RuntimeError::InvalidInput);
    }
    let length = bounded_word(data, head)?;
    if length == 0 || length > MAX_INIT_CODE_BYTES {
        return Err(RuntimeError::InvalidInput);
    }
    let start = head + 32;
    let end = start + length;
    let padded_end = start + length.div_ceil(32) * 32;
    if data.len() != padded_end || data[end..].iter().any(|byte| *byte != 0) {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(&data[start..end])
}

fn bounded_word(data: &[u8], offset: usize) -> RuntimeResult<usize> {
    let word = data
        .get(offset..offset + 32)
        .ok_or(RuntimeError::InvalidInput)?;
    if word[..28] != [0; 28] {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(u32::from_be_bytes(
        word[28..]
            .try_into()
            .map_err(|_| RuntimeError::InvalidInput)?,
    ) as usize)
}

#[cfg(test)]
#[path = "deployment_tests.rs"]
mod tests;
