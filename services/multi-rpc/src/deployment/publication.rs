//! Join exact governed policy bytes to the independently recovered transaction.
//! This produces candidate identity, not an intent, approval or dispatch grant.
use super::*;
use pc_policy_core::deployment_policy::{AdmittedDeploymentPolicy, DeploymentRouteDefinition};

pub fn bind_publication(
    publication: &AdmittedDeploymentPolicy,
    transaction: &SignedTransaction,
    now_ms: u64,
) -> RuntimeResult<(DeploymentConstraints, BoundDeployment)> {
    let constraints = prepare_publication(
        publication,
        transaction.unsigned(),
        transaction.signer(),
        now_ms,
    )?;
    let bound = constraints.bind(transaction)?;
    Ok((constraints, bound))
}

pub(super) fn prepare_publication(
    publication: &AdmittedDeploymentPolicy,
    transaction: &crate::signed_transaction::UnsignedTransaction,
    sender: &[u8; 20],
    now_ms: u64,
) -> RuntimeResult<DeploymentConstraints> {
    publication
        .validate()
        .map_err(|_| RuntimeError::InvalidInput)?;
    let definition = &publication.definition;
    if definition
        .expires_at_ms()
        .map_err(|_| RuntimeError::InvalidInput)?
        <= now_ms
        || !definition
            .allowed_senders
            .iter()
            .any(|allowed| fixed::<20>(allowed).is_ok_and(|allowed| &allowed == sender))
    {
        return Err(RuntimeError::Denied);
    }
    transaction
        .enforce_policy(&definition.transaction_policy)
        .map_err(|_| RuntimeError::Denied)?;
    let artifact = DeploymentArtifact {
        init_code_hash: fixed(&publication.init_code_hash)?,
        runtime_code_hash: fixed(&definition.artifact.runtime_code_hash)?,
    };
    let route = match &definition.route {
        DeploymentRouteDefinition::TransactionCreate => DeploymentRoute::DirectCreate {
            expected_address: transaction
                .creation_address(sender)
                .map_err(|_| RuntimeError::Denied)?,
        },
        DeploymentRouteDefinition::Create {
            canonical_signature,
            code_hash,
            adapter_digest,
            ..
        }
        | DeploymentRouteDefinition::Create2 {
            canonical_signature,
            code_hash,
            adapter_digest,
            ..
        }
        | DeploymentRouteDefinition::Create3 {
            canonical_signature,
            code_hash,
            adapter_digest,
            ..
        } => {
            let factory = publication
                .factory_binding
                .as_ref()
                .ok_or(RuntimeError::InvalidInput)?;
            let address = fixed(&factory.contract_address)?;
            let mechanism = match &definition.route {
                DeploymentRouteDefinition::Create { .. } => FactoryMechanism::Create,
                DeploymentRouteDefinition::Create2 {
                    arguments,
                    salt_namespace_digest,
                    salt_transform,
                    ..
                }
                | DeploymentRouteDefinition::Create3 {
                    arguments,
                    salt_namespace_digest,
                    salt_transform,
                    ..
                } => {
                    let arguments = match arguments.as_str() {
                        "INIT_CODE_SALT" => Create2Arguments::InitCodeSalt,
                        "SALT_INIT_CODE" => Create2Arguments::SaltInitCode,
                        _ => return Err(RuntimeError::InvalidInput),
                    };
                    let data = transaction
                        .data()
                        .get(4..)
                        .ok_or(RuntimeError::InvalidInput)?;
                    let bytes_index = usize::from(arguments == Create2Arguments::SaltInitCode);
                    let salt_index = 1 - bytes_index;
                    let salt: [u8; 32] = data
                        .get(salt_index * 32..(salt_index + 1) * 32)
                        .ok_or(RuntimeError::InvalidInput)?
                        .try_into()
                        .map_err(|_| RuntimeError::InvalidInput)?;
                    let init_code = exact_bytes_argument(data, 2, bytes_index)?;
                    let salt_transform = match salt_transform.as_str() {
                        "IDENTITY" => SaltTransform::Identity,
                        "KECCAK_SENDER_SALT" => SaltTransform::KeccakSenderSalt,
                        _ => return Err(RuntimeError::InvalidInput),
                    };
                    let effective_salt = salt_transform.apply(sender, &salt);
                    if matches!(definition.route, DeploymentRouteDefinition::Create3 { .. }) {
                        let (expected_helper_address, expected_address) =
                            solady_create3_addresses(&address, &effective_salt)?;
                        FactoryMechanism::Create3 {
                            arguments,
                            salt,
                            salt_namespace_digest: digest(salt_namespace_digest)?,
                            salt_transform,
                            expected_helper_address,
                            expected_address,
                        }
                    } else {
                        FactoryMechanism::Create2 {
                            arguments,
                            salt,
                            salt_namespace_digest: digest(salt_namespace_digest)?,
                            salt_transform,
                            expected_address: create2_address(&address, &effective_salt, init_code)
                                .map_err(|_| RuntimeError::Denied)?,
                        }
                    }
                }
                _ => return Err(RuntimeError::InvalidInput),
            };
            DeploymentRoute::Factory(Box::new(FactoryDeployment {
                address,
                code_hash: fixed(code_hash)?,
                code_digest: digest(&factory.code_digest)?,
                abi_digest: digest(&factory.abi_digest)?,
                adapter_digest: digest(adapter_digest)?,
                selector: keccak(canonical_signature.as_bytes())[..4]
                    .try_into()
                    .map_err(|_| RuntimeError::InvalidInput)?,
                mechanism,
            }))
        }
    };
    let constraints = DeploymentConstraints {
        chain_id: definition
            .chain_id
            .parse()
            .map_err(|_| RuntimeError::InvalidInput)?,
        sender: *sender,
        signing_hash: *transaction.signing_hash(),
        profile_digest: digest(&publication.definition_digest)?,
        artifact,
        route,
    };
    constraints.validate_unsigned(transaction, sender)?;
    Ok(constraints)
}

fn fixed<const N: usize>(value: &str) -> RuntimeResult<[u8; N]> {
    let hex = value
        .strip_prefix("0x")
        .filter(|value| value.len() == N * 2)
        .ok_or(RuntimeError::InvalidInput)?;
    let mut out = [0; N];
    for (pair, byte) in hex.as_bytes().as_chunks::<2>().0.iter().zip(&mut out) {
        *byte = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| RuntimeError::InvalidInput)?,
            16,
        )
        .map_err(|_| RuntimeError::InvalidInput)?;
    }
    Ok(out)
}

fn digest(value: &str) -> RuntimeResult<Digest> {
    Digest::parse(
        value
            .strip_prefix("sha256:")
            .ok_or(RuntimeError::InvalidInput)?,
    )
}
