use thiserror::Error;

/// Failure at a protocol or generated-contract boundary.
#[derive(Debug, Error)]
pub enum ContractError {
    #[error("invalid contract data: {0}")]
    InvalidData(String),
    #[error("unsupported contract version: {0}")]
    UnsupportedVersion(String),
}

pub type ContractResult<T> = Result<T, ContractError>;
