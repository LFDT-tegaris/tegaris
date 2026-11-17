#![forbid(unsafe_code)]

//! Deterministic helpers used by contract and later service tests.

mod digest;
mod fixture;

pub use digest::sha256_hex;
pub use fixture::parse_fixture;
