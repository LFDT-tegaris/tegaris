//! Typed identity envelope. Cryptographic and historical validation never
//! establishes present issuer grantability; database and policy owners fence it.
mod generated;
mod scalar;
mod wire;

pub use scalar::*;
pub use wire::*;

#[cfg(test)]
mod tests;
