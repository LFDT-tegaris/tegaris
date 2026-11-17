#![forbid(unsafe_code)]

//! Typed module-manifest identities and the generated frozen catalog inventory.

mod manifest;

pub mod generated;

pub use manifest::{ManifestDigest, ModuleDependencyRef, ModuleVersionRef};
