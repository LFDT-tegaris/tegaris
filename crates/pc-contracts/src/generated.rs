//! Generated Rust contracts are produced under `generated/rust`.
//!
//! The generated tree is committed so downstream crates use the exact contract
//! bindings that passed the I01 generator checks.

pub mod openpc {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../generated/rust/proto/mod.rs"
    ));
}

pub mod json_schema {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../generated/rust/json-schema/mod.rs"
    ));
}

pub mod privacy_explorer {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../generated/rust/privacy-explorer/mod.rs"
    ));
}
