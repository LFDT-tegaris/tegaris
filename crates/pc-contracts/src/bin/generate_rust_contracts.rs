#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    process::Command,
};

use quote::ToTokens;
use schemars::schema::RootSchema;
use serde_json::{Map, Value};
use typify::TypeSpace;

fn canonical_output_root(
    workspace: &Path,
    approved_temporary_root: &Path,
    output_root: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let workspace = std::fs::canonicalize(workspace)?;
    let approved_temporary_root = std::fs::canonicalize(approved_temporary_root)?;
    let output_root = std::fs::canonicalize(output_root)?;
    if output_root.starts_with(&workspace)
        || !output_root.starts_with(&approved_temporary_root)
        || output_root == approved_temporary_root
    {
        return Err(
            "--output-root must resolve below the approved repository-external root".into(),
        );
    }
    Ok(output_root)
}

fn create_owned_directory(
    owner: &Path,
    path: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(path)?;
    let path = std::fs::canonicalize(path)?;
    if !path.starts_with(owner) {
        return Err("generated destination traversed outside --output-root".into());
    }
    Ok(path)
}

fn schema_stem(file_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    file_name
        .strip_suffix(".schema.json")
        .map(|name| name.replace('-', "_"))
        .ok_or_else(|| "schema file name must end in .schema.json".into())
}

fn pointer_key(stem: &str, pointer: &str) -> String {
    let suffix = pointer
        .trim_start_matches('/')
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("{stem}__pointer__{suffix}")
}

fn rewrite_references(
    value: &mut Value,
    source_stem: &str,
    documents: &BTreeMap<String, Value>,
    extracted: &mut Map<String, Value>,
    active_pointers: &mut BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    match value {
        Value::Array(values) => {
            for value in values {
                rewrite_references(value, source_stem, documents, extracted, active_pointers)?;
            }
        }
        Value::Object(values) => {
            if matches!(
                values.get("format").and_then(Value::as_str),
                Some("date") | Some("date-time") | Some("uuid")
            ) {
                // The Rust contract bindings retain the wire representation as
                // validated strings. This avoids Typify 0.7.0 emitting
                // conflicting conversion implementations for native temporal
                // and UUID mappings on Rust 1.98.
                values.remove("format");
            }
            if let Some(Value::String(reference)) = values.get_mut("$ref") {
                let original = reference.clone();
                if let Some(definition) = original.strip_prefix("#/$defs/") {
                    *reference = format!("#/definitions/{source_stem}__{definition}");
                } else if let Some((file_name, fragment)) = original.split_once('#') {
                    let target_stem = schema_stem(file_name)?;
                    if let Some(definition) = fragment.strip_prefix("/$defs/") {
                        *reference = format!("#/definitions/{target_stem}__{definition}");
                    } else if fragment.starts_with('/') {
                        let document = documents.get(file_name).ok_or_else(|| {
                            format!("unknown external schema reference: {original}")
                        })?;
                        let key = pointer_key(&target_stem, fragment);
                        if !extracted.contains_key(&key) && active_pointers.insert(key.clone()) {
                            let mut target =
                                document.pointer(fragment).cloned().ok_or_else(|| {
                                    format!("unresolvable external schema reference: {original}")
                                })?;
                            rewrite_references(
                                &mut target,
                                &target_stem,
                                documents,
                                extracted,
                                active_pointers,
                            )?;
                            extracted.insert(key.clone(), target);
                            active_pointers.remove(&key);
                        }
                        *reference = format!("#/definitions/{key}");
                    }
                }
            }
            for value in values.values_mut() {
                rewrite_references(value, source_stem, documents, extracted, active_pointers)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = std::fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))?;
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[0] != "--output-root" {
        return Err("usage: generate-rust-contracts --output-root <external-staging-root>".into());
    }
    let output_root_argument = PathBuf::from(&arguments[1]);
    let approved_temporary_root = PathBuf::from(
        std::env::var_os("OPENPC_PNC_TMP_ROOT").ok_or("OPENPC_PNC_TMP_ROOT is required")?,
    );
    if !output_root_argument.is_absolute() || !approved_temporary_root.is_absolute() {
        return Err("output and approved temporary roots must be absolute".into());
    }
    let output_root =
        canonical_output_root(&workspace, &approved_temporary_root, &output_root_argument)?;
    if std::env::var_os("PROTOC").is_none() {
        return Err("PROTOC must point to the pinned protoc 35.1 binary".into());
    }
    let proto_root = workspace.join("proto");
    let generated_root = output_root.join("generated");
    std::fs::create_dir_all(&generated_root)?;
    let generated_root = std::fs::canonicalize(generated_root)?;
    if !generated_root.starts_with(&output_root) {
        return Err("generated output traversed outside --output-root".into());
    }
    let output = create_owned_directory(&generated_root, &generated_root.join("rust/proto"))?;
    let json_schema_output =
        create_owned_directory(&generated_root, &generated_root.join("rust/json-schema"))?;
    let protos = [
        "openpc/common/v1/common.proto",
        "openpc/control/v1/control.proto",
        "openpc/evidence/v1/evidence.proto",
        "openpc/facts/v1/facts.proto",
        "openpc/fleet/v1/fleet.proto",
        "openpc/runtime/v1/runtime.proto",
    ]
    .map(|path| proto_root.join(path));

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .out_dir(&output)
        .compile_protos(&protos, &[proto_root])?;

    std::fs::write(
        output.join("mod.rs"),
        "// @generated by pc-contracts; do not edit.\n\
pub mod common { pub mod v1 { include!(\"openpc.common.v1.rs\"); } }\n\
pub mod control { pub mod v1 { include!(\"openpc.control.v1.rs\"); } }\n\
pub mod evidence { pub mod v1 { include!(\"openpc.evidence.v1.rs\"); } }\n\
pub mod facts { pub mod v1 { include!(\"openpc.facts.v1.rs\"); } }\n\
pub mod fleet { pub mod v1 { include!(\"openpc.fleet.v1.rs\"); } }\n\
pub mod runtime { pub mod v1 { include!(\"openpc.runtime.v1.rs\"); } }\n",
    )?;

    let mut paths = std::fs::read_dir(workspace.join("schemas/json"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.to_string_lossy().ends_with(".schema.json"))
        .collect::<Vec<_>>();
    paths.sort();
    let mut documents: BTreeMap<String, Value> = BTreeMap::new();
    for schema_path in &paths {
        let file_name = schema_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("schema file name must be valid UTF-8")?
            .to_owned();
        documents.insert(
            file_name,
            serde_json::from_reader(BufReader::new(File::open(schema_path)?))?,
        );
    }

    let mut definitions = Map::new();
    let mut extracted = Map::new();
    let mut active_pointers = BTreeSet::new();
    for (file_name, document) in &documents {
        let stem = schema_stem(file_name)?;
        if let Some(source_definitions) = document.get("$defs").and_then(Value::as_object) {
            for (name, source_definition) in source_definitions {
                let mut definition = source_definition.clone();
                rewrite_references(
                    &mut definition,
                    &stem,
                    &documents,
                    &mut extracted,
                    &mut active_pointers,
                )?;
                definitions.insert(format!("{stem}__{name}"), definition);
            }
        }
    }
    definitions.extend(extracted);
    let root: RootSchema = serde_json::from_value(serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "definitions": definitions
    }))?;
    let mut type_space = TypeSpace::default();
    type_space.add_root_schema(root)?;
    std::fs::write(
        json_schema_output.join("openpc_contracts.rs"),
        format!(
            "// @generated by pc-contracts and Typify 0.7.0; do not edit.\n#![allow(clippy::derivable_impls, clippy::large_enum_variant)]\n{}\n",
            type_space.into_token_stream(),
        ),
    )?;

    let registry = documents
        .get("privacy-explorer.schema.json")
        .and_then(|schema| schema.get("x-openpc-executionRegistry"))
        .ok_or("privacy-explorer.schema.json must have x-openpc-executionRegistry")?;
    let privacy_output = create_owned_directory(
        &generated_root,
        &generated_root.join("rust/privacy-explorer"),
    )?;
    std::fs::write(
        privacy_output.join("execution_registry.rs"),
        format!(
            "// @generated by pc-contracts from privacy-explorer.schema.json; do not edit.\n\
pub const EXECUTION_REGISTRY_JSON: &str = {};\n",
            serde_json::to_string(&serde_json::to_string(registry)?)?
        ),
    )?;
    std::fs::write(
        privacy_output.join("mod.rs"),
        "// @generated by pc-contracts; do not edit.\npub mod execution_registry;\n",
    )?;
    std::fs::write(
        json_schema_output.join("mod.rs"),
        "// @generated by pc-contracts; do not edit.\npub mod openpc_contracts;\n",
    )?;

    let mut rustfmt = Command::new("rustfmt");
    rustfmt.arg("--edition").arg("2024");
    rustfmt.arg(output.join("mod.rs"));
    for path in std::fs::read_dir(&json_schema_output)? {
        rustfmt.arg(path?.path());
    }
    let status = rustfmt.status()?;
    if !status.success() {
        return Err("rustfmt could not format generated Rust contract modules".into());
    }
    let mut privacy_rustfmt = Command::new("rustfmt");
    privacy_rustfmt.arg("--edition").arg("2024");
    for path in std::fs::read_dir(&privacy_output)? {
        privacy_rustfmt.arg(path?.path());
    }
    if !privacy_rustfmt.status()?.success() {
        return Err("rustfmt could not format generated Privacy Explorer contract modules".into());
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, os::unix::fs::symlink, path::PathBuf};

    use super::canonical_output_root;

    #[test]
    fn rejects_output_symlink_into_repository() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let approved = PathBuf::from(
            std::env::var_os("OPENPC_PNC_TMP_ROOT").expect("OPENPC_PNC_TMP_ROOT must be set"),
        );
        let owner = approved.join(format!("i07-rust-root-test-{}", std::process::id()));
        fs::create_dir_all(&owner).expect("create test owner");
        let valid = owner.join("valid");
        fs::create_dir(&valid).expect("create valid output root");
        let valid_result = canonical_output_root(&workspace, &approved, &valid);
        let escaped = owner.join("escaped");
        symlink(&workspace, &escaped).expect("create repository symlink");
        let escaped_result = canonical_output_root(&workspace, &approved, &escaped);
        fs::remove_dir_all(&owner).expect("clean test owner");
        assert!(valid_result.is_ok());
        assert!(escaped_result.is_err());
    }
}
