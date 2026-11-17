//! Installed Fact retirement target. Only signed execute/cancel messages can
//! mutate the store; readback preserves UNKNOWN and original terminal bytes.
//! Connection, scope and trust are installed files, never caller inputs.
use std::{
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use openpc_fact_service::{
    FactSignatureVerifier, FactStore,
    retirement::{FactRetirementOwner, FactRetirementReadback},
};
use pc_runtime_types::{
    store_retirement::RetirementAttempt,
    store_retirement_authority::{RetirementAuthorityConfiguration, RetirementHost},
};
use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_WIRE: usize = 1_048_576;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Configuration {
    host: RetirementHost,
    authority: RetirementAuthorityConfiguration,
    target_signing_key_file: PathBuf,
    capability_secret_file: PathBuf,
    fact_verify_key_file: PathBuf,
    fact_verify_key_id: String,
    database: Database,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Database {
    host: String,
    port: u16,
    name: String,
    user: String,
    password_file: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "mode", rename_all = "SCREAMING_SNAKE_CASE")]
enum Input {
    Readback { attempt: Box<RetirementAttempt> },
    Execute { signed_wire_hex: String },
    Cancel { signed_wire_hex: String },
}

fn read_file(path: &Path, maximum: usize, secret: bool) -> Result<Zeroizing<Vec<u8>>> {
    if !path.is_absolute() {
        return Err("absolute installed path required".into());
    }
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || (secret && before.permissions().mode() & 0o077 != 0) {
        return Err("installed file rejected".into());
    }
    let file = File::open(path)?;
    let after = file.metadata()?;
    if !after.is_file()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || (secret && after.permissions().mode() & 0o077 != 0)
    {
        return Err("installed file changed".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("installed file size rejected".into());
    }
    Ok(bytes)
}

fn decode_hex(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() > maximum * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("hex input rejected".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

fn secret(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let encoded = read_file(path, 65, true)?;
    let decoded = Zeroizing::new(decode_hex(std::str::from_utf8(&encoded)?.trim(), 32)?);
    Ok(Zeroizing::new(decoded.as_slice().try_into()?))
}

async fn run() -> Result<()> {
    if std::env::args().len() != 1 {
        return Err("target arguments rejected".into());
    }
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_WIRE * 2 + 129) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_WIRE * 2 + 128 {
        return Err("target input too large".into());
    }
    let input: Input = serde_json::from_slice(&bytes)?;
    // Parse bounded inputs before allocating a database connection.
    let wire = match &input {
        Input::Readback { attempt } => {
            attempt.validate()?;
            None
        }
        Input::Execute { signed_wire_hex } | Input::Cancel { signed_wire_hex } => {
            Some(decode_hex(signed_wire_hex, MAX_WIRE)?)
        }
    };
    let path = PathBuf::from(std::env::var("OPENPC_RETIREMENT_FACT_CONFIGURATION_FILE")?);
    let config: Configuration = serde_json::from_slice(&read_file(&path, 65_536, false)?)?;
    config.authority.clone().install(&config.host)?;
    let signing_key = secret(&config.target_signing_key_file)?;
    let public_key = p256::ecdsa::SigningKey::from_bytes((&*signing_key).into())?
        .verifying_key()
        .to_sec1_point(true);
    if public_key.as_bytes() != config.authority.target_public_key_sec1 {
        return Err("installed target key mismatch".into());
    }
    let capability = secret(&config.capability_secret_file)?;
    let verifier = FactSignatureVerifier::from_key_identifier(
        &config.fact_verify_key_id,
        &read_file(&config.fact_verify_key_file, 65, false)?,
    )?;
    let password = read_file(&config.database.password_file, 4096, true)?;
    let pool = tokio::time::timeout(
        Duration::from_secs(5),
        PgPoolOptions::new().max_connections(1).connect_with(
            PgConnectOptions::new()
                .host(&config.database.host)
                .port(config.database.port)
                .database(&config.database.name)
                .username(&config.database.user)
                .password(std::str::from_utf8(&password)?.trim()),
        ),
    )
    .await??;
    let allowed: bool = sqlx::query_scalar(
        "select current_database()='openpc_facts' and current_user=session_user
         and exists(select 1 from pg_roles where rolname=current_user and not rolsuper and not rolbypassrls)
         and pg_has_role(current_user,'openpc_fact_bridge_writer','MEMBER')
         and not pg_has_role(current_user,'openpc_facts_lifecycle_owner','MEMBER')
         and not pg_has_role(current_user,'openpc_facts_capability_owner','MEMBER')")
        .fetch_one(&pool).await?;
    if !allowed {
        return Err("target database role rejected".into());
    }
    let host_digest = pc_runtime_types::Digest::of(serde_json::to_vec(&config.host)?);
    let owner = FactRetirementOwner::from_host_configuration(
        FactStore::new(pool.clone(), *capability),
        config.host,
        config.authority,
        *signing_key,
        verifier,
    )?;
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        match input {
            Input::Readback { attempt } => owner.readback(&attempt).await,
            Input::Execute { .. } => {
                owner
                    .execute(wire.as_deref().expect("parsed execute wire"))
                    .await
            }
            Input::Cancel { .. } => {
                owner
                    .cancel(wire.as_deref().expect("parsed cancel wire"))
                    .await
            }
        }
    })
    .await??;
    let result = match result {
        FactRetirementReadback::Unknown => serde_json::json!({"state":"UNKNOWN"}),
        FactRetirementReadback::Terminal { signed_outcome, .. } => {
            let hex = signed_outcome
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            serde_json::json!({"state":"TERMINAL","signedWireHex":hex})
        }
    };
    println!(
        "{}",
        serde_json::json!({"identity":"OPENPC-FACT-RETIREMENT-TARGET-1","hostDigest":host_digest,"result":result})
    );
    pool.close().await;
    Ok(())
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        // A failed process or lost stdout says nothing about transaction commit.
        eprintln!("fact retirement target unavailable; reconcile original attempt");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unbounded_or_ambiguous_commands() {
        for value in [
            r#"{"mode":"EXECUTE","signed_wire_hex":"aa","database":"attacker"}"#,
            r#"{"mode":"EXECUTE","signed_wire_hex":"aa","signed_wire_hex":"bb"}"#,
            r#"{"mode":"READBACK","attempt":{}}"#,
            r#"{"mode":"DELETE","signed_wire_hex":"aa"}"#,
        ] {
            assert!(serde_json::from_str::<Input>(value).is_err());
        }
        for hex in ["", "AA", "a", "zz", "aaaa"] {
            assert!(decode_hex(hex, 1).is_err());
        }
        assert_eq!(decode_hex("0aff", 2).unwrap(), [10, 255]);
    }
}
