//! Installed indexer reconciliation job. Historical Fact receipts are read from
//! its fixed restricted connection; request bytes cannot assert acknowledgement.
use openpc_indexer_adapter::{
    CandidatePersistenceBinding, CandidateStore, CandidateStoreError, FactDeliveryReader,
};
use serde::Deserialize;
use sqlx::postgres::PgConnectOptions;
use std::{
    fs,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    participant_id: Uuid,
    privacy_domain_id: Uuid,
    source_profile_id: Uuid,
    candidate: Database,
    facts: Database,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Database {
    host: String,
    port: u16,
    user: String,
    password_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    generation_id: Uuid,
    partition_id: Uuid,
}
fn private_file(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    if !path.is_absolute() {
        return Err("installed path rejected".into());
    }
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.mode() & 0o077 != 0 || before.len() == 0 || before.len() > limit
    {
        return Err("installed file rejected".into());
    }
    let file = fs::File::open(path)?;
    let after = file.metadata()?;
    if before.dev() != after.dev() || before.ino() != after.ino() || before.mode() != after.mode() {
        return Err("installed file changed".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err("installed file size rejected".into());
    }
    Ok(bytes)
}
fn options(config: &Database, database: &str, role: &str) -> Result<PgConnectOptions> {
    if config.user != role || config.host.is_empty() || config.host.len() > 253 || config.port == 0
    {
        return Err("installed database rejected".into());
    }
    let password = private_file(&config.password_file, 4096)?;
    Ok(PgConnectOptions::new()
        .host(&config.host)
        .port(config.port)
        .database(database)
        .username(role)
        .password(std::str::from_utf8(&password)?.trim()))
}
async fn run() -> Result<()> {
    if std::env::args_os().len() != 1 {
        return Err("job arguments rejected".into());
    }
    let mut bytes = Vec::new();
    io::stdin().take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err("job input size rejected".into());
    }
    let input: Input = serde_json::from_slice(&bytes)?;
    let path = PathBuf::from(std::env::var(
        "OPENPC_CANDIDATE_DELIVERY_CONFIGURATION_FILE",
    )?);
    let config: Configuration = serde_json::from_slice(&private_file(&path, 16384)?)?;
    for id in [
        config.participant_id,
        config.privacy_domain_id,
        config.source_profile_id,
        input.generation_id,
        input.partition_id,
    ] {
        if id.get_version_num() != 7 {
            return Err("job scope rejected".into());
        }
    }
    let operation = Uuid::now_v7();
    let binding = CandidatePersistenceBinding::try_new(
        config.participant_id,
        config.privacy_domain_id,
        input.generation_id,
        operation,
        operation,
    )?;
    let store = CandidateStore::connect_retirement_target(options(
        &config.candidate,
        "openpc_candidate_index",
        "openpc_indexer_writer",
    )?)
    .await?;
    let reader = FactDeliveryReader::connect(options(
        &config.facts,
        "openpc_facts",
        "openpc_policy_fact_runtime",
    )?)
    .await?;
    let changed = store
        .reconcile_retired_partition_delivery(
            &reader,
            &binding,
            config.source_profile_id,
            input.partition_id,
        )
        .await?;
    println!(
        "{}",
        serde_json::json!({"protocol":"OPENPC-CANDIDATE-DELIVERY-1","reconciledEvents":changed,"authority":"HISTORICAL_RECEIPTS_ONLY"})
    );
    Ok(())
}
#[tokio::main]
async fn main() {
    let result = tokio::time::timeout(Duration::from_secs(30), run()).await;
    if let Ok(Ok(())) = result {
        return;
    }
    // Classification only: never print SQL, connection strings, private paths
    // or the arbitrary underlying database/provider diagnostic.
    let code = match &result {
        Err(_) => "TIMEOUT".to_owned(),
        Ok(Err(error)) => match error.downcast_ref::<CandidateStoreError>() {
            Some(CandidateStoreError::Database(sqlx::Error::Database(database))) => database
                .code()
                .filter(|code| code.len() == 5 && code.bytes().all(|b| b.is_ascii_alphanumeric()))
                .map_or_else(|| "DATABASE".to_owned(), |code| format!("SQLSTATE-{code}")),
            Some(CandidateStoreError::Database(_)) => "DATABASE".to_owned(),
            Some(_) => "BINDING".to_owned(),
            None => "INPUT-OR-INSTALLATION".to_owned(),
        },
        Ok(Ok(())) => unreachable!(),
    };
    eprintln!("OPENPC-CANDIDATE-DELIVERY-REJECTED|{code}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caller_cannot_supply_acknowledgement_or_database_authority() {
        let input = serde_json::json!({"generationId":Uuid::now_v7(),"partitionId":Uuid::now_v7()});
        assert!(serde_json::from_value::<Input>(input.clone()).is_ok());
        for name in [
            "acknowledged",
            "receiptDigest",
            "ready",
            "database",
            "participantId",
        ] {
            let mut forged = input.clone();
            forged[name] = serde_json::json!(true);
            assert!(serde_json::from_value::<Input>(forged).is_err());
        }
    }
}
