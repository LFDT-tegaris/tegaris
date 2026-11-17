//! Installed, read-only candidate archive producer. No eligibility, signature or
//! deletion authority is returned. All diagnostics deliberately omit source data.
#[path = "candidate_archive_reader/source.rs"]
mod source;

use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    participant_id: uuid::Uuid,
    privacy_domain_id: uuid::Uuid,
    source_profile_id: uuid::Uuid,
    host: String,
    port: u16,
    user: String,
    password_file: PathBuf,
}

fn private_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err("installed path rejected");
    }
    let before = fs::symlink_metadata(path).map_err(|_| "installed file unavailable")?;
    if !before.is_file() || before.mode() & 0o077 != 0 || before.len() == 0 || before.len() > limit
    {
        return Err("installed file rejected");
    }
    let file = fs::File::open(path).map_err(|_| "installed file unavailable")?;
    let after = file.metadata().map_err(|_| "installed file unavailable")?;
    if before.dev() != after.dev() || before.ino() != after.ino() || before.mode() != after.mode() {
        return Err("installed file changed");
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "installed file unreadable")?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err("installed file size rejected");
    }
    Ok(bytes)
}

async fn run() -> Result<()> {
    if std::env::args_os().len() != 1 {
        return Err("reader arguments rejected");
    }
    let path = std::env::var_os("OPENPC_CANDIDATE_ARCHIVE_CONFIGURATION_FILE")
        .ok_or("reader configuration missing")?;
    let config: Configuration = serde_json::from_slice(&private_file(Path::new(&path), 16384)?)
        .map_err(|_| "reader configuration rejected")?;
    let mut input = Vec::new();
    io::stdin()
        .take(4097)
        .read_to_end(&mut input)
        .map_err(|_| "reader input unavailable")?;
    if input.len() > 4096 {
        return Err("reader input rejected");
    }
    let request: source::Request =
        serde_json::from_slice(&input).map_err(|_| "reader input rejected")?;
    request.validate()?;
    if request.participant_id != config.participant_id
        || request.privacy_domain_id != config.privacy_domain_id
        || request.source_profile_id != config.source_profile_id
        || config.host.is_empty()
        || config.user.is_empty()
        || config.port == 0
    {
        return Err("reader scope rejected");
    }
    let password = Zeroizing::new(private_file(&config.password_file, 256)?);
    let password_text = std::str::from_utf8(&password)
        .map_err(|_| "reader credential rejected")?
        .trim();
    if password_text.len() < 32 || password_text.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err("reader credential rejected");
    }
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(
            PgConnectOptions::new()
                .host(&config.host)
                .port(config.port)
                .database("openpc_candidate_index")
                .username(&config.user)
                .password(password_text),
        )
        .await
        .map_err(|_| "candidate reader unavailable")?;
    let result = source::read(&pool, &request, &config.user).await;
    pool.close().await;
    let output = serde_json::to_vec(&result?).map_err(|_| "candidate encoding rejected")?;
    if output.len() > 2_200_000 {
        return Err("candidate output bound rejected");
    }
    io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|_| "candidate output unavailable")?;
    Ok(())
}

#[tokio::main]
async fn main() {
    let result = tokio::time::timeout(Duration::from_secs(15), run()).await;
    if !matches!(result, Ok(Ok(()))) {
        eprintln!("{{\"event\":\"candidate_archive_reader_stopped\",\"code\":\"UNAVAILABLE\"}}");
        std::process::exit(1);
    }
}
