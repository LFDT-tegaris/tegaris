//! Shared Control payload reader for Fleet and Fact. This is custody only;
//! qualification, policy and workload admission stay with their existing owners.
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::os::fd::AsRawFd;
use std::{path::PathBuf, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Message {
    wire: Vec<u8>,
    mac: Vec<u8>,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[(byte >> 4) as usize] as char,
                DIGITS[(byte & 15) as usize] as char,
            ]
        })
        .collect()
}

pub async fn authorize_input(connection: &mut PgConnection, input_id: &str) -> Result<(), String> {
    let challenge: Option<serde_json::Value> = sqlx::query_scalar(
        "select openpc.runtime_artifact_materialization_challenge($1::text::uuid)",
    )
    .bind(input_id)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| "runtime source read challenge unavailable")?;
    let Some(challenge) = challenge else {
        return Ok(());
    }; // Original V1 compatibility, never proof.
    let request: Message =
        serde_json::from_value(challenge).map_err(|_| "runtime source challenge rejected")?;
    let directory = PathBuf::from(
        std::env::var_os("OPENPC_RUNTIME_ARTIFACT_SOURCE_SOCKET_DIRECTORY")
            .ok_or("runtime source read endpoint missing")?,
    );
    if !directory.is_absolute() {
        return Err("runtime source read endpoint rejected".into());
    }
    let document: serde_json::Value =
        serde_json::from_slice(&request.wire).map_err(|_| "runtime source challenge rejected")?;
    let generation = document
        .get("binding")
        .and_then(|binding| binding.get("generation_id"))
        .and_then(serde_json::Value::as_str)
        .ok_or("runtime source generation unavailable")?;
    let parsed =
        uuid::Uuid::parse_str(generation).map_err(|_| "runtime source generation rejected")?;
    if parsed.get_version_num() != 7 || parsed.hyphenated().to_string() != generation {
        return Err("runtime source generation rejected".into());
    }
    let parent = std::fs::File::open(directory.join(generation))
        .map_err(|_| "runtime source read endpoint unavailable")?;
    let path = format!("/proc/self/fd/{}/read.sock", parent.as_raw_fd());
    let response = tokio::time::timeout(Duration::from_secs(3), async {
        let bytes =
            serde_json::to_vec(&request).map_err(|_| "runtime source challenge rejected")?;
        if bytes.is_empty() || bytes.len() > 65536 {
            return Err("runtime source challenge rejected");
        }
        let mut stream = UnixStream::connect(&path)
            .await
            .map_err(|_| "runtime source read endpoint unavailable")?;
        stream
            .write_u32(bytes.len() as u32)
            .await
            .map_err(|_| "runtime source read request unavailable")?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|_| "runtime source read request unavailable")?;
        let size = stream
            .read_u32()
            .await
            .map_err(|_| "runtime source read refused")? as usize;
        if size == 0 || size > 65536 {
            return Err("runtime source response rejected");
        }
        let mut bytes = vec![0; size];
        stream
            .read_exact(&mut bytes)
            .await
            .map_err(|_| "runtime source response unavailable")?;
        let response: Message =
            serde_json::from_slice(&bytes).map_err(|_| "runtime source response rejected")?;
        if response.wire.is_empty() || response.wire.len() > 16384 || response.mac.len() != 32 {
            return Err("runtime source response rejected");
        }
        Ok(response)
    })
    .await
    .map_err(|_| "runtime source read timed out")??;
    // The server verifies this again on every payload release. Client storage
    // of an untrusted response is not a grant; copied GUCs cannot authenticate it.
    sqlx::query("select set_config('openpc.runtime_source_read_permits', (coalesce(nullif(current_setting('openpc.runtime_source_read_permits',true),''),'{}')::jsonb || jsonb_build_object($1::text,jsonb_build_object('wire',$2::text,'mac',$3::text)))::text,true)")
        .bind(input_id).bind(hex(&response.wire)).bind(hex(&response.mac))
        .execute(connection).await.map_err(|_| "runtime source read permit unavailable")?;
    Ok(())
}
