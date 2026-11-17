use openpc_fact_service::runtime::{RuntimeConfig, serve};
use std::io::{Read, Write};

fn healthcheck() -> bool {
    let Ok(mut stream) = std::net::TcpStream::connect("127.0.0.1:8081") else {
        return false;
    };
    if stream
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    stream.read_to_string(&mut response).is_ok() && response.starts_with("HTTP/1.1 200")
}

#[tokio::main]
async fn main() {
    if std::env::args().nth(1).as_deref() == Some("prepare-secret") {
        let result = match std::env::var_os("OPENPC_FACT_BRIDGE_CONFIGURATION_FILE") {
            Some(path) => {
                openpc_fact_service::deployment::DeployedFactBridge::prepare_candidate_secret(
                    std::path::Path::new(&path),
                )
                .await
            }
            None => Err("fact deployment configuration missing".into()),
        };
        if result.is_err() {
            eprintln!(r#"{{"level":"error","event":"fact_secret_preparation_rejected"}}"#);
            std::process::exit(1);
        }
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(if healthcheck() { 0 } else { 1 });
    }
    let result = match RuntimeConfig::from_env() {
        Ok(config) => serve(config).await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!(
            "{}",
            serde_json::json!({
                "level": "error",
                "event": "fact_runtime_stopped",
                "classification": error,
            })
        );
        std::process::exit(1);
    }
}
