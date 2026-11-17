//! Actual installed target process, using only trust bootstrap and no fabricated
//! physical source. This proves deny/cancel/recovery transport, not retirement.
use super::*;
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
};

#[tokio::test]
#[ignore = "requires migrated FactStore, writer role and built installed target"]
async fn installed_target_preserves_unknown_cancellation_and_original_bytes() {
    let fixture = Fixture::new().await;
    let root = PathBuf::from(std::env::var("OPENPC_TEST_ROOT").unwrap())
        .join(format!("retirement-target-{}", Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let path = root.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let target_key = write("target.key", "20".repeat(32).as_bytes());
    let capability = write(
        "capability.key",
        std::env::var("OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX")
            .unwrap()
            .as_bytes(),
    );
    let fact_key = write("fact.sec1", &fixture.owner.fact_verifier.sec1_bytes());
    let options =
        sqlx::postgres::PgConnectOptions::from_str(&std::env::var("DATABASE_URL").unwrap())
            .unwrap();
    let config = serde_json::json!({
        "host":fixture.claims.host,"authority":fixture.configuration,
        "targetSigningKeyFile":target_key,"capabilitySecretFile":capability,
        "factVerifyKeyFile":fact_key,"factVerifyKeyId":format!("sha256:{}","2a".repeat(32)),
        "database":{"host":options.get_host(),"port":options.get_port(),"name":options.get_database(),
            "user":options.get_username(),"passwordFile":std::env::var("POLICY_FACT_DATABASE_PASSWORD_FILE").unwrap()}
    });
    let config_path = write("target.json", &serde_json::to_vec(&config).unwrap());
    let invoke = |input: serde_json::Value| {
        let mut child = Command::new(std::env::var("OPENPC_FACT_RETIREMENT_OWNER_BIN").unwrap())
            .env("OPENPC_RETIREMENT_FACT_CONFIGURATION_FILE", &config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&input).unwrap())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let readback = || serde_json::json!({"mode":"READBACK","attempt":fixture.claims.attempt});
    let parse = |output: std::process::Output| {
        assert!(
            output.status.success(),
            "installed target returned safe failure"
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["identity"], "OPENPC-FACT-RETIREMENT-TARGET-1");
        assert_eq!(
            value["hostDigest"],
            serde_json::to_value(Digest::of(canonical_bytes(&fixture.claims.host).unwrap()))
                .unwrap()
        );
        value["result"].clone()
    };
    assert_eq!(
        parse(invoke(readback())),
        serde_json::json!({"state":"UNKNOWN"})
    );
    assert_eq!(fixture.counts().await, (0, 0, 0));
    let malformed = invoke(
        serde_json::json!({"mode":"EXECUTE","signed_wire_hex":"00","host":fixture.claims.host}),
    );
    assert!(!malformed.status.success());
    assert!(malformed.stdout.is_empty());
    let mut wrong = config.clone();
    wrong["database"]["user"] = serde_json::json!("openpc_i05_policy_reader");
    write("target.json", &serde_json::to_vec(&wrong).unwrap());
    let denied = invoke(readback());
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    write("target.json", &serde_json::to_vec(&config).unwrap());
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let cancelled = parse(invoke(
        serde_json::json!({"mode":"CANCEL","signed_wire_hex":hex(&fixture.cancellation())}),
    ));
    assert_eq!(cancelled["state"], "TERMINAL");
    let (_, original) = terminal(
        fixture
            .owner
            .readback(&fixture.claims.attempt)
            .await
            .unwrap(),
    );
    assert_eq!(cancelled["signedWireHex"], hex(&original));
    // A separate process and a late signed request retain the exact tombstone.
    assert_eq!(parse(invoke(readback())), cancelled);
    assert_eq!(
        parse(invoke(
            serde_json::json!({"mode":"EXECUTE","signed_wire_hex":hex(&fixture.request())})
        )),
        cancelled
    );
    assert_eq!(fixture.counts().await, (1, 1, 0));
    fs::remove_dir_all(root).unwrap();
}
