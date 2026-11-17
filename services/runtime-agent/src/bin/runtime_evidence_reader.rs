//! Bounded off-path adapter over the authoritative spool and primary activation
//! receipt owners. Host worker configuration supplies paths, keys and scope.
use openpc_runtime_agent::{
    RuntimeWireVerifier,
    decision_evidence::{EvidenceSpoolBinding, read_spool_for_export},
};
use pc_runtime_types::Digest;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    Unavailable,
    Rejected,
}
impl Failure {
    // Closed diagnostics only: never format the underlying error or input.
    fn diagnostic(self) -> &'static [u8] {
        match self {
            Self::Unavailable => b"{\"version\":1,\"code\":\"UNAVAILABLE\"}\n",
            Self::Rejected => b"{\"version\":1,\"code\":\"REJECTED\"}\n",
        }
    }
}

#[derive(Deserialize, serde::Serialize)]
#[serde(tag = "command", content = "value", deny_unknown_fields)]
enum Input {
    Read {
        directory: PathBuf,
        binding: EvidenceSpoolBinding,
        key_file: PathBuf,
        after_sequence: u64,
        prior_source_digest: Option<Digest>,
    },
    VerifyActivations {
        target_runtime_id: String,
        signer_id: String,
        public_key_file: PathBuf,
        receipts: BTreeMap<String, String>,
        records: Vec<ExpectedActivation>,
    },
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedActivation {
    capsule_digest: Digest,
    reserved_at_ns: String,
}

fn hex(value: &str) -> Result<Vec<u8>, ()> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() > 524_288
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
fn key_file(path: &Path) -> Result<[u8; 32], Failure> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(Failure::Rejected);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| Failure::Unavailable)?;
    if !metadata.is_file() || metadata.len() > 128 {
        return Err(Failure::Rejected);
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| Failure::Unavailable)?
        .take(129)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Unavailable)?;
    if bytes.len() > 128 {
        return Err(Failure::Rejected);
    }
    // UTF-8/hex rejection is not filesystem unavailability.
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Rejected)?;
    hex(text.trim())
        .map_err(|_| Failure::Rejected)?
        .try_into()
        .map_err(|_| Failure::Rejected)
}
fn execute(input: Input) -> Result<serde_json::Value, Failure> {
    match input {
        Input::Read {
            directory,
            binding,
            key_file: path,
            after_sequence,
            prior_source_digest,
        } => {
            if !directory.is_absolute() {
                return Err(Failure::Rejected);
            }
            let records = read_spool_for_export(
                &directory,
                &binding,
                key_file(&path)?,
                after_sequence,
                prior_source_digest.as_ref(),
            )
            // RuntimeUnavailable also represents malformed stored JSON and
            // unsafe storage shapes. Its cause is not classified by this API.
            .map_err(|_| Failure::Rejected)?;
            serde_json::to_value(records).map_err(|_| Failure::Rejected)
        }
        Input::VerifyActivations {
            target_runtime_id,
            signer_id,
            public_key_file,
            receipts,
            records,
        } => {
            if records.is_empty() || records.len() > 8 || receipts.is_empty() || receipts.len() > 8
            {
                return Err(Failure::Rejected);
            }
            let public_key = key_file(&public_key_file)?;
            let verifier = RuntimeWireVerifier::from_public_key_bytes(&public_key)
                .map_err(|_| Failure::Rejected)?;
            let mut verified = BTreeMap::new();
            for (digest, bytes) in receipts {
                let receipt = verifier
                    .verify_receipt(&hex(&bytes).map_err(|_| Failure::Rejected)?)
                    .map_err(|_| Failure::Rejected)?;
                if receipt.target_runtime_id != target_runtime_id
                    || receipt.signer_id != signer_id
                    || receipt.capsule_digest.as_str() != digest
                    || receipt.status != 1
                    || receipt.reason_code != "ACTIVE_LOCAL"
                {
                    return Err(Failure::Rejected);
                }
                verified.insert(digest, receipt.observed_at_ns);
            }
            for record in records {
                if *verified
                    .get(record.capsule_digest.as_str())
                    .ok_or(Failure::Rejected)?
                    > record
                        .reserved_at_ns
                        .parse::<u64>()
                        .map_err(|_| Failure::Rejected)?
                {
                    return Err(Failure::Rejected);
                }
            }
            Ok(
                serde_json::json!({"verified":true,"authority":"NONE", "verificationKeyDigest": Digest::of(public_key)}),
            )
        }
    }
}
fn run(input: impl Read, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    let mut bytes = Vec::new();
    let result = input
        .take(2_097_153)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Rejected)
        .and({
            if bytes.len() > 2_097_152 {
                Err(Failure::Rejected)
            } else {
                Ok(())
            }
        })
        .and_then(|_| serde_json::from_slice(&bytes).map_err(|_| Failure::Rejected))
        .and_then(execute);
    let failure = match result {
        Ok(result) if writeln!(stdout, "{result}").is_ok() => return 0,
        Ok(_) => Failure::Rejected,
        Err(failure) => failure,
    };
    // A broken output pipe must not trigger panic diagnostics containing input.
    let _ = stderr.write_all(failure.diagnostic());
    1
}

fn main() -> ExitCode {
    ExitCode::from(run(
        io::stdin().lock(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpc_runtime_agent::decision_evidence::DecisionEvidenceStore;
    use openpc_runtime_agent::{RuntimeWireSigner, TargetActivationReceipt};
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    fn wire(bytes: &[u8]) -> (u8, Vec<u8>, Vec<u8>) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(bytes, &mut stdout, &mut stderr);
        (exit, stdout, stderr)
    }

    fn assert_wire_failure(input: Input, expected: &[u8]) {
        let (exit, stdout, stderr) = wire(&serde_json::to_vec(&input).unwrap());
        assert_eq!(exit, 1);
        assert!(
            stdout.is_empty(),
            "failure must not look like an empty batch"
        );
        assert_eq!(stderr, expected);
        assert!(stderr.len() <= 128);
        assert_eq!(stderr.iter().filter(|&&byte| byte == b'\n').count(), 1);
    }

    fn assert_wire_success(input: Input, expected: serde_json::Value) {
        assert_eq!(
            wire(&serde_json::to_vec(&input).unwrap()),
            (0, format!("{expected}\n").into_bytes(), vec![])
        );
    }

    fn test_directory(prefix: &str) -> PathBuf {
        let root = std::env::var_os("OPENPC_LOCAL_RUNTIME_TMP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)
            .unwrap();
        let directory = root.join(format!("{prefix}-{}", uuid::Uuid::now_v7()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        directory
    }

    struct SpoolFixture {
        root: PathBuf,
        directory: PathBuf,
        binding: EvidenceSpoolBinding,
        key: PathBuf,
    }
    impl SpoolFixture {
        fn new() -> Self {
            let root = test_directory("native-spool-reader");
            let directory = root.join("spool");
            let binding = EvidenceSpoolBinding {
                participant_id: uuid::Uuid::now_v7().to_string(),
                privacy_domain_id: uuid::Uuid::now_v7().to_string(),
                target_runtime_id: "reader-runtime".into(),
                spool_id: "reader-spool".into(),
                key_id: "reader-key".into(),
            };
            drop(
                DecisionEvidenceStore::open_sealed(&directory, binding.clone(), [53; 32], 8)
                    .unwrap(),
            );
            let key = root.join("spool.key");
            Self {
                root,
                directory,
                binding,
                key,
            }
        }
        fn install_key(&self) {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&self.key)
                .unwrap();
            file.write_all("35".repeat(32).as_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        fn request(&self, path: &Path) -> Input {
            Input::Read {
                directory: self.directory.clone(),
                binding: self.binding.clone(),
                key_file: path.to_owned(),
                after_sequence: 0,
                prior_source_digest: None,
            }
        }
    }
    impl Drop for SpoolFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn missing_and_restored_reader_key_preserves_the_exact_committed_spool() {
        let f = SpoolFixture::new();
        let committed = f.directory.join("sealed-decisions.json");
        let original = fs::read(&committed).unwrap();
        let pending = f.directory.join("sealed-decisions.next");
        fs::write(&pending, b"off-path reader must not perform recovery").unwrap();
        // Key absence is not an empty result, successful export or new spool.
        assert_eq!(execute(f.request(&f.key)), Err(Failure::Unavailable));
        assert_wire_failure(
            f.request(&f.key),
            b"{\"version\":1,\"code\":\"UNAVAILABLE\"}\n",
        );
        assert_eq!(fs::read(&committed).unwrap(), original);
        f.install_key();
        assert_eq!(execute(f.request(&f.key)).unwrap(), serde_json::json!([]));
        assert_wire_success(f.request(&f.key), serde_json::json!([]));
        fs::remove_file(&f.key).unwrap();
        assert_eq!(execute(f.request(&f.key)), Err(Failure::Unavailable));
        assert_wire_failure(
            f.request(&f.key),
            b"{\"version\":1,\"code\":\"UNAVAILABLE\"}\n",
        );
        f.install_key();
        assert_eq!(execute(f.request(&f.key)).unwrap(), serde_json::json!([]));
        assert_wire_success(f.request(&f.key), serde_json::json!([]));
        assert_eq!(fs::read(&committed).unwrap(), original);
        assert_eq!(
            fs::read(&pending).unwrap(),
            b"off-path reader must not perform recovery"
        );
        assert!(!f.directory.join("decisions.json").exists());
    }

    #[test]
    fn rejected_key_inputs_scope_and_cursor_never_become_successful_empty_export() {
        let f = SpoolFixture::new();
        let original = fs::read(f.directory.join("sealed-decisions.json")).unwrap();
        assert_eq!(
            execute(f.request(Path::new("relative.key"))),
            Err(Failure::Rejected)
        );
        assert_eq!(execute(f.request(&f.root)), Err(Failure::Rejected));
        let nul_path = f.root.join("private\0key");
        for path in [
            Path::new("relative.key"),
            f.root.as_path(),
            nul_path.as_path(),
        ] {
            assert_wire_failure(f.request(path), b"{\"version\":1,\"code\":\"REJECTED\"}\n");
        }
        for bytes in [
            String::new(),
            "35".repeat(31),
            "35".repeat(33),
            "gg".repeat(32),
            "35".repeat(65),
            "36".repeat(32), // Well-formed but cryptographically wrong.
        ] {
            fs::write(&f.key, bytes).unwrap();
            assert_eq!(execute(f.request(&f.key)), Err(Failure::Rejected));
            assert_wire_failure(
                f.request(&f.key),
                b"{\"version\":1,\"code\":\"REJECTED\"}\n",
            );
            assert_eq!(
                fs::read(f.directory.join("sealed-decisions.json")).unwrap(),
                original
            );
        }
        fs::remove_file(&f.key).unwrap();
        f.install_key();
        let symlink = f.root.join("redirected.key");
        std::os::unix::fs::symlink(&f.key, &symlink).unwrap();
        assert_eq!(execute(f.request(&symlink)), Err(Failure::Rejected));
        assert_wire_failure(
            f.request(&symlink),
            b"{\"version\":1,\"code\":\"REJECTED\"}\n",
        );
        let mut binding = f.binding.clone();
        binding.privacy_domain_id = uuid::Uuid::now_v7().to_string();
        assert_eq!(
            execute(Input::Read {
                directory: f.directory.clone(),
                binding,
                key_file: f.key.clone(),
                after_sequence: 0,
                prior_source_digest: None,
            }),
            Err(Failure::Rejected)
        );
        for (after_sequence, prior_source_digest) in [
            (0, Some(Digest::of(b"invented"))),
            (1, None),
            (1, Some(Digest::of(b"invented"))),
        ] {
            assert_eq!(
                execute(Input::Read {
                    directory: f.directory.clone(),
                    binding: f.binding.clone(),
                    key_file: f.key.clone(),
                    after_sequence,
                    prior_source_digest,
                }),
                Err(Failure::Rejected)
            );
        }
        assert_eq!(execute(f.request(&f.key)).unwrap(), serde_json::json!([]));
        assert_eq!(
            fs::read(f.directory.join("sealed-decisions.json")).unwrap(),
            original
        );
    }

    #[test]
    fn malformed_input_and_key_encoding_emit_only_fixed_rejection() {
        for bytes in [
            b"private-malformed-input".to_vec(),
            vec![0xff],
            br#"{"command":"Unknown","value":{"key":"private-value"}}"#.to_vec(),
            vec![b' '; 2_097_153],
        ] {
            assert_eq!(
                wire(&bytes),
                (
                    1,
                    vec![],
                    b"{\"version\":1,\"code\":\"REJECTED\"}\n".to_vec()
                )
            );
        }
        let f = SpoolFixture::new();
        fs::write(&f.key, [0xff; 64]).unwrap();
        assert_wire_failure(
            f.request(&f.key),
            b"{\"version\":1,\"code\":\"REJECTED\"}\n",
        );
        fs::remove_file(&f.key).unwrap();
        f.install_key();
        let mut input = serde_json::to_value(f.request(&f.key)).unwrap();
        input["value"]["unexpected"] = "private-field".into();
        assert_eq!(
            wire(&serde_json::to_vec(&input).unwrap()),
            (
                1,
                vec![],
                b"{\"version\":1,\"code\":\"REJECTED\"}\n".to_vec()
            )
        );
    }

    #[test]
    fn ambiguous_spool_read_failures_remain_rejected_without_mutation() {
        let f = SpoolFixture::new();
        f.install_key();
        let committed = f.directory.join("sealed-decisions.json");
        let original = fs::read(&committed).unwrap();
        fs::remove_file(&committed).unwrap();
        assert_wire_failure(
            f.request(&f.key),
            b"{\"version\":1,\"code\":\"REJECTED\"}\n",
        );
        assert!(!committed.exists());
        fs::write(&committed, b"private-malformed-stored-state").unwrap();
        assert_wire_failure(
            f.request(&f.key),
            b"{\"version\":1,\"code\":\"REJECTED\"}\n",
        );
        assert_eq!(
            fs::read(&committed).unwrap(),
            b"private-malformed-stored-state"
        );
        fs::write(&committed, &original).unwrap();
        assert_wire_success(f.request(&f.key), serde_json::json!([]));
        assert_eq!(fs::read(&committed).unwrap(), original);
    }

    #[test]
    fn archive_activation_uses_primary_receipt_trust_exact_target_capsule_and_time() {
        let root = test_directory("rpc-source-trust");
        let key = root.join("agent-public.hex");
        let signer = RuntimeWireSigner::from_secret_bytes([71; 32]).unwrap();
        let hex_encode =
            |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        fs::write(&key, hex_encode(&signer.verifier().public_key_bytes())).unwrap();
        let capsule = Digest::of(b"actual-capsule");
        let receipt = TargetActivationReceipt {
            receipt_id: uuid::Uuid::now_v7().to_string(),
            target_runtime_id: "runtime-one".into(),
            capsule_digest: capsule.clone(),
            contract_set_manifest_digest: Digest::of(b"contracts"),
            complete_component_set_digest: Digest::of(b"components"),
            status: 1,
            reason_code: "ACTIVE_LOCAL".into(),
            observed_at_ns: 7,
            agent_sequence: 1,
            signer_id: "runtime-agent".into(),
        };
        let signed = hex_encode(&signer.sign_receipt(&receipt).unwrap());
        let request =
            |target: &str, expected: Digest, time: u64, bytes: &str| Input::VerifyActivations {
                target_runtime_id: target.into(),
                signer_id: "runtime-agent".into(),
                public_key_file: key.clone(),
                receipts: BTreeMap::from([(capsule.as_str().into(), bytes.into())]),
                records: vec![ExpectedActivation {
                    capsule_digest: expected,
                    reserved_at_ns: time.to_string(),
                }],
            };
        assert_eq!(
            execute(request("runtime-one", capsule.clone(), 8, &signed)).unwrap(),
            serde_json::json!({"verified":true,"authority":"NONE", "verificationKeyDigest": Digest::of(signer.verifier().public_key_bytes())})
        );
        fs::remove_file(&key).unwrap();
        assert_wire_failure(
            request("runtime-one", capsule.clone(), 8, &signed),
            b"{\"version\":1,\"code\":\"UNAVAILABLE\"}\n",
        );
        fs::write(&key, hex_encode(&signer.verifier().public_key_bytes())).unwrap();
        assert_wire_success(
            request("runtime-one", capsule.clone(), 8, &signed),
            serde_json::json!({"verified":true,"authority":"NONE", "verificationKeyDigest": Digest::of(signer.verifier().public_key_bytes())}),
        );
        assert!(execute(request("foreign-runtime", capsule.clone(), 8, &signed)).is_err());
        assert!(
            execute(request(
                "runtime-one",
                Digest::of(b"foreign-capsule"),
                8,
                &signed
            ))
            .is_err()
        );
        assert!(execute(request("runtime-one", capsule.clone(), 6, &signed)).is_err());
        let mut rejected = receipt.clone();
        rejected.status = 2;
        assert!(
            execute(request(
                "runtime-one",
                capsule.clone(),
                8,
                &hex_encode(&signer.sign_receipt(&rejected).unwrap())
            ))
            .is_err()
        );
        let wrong = RuntimeWireSigner::from_secret_bytes([72; 32]).unwrap();
        assert!(
            execute(request(
                "runtime-one",
                capsule.clone(),
                8,
                &hex_encode(&wrong.sign_receipt(&receipt).unwrap())
            ))
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
