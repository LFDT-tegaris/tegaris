//! Durable owner regressions; provider transport is the only simulated system.
use super::*;
use crate::tests::{MockProvider, bindings, decision, digest, request, response};
use pc_runtime_types::PurposeSigner;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "openpc-broker-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
    fn open(&self, capacity: usize) -> BrokerService {
        let signer =
            PurposeSigner::from_secret_bytes(PURPOSE_BROKER_CAPABILITY_V1, [9; 32]).unwrap();
        BrokerService::open(
            "target-1",
            &signer.verifier().sec1_bytes(),
            capacity,
            &self.0,
        )
        .unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if self.0.exists() {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
fn provider() -> MockProvider {
    MockProvider {
        outcomes: vec![ProviderOutcome::Response(response())],
        calls: 0,
        reconciliation: None,
        reconciliation_calls: 0,
    }
}
fn dispatch(
    broker: &BrokerService,
    id: &str,
    provider: &mut dyn ProviderTransport,
) -> RuntimeResult<AttemptResolution> {
    broker.dispatch(
        &request(RequestClass::Read),
        &bindings(),
        &decision(RequestClass::Read, id),
        110,
        &digest("anchor"),
        ReadLaw {
            same_route_retries: 0,
            parity_failover: false,
        },
        provider,
        None,
    )
}
#[test]
fn lost_reply_replay_and_metadata_survive_restart_without_storing_provider_body() {
    let directory = Directory::new();
    let broker = directory.open(4);
    let result = dispatch(&broker, "cap-durable", &mut provider()).unwrap();
    let before = broker.read_attempt(&result.attempt_id).unwrap();
    assert!(matches!(before.status, ReadAttemptStatus::Completed { .. }));
    let disk = fs::read_to_string(directory.0.join("broker.json")).unwrap();
    assert!(!disk.contains("jsonrpc"));
    drop(broker);
    let broker = directory.open(4);
    assert_eq!(broker.read_attempt(&result.attempt_id).unwrap(), before);
    let mut external = provider();
    assert_eq!(
        dispatch(&broker, "cap-durable", &mut external),
        Err(RuntimeError::Replay)
    );
    assert_eq!(external.calls, 0);
    let second = dispatch(&broker, "cap-next", &mut external).unwrap();
    assert_ne!(second.attempt_id, result.attempt_id);
}
#[test]
fn capacity_and_uncertain_admission_prevent_provider_contact() {
    let directory = Directory::new();
    let broker = directory.open(1);
    dispatch(&broker, "cap-first", &mut provider()).unwrap();
    let mut external = provider();
    assert_eq!(
        dispatch(&broker, "cap-full", &mut external),
        Err(RuntimeError::ReplayCapacity)
    );
    assert_eq!(external.calls, 0);
    drop(broker);
    let broker = directory.open(2);
    fs::create_dir(directory.0.join("broker.next")).unwrap();
    assert_eq!(
        dispatch(&broker, "cap-uncommitted", &mut external),
        Err(RuntimeError::RuntimeUnavailable)
    );
    assert_eq!(external.calls, 0);
    assert!(
        broker
            .read_attempt("local-attempt-0000000000000001")
            .is_err()
    );
    fs::remove_dir(directory.0.join("broker.next")).unwrap();
    assert!(dispatch(&broker, "cap-poisoned", &mut external).is_err());
    assert_eq!(external.calls, 0);
    drop(broker);
    let broker = directory.open(2);
    dispatch(&broker, "cap-uncommitted", &mut external).unwrap();
    assert_eq!(external.calls, 1);
}
#[test]
fn uncertain_terminal_commit_withholds_response_and_restarts_as_interrupted() {
    struct FailCommit(PathBuf);
    impl ProviderTransport for FailCommit {
        fn send(&mut self, _: &RuntimeRequest, _: &str) -> ProviderOutcome {
            fs::create_dir(self.0.join("broker.next")).unwrap();
            ProviderOutcome::Response(response())
        }
        fn reconcile(&mut self, _: &Digest) -> Option<ProviderResponse> {
            panic!()
        }
    }
    let directory = Directory::new();
    let broker = directory.open(2);
    assert_eq!(
        dispatch(
            &broker,
            "cap-uncertain",
            &mut FailCommit(directory.0.clone())
        ),
        Err(RuntimeError::RuntimeUnavailable)
    );
    drop(broker);
    fs::remove_dir(directory.0.join("broker.next")).unwrap();
    let broker = directory.open(2);
    assert_eq!(
        broker
            .read_attempt("local-attempt-0000000000000001")
            .unwrap()
            .status,
        ReadAttemptStatus::Interrupted
    );
    let mut external = provider();
    assert_eq!(
        dispatch(&broker, "cap-uncertain", &mut external),
        Err(RuntimeError::Replay)
    );
    assert_eq!(external.calls, 0);
}
#[test]
fn broker_crash_child() {
    let Some(path) = std::env::var_os("OPENPC_BROKER_CRASH_PATH") else {
        return;
    };
    struct ExitProvider;
    impl ProviderTransport for ExitProvider {
        fn send(&mut self, _: &RuntimeRequest, _: &str) -> ProviderOutcome {
            std::process::exit(74);
        }
        fn reconcile(&mut self, _: &Digest) -> Option<ProviderResponse> {
            panic!()
        }
    }
    let directory = Directory(PathBuf::from(path));
    let broker = directory.open(2);
    let _ = dispatch(&broker, "cap-crash", &mut ExitProvider);
    panic!("provider must terminate child");
}
#[test]
fn abrupt_process_exit_retains_consumption_and_never_reissues_provider_request() {
    let directory = Directory::new();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "durability_tests::broker_crash_child",
            "--nocapture",
        ])
        .env("OPENPC_BROKER_CRASH_PATH", &directory.0)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(74));
    let broker = directory.open(2);
    assert_eq!(
        broker
            .read_attempt("local-attempt-0000000000000001")
            .unwrap()
            .status,
        ReadAttemptStatus::Interrupted
    );
    let mut external = provider();
    assert_eq!(
        dispatch(&broker, "cap-crash", &mut external),
        Err(RuntimeError::Replay)
    );
    assert_eq!(external.calls, 0);
}
