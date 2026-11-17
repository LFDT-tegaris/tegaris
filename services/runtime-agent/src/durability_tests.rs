use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    public: Vec<u8>,
    desired: SignedEnvelope<DesiredGeneration>,
    token: SignedEnvelope<ActivationToken>,
    bundle: ArtifactBundle,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "openpc-agent-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let signer = tests::fleet_signer(PURPOSE_DESIRED_GENERATION_V1);
        let bundle = tests::bundle();
        let desired = signer.sign(tests::desired(&bundle, None)).unwrap();
        let token = tests::fleet_signer(PURPOSE_ACTIVATION_TOKEN_V1)
            .sign(ActivationToken {
                token_id: "durable-token".into(),
                occurrence_id: desired.claims.occurrence_id.clone(),
                target_id: desired.claims.target_id.clone(),
                capsule_digest: desired.claims.capsule_digest.clone(),
                xds_version_digest: desired.claims.xds_snapshot_digest.clone(),
                expected_previous_generation_digest: None,
                issued_at_ms: 100,
                expires_at_ms: 180,
            })
            .unwrap();
        Self {
            directory,
            public: signer.verifier().sec1_bytes(),
            desired,
            token,
            bundle,
        }
    }

    fn open(&self, capacity: usize) -> RuntimeAgent {
        RuntimeAgent::open(
            "target-1",
            &self.public,
            [4; 32],
            capacity,
            2048,
            &self.directory,
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn preparation_and_lost_activation_ack_recover_exactly_after_reopen() {
    let fixture = Fixture::new();
    let agent = fixture.open(4);
    let prepared = agent
        .prepare(&fixture.desired, &fixture.bundle, 100)
        .unwrap();
    drop(agent);
    let agent = fixture.open(4);
    assert_eq!(
        agent
            .prepare(&fixture.desired, &fixture.bundle, 101)
            .unwrap(),
        prepared
    );
    assert_eq!(agent.active_generation().unwrap(), None);
    let receipt = agent.activate(&fixture.token, 110).unwrap();
    // Simulate loss of the response after the owner's durable commit.
    drop(agent);
    let agent = fixture.open(4);
    assert_eq!(agent.replay_receipts().unwrap(), vec![receipt.clone()]);
    assert_eq!(
        agent.activate(&fixture.token, 111),
        Err(RuntimeError::Replay)
    );
    assert_eq!(
        agent.active_generation().unwrap(),
        Some((
            fixture.desired.claims.capsule_digest.clone(),
            fixture.desired.claims.xds_snapshot_digest.clone(),
            1
        ))
    );
    assert_eq!(receipt.claims.journal_sequence, 1);
}

#[test]
fn exclusive_process_owner_and_wrong_target_or_signer_fail_closed() {
    let fixture = Fixture::new();
    let agent = fixture.open(4);
    assert!(
        RuntimeAgent::open(
            "target-1",
            &fixture.public,
            [4; 32],
            4,
            2048,
            &fixture.directory
        )
        .is_err()
    );
    agent
        .prepare(&fixture.desired, &fixture.bundle, 100)
        .unwrap();
    agent.activate(&fixture.token, 110).unwrap();
    drop(agent);
    for (target, secret) in [("target-2", [4; 32]), ("target-1", [5; 32])] {
        assert!(
            RuntimeAgent::open(target, &fixture.public, secret, 4, 2048, &fixture.directory)
                .is_err()
        );
    }
    let agent = fixture.open(4);
    assert_eq!(agent.replay_receipts().unwrap().len(), 1);
}

#[test]
fn interrupted_staging_is_not_adopted_and_corrupt_committed_state_is_not_reset() {
    let fixture = Fixture::new();
    let agent = fixture.open(4);
    agent
        .prepare(&fixture.desired, &fixture.bundle, 100)
        .unwrap();
    drop(agent);
    fs::write(
        fixture.directory.join("activation.next"),
        b"partial replacement",
    )
    .unwrap();
    let agent = fixture.open(4);
    assert_eq!(agent.active_generation().unwrap(), None);
    agent.activate(&fixture.token, 110).unwrap();
    drop(agent);
    fs::write(fixture.directory.join("activation.json"), b"corrupt").unwrap();
    assert!(
        RuntimeAgent::open(
            "target-1",
            &fixture.public,
            [4; 32],
            4,
            2048,
            &fixture.directory
        )
        .is_err()
    );
    assert_eq!(
        fs::read(fixture.directory.join("activation.json")).unwrap(),
        b"corrupt"
    );
}

#[test]
fn uncertain_persistence_withholds_receipt_and_poisons_owner_until_recovery() {
    let fixture = Fixture::new();
    let agent = fixture.open(4);
    agent
        .prepare(&fixture.desired, &fixture.bundle, 100)
        .unwrap();
    // A failed exclusive staging-file creation is a real filesystem failure.
    fs::write(fixture.directory.join("activation.next"), b"interrupted").unwrap();
    assert_eq!(
        agent.activate(&fixture.token, 110),
        Err(RuntimeError::RuntimeUnavailable)
    );
    assert_eq!(
        agent.active_generation(),
        Err(RuntimeError::RuntimeUnavailable)
    );
    assert_eq!(
        agent.replay_receipts(),
        Err(RuntimeError::RuntimeUnavailable)
    );
    drop(agent);
    let agent = fixture.open(4);
    assert_eq!(agent.active_generation().unwrap(), None);
    assert_eq!(
        agent
            .activate(&fixture.token, 111)
            .unwrap()
            .claims
            .journal_sequence,
        1
    );
}

#[test]
fn preparation_conflict_expiry_and_local_capacity_cannot_be_overridden() {
    let fixture = Fixture::new();
    let agent = fixture.open(1);
    agent
        .prepare(&fixture.desired, &fixture.bundle, 100)
        .unwrap();
    let mut changed = fixture.desired.claims.clone();
    changed.xds_snapshot_digest = Digest::of("different");
    let signer = tests::fleet_signer(PURPOSE_DESIRED_GENERATION_V1);
    assert_eq!(
        agent.prepare(&signer.sign(changed.clone()).unwrap(), &fixture.bundle, 101),
        Err(RuntimeError::GenerationMismatch)
    );
    changed.occurrence_id = "another-occurrence".into();
    assert_eq!(
        agent.prepare(&signer.sign(changed).unwrap(), &fixture.bundle, 101),
        Err(RuntimeError::ReplayCapacity)
    );
    let mut late = fixture.token.claims.clone();
    late.expires_at_ms = 300;
    assert_eq!(
        agent.activate(
            &tests::fleet_signer(PURPOSE_ACTIVATION_TOKEN_V1)
                .sign(late)
                .unwrap(),
            201
        ),
        Err(RuntimeError::GenerationMismatch)
    );
    assert_eq!(agent.active_generation().unwrap(), None);
    drop(agent);
    assert!(
        RuntimeAgent::open(
            "target-1",
            &fixture.public,
            [4; 32],
            4,
            512,
            &fixture.directory
        )
        .is_err()
    );
}

#[test]
fn concurrent_activation_has_one_durable_winner() {
    let fixture = Fixture::new();
    let agent = fixture.open(4);
    agent
        .prepare(&fixture.desired, &fixture.bundle, 100)
        .unwrap();
    std::thread::scope(|scope| {
        let attempts = (0..8)
            .map(|_| scope.spawn(|| agent.activate(&fixture.token, 110)))
            .collect::<Vec<_>>();
        let results = attempts
            .into_iter()
            .map(|task| task.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(RuntimeError::Replay))
                .count(),
            7
        );
    });
    drop(agent);
    let agent = fixture.open(4);
    assert_eq!(agent.active_generation().unwrap().unwrap().2, 1);
    assert_eq!(agent.replay_receipts().unwrap().len(), 1);
}

#[test]
fn abrupt_process_exit_preserves_commit_before_receipt_delivery() {
    let fixture = Fixture::new();
    let agent = fixture.open(4);
    agent
        .prepare(&fixture.desired, &fixture.bundle, 100)
        .unwrap();
    drop(agent);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "durability_tests::activation_crash_child"])
        .env("OPENPC_AGENT_CRASH_TEST_DIRECTORY", &fixture.directory)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    let agent = fixture.open(4);
    assert_eq!(agent.active_generation().unwrap().unwrap().2, 1);
    assert_eq!(
        agent.activate(&fixture.token, 111),
        Err(RuntimeError::Replay)
    );
    assert_eq!(
        agent.replay_receipts().unwrap()[0].claims.occurrence_id,
        fixture.desired.claims.occurrence_id
    );
}

#[test]
fn activation_crash_child() {
    let Some(directory) = std::env::var_os("OPENPC_AGENT_CRASH_TEST_DIRECTORY") else {
        return;
    };
    let mut fixture = Fixture::new();
    fixture.directory = PathBuf::from(directory);
    let agent = fixture.open(4);
    agent.activate(&fixture.token, 110).unwrap();
    // Exit without destructors, receipt transmission or any parent-side flush.
    std::process::exit(73);
}

#[test]
fn symlink_journal_and_shared_writable_directory_are_rejected_without_following() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new();
    drop(fixture.open(4));
    let external = fixture.directory.join("unrelated");
    fs::write(&external, b"preserve").unwrap();
    symlink(&external, fixture.directory.join("activation.json")).unwrap();
    assert!(
        RuntimeAgent::open(
            "target-1",
            &fixture.public,
            [4; 32],
            4,
            2048,
            &fixture.directory
        )
        .is_err()
    );
    assert_eq!(fs::read(&external).unwrap(), b"preserve");
    fs::remove_file(fixture.directory.join("activation.json")).unwrap();
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        RuntimeAgent::open(
            "target-1",
            &fixture.public,
            [4; 32],
            4,
            2048,
            &fixture.directory
        )
        .is_err()
    );
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn receipt_capacity_holds_required_replay_window_then_reclaims_old_receipts() {
    let fixture = Fixture::new();
    let agent = fixture.open(2);
    agent
        .prepare(&fixture.desired, &fixture.bundle, 100)
        .unwrap();
    let first = agent.activate(&fixture.token, 110).unwrap();
    let mut bundle = fixture.bundle.clone();
    bundle.manifest_digest = Digest::of("second-manifest");
    let generation = Digest::of(canonical_bytes(&bundle).unwrap());
    let mut desired = fixture.desired.claims.clone();
    desired.occurrence_id = "second".into();
    desired.capsule_digest = generation.clone();
    desired.expected_previous_generation_digest =
        Some(fixture.desired.claims.capsule_digest.clone());
    desired.expires_at_ms = 2 * RECEIPT_REPLAY_WINDOW_MS;
    let mut token = fixture.token.claims.clone();
    token.token_id = "second-token".into();
    token.occurrence_id = desired.occurrence_id.clone();
    token.capsule_digest = generation.clone();
    token.expected_previous_generation_digest = desired.expected_previous_generation_digest.clone();
    token.expires_at_ms = desired.expires_at_ms;
    agent
        .prepare(
            &tests::fleet_signer(PURPOSE_DESIRED_GENERATION_V1)
                .sign(desired.clone())
                .unwrap(),
            &bundle,
            120,
        )
        .unwrap();
    let second = agent
        .activate(
            &tests::fleet_signer(PURPOSE_ACTIVATION_TOKEN_V1)
                .sign(token.clone())
                .unwrap(),
            121,
        )
        .unwrap();
    desired.occurrence_id = "third".into();
    desired.expected_previous_generation_digest = Some(generation);
    token.token_id = "third-token".into();
    token.occurrence_id = "third".into();
    token.expected_previous_generation_digest = desired.expected_previous_generation_digest.clone();
    agent
        .prepare(
            &tests::fleet_signer(PURPOSE_DESIRED_GENERATION_V1)
                .sign(desired)
                .unwrap(),
            &bundle,
            122,
        )
        .unwrap();
    let signed_token = tests::fleet_signer(PURPOSE_ACTIVATION_TOKEN_V1)
        .sign(token)
        .unwrap();
    assert_eq!(
        agent.activate(&signed_token, 123),
        Err(RuntimeError::ReplayCapacity)
    );
    assert_eq!(
        agent.replay_receipts().unwrap(),
        vec![first, second.clone()]
    );
    let third = agent
        .activate(&signed_token, 110 + RECEIPT_REPLAY_WINDOW_MS)
        .unwrap();
    assert_eq!(agent.replay_receipts().unwrap(), vec![second, third]);
    drop(agent);
    assert_eq!(fixture.open(2).active_generation().unwrap().unwrap().2, 3);
}

#[test]
fn outstanding_preparation_cannot_ack_a_stale_predecessor_after_cutover() {
    let fixture = Fixture::new();
    let agent = fixture.open(4);
    agent
        .prepare(&fixture.desired, &fixture.bundle, 100)
        .unwrap();
    let mut other = fixture.desired.claims.clone();
    other.occurrence_id = "competing-preparation".into();
    let signed = tests::fleet_signer(PURPOSE_DESIRED_GENERATION_V1)
        .sign(other)
        .unwrap();
    agent.prepare(&signed, &fixture.bundle, 100).unwrap();
    drop(agent);
    assert!(
        RuntimeAgent::open(
            "target-1",
            &fixture.public,
            [4; 32],
            4,
            1024,
            &fixture.directory
        )
        .is_err()
    );
    let agent = fixture.open(4);
    agent.activate(&fixture.token, 110).unwrap();
    assert_eq!(
        agent.prepare(&signed, &fixture.bundle, 111),
        Err(RuntimeError::GenerationMismatch)
    );
    assert_eq!(agent.active_generation().unwrap().unwrap().2, 1);
}
