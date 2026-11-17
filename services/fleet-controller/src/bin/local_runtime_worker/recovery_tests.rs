//! Component join after the public profile approval fixture: real local
//! activation custody and the production PostgreSQL observation writer. This
//! does not claim a second public serving/convergence journey.
use super::*;
use pc_runtime_types::{RuntimeError, RuntimeResult};

/// Existing installed local-runtime fixture only. Config supplies verification
/// trust, the real target certificate supplies identity, and Control selects
/// the original work. Nothing here seeds activation, approval, ACK or success.
struct TargetFactFixture {
    config: Config,
    pool: PgPool,
    store: openpc_fleet_controller::target_disposition::TargetDispositionStore,
    facts: disposition_restore::FactCustody,
    verifier: FactSignatureVerifier,
    peer: TargetIdentity,
    original: retained_target::RetainedTarget,
}
impl TargetFactFixture {
    async fn read() -> Self {
        use openpc_fleet_controller::target_disposition::TargetDispositionStore;
        let config = Config::read().unwrap();
        let pool = config.connect().await.unwrap();
        let installed = RuntimePlaneConfig::read().unwrap();
        let peer = runtime_tls::target_identity_from_pem(
            &fs::read(&installed.target_client_certificate).unwrap(),
        )
        .unwrap();
        let mut tx = result_transaction(&pool, &config, "RUNTIME_ACTIVATION")
            .await
            .unwrap();
        let row = sqlx::query("select w.configuration_work_id::text work,w.operation_id::text operation,(select ot.activation_occurrence_id::text from control.policy_activation_occurrence_target ot where ot.participant_id=w.participant_id and ot.privacy_domain_id=w.privacy_domain_id and ot.configuration_work_id=w.configuration_work_id) occurrence,w.runtime_configuration_generation_id::text generation,w.policy_generation_digest,w.predecessor_digest,w.xds_version_digest,w.execution_attempt_id::text attempt from control.configuration_work w join control.runtime_target_disposition_admission a on a.participant_id=w.participant_id and a.privacy_domain_id=w.privacy_domain_id and a.binding->'source'->>'original_work_id'=w.configuration_work_id::text where a.runtime_target_id=$1::text::uuid and w.state='COMPLETED' order by a.revision desc limit 1")
            .bind(&peer.target_id).fetch_one(&mut *tx).await.unwrap();
        // A selector for read_from, never passed to execute/complete/retry.
        let mut selector = super::tests::work();
        selector.participant_id = config.participant_id.clone();
        selector.privacy_domain_id = config.privacy_domain_id.clone();
        selector.work_id = row.get("work");
        selector.operation_id = row.get("operation");
        selector.occurrence_id = row.get("occurrence");
        selector.target_id = Some(peer.target_id.clone());
        selector.generation_id = Some(row.get("generation"));
        selector.execution_attempt_id = row.get("attempt");
        selector.policy.as_mut().unwrap().generation_digest =
            parse_digest(row.get("policy_generation_digest")).unwrap();
        selector.predecessor_digest = row
            .get::<Option<String>, _>("predecessor_digest")
            .map(|value| parse_digest(value).unwrap());
        selector.xds_version_digest = Some(parse_digest(row.get("xds_version_digest")).unwrap());
        tx.rollback().await.unwrap();
        let original = retained_target::read_from(
            &config,
            &selector,
            &PathBuf::from(required("OPENPC_TARGET_FACT_JOURNAL_ROOT").unwrap()),
        )
        .unwrap()
        .unwrap();
        assert_ne!(
            original.capsule.policy_fact_state_digest,
            Digest::of(openpc_runtime_agent::indexer_custody::NO_FACT_PUBLICATION)
        );
        let store = TargetDispositionStore::from_host_installation(
            pool.clone(),
            config.participant_id.clone(),
            config.privacy_domain_id.clone(),
            config.fleet_key,
            read_key(&required("CONTROL_WORKER_TARGET_DISPOSITION_KEY_FILE").unwrap()).unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        store
            .register_host_target_key(
                &peer.target_id,
                &PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, config.agent_key)
                    .unwrap()
                    .verifier()
                    .sec1_bytes(),
            )
            .unwrap();
        store
            .register_host_runtime_target_key(
                &peer.target_id,
                &RuntimeWireSigner::from_secret_bytes(config.agent_key)
                    .unwrap()
                    .verifier()
                    .public_key_bytes(),
            )
            .unwrap();
        let verifier = FactSignatureVerifier::from_key_identifier(
            &config.fact_verify_key_id,
            &config.fact_verify_key,
        )
        .unwrap();
        let facts = disposition_restore::FactCustody::connect(&config)
            .await
            .unwrap();
        Self {
            config,
            pool,
            store,
            facts,
            verifier,
            peer,
            original,
        }
    }
    fn input(&self) -> openpc_fleet_controller::target_disposition::OriginalTargetActivation<'_> {
        openpc_fleet_controller::target_disposition::OriginalTargetActivation {
            peer: &self.peer,
            capsule: &self.original.capsule,
            signed_token: &self.original.activation_token,
            signed_receipt: &self.original.activation_receipt,
            artifacts: &self.original.artifacts,
        }
    }
    fn trust(&self) -> openpc_fleet_controller::target_disposition::TargetFactTrust<'_> {
        openpc_fleet_controller::target_disposition::TargetFactTrust {
            fact_verifier: &self.verifier,
            installed_authority_signer_id: &self.config.worker_id,
        }
    }
    async fn snapshot(&self) -> Value {
        let mut tx = result_transaction(&self.pool, &self.config, "RUNTIME_ACTIVATION")
            .await
            .unwrap();
        let value: Value = sqlx::query_scalar("select jsonb_build_object('admissions',(select jsonb_agg(to_jsonb(a) order by revision) from control.runtime_target_disposition_admission a where runtime_target_id=$1::text::uuid),'deliveries',(select jsonb_agg(to_jsonb(d) order by revision) from control.runtime_target_disposition_delivery d where runtime_target_id=$1::text::uuid),'acknowledgements',(select jsonb_agg(to_jsonb(k) order by delivery_digest) from control.runtime_target_disposition_acknowledgement k where runtime_target_id=$1::text::uuid),'work',(select jsonb_agg(to_jsonb(w) order by configuration_work_id) from control.configuration_work w where runtime_target_id=$1::text::uuid),'observations',(select jsonb_agg(to_jsonb(o) order by configuration_work_id) from control.runtime_activation_observation o where runtime_target_id=$1::text::uuid))")
            .bind(&self.peer.target_id).fetch_one(&mut *tx).await.unwrap();
        tx.rollback().await.unwrap();
        value
    }
}

#[tokio::test]
#[ignore = "requires an exclusively owned, freshly completed public Fact runtime fixture and both real databases"]
async fn native_fact_confirmation_matches_original_rows_and_rejects_changed_custody() {
    let fixture = TargetFactFixture::read().await;
    let before = fixture.snapshot().await;
    let head = before["admissions"].as_array().unwrap().last().unwrap();
    assert_eq!(head["binding"]["action"], "ConfirmActivation");
    let proof = &head["activation_proof"];
    assert_eq!(proof["sourceMode"], "FACT_BOUND");
    let prepared = fixture
        .store
        .prepare_target_fact_custody(
            fixture.facts.reader(),
            fixture.trust(),
            &fixture.original.capsule,
            &fixture.original.artifacts,
            5000,
        )
        .await
        .unwrap();
    let custody = &proof["factCustody"];
    assert_eq!(custody["capsuleDigest"], prepared.capsule_digest().as_str());
    assert_eq!(
        custody["factStateDigest"],
        fixture.original.capsule.policy_fact_state_digest.as_str()
    );
    assert_eq!(
        custody["dependencyDigest"],
        prepared.facts().dependency_digest().as_str()
    );
    assert_eq!(
        custody["originalRecordsDigest"],
        prepared.facts().original_records_digest().as_str()
    );
    let until: u64 = custody["validUntilNs"].as_str().unwrap().parse().unwrap();
    assert!(until <= prepared.facts().valid_until_ns());
    assert!(now_ms().unwrap().saturating_mul(1_000_000) < until);
    for _ in 0..2 {
        // This fixture requires the original committed head and ACK. This is
        // exact replay coverage, never an uncertain/absent-head signing test.
        assert!(
            fixture
                .store
                .lookup_fact_activation_confirmation(
                    fixture.input(),
                    fixture.facts.reader(),
                    fixture.trust()
                )
                .await
                .unwrap()
        );
        assert_eq!(fixture.snapshot().await, before);
    }
    for changed in [
        "target",
        "certificate",
        "epoch",
        "token",
        "receipt",
        "capsule",
        "artifact",
        "signer",
    ] {
        let mut peer = fixture.peer.clone();
        let mut capsule = fixture.original.capsule.clone();
        let mut token = fixture.original.activation_token.clone();
        let mut receipt = fixture.original.activation_receipt.clone();
        let mut artifacts = fixture.original.artifacts.clone();
        let mut trust = fixture.trust();
        match changed {
            "target" => peer.target_id = uuid::Uuid::now_v7().to_string(),
            "certificate" => peer.certificate_fingerprint = Digest::of(b"other installed peer"),
            "epoch" => peer.workload_epoch += 1,
            "token" => token[0] ^= 1,
            "receipt" => receipt[0] ^= 1,
            "capsule" => capsule.hard_expiry_ns += 1,
            "artifact" => {
                let component = capsule
                    .artifact_components
                    .iter()
                    .find(|component| component.component_id == "openpc.fact.signed-shard")
                    .unwrap();
                artifacts.get_mut(&component.content_digest).unwrap()[0] ^= 1;
            }
            "signer" => trust.installed_authority_signer_id = "other-host",
            _ => unreachable!(),
        }
        let original = openpc_fleet_controller::target_disposition::OriginalTargetActivation {
            peer: &peer,
            capsule: &capsule,
            signed_token: &token,
            signed_receipt: &receipt,
            artifacts: &artifacts,
        };
        assert!(
            fixture
                .store
                .lookup_fact_activation_confirmation(original, fixture.facts.reader(), trust)
                .await
                .is_err(),
            "{changed}"
        );
        assert_eq!(fixture.snapshot().await, before, "{changed}");
    }
    // The live-boundary assertions prevent expiry from impersonating these
    // intended custody denials; a slow fixture fails instead of mislabelling.
    assert!(now_ms().unwrap().saturating_mul(1_000_000) < until);
    for foreign_participant in [false, true] {
        let foreign = uuid::Uuid::now_v7().to_string();
        let store = openpc_fleet_controller::target_disposition::TargetDispositionStore::from_host_installation(
            fixture.pool.clone(),
            if foreign_participant { foreign.clone() } else { fixture.config.participant_id.clone() },
            if foreign_participant { fixture.config.privacy_domain_id.clone() } else { foreign },
            fixture.config.fleet_key,
            read_key(&required("CONTROL_WORKER_TARGET_DISPOSITION_KEY_FILE").unwrap()).unwrap(),
            BTreeMap::new(),
        ).unwrap();
        store
            .register_host_target_key(
                &fixture.peer.target_id,
                &PurposeSigner::from_secret_bytes(
                    PURPOSE_ACTIVATION_RECEIPT_V1,
                    fixture.config.agent_key,
                )
                .unwrap()
                .verifier()
                .sec1_bytes(),
            )
            .unwrap();
        store
            .register_host_runtime_target_key(
                &fixture.peer.target_id,
                &RuntimeWireSigner::from_secret_bytes(fixture.config.agent_key)
                    .unwrap()
                    .verifier()
                    .public_key_bytes(),
            )
            .unwrap();
        assert!(
            store
                .lookup_fact_activation_confirmation(
                    fixture.input(),
                    fixture.facts.reader(),
                    fixture.trust()
                )
                .await
                .is_err()
        );
        assert_eq!(fixture.snapshot().await, before);
    }
    assert!(now_ms().unwrap().saturating_mul(1_000_000) < until);
}

#[tokio::test]
#[ignore = "requires an original expired public Fact activation with retained target journal and both real databases"]
async fn native_fact_expiry_preserves_historical_result_without_renewal() {
    let fixture = TargetFactFixture::read().await;
    let before = fixture.snapshot().await;
    let head = before["admissions"].as_array().unwrap().last().unwrap();
    let until: u64 = head["activation_proof"]["factCustody"]["validUntilNs"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(now_ms().unwrap().saturating_mul(1_000_000) >= until);
    assert!(
        fixture
            .store
            .lookup_fact_activation_confirmation(
                fixture.input(),
                fixture.facts.reader(),
                fixture.trust()
            )
            .await
            .is_err()
    );
    assert_eq!(fixture.snapshot().await, before);
}

#[tokio::test]
#[ignore = "requires an exclusive fresh public Fact predecessor, a queued public successor, the real target, and installed runtime paths"]
async fn native_fact_restore_follows_three_real_unstarted_worker_failures() {
    use openpc_fleet_controller::target_disposition::{OriginalTargetActivation, TargetFactTrust};
    use pc_runtime_types::target_disposition::{
        TARGET_DISPOSITION_ACK_PURPOSE, TARGET_DISPOSITION_DELIVERY_PURPOSE,
        TargetDispositionAction, TargetDispositionIdentity, TargetDispositionSource,
        TargetDispositionVerifier,
    };
    let fixture = TargetFactFixture::read().await;
    let before = fixture.snapshot().await;
    let expected_source: TargetDispositionSource = serde_json::from_value(
        before["admissions"].as_array().unwrap().last().unwrap()["binding"]["source"].clone(),
    )
    .unwrap();
    let expected_target: TargetDispositionIdentity = serde_json::from_value(
        before["admissions"].as_array().unwrap().last().unwrap()["binding"]["target"].clone(),
    )
    .unwrap();
    let expected_work = required("OPENPC_TARGET_FACT_FAILED_WORK_ID").unwrap();
    assert!(
        before["work"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |work| work["configuration_work_id"] == expected_work && work["state"] == "PENDING"
            )
    );
    let TargetFactFixture {
        mut config,
        pool,
        store,
        facts,
        verifier,
        peer,
        original,
    } = fixture;
    let original_digest = original.capsule.digest().unwrap();
    let trust = || TargetFactTrust {
        fact_verifier: &verifier,
        installed_authority_signer_id: &config.worker_id,
    };
    let prepared = store
        .prepare_target_fact_custody(
            facts.reader(),
            trust(),
            &original.capsule,
            &original.artifacts,
            5000,
        )
        .await
        .unwrap();
    let original_until = prepared.facts().valid_until_ns();
    assert!(now_ms().unwrap().saturating_mul(1_000_000) < original_until);
    // A real host quota rejects reopening the retained artifact set before
    // mark_effect_started. Do not edit work rows or manufacture NO_EFFECT.
    config.artifact_capacity_bytes = 1;
    let inputs = openpc_fleet_controller::runtime_configuration_input::RuntimeConfigurationInputSource::from_environment().unwrap();
    let source = openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker::from_environment(
        &pool, &config.participant_id, &config.privacy_domain_id, inputs.as_ref().map(|value| value.path()),
    ).await.unwrap();
    let plane = RuntimePlane::start(&config, &pool, facts, source)
        .await
        .unwrap();
    struct StopServer(tokio::task::AbortHandle);
    impl Drop for StopServer {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _server = StopServer(plane.server.abort_handle());
    for attempt in 1..=3 {
        let work = claim(&pool, &config).await.unwrap().unwrap();
        assert_eq!(work.work_id, expected_work);
        assert_eq!(work.attempt_count, attempt);
        assert_eq!(work.predecessor_digest.as_ref(), Some(&original_digest));
        assert!(!work.reconcile_only);
        assert!(work.execution_attempt_id.is_none());
        assert_eq!(
            execute(&pool, &work, &config, &plane).await.unwrap_err(),
            "canonical runtime agent open rejected"
        );
        let mut tx = result_transaction(&pool, &config, "RUNTIME_ACTIVATION")
            .await
            .unwrap();
        let untouched: bool = sqlx::query_scalar("select execution_started_at is null and execution_attempt_id is null and not exists(select 1 from control.runtime_activation_observation o where o.configuration_work_id=w.configuration_work_id) from control.configuration_work w where configuration_work_id=$1::text::uuid")
            .bind(&expected_work).fetch_one(&mut *tx).await.unwrap();
        assert!(
            untouched,
            "A post-start failure cannot count as unstarted restoration"
        );
        tx.rollback().await.unwrap();
        cigl_activation::restore_unstarted(&pool, &config, &work)
            .await
            .unwrap();
        assert_eq!(
            retry_or_fail(&pool, &work, &config, false, &plane.source_custody, false)
                .await
                .unwrap(),
            attempt == 3
        );
        assert!(
            now_ms().unwrap().saturating_mul(1_000_000) < original_until,
            "Expiry cannot prove an unstarted failure or positive restoration"
        );
    }
    assert_eq!(
        store.unstarted_restore_cause(&peer).await.unwrap(),
        Some(expected_work.clone())
    );
    // This is one first-issue call. An error is retained as FAIL/UNKNOWN; this
    // test never calls publish again after a lost/uncertain result.
    store
        .publish_fact_unstarted_restore(
            OriginalTargetActivation {
                peer: &peer,
                capsule: &original.capsule,
                signed_token: &original.activation_token,
                signed_receipt: &original.activation_receipt,
                artifacts: &original.artifacts,
            },
            plane.facts.reader(),
            TargetFactTrust {
                fact_verifier: &verifier,
                installed_authority_signer_id: &config.worker_id,
            },
        )
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut tx = result_transaction(&pool, &config, "RUNTIME_ACTIVATION")
            .await
            .unwrap();
        let row = sqlx::query("select a.binding,a.restoration_proof,d.signed_delivery,k.signed_acknowledgement from control.runtime_target_disposition_admission a join control.runtime_target_disposition_delivery d using(participant_id,privacy_domain_id,runtime_target_id,revision) left join control.runtime_target_disposition_acknowledgement k using(participant_id,privacy_domain_id,runtime_target_id,delivery_digest) where a.runtime_target_id=$1::text::uuid order by a.revision desc limit 1")
            .bind(&peer.target_id).fetch_one(&mut *tx).await.unwrap();
        let binding: Value = row.get("binding");
        assert_eq!(binding["action"], "Restore");
        assert_eq!(binding["cause"]["work_id"], expected_work);
        assert_eq!(
            binding["source"]["capsule_digest"],
            original_digest.as_str()
        );
        let proof: Value = row.get("restoration_proof");
        assert_eq!(proof["sourceMode"], "FACT_BOUND");
        let until: u64 = proof["factCustody"]["validUntilNs"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(until <= original_until);
        assert!(now_ms().unwrap().saturating_mul(1_000_000) < until);
        let custody: Value = sqlx::query_scalar("select jsonb_build_object('state',state,'attempts',attempt_count,'unstarted',execution_started_at is null and execution_attempt_id is null,'receipt',result_receipt_digest) from control.configuration_work where configuration_work_id=$1::text::uuid")
            .bind(&expected_work).fetch_one(&mut *tx).await.unwrap();
        assert_eq!(custody["state"], "FAILED");
        assert_eq!(custody["attempts"], 3);
        assert_eq!(custody["unstarted"], true);
        let originals: Value = sqlx::query_scalar("select jsonb_agg(to_jsonb(w) order by configuration_work_id) from control.configuration_work w where runtime_target_id=$1::text::uuid and configuration_work_id<>$2::text::uuid")
            .bind(&peer.target_id).bind(&expected_work).fetch_one(&mut *tx).await.unwrap();
        let expected: Vec<Value> = before["work"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|work| work["configuration_work_id"] != expected_work)
            .cloned()
            .collect();
        assert_eq!(originals, serde_json::json!(expected));
        tx.rollback().await.unwrap();
        if let Some(ack) = row.get::<Option<Vec<u8>>, _>("signed_acknowledgement") {
            let wire: Vec<u8> = row.get("signed_delivery");
            let verifier = TargetDispositionVerifier::from_host_keys(
                expected_target.clone(),
                &PurposeSigner::from_secret_bytes(
                    TARGET_DISPOSITION_DELIVERY_PURPOSE,
                    config.fleet_key,
                )
                .unwrap()
                .verifier()
                .sec1_bytes(),
                &PurposeSigner::from_secret_bytes(TARGET_DISPOSITION_ACK_PURPOSE, config.agent_key)
                    .unwrap()
                    .verifier()
                    .sec1_bytes(),
            )
            .unwrap();
            let signed = verifier.verify_delivery(&wire, &expected_source).unwrap();
            assert_eq!(signed.claims().action, TargetDispositionAction::Restore);
            verifier.verify_acknowledgement(&ack, &signed).unwrap();
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Real target restoration ACK missing"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

struct PinnedFixtureArtifacts(BTreeMap<Digest, Vec<u8>>);

#[test]
#[ignore = "requires the preserved public rollback work and authenticated target journal"]
fn retained_rollback_readback_requires_exact_predecessor_authority() {
    let root = PathBuf::from(env::var("OPENPC_ROLLBACK_OWNER_FIXTURE").unwrap());
    let input: Value = serde_json::from_slice(&fs::read(root.join("work.json")).unwrap()).unwrap();
    let text = |name: &str| input[name].as_str().unwrap().to_owned();
    let mut work = super::tests::work();
    work.work_id = text("work_id");
    work.occurrence_id = Some(text("occurrence_id"));
    work.generation_id = Some(text("generation_id"));
    work.target_id = Some(text("target_id"));
    work.participant_id = text("participant_id");
    work.privacy_domain_id = text("privacy_domain_id");
    work.policy.as_mut().unwrap().generation_digest =
        parse_digest(text("policy_generation_digest")).unwrap();
    work.predecessor_digest = Some(parse_digest(text("predecessor_digest")).unwrap());
    work.xds_version_digest = Some(parse_digest(text("xds_version_digest")).unwrap());
    let mut config = super::tests::test_config(&work);
    let secrets = PathBuf::from(env::var("OPENPC_ROLLBACK_OWNER_SECRETS").unwrap());
    config.fleet_key = read_key(
        secrets
            .join("fleet_controller_signing_secret.txt")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    config.agent_key = read_key(
        secrets
            .join("runtime_agent_signing_secret.txt")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let public = PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, config.fleet_key)
        .unwrap()
        .verifier()
        .sec1_bytes();
    let manifest = read_target_bootstrap(
        &root
            .join("target-bootstrap")
            .join(work.target_id.as_ref().unwrap()),
        &public,
    )
    .unwrap();
    config.worker_id = manifest.authority_signer_id.clone();
    config.identity_runtime_public_key = manifest.identity_runtime_public_key.clone();
    config.fact_verify_key = manifest.fact_verify_key.clone();
    config.fact_verify_key_id = manifest.fact_verify_key_id.clone();
    assert!(manifest.source_only);
    let read = |work: &ClaimedWork| retained_target::read_from(&config, work, &root.join("agent"));
    let actual = read(&work).unwrap().unwrap();
    let receipt = RuntimeWireSigner::from_secret_bytes(config.agent_key)
        .unwrap()
        .verifier()
        .verify_receipt(&actual.activation_receipt)
        .unwrap();
    assert_eq!(actual.capsule.digest().unwrap(), manifest.capsule_digest);
    assert_eq!(
        actual.capsule.policy_bundle_digest,
        work.policy.as_ref().unwrap().generation_digest
    );
    assert!(receipt.observed_at_ns >= actual.capsule.not_before_ns);
    assert!(receipt.observed_at_ns < actual.capsule.hard_expiry_ns);
    assert!(now_ms().unwrap().saturating_mul(1_000_000) >= actual.capsule.hard_expiry_ns);
    // A still-installed forward generation is pending for the requested next
    // effect, never evidence that the requested predecessor policy was restored.
    let mut pending = work.clone();
    pending.predecessor_digest = Some(actual.capsule.digest().unwrap());
    pending.generation_id = Some(uuid::Uuid::now_v7().to_string());
    assert!(read(&pending).unwrap().is_none());
    for mutation in [
        "generation",
        "policy",
        "predecessor",
        "target",
        "occurrence",
        "xds",
        "privacy",
    ] {
        let mut unknown = work.clone();
        match mutation {
            "generation" => unknown.generation_id = Some(uuid::Uuid::now_v7().to_string()),
            "policy" => {
                unknown.policy.as_mut().unwrap().generation_digest =
                    Digest::of(b"unauthorized predecessor policy")
            }
            "predecessor" => {
                unknown.predecessor_digest = Some(Digest::of(b"unrelated forward generation"))
            }
            "target" => unknown.target_id = Some(uuid::Uuid::now_v7().to_string()),
            "occurrence" => unknown.occurrence_id = Some(uuid::Uuid::now_v7().to_string()),
            "xds" => unknown.xds_version_digest = Some(Digest::of(b"unknown transport")),
            "privacy" => unknown.privacy_domain_id = uuid::Uuid::now_v7().to_string(),
            _ => unreachable!(),
        }
        assert!(read(&unknown).is_err(), "{mutation}");
    }
    println!(
        "OPENPC_ROLLBACK_OWNER|PASS|exact-signed-predecessor-policy|forward=pending|unknown=rejected|expired-effect=historical-only|generation={}",
        actual.capsule.generation
    );
}
impl ArtifactAdmission for PinnedFixtureArtifacts {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()> {
        if self.0.get(&component.content_digest).map(Vec::as_slice) == Some(bytes) {
            Ok(())
        } else {
            Err(RuntimeError::InvalidDigest)
        }
    }
    fn validate_bundle(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeSet<Digest>> {
        if artifacts != &self.0 {
            return Err(RuntimeError::InvalidDigest);
        }
        for component in &capsule.artifact_components {
            self.validate(
                component,
                artifacts
                    .get(&component.content_digest)
                    .ok_or(RuntimeError::InvalidInput)?,
            )?;
        }
        Ok(artifacts.keys().cloned().collect())
    }
}

#[tokio::test]
#[ignore = "requires completed public CIGL fixture in run-decision-owner.py --cigl-analysis"]
async fn postgres_lost_activation_observation_uses_original_custody() {
    let root = PathBuf::from(env::var("OPENPC_ASTRA05_DECISION_OWNER_ROOT").unwrap());
    let queued: Value =
        serde_json::from_slice(&fs::read(root.join("profile-activation-queued.json")).unwrap())
            .unwrap();
    let source: Value =
        serde_json::from_slice(&fs::read(root.join("analysis-compilation-source.json")).unwrap())
            .unwrap();
    let mut capsule = RuntimeCapsule::decode(&receipt_bytes(&source, "capsule").unwrap()).unwrap();
    let artifacts: BTreeMap<Digest, Vec<u8>> =
        serde_json::from_value(source["artifacts"].clone()).unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&env::var("OPENPC_CIGL_COMPILATION_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut work = super::tests::work();
    work.work_id = queued["workId"].as_str().unwrap().into();
    work.generation_id = Some(queued["generationId"].as_str().unwrap().into());
    let mut config = super::tests::test_config(&work);
    let mut tx = result_transaction(&pool, &config, "RUNTIME_ACTIVATION")
        .await
        .unwrap();
    // Claim only this real approved work item; no approval, target observation
    // or execution result is seeded. STARTED uses its production owner below.
    let row=sqlx::query("update control.configuration_work set state='LEASED',lease_owner=$2,lease_until=clock_timestamp()+interval '90 seconds',attempt_count=attempt_count+1 where configuration_work_id=$1::text::uuid and state='PENDING' returning operation_id::text,resource_id::text,participant_id::text,privacy_domain_id::text,runtime_target_id::text,generation_digest,predecessor_digest,policy_generation_digest,xds_version_digest,configuration_digest")
        .bind(&work.work_id).bind(&config.worker_id).fetch_one(&mut *tx).await.unwrap();
    work.operation_id = row.get("operation_id");
    work.resource_id = row.get("resource_id");
    work.participant_id = row.get("participant_id");
    work.privacy_domain_id = row.get("privacy_domain_id");
    work.target_id = Some(row.get("runtime_target_id"));
    work.generation_digest = Some(parse_digest(row.get("generation_digest")).unwrap());
    work.predecessor_digest = Some(parse_digest(row.get("predecessor_digest")).unwrap());
    work.policy.as_mut().unwrap().generation_digest =
        parse_digest(row.get("policy_generation_digest")).unwrap();
    work.xds_version_digest = Some(parse_digest(row.get("xds_version_digest")).unwrap());
    work.configuration_digest = parse_digest(row.get("configuration_digest")).unwrap();
    let input_id: String = sqlx::query_scalar("select runtime_configuration_input_id::text from control.runtime_configuration_input where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and configuration_digest=decode($3,'hex')")
        .bind(&work.participant_id).bind(&work.privacy_domain_id).bind(work.configuration_digest.as_str())
        .fetch_one(&mut *tx).await.unwrap();
    openpc_indexer_adapter::control_materialization::authorize_input(&mut tx, &input_id)
        .await
        .unwrap();
    work.configuration_cbor =
        sqlx::query_scalar("select openpc.runtime_artifact_input_payload($1::text::uuid)")
            .bind(&input_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    config.participant_id = work.participant_id.clone();
    config.privacy_domain_id = work.privacy_domain_id.clone();
    assert_eq!(
        capsule.digest().unwrap(),
        *work.predecessor_digest.as_ref().unwrap()
    );
    let fleet = RuntimeWireSigner::from_secret_bytes(config.fleet_key).unwrap();
    let trust = CapsuleTrust {
        target_id: capsule.target_runtime_id.clone(),
        fleet_id: capsule.fleet_id.clone(),
        fleet_signer_id: capsule.signer_id.clone(),
        agent_signer_id: "openpc-local-agent-signer".into(),
        contract_set_manifest_digest: capsule.contract_set_manifest_digest.clone(),
        schema_registry_digest: capsule.schema_registry_digest.clone(),
        cose_purpose_registry_digest: capsule.cose_purpose_registry_digest.clone(),
        complete_component_set_digest: capsule.complete_component_set_digest.clone(),
    };
    let directory = root.join("lost-observation-custody");
    let open = || {
        RuntimeAgent::open_canonical(
            trust.clone(),
            &fleet.verifier().public_key_bytes(),
            config.agent_key,
            8,
            4 * 1024 * 1024,
            &directory,
            Arc::new(PinnedFixtureArtifacts(artifacts.clone())),
        )
        .unwrap()
    };
    let agent = open();
    let token = |capsule: &RuntimeCapsule, occurrence: &str, xds: Digest| {
        openpc_runtime_agent::RuntimeActivationToken {
            token_id: uuid::Uuid::now_v7().to_string(),
            target_runtime_id: capsule.target_runtime_id.clone(),
            occurrence_id: occurrence.into(),
            desired_generation_digest: capsule.digest().unwrap(),
            xds_version_digest: xds,
            expected_previous_generation_digest: capsule.previous_capsule_digest.clone(),
            issued_at_ns: capsule.not_before_ns,
            expires_at_ns: capsule.hard_expiry_ns,
        }
    };
    // Reuse the authenticated fixture's target clock; this is a custody/store
    // regression, not renewed live permission from expired identity material.
    agent
        .prepare_capsule(
            fleet.sign_capsule(&capsule).unwrap(),
            artifacts.clone(),
            capsule.not_before_ns,
        )
        .unwrap();
    agent
        .activate_capsule_authorized(
            &fleet
                .sign_activation_token(&token(
                    &capsule,
                    "fixture-predecessor",
                    Digest::of(b"prior-xds"),
                ))
                .unwrap(),
            capsule.not_before_ns + 1,
        )
        .unwrap();
    capsule.previous_capsule_digest = Some(capsule.digest().unwrap());
    capsule.capsule_id = work.generation_id.clone().unwrap();
    capsule.generation += 1;
    capsule.lifecycle_mode = 2;
    agent
        .prepare_capsule(
            fleet.sign_capsule(&capsule).unwrap(),
            artifacts.clone(),
            capsule.not_before_ns + 2,
        )
        .unwrap();
    work.execution_attempt_id = Some(mark_effect_started(&pool, &work, &config).await.unwrap());
    let signed_token = fleet
        .sign_activation_token(&token(
            &capsule,
            &work.work_id,
            work.xds_version_digest.clone().unwrap(),
        ))
        .unwrap();
    let receipt = agent
        .activate_capsule_authorized(&signed_token, capsule.not_before_ns + 3)
        .unwrap();
    let sequence = agent.active_canonical_generation().unwrap().unwrap();
    drop(agent); // Simulated loss before the Control observation call.
    let agent = open();
    let (actual, original) = RuntimeAgent::read_canonical_activation(
        &trust,
        &fleet.verifier().public_key_bytes(),
        &RuntimeWireSigner::from_secret_bytes(config.agent_key)
            .unwrap()
            .verifier()
            .public_key_bytes(),
        &directory,
        None,
        &PinnedFixtureArtifacts(artifacts.clone()),
        |capsule, _, token, receipt| {
            assert_eq!(token, signed_token);
            Ok((capsule.clone(), receipt.to_vec()))
        },
    )
    .unwrap();
    assert_eq!(original, receipt);
    let mut changed = actual.clone();
    changed.capsule_id = uuid::Uuid::now_v7().to_string();
    assert!(
        retained_target::record_verified_activation(&pool, &config, &work, &changed, &original)
            .await
            .is_err()
    );
    let recovered =
        retained_target::record_verified_activation(&pool, &config, &work, &actual, &original)
            .await
            .unwrap();
    let inputs = openpc_fleet_controller::runtime_configuration_input::RuntimeConfigurationInputSource::from_environment().unwrap();
    let source = openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker::from_environment(
        &pool, &config.participant_id, &config.privacy_domain_id, inputs.as_ref().map(|value| value.path()),
    ).await.unwrap();
    let mut tx = result_transaction(&pool, &config, "RUNTIME_ACTIVATION")
        .await
        .unwrap();
    let stored:Value=sqlx::query_scalar("select activation_receipt from control.runtime_activation_observation where configuration_work_id=$1::text::uuid")
        .bind(&work.work_id).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(stored, recovered.1);
    // An existing effect can never be terminalized by the no-effect branch.
    assert!(
        retained_target::no_effect(&mut tx, &config, &work, &source)
            .await
            .unwrap()
            .is_none()
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        agent.active_canonical_generation().unwrap().unwrap(),
        sequence
    );
    assert_eq!(agent.replay_canonical_receipts().unwrap().len(), 2);
    assert!(
        agent
            .expired_preparation_no_effect(
                &actual.capsule_id,
                work.predecessor_digest.as_ref().unwrap(),
                &work.policy.as_ref().unwrap().generation_digest,
                actual.hard_expiry_ns
            )
            .unwrap()
            .is_none()
    );
    pool.close().await;
}

#[test]
fn effect_admission_binds_original_bytes_and_scope_without_changing_history() {
    let mut original = super::tests::work();
    original.configuration_cbor = b"original configuration".to_vec();
    original.configuration_digest = Digest::of(&original.configuration_cbor);
    let config = super::tests::test_config(&original);
    assert!(require_work_configuration(&original, &config).is_ok());
    for field in ["bytes", "digest", "participant", "privacy", "empty"] {
        let mut changed = original.clone();
        match field {
            "bytes" => changed.configuration_cbor.push(1),
            "digest" => changed.configuration_digest = Digest::of(b"foreign input"),
            "participant" => changed.participant_id = uuid::Uuid::now_v7().to_string(),
            "privacy" => changed.privacy_domain_id = uuid::Uuid::now_v7().to_string(),
            "empty" => changed.configuration_cbor.clear(),
            _ => unreachable!(),
        }
        assert!(
            require_work_configuration(&changed, &config).is_err(),
            "{field}"
        );
    }
    let mut original_started = original.clone();
    original_started.execution_attempt_id = Some(uuid::Uuid::now_v7().to_string());
    original_started.reconcile_only = true;
    let attempt = original_started.execution_attempt_id.clone();
    assert!(require_work_configuration(&original_started, &config).is_ok());
    assert_eq!(original_started.execution_attempt_id, attempt);
    assert_eq!(
        original_started.configuration_cbor,
        original.configuration_cbor
    );
}

fn bootstrap_fixture(work: &ClaimedWork, config: &Config) -> TargetBootstrapManifest {
    TargetBootstrapManifest {
        version: 1,
        participant_id: work.participant_id.clone(),
        privacy_domain_id: work.privacy_domain_id.clone(),
        target_runtime_id: work.target_id.clone().unwrap(),
        fleet_id: "fixture-fleet".into(),
        fleet_signer_id: "fixture-fleet-signer".into(),
        agent_signer_id: "fixture-agent-signer".into(),
        authority_signer_id: config.worker_id.clone(),
        fleet_runtime_public_key: Vec::new(),
        identity_runtime_public_key: Vec::new(),
        fact_verify_key: Vec::new(),
        fact_verify_key_id: "fixture-fact".into(),
        contract_set_manifest_digest: Digest::of(b"contract"),
        schema_registry_digest: Digest::of(b"schema"),
        cose_purpose_registry_digest: Digest::of(b"purpose"),
        complete_component_set_digest: Digest::of(b"components"),
        capsule_id: work.generation_id.clone().unwrap(),
        capsule_generation: 1,
        capsule_digest: Digest::of(b"original capsule"),
        identity_profile_digest: Digest::of(b"identity"),
        mrpc_runtime_profile: Vec::new(),
        routing_source: Vec::new(),
        certification_source: Vec::new(),
        protected_class_set_digest: protected_class_set_digest(),
        source_only: true,
        emergency_delivery: None,
        suspended_for_work: None,
        target_disposition: None,
    }
}

#[test]
fn original_bootstrap_identity_never_clears_suspension_or_renews_authority() {
    let work = super::tests::work();
    let config = super::tests::test_config(&work);
    let mut manifest = bootstrap_fixture(&work, &config);
    let expected = manifest.capsule_digest.clone();
    assert!(
        retained_target::existing_serving_bootstrap(&manifest, &config, &work, &expected).unwrap()
    );
    manifest.suspended_for_work = Some(work.work_id.clone());
    let before = serde_json::to_value(&manifest).unwrap();
    assert!(
        !retained_target::existing_serving_bootstrap(&manifest, &config, &work, &expected).unwrap()
    );
    assert_eq!(serde_json::to_value(&manifest).unwrap(), before);
    let mut successor = work.clone();
    successor.predecessor_digest = Some(expected);
    // Even a correctly bound predecessor plus original NO_EFFECT cannot restore
    // serving without the separate disposition and antirollback owner.
    assert!(
        !retained_target::existing_serving_bootstrap(
            &manifest,
            &config,
            &successor,
            &Digest::of(b"successor capsule"),
        )
        .unwrap()
    );
    assert_eq!(serde_json::to_value(&manifest).unwrap(), before);
}

#[test]
fn bootstrap_restore_rejects_foreign_scope_and_changed_original() {
    let work = super::tests::work();
    let config = super::tests::test_config(&work);
    let original = bootstrap_fixture(&work, &config);
    for field in [
        "participant",
        "privacy",
        "target",
        "signer",
        "capsule",
        "work",
    ] {
        let mut manifest = original.clone();
        match field {
            "participant" => manifest.participant_id = uuid::Uuid::now_v7().to_string(),
            "privacy" => manifest.privacy_domain_id = uuid::Uuid::now_v7().to_string(),
            "target" => manifest.target_runtime_id = uuid::Uuid::now_v7().to_string(),
            "signer" => manifest.authority_signer_id = "foreign signer".into(),
            "capsule" => manifest.capsule_digest = Digest::of(b"another capsule"),
            "work" => manifest.suspended_for_work = Some(uuid::Uuid::now_v7().to_string()),
            _ => unreachable!(),
        }
        assert!(
            retained_target::existing_serving_bootstrap(
                &manifest,
                &config,
                &work,
                &original.capsule_digest,
            )
            .is_err(),
            "{field}"
        );
    }
}

#[test]
fn missing_database_enforcement_is_not_retryable_or_permission() {
    for error in [
        sqlx::Error::RowNotFound,
        sqlx::Error::PoolClosed,
        sqlx::Error::PoolTimedOut,
    ] {
        assert_eq!(
            runtime_artifact_database_error(error),
            "runtime artifact retirement enforcement unavailable"
        );
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OriginalRetirementFixture {
    participant_id: String,
    privacy_domain_id: String,
    configuration_digest: String,
    runtime_configuration_input_id: String,
    deletion_job_id: String,
    operation_id: String,
}

async fn original_retirement_fixture() -> (PgPool, Config, OriginalRetirementFixture, Digest) {
    use std::io::Read;
    let path = env::var("OPENPC_RUNTIME_ARTIFACT_RETIREMENT_FIXTURE").unwrap();
    let mut bytes = Vec::new();
    fs::File::open(path)
        .unwrap()
        .take(4097)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 4096);
    let fixture: OriginalRetirementFixture = serde_json::from_slice(&bytes).unwrap();
    for value in [
        &fixture.participant_id,
        &fixture.privacy_domain_id,
        &fixture.runtime_configuration_input_id,
        &fixture.deletion_job_id,
        &fixture.operation_id,
    ] {
        let id = uuid::Uuid::parse_str(value).unwrap();
        assert_eq!(id.get_version_num(), 7);
        assert_eq!(id.to_string(), *value);
    }
    let digest = parse_digest(fixture.configuration_digest.clone()).unwrap();
    let mut config = super::tests::test_config(&super::tests::work());
    config.participant_id = fixture.participant_id.clone();
    config.privacy_domain_id = fixture.privacy_domain_id.clone();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&env::var("OPENPC_I02_RUNTIME_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    set_context(&mut tx, &config).await.unwrap();
    assert!(
        !runtime_artifact_new_use_allowed(
            &mut tx,
            &config.participant_id,
            &config.privacy_domain_id,
            &digest
        )
        .await
        .unwrap()
    );
    // Require the genuine original effect/receipt chain, not seeded metadata.
    let rows = sqlx::query("select openpc.assert_runtime_artifact_retirement_committed(r) from control.runtime_artifact_retirement r join control.deletion_job j using(participant_id,privacy_domain_id,deletion_job_id) where r.runtime_configuration_input_id=$1::text::uuid and r.deletion_job_id=$2::text::uuid and r.configuration_digest=$3 and j.operation_id=$4::text::uuid")
        .bind(&fixture.runtime_configuration_input_id).bind(&fixture.deletion_job_id)
        .bind(&fixture.configuration_digest).bind(&fixture.operation_id).fetch_all(&mut *tx).await.unwrap();
    assert_eq!(rows.len(), 1);
    tx.rollback().await.unwrap();
    (pool, config, fixture, digest)
}

#[tokio::test]
#[ignore = "requires an original public physical retirement and installed canonical SQL owners"]
async fn native_retirement_fence_is_scoped_and_lives_until_commit_or_rollback() {
    let (pool, config, _, digest) = original_retirement_fixture().await;
    for commit in [false, true] {
        let mut first = pool.begin().await.unwrap();
        set_context(&mut first, &config).await.unwrap();
        assert!(
            !runtime_artifact_new_use_allowed(
                &mut first,
                &config.participant_id,
                &config.privacy_domain_id,
                &digest
            )
            .await
            .unwrap()
        );
        let mut second = pool.begin().await.unwrap();
        set_context(&mut second, &config).await.unwrap();
        assert_eq!(
            runtime_artifact_new_use_allowed(
                &mut second,
                &config.participant_id,
                &config.privacy_domain_id,
                &digest
            )
            .await,
            Err(RUNTIME_ARTIFACT_BUSY.into())
        );
        second.rollback().await.unwrap();
        if commit {
            first.commit().await.unwrap();
        } else {
            first.rollback().await.unwrap();
        }
        let mut after = pool.begin().await.unwrap();
        set_context(&mut after, &config).await.unwrap();
        assert!(
            !runtime_artifact_new_use_allowed(
                &mut after,
                &config.participant_id,
                &config.privacy_domain_id,
                &digest
            )
            .await
            .unwrap()
        );
        after.rollback().await.unwrap();
    }
    for foreign_participant in [false, true] {
        let mut tx = pool.begin().await.unwrap();
        set_context(&mut tx, &config).await.unwrap();
        let foreign = uuid::Uuid::now_v7().to_string();
        assert!(
            runtime_artifact_new_use_allowed(
                &mut tx,
                if foreign_participant {
                    &foreign
                } else {
                    &config.participant_id
                },
                if foreign_participant {
                    &config.privacy_domain_id
                } else {
                    &foreign
                },
                &digest,
            )
            .await
            .is_err()
        );
        tx.rollback().await.unwrap();
    }
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires public retirement, retained original bytes and a valid selected successor"]
async fn retired_mount_cannot_reselect_same_bytes_or_deselect_successor() {
    use openpc_fleet_controller::runtime_configuration_input::RuntimeConfigurationInputSource;
    use std::io::Read;
    let (pool, config, fixture, digest) = original_retirement_fixture().await;
    let path = PathBuf::from(env::var("OPENPC_RUNTIME_ARTIFACT_RETIRED_INPUT_FILE").unwrap());
    let mut original = Vec::new();
    fs::File::open(&path)
        .unwrap()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut original)
        .unwrap();
    assert!(original.len() <= 4 * 1024 * 1024);
    assert_eq!(Digest::of(&original), digest);
    let selected = async || {
        let mut tx = pool.begin().await.unwrap();
        set_context(&mut tx, &config).await.unwrap();
        let rows: Vec<(String, String, String)> = sqlx::query_as("select runtime_configuration_input_id::text,module_configuration_generation_id::text,encode(configuration_digest,'hex') from control.runtime_configuration_input_current order by runtime_configuration_input_id")
            .fetch_all(&mut *tx).await.unwrap();
        tx.rollback().await.unwrap();
        rows
    };
    let count_inputs = async || {
        let mut tx = pool.begin().await.unwrap();
        set_context(&mut tx, &config).await.unwrap();
        let count: i64 = sqlx::query_scalar("select count(*) from control.runtime_configuration_input where 'sha256:'||encode(configuration_digest,'hex')=$1")
            .bind(&fixture.configuration_digest).fetch_one(&mut *tx).await.unwrap();
        let original_exists: bool = sqlx::query_scalar("select exists(select 1 from control.runtime_configuration_input where runtime_configuration_input_id=$1::text::uuid)")
            .bind(&fixture.runtime_configuration_input_id).fetch_one(&mut *tx).await.unwrap();
        assert!(!original_exists);
        tx.rollback().await.unwrap();
        count
    };
    let before_count = count_inputs().await;
    let before = selected().await;
    assert_eq!(before.len(), 1);
    assert_ne!(before[0].2, digest.as_str());
    let source = RuntimeConfigurationInputSource::new(path).unwrap();
    for _ in 0..2 {
        source
            .refresh(&pool, &config.participant_id, &config.privacy_domain_id)
            .await
            .unwrap();
        assert_eq!(selected().await, before);
    }
    // The same retired bytes remain denied regardless of a newly chosen
    // generation/input identity; no caller-generated business state is inserted.
    let mut proposed = super::tests::work();
    proposed.participant_id = config.participant_id.clone();
    proposed.privacy_domain_id = config.privacy_domain_id.clone();
    proposed.work_id = uuid::Uuid::now_v7().to_string();
    proposed.generation_id = Some(uuid::Uuid::now_v7().to_string());
    proposed.configuration_cbor = original;
    proposed.configuration_digest = digest;
    assert_eq!(
        mark_effect_started(&pool, &proposed, &config).await,
        Err("runtime artifact retired".into())
    );
    // Other pre-existing copies may remain; this attempt creates none.
    assert_eq!(count_inputs().await, before_count);
    assert_eq!(selected().await, before);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a preserved public unretired old input and a different valid successor"]
async fn known_unretired_stale_mount_preserves_the_selected_successor() {
    use openpc_fleet_controller::runtime_configuration_input::RuntimeConfigurationInputSource;
    use std::io::Read;
    let (pool, config, _, _) = original_retirement_fixture().await;
    let path = PathBuf::from(env::var("OPENPC_RUNTIME_ARTIFACT_STALE_INPUT_FILE").unwrap());
    let mut bytes = Vec::new();
    fs::File::open(&path)
        .unwrap()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(!bytes.is_empty() && bytes.len() <= 4 * 1024 * 1024);
    let digest = Digest::of(&bytes);
    let snapshot = async || {
        let mut tx = pool.begin().await.unwrap();
        set_context(&mut tx, &config).await.unwrap();
        assert!(
            runtime_artifact_new_use_allowed(
                &mut tx,
                &config.participant_id,
                &config.privacy_domain_id,
                &digest
            )
            .await
            .unwrap()
        );
        let known: bool = sqlx::query_scalar("select exists(select 1 from control.runtime_configuration_input where configuration_digest=decode($1,'hex'))")
            .bind(digest.as_str()).fetch_one(&mut *tx).await.unwrap();
        assert!(known);
        let rows: Vec<(String, String, String)> = sqlx::query_as("select runtime_configuration_input_id::text,module_configuration_generation_id::text,encode(configuration_digest,'hex') from control.runtime_configuration_input_current order by runtime_configuration_input_id")
            .fetch_all(&mut *tx).await.unwrap();
        tx.rollback().await.unwrap();
        rows
    };
    let before = snapshot().await;
    assert_eq!(before.len(), 1);
    assert_ne!(before[0].2, digest.as_str());
    RuntimeConfigurationInputSource::new(path)
        .unwrap()
        .refresh(&pool, &config.participant_id, &config.privacy_domain_id)
        .await
        .unwrap();
    assert_eq!(snapshot().await, before);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires original governed inputs and completed work in a retained store"]
async fn native_original_input_admission_preserves_custody_and_successor() {
    use openpc_fleet_controller::runtime_configuration_input::RuntimeConfigurationInputSource;
    let fixture: Value = serde_json::from_slice(
        &fs::read(env::var("OPENPC_RUNTIME_ARTIFACT_NATIVE_FIXTURE").unwrap()).unwrap(),
    )
    .unwrap();
    let text = |key: &str| fixture[key].as_str().unwrap().to_owned();
    let mut config = super::tests::test_config(&super::tests::work());
    config.participant_id = text("participantId");
    config.privacy_domain_id = text("privacyDomainId");
    let digest = parse_digest(text("configurationDigest")).unwrap();
    let input_id = text("runtimeConfigurationInputId");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&env::var("OPENPC_I02_RUNTIME_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let snapshot = async || {
        let mut tx = pool.begin().await.unwrap();
        set_context(&mut tx, &config).await.unwrap();
        assert!(
            runtime_artifact_new_use_allowed(
                &mut tx,
                &config.participant_id,
                &config.privacy_domain_id,
                &digest
            )
            .await
            .unwrap()
        );
        let rows: Value = sqlx::query_scalar("select jsonb_agg(to_jsonb(i) order by runtime_configuration_input_id) from (select runtime_configuration_input_id,participant_id,privacy_domain_id,module_installation_id,module_configuration_generation_id,configuration_digest,resource_bindings,selected,created_at from control.runtime_configuration_input) i")
            .fetch_one(&mut *tx).await.unwrap();
        let work: Value = sqlx::query_scalar("select jsonb_agg(to_jsonb(w) order by configuration_work_id) from control.configuration_work w")
            .fetch_one(&mut *tx).await.unwrap();
        assert!(
            work.as_array()
                .unwrap()
                .iter()
                .all(|w| w["state"] == "COMPLETED")
        );
        let bytes_match: bool = sqlx::query_scalar("select (openpc.runtime_artifact_input_information(runtime_configuration_input_id)->>'bytesMatch')::boolean from control.runtime_configuration_input where runtime_configuration_input_id=$1::text::uuid and selected=false")
            .bind(&input_id).fetch_one(&mut *tx).await.unwrap();
        assert!(bytes_match);
        assert_eq!(Digest::of(fs::read(text("inputFile")).unwrap()), digest);
        tx.rollback().await.unwrap();
        (rows, work)
    };
    let before = snapshot().await;
    // A real transaction fence is held through COMMIT as well as ROLLBACK.
    for commit in [false, true] {
        let mut first = pool.begin().await.unwrap();
        set_context(&mut first, &config).await.unwrap();
        assert!(
            runtime_artifact_new_use_allowed(
                &mut first,
                &config.participant_id,
                &config.privacy_domain_id,
                &digest
            )
            .await
            .unwrap()
        );
        let mut second = pool.begin().await.unwrap();
        set_context(&mut second, &config).await.unwrap();
        assert_eq!(
            runtime_artifact_new_use_allowed(
                &mut second,
                &config.participant_id,
                &config.privacy_domain_id,
                &digest
            )
            .await,
            Err(RUNTIME_ARTIFACT_BUSY.into())
        );
        second.rollback().await.unwrap();
        if commit {
            first.commit().await.unwrap();
        } else {
            first.rollback().await.unwrap();
        }
        assert_eq!(snapshot().await, before);
    }
    for foreign_participant in [false, true] {
        let mut tx = pool.begin().await.unwrap();
        set_context(&mut tx, &config).await.unwrap();
        let foreign = uuid::Uuid::now_v7().to_string();
        assert!(
            runtime_artifact_new_use_allowed(
                &mut tx,
                if foreign_participant {
                    &foreign
                } else {
                    &config.participant_id
                },
                if foreign_participant {
                    &config.privacy_domain_id
                } else {
                    &foreign
                },
                &digest
            )
            .await
            .is_err()
        );
        tx.rollback().await.unwrap();
    }
    // This retained scope has only completed original work. The real claim SQL
    // must execute, return none, and leave every original result byte unchanged.
    assert!(claim(&pool, &config).await.unwrap().is_none());
    let source = RuntimeConfigurationInputSource::new(PathBuf::from(text("inputFile"))).unwrap();
    for _ in 0..2 {
        source
            .refresh(&pool, &config.participant_id, &config.privacy_domain_id)
            .await
            .unwrap();
        assert_eq!(snapshot().await, before);
    }
    pool.close().await;
}
