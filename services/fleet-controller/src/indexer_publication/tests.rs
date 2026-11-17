//! The retained public lifecycle supplies the source; this test creates no
//! qualification, approval or provider observation. Expiry must remove the
//! earlier publication, without changing its immutable source bytes.
use super::*;

#[tokio::test]
#[ignore = "requires the migrated database in run-participant-readback.sh"]
async fn postgres_publication_observation_defers_lifecycle_before_source_or_effect() {
    let pool =
        PgPool::connect(&std::env::var("OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL").unwrap())
            .await
            .unwrap();
    let participant = "018f0000-0000-7000-8000-000000000101";
    let privacy = "018f0000-0000-7000-8000-000000000201";
    let mut fence = pool.begin().await.unwrap();
    sqlx::query(
        "select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1::text,0))",
    )
    .bind(participant)
    .execute(&mut *fence)
    .await
    .unwrap();
    let deferred = tokio::time::timeout(
        Duration::from_secs(2),
        begin_publication_observation(&pool, participant, privacy),
    )
    .await
    .expect("contention must not reverse-wait")
    .unwrap();
    assert!(
        deferred.is_none(),
        "no transaction may authorize source or candidate I/O"
    );
    // A deferred poll must release its earlier module fence as well.
    let module_free: bool = sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended('module-admission:'||$1::text||':'||$2::text,0))")
        .bind(participant).bind(privacy).fetch_one(&mut *fence).await.unwrap();
    assert!(module_free);
    fence.rollback().await.unwrap();
    for _ in 0..2 {
        let mut observed = begin_publication_observation(&pool, participant, privacy)
            .await
            .unwrap()
            .expect("the same installed observer must continue after release");
        let mut contender = pool.begin().await.unwrap();
        let available: bool = sqlx::query_scalar(
            "select pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1::text,0))",
        )
        .bind(participant)
        .fetch_one(&mut *contender)
        .await
        .unwrap();
        assert!(
            !available,
            "the actual fence must live through the publication observation"
        );
        contender.rollback().await.unwrap();
        assert!(
            source_current::load(&mut observed, participant, privacy, None, true)
                .await
                .unwrap()
                .is_empty(),
            "only initial trust exists; no source qualification is seeded"
        );
        observed.rollback().await.unwrap();
    }
    assert!(
        begin_publication_observation(&pool, "invalid-scope", privacy)
            .await
            .is_err()
    );
    pool.close().await;
    assert!(
        begin_publication_observation(&pool, participant, privacy)
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires the joined public source replacement and retained admitted facts"]
async fn postgres_public_source_withdrawals_emit_one_durable_event_across_restart() {
    let control = PgPool::connect(&std::env::var("OPENPC_PUBLICATION_TEST_CONTROL_URL").unwrap())
        .await
        .unwrap();
    let manager_url = std::env::var("OPENPC_PUBLICATION_TEST_MANAGER_URL").unwrap();
    let candidates = PgPool::connect(&manager_url).await.unwrap();
    let participant = std::env::var("OPENPC_PUBLICATION_TEST_PARTICIPANT").unwrap();
    let privacy = std::env::var("OPENPC_PUBLICATION_TEST_PRIVACY").unwrap();
    let mut observed = None;
    for _ in 0..2 {
        let mut worker = IndexerPublicationWorker {
            store: CandidatePublicationStore::connect(&manager_url)
                .await
                .unwrap(),
            next_poll: Instant::now(),
        };
        worker.tick(&control, &participant, &privacy).await.unwrap();
        let mut tx = candidates.begin().await.unwrap();
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CANDIDATE_WRITE-V1',true)")
            .bind(&participant).bind(&privacy).execute(&mut *tx).await.unwrap();
        let events: Vec<(Uuid, Vec<u8>)> = sqlx::query_as("select event.event_id,event.payload_cbor
            from candidate.source_publication pub join candidate.candidate_partition part using(participant_id,privacy_domain_id,projection_generation_id)
            join candidate.outbox_event event on event.participant_id=pub.participant_id and event.privacy_domain_id=pub.privacy_domain_id
              and event.aggregate_type='candidate-partition' and event.aggregate_id=part.candidate_partition_id
            where pub.state='FENCED' and event.event_type='io.openpc.indexer.projection.source.fenced.v1' order by event.event_id")
            .fetch_all(&mut *tx).await.unwrap();
        assert!(
            !events.is_empty(),
            "the public source replacement must produce a durable removal occurrence"
        );
        let missing: i64 = sqlx::query_scalar("select count(*) from candidate.source_publication pub
            join candidate.candidate_partition part using(participant_id,privacy_domain_id,projection_generation_id)
            where pub.state='FENCED' and not exists(select 1 from candidate.outbox_event event
              where event.participant_id=pub.participant_id and event.privacy_domain_id=pub.privacy_domain_id
                and event.aggregate_id=part.candidate_partition_id and event.event_type='io.openpc.indexer.projection.source.fenced.v1')")
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(missing, 0);
        tx.rollback().await.unwrap();
        if let Some(previous) = &observed {
            assert_eq!(previous, &events);
        } else {
            observed = Some(events);
        }
    }
    control.close().await;
    candidates.close().await;
}

#[tokio::test]
#[ignore = "requires the retained public source activation and scoped reader fence"]
async fn postgres_source_reader_selects_the_exact_locked_publication() {
    let pool = PgPool::connect(&std::env::var("OPENPC_SOURCE_FENCE_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let participant = std::env::var("OPENPC_SOURCE_FENCE_PARTICIPANT").unwrap();
    let privacy = std::env::var("OPENPC_SOURCE_FENCE_PRIVACY").unwrap();
    let target = std::env::var("OPENPC_SOURCE_FENCE_TARGET").unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("set local role openpc_control_reader")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-RUNTIME_READ_RPC-V1',false)")
        .bind(&participant).bind(&privacy).execute(&mut *tx).await.unwrap();
    let capsule: String = sqlx::query_scalar("select active_generation_digest from control.runtime_target where runtime_target_id=$1::text::uuid and state='ACTIVE_MATCHED'")
        .bind(&target).fetch_one(&mut *tx).await.unwrap();
    let plan: String =
        sqlx::query_scalar("select openpc.lock_indexer_dispatch_source($1::text::uuid,$2)::text")
            .bind(&target)
            .bind(capsule)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    let rows = source_current::load(&mut tx, &participant, &privacy, Some(&plan), false)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let current = prepare(&rows[0], &participant, &privacy).unwrap().unwrap();
    assert_eq!(current.input.projection_plan_id.to_string(), plan);
    assert_eq!(current.target_id, target);
    assert!(
        source_current::load(
            &mut tx,
            &participant,
            &privacy,
            Some(&Uuid::now_v7().to_string()),
            false
        )
        .await
        .unwrap()
        .is_empty()
    );
    tx.rollback().await.unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the retained public provider qualification after its real expiry"]
async fn postgres_source_provider_fence_rejects_expired_qualification() {
    let pool = PgPool::connect(&std::env::var("OPENPC_SOURCE_FENCE_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let participant = std::env::var("OPENPC_SOURCE_FENCE_PARTICIPANT").unwrap();
    let privacy = std::env::var("OPENPC_SOURCE_FENCE_PRIVACY").unwrap();
    for (role, action) in [
        ("openpc_control_reader", "ACT-RUNTIME_READ_RPC-V1"),
        ("openpc_control_worker", "ACT-CANDIDATE_WRITE-V1"),
    ] {
        let mut tx = pool.begin().await.unwrap();
        let sql = if role == "openpc_control_reader" {
            "set local role openpc_control_reader"
        } else {
            "set local role openpc_control_worker"
        };
        sqlx::query(sql).execute(&mut *tx).await.unwrap();
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),$3,false)")
            .bind(&participant).bind(&privacy).bind(action).execute(&mut *tx).await.unwrap();
        let providers: Vec<(String, String)> = sqlx::query_as("select p.provider_profile_id::text,p.behavior_fingerprint from control.provider_profile p join control.provider_probe_observation o on o.observation_id=p.qualification_observation_id where p.state in ('QUALIFIED','ACTIVE') and o.valid_until<=clock_timestamp()")
            .fetch_all(&mut *tx).await.unwrap();
        assert!(!providers.is_empty(), "requires real expired qualification");
        for (id, digest) in providers {
            assert_eq!(
                provider_qualification_deadline(&mut tx, &id, &digest)
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(
                provider_qualification_deadline(
                    &mut tx,
                    &id,
                    &format!("sha256:{}", "0".repeat(64))
                )
                .await
                .unwrap(),
                None
            );
        }
        tx.rollback().await.unwrap();
    }
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("set local role openpc_control_reader")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
        .bind(&participant).bind(&privacy).execute(&mut *tx).await.unwrap();
    assert!(
        provider_qualification_deadline(
            &mut tx,
            &Uuid::now_v7().to_string(),
            &format!("sha256:{}", "0".repeat(64))
        )
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a publicly published source whose provider qualification has expired"]
async fn postgres_reconciles_expired_public_source_and_restart() {
    let control = PgPool::connect(&std::env::var("OPENPC_PUBLICATION_TEST_CONTROL_URL").unwrap())
        .await
        .unwrap();
    let manager_url = std::env::var("OPENPC_PUBLICATION_TEST_MANAGER_URL").unwrap();
    let candidates = PgPool::connect(&manager_url).await.unwrap();
    let participant = std::env::var("OPENPC_PUBLICATION_TEST_PARTICIPANT").unwrap();
    let privacy = std::env::var("OPENPC_PUBLICATION_TEST_PRIVACY").unwrap();
    let source = std::env::var("OPENPC_PUBLICATION_TEST_SOURCE").unwrap();
    let mut tx = control.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CANDIDATE_WRITE-V1',true)")
        .bind(&participant).bind(&privacy).execute(&mut *tx).await.unwrap();
    let qualified: i64 = sqlx::query_scalar("select count(*) from control.indexer_profile where indexer_profile_id=$1::text::uuid and state in ('QUALIFIED','ACTIVE')")
        .bind(&source).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(qualified, 1, "public source lifecycle must be retained");
    let observations: (i64, i64) = sqlx::query_as("select count(*),count(*) filter(where o.valid_until>clock_timestamp()) from control.provider_profile p join control.provider_probe_observation o on o.observation_id=p.qualification_observation_id where p.state in ('QUALIFIED','ACTIVE')")
        .fetch_one(&mut *tx).await.unwrap();
    assert!(
        observations.0 > 0 && observations.1 == 0,
        "requires observed, now expired provider qualification"
    );
    tx.rollback().await.unwrap();
    let before = read_publication(&candidates, &participant, &privacy, &source).await;
    assert_eq!(before.0, "PUBLISHED");
    assert!(matches!(before.1.as_str(), "READY" | "ACTIVE"));
    let mut worker = IndexerPublicationWorker {
        store: CandidatePublicationStore::connect(&manager_url)
            .await
            .unwrap(),
        next_poll: Instant::now(),
    };
    worker.tick(&control, &participant, &privacy).await.unwrap();
    let after = read_publication(&candidates, &participant, &privacy, &source).await;
    assert_eq!(after.0, "FENCED");
    assert_eq!(after.1, "STALE");
    assert_eq!(
        before.2, after.2,
        "historical publication bytes remain immutable"
    );
    drop(worker);
    let mut restarted = IndexerPublicationWorker {
        store: CandidatePublicationStore::connect(&manager_url)
            .await
            .unwrap(),
        next_poll: Instant::now(),
    };
    restarted
        .tick(&control, &participant, &privacy)
        .await
        .unwrap();
    assert_eq!(
        read_publication(&candidates, &participant, &privacy, &source).await,
        after
    );
}

async fn read_publication(
    pool: &PgPool,
    participant: &str,
    privacy: &str,
    source: &str,
) -> (String, String, Vec<u8>) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CANDIDATE_WRITE-V1',true)")
        .bind(participant).bind(privacy).execute(&mut *tx).await.unwrap();
    let rows: Vec<(String, String, Vec<u8>)> = sqlx::query_as("select p.state::text,g.state::text,p.publication_cbor from candidate.source_publication p join candidate.projection_generation g using(projection_generation_id,participant_id,privacy_domain_id) join candidate.projection_profile mapping using(projection_profile_id,participant_id,privacy_domain_id) join candidate.source_profile s using(source_profile_id,participant_id,privacy_domain_id) where s.indexer_profile_id=$1::text::uuid and not p.authority_eligible")
        .bind(source).fetch_all(&mut *tx).await.unwrap();
    assert_eq!(rows.len(), 1);
    tx.rollback().await.unwrap();
    rows.into_iter().next().unwrap()
}

// These cases use the existing public-source fixture and its native stores.
// The caller must exclusively own the scope and leave background publication
// stopped. No source/module/configuration/approval state is seeded here.
struct ModuleFenceFixture {
    control: PgPool,
    worker_control: PgPool,
    candidates: PgPool,
    manager_url: String,
    participant: String,
    privacy: String,
    source: String,
}

#[derive(PartialEq)]
struct NativePublicationState {
    // generation, publication state, generation state, immutable digest,
    // original governed configuration digest; never raw protected payloads.
    publications: Vec<(String, String, String, String, String)>,
    events: Vec<String>,
}

impl ModuleFenceFixture {
    async fn connect() -> Self {
        let control_url = std::env::var("OPENPC_PUBLICATION_TEST_CONTROL_URL").unwrap();
        let control = PgPool::connect(&control_url).await.unwrap();
        let safe: bool = sqlx::query_scalar("select current_database()='openpc_control' and current_user=session_user and session_user='openpc_control_worker' and not rolsuper and not rolbypassrls from pg_roles where rolname=session_user")
            .fetch_one(&control).await.unwrap();
        assert!(
            safe,
            "requires the actual unprivileged Control worker login"
        );
        // One dedicated connection makes termination target only this worker.
        // A non-default isolation setting exposes accidental pre-fence snapshots.
        let worker_control = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("set default_transaction_isolation='repeatable read'")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&control_url)
            .await
            .unwrap();
        let manager_url = std::env::var("OPENPC_PUBLICATION_TEST_MANAGER_URL").unwrap();
        let candidates = PgPool::connect(&manager_url).await.unwrap();
        let value = Self {
            control,
            worker_control,
            candidates,
            manager_url,
            participant: std::env::var("OPENPC_PUBLICATION_TEST_PARTICIPANT").unwrap(),
            privacy: std::env::var("OPENPC_PUBLICATION_TEST_PRIVACY").unwrap(),
            source: std::env::var("OPENPC_PUBLICATION_TEST_SOURCE").unwrap(),
        };
        for id in [&value.participant, &value.privacy, &value.source] {
            let parsed = Uuid::parse_str(id).unwrap();
            assert_eq!(parsed.get_version_num(), 7);
            assert_eq!(parsed.to_string(), *id);
        }
        value
    }

    async fn worker(&self) -> IndexerPublicationWorker {
        IndexerPublicationWorker {
            store: CandidatePublicationStore::connect(&self.manager_url)
                .await
                .unwrap(),
            next_poll: Instant::now(),
        }
    }

    async fn exclusive_module_fence(&self) -> Transaction<'static, Postgres> {
        let mut tx = self.control.begin().await.unwrap();
        let acquired: bool =
            sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended($1,0))")
                .bind(format!(
                    "module-admission:{}:{}",
                    self.participant, self.privacy
                ))
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert!(
            acquired,
            "the public fixture scope must have one test owner"
        );
        tx
    }

    async fn exclusive_available(&self, participant: &str, privacy: &str) -> bool {
        let mut tx = self.control.begin().await.unwrap();
        let available =
            sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended($1,0))")
                .bind(format!("module-admission:{participant}:{privacy}"))
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        tx.rollback().await.unwrap();
        available
    }

    async fn native_state(&self) -> NativePublicationState {
        let mut tx = self.candidates.begin().await.unwrap();
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CANDIDATE_WRITE-V1',true)")
            .bind(&self.participant).bind(&self.privacy).execute(&mut *tx).await.unwrap();
        let publications = sqlx::query_as("select p.projection_generation_id::text,p.state,g.state::text,encode(p.publication_digest,'hex'),encode(p.configuration_digest,'hex') from candidate.source_publication p join candidate.projection_generation g using(participant_id,privacy_domain_id,projection_generation_id) where p.participant_id=$1::text::uuid and p.privacy_domain_id=$2::text::uuid order by p.projection_generation_id")
            .bind(&self.participant).bind(&self.privacy).fetch_all(&mut *tx).await.unwrap();
        let events = sqlx::query_scalar("select event_id::text||':'||state::text||':'||encode(payload_digest,'hex') from candidate.outbox_event where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid order by event_id")
            .bind(&self.participant).bind(&self.privacy).fetch_all(&mut *tx).await.unwrap();
        tx.rollback().await.unwrap();
        NativePublicationState {
            publications,
            events,
        }
    }

    async fn current_configuration(&self) -> String {
        let mut tx =
            begin_publication_observation(&self.worker_control, &self.participant, &self.privacy)
                .await
                .unwrap()
                .unwrap();
        let rows = source_current::load(&mut tx, &self.participant, &self.privacy, None, true)
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "requires one complete public source in this scope"
        );
        let current = prepare(&rows[0], &self.participant, &self.privacy)
            .unwrap()
            .expect("requires actual admitted acquisition inputs");
        assert_eq!(current.input.indexer_profile_id.to_string(), self.source);
        assert!(
            validate_providers(&mut tx, &current.configuration, &current.rule)
                .await
                .unwrap(),
            "renew real provider qualification before this live-authority phase"
        );
        tx.rollback().await.unwrap();
        current.input.configuration_digest
    }

    async fn candidate_blocker(&self) -> Transaction<'static, Postgres> {
        let mut tx = self.candidates.begin().await.unwrap();
        sqlx::query("select pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "openpc:candidate-publication:{}:{}",
                self.participant, self.privacy
            ))
            .execute(&mut *tx)
            .await
            .unwrap();
        tx
    }

    async fn wait_for_native_block<F>(&self, tick: F) -> i32
    where
        F: std::future::Future<Output = Result<(), String>>,
    {
        let waiting = async {
            loop {
                let pids: Vec<i32> = sqlx::query_scalar("select l.pid from pg_locks l join pg_stat_activity a on a.pid=l.pid where l.locktype='advisory' and l.database=(select oid from pg_database where datname=current_database()) and l.classid::bigint=((hashtextextended($1,0)>>32)&4294967295::bigint) and l.objid::bigint=(hashtextextended($1,0)&4294967295::bigint) and l.objsubid=1 and not l.granted and a.usename=current_user")
                    .bind(format!("openpc:candidate-publication:{}:{}", self.participant, self.privacy))
                    .fetch_all(&self.candidates).await.unwrap();
                assert!(
                    pids.len() <= 1,
                    "unexpected competing native writer in the owned scope"
                );
                if let Some(pid) = pids.first() {
                    return *pid;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::select! {
            result = tick => panic!("publication ended before the native fence: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(3), waiting) => result.expect("publication did not reach the actual native fence"),
        }
    }

    async fn close(self) {
        self.worker_control.close().await;
        self.control.close().await;
        self.candidates.close().await;
    }
}

#[tokio::test]
#[ignore = "requires an exclusively owned publicly qualified source before its first candidate publication"]
async fn postgres_module_publication_fence_covers_first_publication_and_failures() {
    let fixture = ModuleFenceFixture::connect().await;
    let original_configuration = fixture.current_configuration().await;
    let original = fixture.native_state().await;
    assert!(
        original.publications.is_empty() && original.events.is_empty(),
        "requires the original public source before first native publication, never reset a used scope"
    );

    let exclusive = fixture.exclusive_module_fence().await;
    let mut worker = fixture.worker().await;
    assert_eq!(
        worker
            .tick(
                &fixture.worker_control,
                &fixture.participant,
                &fixture.privacy
            )
            .await,
        Ok(())
    );
    assert!(
        fixture.native_state().await == original,
        "busy DISABLE fence changed native state"
    );
    exclusive.rollback().await.unwrap();
    drop(worker);

    // Each fault happens before first publication. Preserve the same governed
    // inputs; only the final healthy run may publish the original identity.
    for failure in [
        "CANDIDATE_QUERY_CANCELLED",
        "CONTROL_CONNECTION_LOST",
        "NONE",
    ] {
        let mut worker = fixture.worker().await;
        let control_pid: i32 = sqlx::query_scalar("select pg_backend_pid()")
            .fetch_one(&fixture.worker_control)
            .await
            .unwrap();
        let blocker = fixture.candidate_blocker().await;
        let tick = worker.tick(
            &fixture.worker_control,
            &fixture.participant,
            &fixture.privacy,
        );
        tokio::pin!(tick);
        let candidate_pid = fixture.wait_for_native_block(tick.as_mut()).await;
        assert!(
            !fixture
                .exclusive_available(&fixture.participant, &fixture.privacy)
                .await,
            "module fence was released before candidate reconciliation/publication"
        );
        if failure == "CANDIDATE_QUERY_CANCELLED" {
            let cancelled: bool = sqlx::query_scalar("select pg_cancel_backend($1)")
                .bind(candidate_pid)
                .fetch_one(&fixture.candidates)
                .await
                .unwrap();
            assert!(cancelled);
            let result = tokio::time::timeout(Duration::from_secs(3), tick.as_mut())
                .await
                .unwrap();
            assert_eq!(
                result,
                Err("obsolete candidate source fence unavailable".into())
            );
            blocker.rollback().await.unwrap();
        } else {
            if failure == "CONTROL_CONNECTION_LOST" {
                // The dedicated single-connection pool identifies only this
                // test's Control backend, never another worker/user connection.
                let terminated: bool = sqlx::query_scalar("select pg_terminate_backend($1)")
                    .bind(control_pid)
                    .fetch_one(&fixture.control)
                    .await
                    .unwrap();
                assert!(terminated);
            }
            blocker.rollback().await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(3), tick.as_mut())
                .await
                .unwrap();
            if failure == "NONE" {
                assert_eq!(result, Ok(()));
            } else {
                assert_eq!(result, Err("indexer publication observation lost".into()));
            }
        }
        // Reacquisition drains SQLx's dropped-transaction rollback, or reconnects
        // the terminated session. This is not a business retry.
        sqlx::query("select 1")
            .execute(&fixture.worker_control)
            .await
            .unwrap();
        assert!(
            fixture
                .exclusive_available(&fixture.participant, &fixture.privacy)
                .await,
            "failed/finished publication leaked its module transaction fence"
        );
        if failure != "NONE" {
            assert!(
                fixture.native_state().await == original,
                "failed pre-publication case changed the original native state"
            );
        }
    }
    let published = fixture.native_state().await;
    assert_eq!(published.publications.len(), 1);
    assert_eq!(published.publications[0].1, "PUBLISHED");
    assert_eq!(
        published.publications[0].4,
        original_configuration.trim_start_matches("sha256:")
    );
    let mut restarted = fixture.worker().await;
    restarted
        .tick(
            &fixture.worker_control,
            &fixture.participant,
            &fixture.privacy,
        )
        .await
        .unwrap();
    assert!(
        fixture.native_state().await == published,
        "restart rewrote original publication identity or duplicated its outbox"
    );
    drop(restarted);
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires the real Control worker and public-source scope"]
async fn postgres_module_publication_fence_uses_canonical_scope_and_fresh_isolation() {
    let fixture = ModuleFenceFixture::connect().await;
    let exclusive = fixture.exclusive_module_fence().await;
    let alias = begin_publication_observation(
        &fixture.worker_control,
        &fixture.participant.to_uppercase(),
        &fixture.privacy.to_uppercase(),
    )
    .await;
    assert!(
        matches!(alias, Ok(None)),
        "UUID text aliases must not select another advisory fence"
    );
    exclusive.rollback().await.unwrap();
    let mut current = begin_publication_observation(
        &fixture.worker_control,
        &fixture.participant,
        &fixture.privacy,
    )
    .await
    .unwrap()
    .expect("uncontended module fence");
    let isolation: String = sqlx::query_scalar("show transaction_isolation")
        .fetch_one(&mut *current)
        .await
        .unwrap();
    assert_eq!(
        isolation, "read committed",
        "context setup must not pin an older MVCC snapshot"
    );
    assert!(
        !fixture
            .exclusive_available(&fixture.participant, &fixture.privacy)
            .await
    );
    // Namespace contention check only; random foreign IDs confer no authority
    // and create no business state or acceptance claim for a foreign actor.
    assert!(
        fixture
            .exclusive_available(&Uuid::now_v7().to_string(), &fixture.privacy)
            .await
    );
    assert!(
        fixture
            .exclusive_available(&fixture.participant, &Uuid::now_v7().to_string())
            .await
    );
    current.rollback().await.unwrap();
    assert!(
        fixture
            .exclusive_available(&fixture.participant, &fixture.privacy)
            .await
    );
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires the existing governed source-replacement journey before publication reconciliation"]
async fn postgres_module_publication_uses_current_owners_after_governed_replacement() {
    let fixture = ModuleFenceFixture::connect().await;
    // Historical comparison only, supplied from the original public readback.
    // This value is never used as publication input or source authority.
    let previous = std::env::var("OPENPC_PUBLICATION_TEST_PREVIOUS_CONFIGURATION_DIGEST").unwrap();
    Digest::parse(previous.strip_prefix("sha256:").unwrap_or(&previous)).unwrap();
    let current = fixture.current_configuration().await;
    assert_ne!(
        previous, current,
        "requires a real governed source replacement"
    );
    let before = fixture.native_state().await;
    assert!(
        before
            .publications
            .iter()
            .any(|row| row.1 == "PUBLISHED" && row.4 == previous.trim_start_matches("sha256:")),
        "requires the original retained publication before reconciliation"
    );
    let exclusive = fixture.exclusive_module_fence().await;
    let mut worker = fixture.worker().await;
    assert_eq!(
        worker
            .tick(
                &fixture.worker_control,
                &fixture.participant,
                &fixture.privacy
            )
            .await,
        Ok(())
    );
    assert!(
        fixture.native_state().await == before,
        "busy fence must not run remove-only reconciliation"
    );
    exclusive.rollback().await.unwrap();
    drop(worker);
    let mut restarted = fixture.worker().await;
    restarted
        .tick(
            &fixture.worker_control,
            &fixture.participant,
            &fixture.privacy,
        )
        .await
        .unwrap();
    let after = fixture.native_state().await;
    let active: Vec<_> = after
        .publications
        .iter()
        .filter(|row| row.1 == "PUBLISHED")
        .collect();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].4, current.trim_start_matches("sha256:"));
    for original in &before.publications {
        let retained = after
            .publications
            .iter()
            .find(|row| row.0 == original.0)
            .expect("original publication must remain");
        assert_eq!(
            retained.3, original.3,
            "original immutable publication digest changed"
        );
        if original.4 == previous.trim_start_matches("sha256:") {
            assert_eq!(retained.1, "FENCED");
            assert_eq!(retained.2, "STALE");
        }
    }
    drop(restarted);
    fixture.close().await;
}
