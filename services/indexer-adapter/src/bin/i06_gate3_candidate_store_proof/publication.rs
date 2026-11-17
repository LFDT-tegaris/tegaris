//! Installed-role/database component proof. The public governance journey must
//! separately obtain these inputs from real approved Control operations.
use super::*;
use openpc_indexer_adapter::{
    AcquisitionConfiguration, AcquisitionRequest, CandidatePublicationStore, FinalityMode,
    FinalityRule, GovernedSourcePublication,
};

pub(super) async fn prove(
    manager_url: &str,
    writer_url: &str,
    owner_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        CandidatePublicationStore::connect(writer_url).await,
        Err(CandidateStoreError::WrongStoreIdentity)
    ));
    let manager = CandidatePublicationStore::connect(manager_url).await?;
    let acquisition = AcquisitionConfiguration {
        rate_limit: None,
        runtime_target_id: Uuid::now_v7().to_string(),
        request: AcquisitionRequest::StateCall {
            target_address: format!("0x{}", "44".repeat(20)),
            calldata: "0x11223344".into(),
        },
    };
    let finality = FinalityRule {
        rule_id: format!("urn:openpc:finality-rule:{}", Uuid::now_v7()),
        receipt_digest: format!("sha256:{}", d("publication-component-receipt")),
        mode: FinalityMode::Confirmations { count: 12 },
        canonical_provider_digests: vec![format!("sha256:{}", d("publication-component-provider"))],
        required_observations: 1,
    };
    let mut profile = profile_for_class("STATE_CALL");
    let acquisition_cbor = acquisition.encode()?;
    let finality_cbor = finality.encode()?;
    profile.configuration_digest = format!("sha256:{}", digest_hex(&acquisition_cbor));
    profile.finality_rule_digest = format!("sha256:{}", digest_hex(&finality_cbor));
    let mut plan = projection_plan();
    plan.finality_rule_digest = profile.finality_rule_digest.clone();
    for partition in &mut plan.partitions {
        partition.finality_digest = profile.finality_rule_digest.clone();
    }
    let mut input = GovernedSourcePublication {
        participant_id: uuid(PARTICIPANT),
        privacy_domain_id: uuid(PRIVACY),
        indexer_profile_id: Uuid::now_v7(),
        source_revision: 3,
        qualification_operation_id: Uuid::now_v7(),
        projection_plan_id: Uuid::now_v7(),
        projection_revision: 2,
        validation_operation_id: Uuid::now_v7(),
        action_intent_id: PROOF_ACTION.into(),
        configuration_digest: format!("sha256:{}", d("publication-component-configuration")),
        profile_cbor: encode_client_indexer_profile_pc_cbor(&profile)?,
        plan_cbor: encode_projection_plan_pc_cbor(&plan)?,
        finality_rule_cbor: finality_cbor,
        acquisition_configuration_cbor: acquisition_cbor,
    };
    let published = manager.publish(&input).await?;
    assert_eq!(manager.publish(&input).await?, published);
    let restarted = CandidatePublicationStore::connect(manager_url).await?;
    assert_eq!(restarted.publish(&input).await?, published);
    for substitution in [
        "scope",
        "qualification",
        "revision",
        "configuration",
        "finality",
    ] {
        let mut changed = input.clone();
        match substitution {
            "scope" => changed.privacy_domain_id = Uuid::now_v7(),
            "qualification" => changed.qualification_operation_id = Uuid::now_v7(),
            "revision" => changed.source_revision += 2,
            "configuration" => changed.acquisition_configuration_cbor = vec![0x80],
            "finality" => changed.finality_rule_cbor = vec![0x80],
            _ => unreachable!(),
        }
        assert!(
            matches!(
                manager.publish(&changed).await,
                Err(CandidateStoreError::InvalidBinding)
            ),
            "{substitution}"
        );
    }
    let writer = CandidateStore::connect(writer_url).await?;
    let binding = CandidatePersistenceBinding::try_new(
        uuid(PARTICIPANT),
        uuid(PRIVACY),
        published.projection_generation_id,
        uuid(OPERATION),
        uuid(CORRELATION),
    )?;
    let loaded = writer.acquisition_inputs(&binding).await?;
    assert_eq!(loaded.source().profile_cbor, input.profile_cbor);
    assert_eq!(loaded.source().plan_cbor, input.plan_cbor);
    assert_eq!(loaded.published(), &published);
    assert_eq!(loaded.profile(), &profile);
    assert_eq!(loaded.plan(), &plan);
    assert_eq!(loaded.acquisition(), &acquisition);
    assert_eq!(loaded.finality_rule(), &finality);
    for (participant, privacy, generation) in [
        (
            Uuid::now_v7(),
            uuid(PRIVACY),
            published.projection_generation_id,
        ),
        (
            uuid(PARTICIPANT),
            Uuid::now_v7(),
            published.projection_generation_id,
        ),
        (uuid(PARTICIPANT), uuid(PRIVACY), Uuid::now_v7()),
    ] {
        let foreign = CandidatePersistenceBinding::try_new(
            participant,
            privacy,
            generation,
            uuid(OPERATION),
            uuid(CORRELATION),
        )?;
        assert!(matches!(
            writer.acquisition_inputs(&foreign).await,
            Err(CandidateStoreError::InvalidBinding)
        ));
    }
    writer
        .register_partition(&profile, &plan, &binding, "source", "partition")
        .await?;
    let batch = batch(1, 1, 10, "publication-batch", "GENESIS");
    let wrong = material_for_class(&profile, &plan, &batch, &binding, "STATE_CALL")?;
    assert!(
        matches!(
            writer.persist_batch(&wrong).await,
            Err(CandidateStoreError::InvalidBinding)
        ),
        "unbound call parameters must not create a feed row"
    );
    let mut records = record_materials_for_class(&batch, "STATE_CALL");
    for record in &mut records {
        if let CandidateRecordIdentityV1::StateCall {
            call_parameter_digest,
            ..
        } = &mut record.identity
        {
            *call_parameter_digest =
                acquisition.state_call_parameter_digest(record.record.block_number)?;
        }
    }
    let material = CandidateBatchMaterialV1::try_new(
        (&profile, &plan, &batch, &binding),
        block_observations(&profile, &batch),
        records,
        false,
    )?;
    let _ = writer.persist_batch(&material).await?;

    let owner = PgPoolOptions::new()
        .max_connections(1)
        .connect(owner_url)
        .await?;
    admission_view::prove(&owner, &input, published.projection_generation_id, false).await?;
    for role in [
        "openpc_indexer_manager",
        "openpc_indexer_writer",
        "openpc_fact_bridge_reader",
    ] {
        let grants: (bool,bool,bool) = sqlx::query_as("select has_table_privilege($1,'candidate.source_publication','INSERT'),has_table_privilege($1,'candidate.candidate_event','INSERT'),has_table_privilege($1,'candidate.source_profile','UPDATE')")
            .bind(role).fetch_one(&owner).await?;
        assert_eq!(
            grants,
            (
                role == "openpc_indexer_manager",
                role == "openpc_indexer_writer",
                false
            ),
            "{role}"
        );
        for (participant, privacy, expected) in [
            (uuid(PARTICIPANT), uuid(PRIVACY), 1_i64),
            (Uuid::now_v7(), uuid(PRIVACY), 0),
            (uuid(PARTICIPANT), Uuid::now_v7(), 0),
        ] {
            let mut scoped = owner.begin().await?;
            sqlx::query(match role {
                "openpc_indexer_manager" => "set local role openpc_indexer_manager",
                "openpc_indexer_writer" => "set local role openpc_indexer_writer",
                "openpc_fact_bridge_reader" => "set local role openpc_fact_bridge_reader",
                _ => unreachable!(),
            })
            .execute(&mut *scoped)
            .await?;
            sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)")
                .bind(participant)
                .bind(privacy)
                .bind(uuid(OPERATION))
                .bind(PROOF_ACTION)
                .execute(&mut *scoped)
                .await?;
            let visible: i64 = sqlx::query_scalar("select count(*) from candidate.source_publication where projection_generation_id=$1 and not authority_eligible")
                .bind(published.projection_generation_id)
                .fetch_one(&mut *scoped)
                .await?;
            assert_eq!(visible, expected, "publication isolation for {role}");
            scoped.rollback().await?;
        }
    }
    // Reconciliation uses complete exact tuples, not resource IDs or matching
    // source bytes alone. Invalid snapshots must leave the old row unchanged.
    assert!(
        manager
            .fence_obsolete(uuid(PARTICIPANT), uuid(PRIVACY), uuid(OPERATION), &[&input])
            .await?
            .is_empty()
    );
    assert!(
        manager
            .fence_obsolete(Uuid::now_v7(), uuid(PRIVACY), uuid(OPERATION), &[])
            .await?
            .is_empty()
    );
    assert!(
        manager
            .fence_obsolete(uuid(PARTICIPANT), Uuid::now_v7(), uuid(OPERATION), &[])
            .await?
            .is_empty()
    );
    let mut foreign = input.clone();
    foreign.privacy_domain_id = Uuid::now_v7();
    assert!(matches!(
        manager
            .fence_obsolete(
                uuid(PARTICIPANT),
                uuid(PRIVACY),
                uuid(OPERATION),
                &[&foreign]
            )
            .await,
        Err(CandidateStoreError::InvalidBinding)
    ));
    assert!(matches!(
        manager
            .fence_obsolete(
                uuid(PARTICIPANT),
                uuid(PRIVACY),
                uuid(OPERATION),
                &[&input, &input]
            )
            .await,
        Err(CandidateStoreError::InvalidBinding)
    ));
    assert_eq!(
        writer.acquisition_inputs(&binding).await?.published(),
        &published
    );

    let mut requalified = input.clone();
    requalified.source_revision += 2;
    requalified.qualification_operation_id = Uuid::now_v7();
    // An in-flight candidate transaction holds the generation's shared lock.
    // Removal must serialize before any later writer can use the old tuple.
    let mut held = owner.begin().await?;
    sqlx::query("select projection_generation_id from candidate.projection_generation where projection_generation_id=$1 for share")
        .bind(published.projection_generation_id).fetch_one(&mut *held).await?;
    let current = [&requalified];
    let removal =
        manager.fence_obsolete(uuid(PARTICIPANT), uuid(PRIVACY), uuid(OPERATION), &current);
    tokio::pin!(removal);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut removal)
            .await
            .is_err(),
        "fence must wait for the candidate transaction"
    );
    held.rollback().await?;
    assert_eq!(removal.await?, vec![published.projection_generation_id]);
    admission_view::prove(&owner, &input, published.projection_generation_id, true).await?;
    assert!(
        restarted
            .fence_obsolete(uuid(PARTICIPANT), uuid(PRIVACY), uuid(OPERATION), &[])
            .await?
            .is_empty()
    );
    assert!(matches!(
        writer.acquisition_inputs(&binding).await,
        Err(CandidateStoreError::InvalidBinding)
    ));
    assert!(matches!(
        writer.persist_batch(&material).await,
        Err(CandidateStoreError::InvalidBinding)
    ));
    assert!(matches!(
        manager.publish(&input).await,
        Err(CandidateStoreError::InvalidBinding)
    ));
    let mut tx = owner.begin().await?;
    sqlx::query("set local role openpc_indexer_manager")
        .execute(&mut *tx)
        .await?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)")
        .bind(uuid(PARTICIPANT))
        .bind(uuid(PRIVACY))
        .bind(uuid(OPERATION))
        .bind(PROOF_ACTION)
        .execute(&mut *tx)
        .await?;
    assert!(sqlx::query("update candidate.source_publication set state='PUBLISHED' where projection_generation_id=$1")
        .bind(published.projection_generation_id).execute(&mut *tx).await.is_err(),"fenced publication cannot be revived");
    tx.rollback().await?;

    // A governed plan update retains the public identity while creating a new
    // immutable mapping and generation. The earlier mapping is never edited.
    plan.lifecycle_generation += 1;
    input.plan_cbor = encode_projection_plan_pc_cbor(&plan)?;
    input.projection_revision += 2;
    input.validation_operation_id = Uuid::now_v7();
    let replacement = manager.publish(&input).await?;
    assert_ne!(
        published.projection_generation_id,
        replacement.projection_generation_id
    );
    assert_ne!(published.generation_digest, replacement.generation_digest);
    // Complete disappearance fences the replacement too, while retry remains
    // idempotent. An earlier exact snapshot can never revive the first row.
    assert_eq!(
        manager
            .fence_obsolete(uuid(PARTICIPANT), uuid(PRIVACY), uuid(OPERATION), &[])
            .await?,
        vec![replacement.projection_generation_id]
    );
    assert!(matches!(
        manager.publish(&input).await,
        Err(CandidateStoreError::InvalidBinding)
    ));
    writer.close().await;
    owner.close().await;
    println!(
        "OPENPC_CANDIDATE_PUBLICATION|PASS|installed-manager-role|exact-replay|restart|source-tuple-denial|request-binding|monotonic-fence|immutable-mapping-replacement|obsolete-scope-reconciliation|fence-writer-serialization|candidate-only"
    );
    Ok(())
}
