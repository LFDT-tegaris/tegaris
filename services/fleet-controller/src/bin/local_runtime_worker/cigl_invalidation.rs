//! Current-source scan on the existing Fleet process. The grant fence also
//! serializes delivery with profile activation, so a stale scan cannot replace
//! the bootstrap of a newer generation. No live target journal is opened here.
use super::*;
use openpc_fleet_controller::{
    cigl_publication::profile_invalidation::{generation_is_invalidated, lock_sources},
    runtime_target::restrict_target_generation,
};

async fn context(
    pool: &PgPool,
    participant: &str,
    privacy: &str,
) -> WorkerResult<Transaction<'static, Postgres>> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| "CIGL invalidation transaction unavailable")?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
        .bind(participant).bind(privacy).execute(&mut *tx).await.map_err(|_| "CIGL invalidation scope rejected")?;
    Ok(tx)
}

pub(super) async fn run(
    pool: PgPool,
    participant: String,
    privacy: String,
    fleet_key: [u8; 32],
    source: openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker,
) -> WorkerResult<()> {
    let public = PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, fleet_key)
        .map_err(|_| "CIGL invalidation trust unavailable")?
        .verifier()
        .sec1_bytes();
    let mut after = String::new();
    loop {
        let mut tx = context(&pool, &participant, &privacy).await?;
        let targets: Vec<String> = sqlx::query_scalar(r#"select target.runtime_target_id::text
          from control.runtime_target target where target.runtime_target_id::text>$1
           and exists(select 1 from control.runtime_activation_observation observation
            join control.runtime_configuration_generation generation
             on generation.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
              and generation.participant_id=target.participant_id and generation.privacy_domain_id=target.privacy_domain_id
            where observation.runtime_target_id=target.runtime_target_id and observation.participant_id=target.participant_id
             and observation.privacy_domain_id=target.privacy_domain_id
             and generation.state in ('ACTIVE','ACTIVATING') and generation.cigl_profile_selection is not null)
          order by target.runtime_target_id limit 64"#)
            .bind(&after).fetch_all(&mut *tx).await.map_err(|_| "CIGL invalidation targets unavailable")?;
        tx.rollback()
            .await
            .map_err(|_| "CIGL invalidation scan release failed")?;
        for target in &targets {
            let mut tx = context(&pool, &participant, &privacy).await?;
            match source.lock_consumer_scope(&mut tx).await {
                Ok(()) => {}
                Err(openpc_fleet_controller::runtime_artifact_source::SourceCustodyError::Busy) => {
                    tx.rollback()
                        .await
                        .map_err(|_| "CIGL invalidation source release failed")?;
                    continue;
                }
                Err(_) => return Err("CIGL invalidation source custody unavailable".into()),
            }
            // Acquire before reading the file: activation holds this same fence
            // until its observation is durable and the new bootstrap is written.
            lock_sources(&mut tx)
                .await
                .map_err(|_| "CIGL invalidation fence unavailable")?;
            let directory = Path::new("/runtime/target-bootstrap").join(target);
            let mut manifest = read_target_bootstrap(&directory, &public)?;
            if manifest.participant_id != participant
                || manifest.privacy_domain_id != privacy
                || manifest.target_runtime_id != *target
            {
                return Err("CIGL invalidation target identity rejected".into());
            }
            match generation_is_invalidated(
                &mut tx,
                target,
                &manifest.capsule_id,
                &manifest.capsule_digest,
            )
            .await
            {
                Ok(true) => {
                    record_bootstrap_source_restriction(
                        &mut tx,
                        &source,
                        &manifest,
                        "cigl-invalidation",
                    )
                    .await?;
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| "CIGL invalidation clock unavailable")?
                        .as_nanos();
                    let now = u64::try_from(now).map_err(|_| "CIGL invalidation clock rejected")?;
                    if let Some(delivery) = restrict_target_generation(
                        &manifest,
                        fleet_key,
                        now,
                        now.saturating_add(300_000_000_000),
                    )
                    .map_err(|_| "CIGL invalidation restriction rejected")?
                    {
                        manifest.emergency_delivery = Some(delivery);
                        write_target_bootstrap(&directory, manifest, fleet_key)?;
                    }
                }
                Ok(false) | Err(pc_runtime_types::RuntimeError::GenerationMismatch) => {}
                Err(_) => return Err("CIGL invalidation sources unavailable".into()),
            }
            tx.rollback()
                .await
                .map_err(|_| "CIGL invalidation source release failed")?;
        }
        if targets.len() < 64 {
            after.clear();
            tokio::time::sleep(Duration::from_secs(5)).await;
        } else {
            after = targets.last().expect("nonempty page").clone();
        }
    }
}
