//! Denial-only processing of an approved root replacement's immutable cohort.
//! Missing signed custody remains UNKNOWN; no new activation or reconstructed
//! first-issue signing permit is used to make it appear acknowledged.
use super::*;
use serde_json::json;

#[derive(Default)]
pub(super) struct Withdrawal {
    next: Option<tokio::time::Instant>,
    reported: BTreeSet<(String, String)>,
    announced: BTreeSet<(String, String)>,
    adopted: Option<Digest>,
}

impl Withdrawal {
    pub(super) async fn tick(&mut self, pool: &PgPool, config: &Config, plane: &RuntimePlane) {
        let now = tokio::time::Instant::now();
        if self.next.is_some_and(|next| now < next) {
            return;
        }
        self.next = Some(now + Duration::from_secs(2));
        let Ok(pending) = pending(pool, config).await else {
            if self
                .reported
                .insert(("source".into(), "source_read".into()))
            {
                eprintln!(
                    r#"{{"level":"warn","event":"platform_scope_withdrawal_blocked","stage":"source_read","retry_disposition":"WAIT_FOR_CURRENT_SOURCE"}}"#
                );
            }
            return;
        };
        let Some(store) = &plane.disposition else {
            self.configuration_blocked("native_disposition_owner_missing");
            return;
        };
        let Ok(pem) = fs::read(&plane.config.target_client_certificate) else {
            self.configuration_blocked("target_certificate_unavailable");
            return;
        };
        let Ok(peer) = runtime_tls::target_identity_from_pem(&pem) else {
            self.configuration_blocked("target_certificate_identity_rejected");
            return;
        };
        if self.adopted.as_ref() != Some(&peer.certificate_fingerprint) {
            if adopt_credential_bootstrap(pool, config, plane, store, &peer)
                .await
                .is_err()
            {
                self.configuration_blocked("credential_bootstrap_adoption_unavailable");
                return;
            }
            self.adopted = Some(peer.certificate_fingerprint.clone());
        }
        if pending.is_empty() {
            self.reported.clear();
            self.announced.clear();
            return;
        }
        for (replacement, target, unsigned) in pending {
            if target != peer.target_id {
                continue;
            }
            let key = (replacement.clone(), target.clone());
            if self.announced.insert(key.clone()) {
                eprintln!(
                    "{}",
                    json!({"level":"info","event":"platform_scope_withdrawal_started",
                  "replacement_id":replacement,"target_id":target,"worker_id":config.worker_id,
                  "stage":"resolve_original_custody","retry_disposition":"DENIAL_ONLY"})
                );
            }
            if unsigned {
                if self.reported.insert(key) {
                    eprintln!(
                        "{}",
                        json!({"level":"warn","event":"platform_scope_withdrawal_blocked",
                        "replacement_id":replacement,"target_id":target,"stage":"unsigned_original_admission",
                        "retry_disposition":"WAIT_FOR_CUSTODY_RECONCILIATION"})
                    );
                }
                continue;
            }
            match store
                .publish_platform_scope_withdrawal(&peer, &replacement, &config.worker_id)
                .await
            {
                Ok(true) => {
                    self.reported.remove(&key);
                    eprintln!(
                        "{}",
                        json!({"level":"info","event":"platform_scope_withdrawal_acknowledged",
                      "replacement_id":replacement,"target_id":target,"stage":"verified_signed_acknowledgement",
                      "retry_disposition":"AWAIT_GOVERNED_ROOT_COMMIT"})
                    );
                }
                Ok(false) => {}
                Err(error)
                    if error
                        == openpc_fleet_controller::target_disposition::TARGET_DISPOSITION_BUSY => {
                }
                Err(error) => {
                    let (owner_stage, error_class, sqlstate) =
                        openpc_fleet_controller::target_disposition::withdrawal_failure_diagnostic(
                            &error,
                        );
                    if self.reported.insert(key) {
                        eprintln!(
                            "{}",
                            json!({"level":"warn","event":"platform_scope_withdrawal_blocked",
                            "replacement_id":replacement,"target_id":target,"stage":"signed_withdrawal","owner_stage":owner_stage,
                            "error_class":error_class,"sqlstate":sqlstate,
                            "retry_disposition":"WAIT_FOR_CURRENT_SOURCE_OR_ORIGINAL_CUSTODY"})
                        );
                    }
                }
            }
        }
    }

    fn configuration_blocked(&mut self, stage: &'static str) {
        if self.reported.insert(("configuration".into(), stage.into())) {
            eprintln!(
                "{}",
                json!({"level":"warn","event":"platform_scope_withdrawal_blocked",
                "stage":stage,"retry_disposition":"WAIT_FOR_LOCAL_RUNTIME_OWNER"})
            );
        }
    }
}

async fn pending(pool: &PgPool, config: &Config) -> WorkerResult<Vec<(String, String, bool)>> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| "Platform withdrawal source unavailable")?;
    set_context(&mut tx, config).await?;
    let rows = sqlx::query(r#"select q.replacement_id::text replacement,q.runtime_target_id::text target,
      (head.binding->'cause'=jsonb_build_object('kind','Dependency','owner','Platform',
        'resource_id',r.replacement_id::text,'operation_id',r.prepare_operation_id::text,'revision',1)
        and delivery.delivery_digest is null) as unsigned
      from control.platform_scope_target_withdrawal q join control.platform_scope_replacement r
        on r.replacement_id=q.replacement_id and r.participant_id=q.participant_id and r.privacy_domain_id=q.privacy_domain_id
      left join lateral(select a.* from control.runtime_target_disposition_admission a
        where a.participant_id=q.participant_id and a.privacy_domain_id=q.privacy_domain_id
          and a.runtime_target_id=q.runtime_target_id order by a.revision desc limit 1) head on true
      left join control.runtime_target_disposition_delivery delivery on delivery.participant_id=q.participant_id
        and delivery.privacy_domain_id=q.privacy_domain_id and delivery.runtime_target_id=q.runtime_target_id and delivery.revision=head.revision
      left join control.runtime_target_disposition_acknowledgement ack on ack.participant_id=q.participant_id
        and ack.privacy_domain_id=q.privacy_domain_id and ack.runtime_target_id=q.runtime_target_id and ack.delivery_digest=delivery.delivery_digest
      where q.participant_id=$1::text::uuid and q.privacy_domain_id=$2::text::uuid and r.state='WITHDRAWING'
        and not coalesce((head.binding->>'action'='Withdraw' and head.binding->'cause'=jsonb_build_object('kind','Dependency','owner','Platform',
          'resource_id',r.replacement_id::text,'operation_id',r.prepare_operation_id::text,'revision',1) and ack.delivery_digest is not null),false)
      order by q.replacement_id,q.runtime_target_id limit 257"#)
        .bind(&config.participant_id).bind(&config.privacy_domain_id).fetch_all(&mut *tx).await
        .map_err(|_| "Platform withdrawal source unavailable")?;
    if rows.len() > 256 {
        return Err("Platform withdrawal source capacity exceeded".into());
    }
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        result.push((
            row.try_get("replacement")
                .map_err(|_| "Platform withdrawal source rejected")?,
            row.try_get("target")
                .map_err(|_| "Platform withdrawal source rejected")?,
            row.try_get::<Option<bool>, _>("unsigned")
                .map_err(|_| "Platform withdrawal source rejected")?
                .unwrap_or(false),
        ));
    }
    tx.commit()
        .await
        .map_err(|_| "Platform withdrawal source unavailable")?;
    Ok(result)
}

/// Same original capsule/work/journal, never activation replay. The actual
/// completed discovery owner supplies the one-hop predecessor before Fleet
/// signs the current host pointer. Original bootstrap bytes remain immutable.
async fn adopt_credential_bootstrap(
    pool: &PgPool,
    config: &Config,
    plane: &RuntimePlane,
    store: &openpc_fleet_controller::target_disposition::TargetDispositionStore,
    peer: &TargetIdentity,
) -> WorkerResult<()> {
    let directory = Path::new("/runtime/target-bootstrap").join(&peer.target_id);
    let fleet_public =
        PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, config.fleet_key)
            .map_err(|_| "credential adoption bootstrap trust unavailable")?
            .verifier()
            .sec1_bytes();
    let (mut prior, old_bytes) =
        openpc_fleet_controller::runtime_target::read_target_bootstrap_with_custody(
            &directory,
            &fleet_public,
        )?;
    if prior.target_runtime_id != peer.target_id
        || prior.participant_id != config.participant_id
        || prior.privacy_domain_id != config.privacy_domain_id
        || prior.authority_signer_id != config.worker_id
    {
        return Err("credential adoption original bootstrap context rejected".into());
    }
    let original = prior
        .target_disposition
        .as_ref()
        .ok_or("credential adoption original disposition unavailable")?;
    if original.target.certificate_digest == peer.certificate_fingerprint {
        return Ok(());
    }
    let retained = retained_target::read_installed(config, &peer.target_id)
        .map_err(|_| "credential adoption original target custody unavailable")?;
    let digest = retained
        .capsule
        .digest()
        .map_err(|_| "credential adoption original capsule rejected")?;
    if digest != prior.capsule_digest {
        return Err("credential adoption original capsule changed".into());
    }
    let current = store
        .bootstrap_for_activation(peer, &retained.capsule)
        .await?;
    if current.source != original.source
        || current.credential_predecessor.as_ref() != Some(&original.target)
    {
        return Err("credential adoption governed predecessor rejected".into());
    }
    let archive = directory.join(format!(
        "bootstrap.{}.json",
        Digest::of(&old_bytes).as_str()
    ));
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| "credential adoption source transaction unavailable")?;
    set_context(&mut tx, config).await?;
    record_bootstrap_source_restriction(
        &mut tx,
        &plane.source_custody,
        &prior,
        "prior-bootstrap-binding",
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| "credential adoption source custody commit failed")?;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&archive)
    {
        Ok(mut file) => file
            .write_all(&old_bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "credential adoption original custody persistence failed")?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&archive)
                .map_err(|_| "credential adoption original custody unavailable")?;
            use std::os::unix::fs::MetadataExt;
            if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
                return Err("credential adoption original custody permissions rejected".into());
            }
            if fs::read(&archive).map_err(|_| "credential adoption original custody unavailable")?
                != old_bytes
            {
                return Err("credential adoption original custody conflict".into());
            }
            fs::File::open(&archive)
                .and_then(|file| file.sync_all())
                .map_err(|_| "credential adoption original custody persistence failed")?;
        }
        Err(_) => return Err("credential adoption original custody unavailable".into()),
    }
    fs::File::open(&directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| "credential adoption custody directory sync failed")?;
    if fs::read(directory.join("bootstrap.json"))
        .map_err(|_| "credential adoption pointer unavailable")?
        != old_bytes
    {
        return Err("credential adoption pointer changed".into());
    }
    prior.target_disposition = Some(current);
    write_target_bootstrap(&directory, prior, config.fleet_key)?;
    Ok(())
}
