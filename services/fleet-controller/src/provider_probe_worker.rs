//! Autonomous, off-path observation of governed registered provider candidates.
//! No request, health response, fixture flag or declared lifecycle can mint an
//! observation. Publication follows the real authenticated TLS protocol probe and a fresh
//! database compare-and-swap. Independent public approval remains separate.
use crate::provider_probe_source::{self, now_ms};
use openpc_multi_rpc::{
    provider_connection::{ConnectionError, ConnectionRegistry},
    provider_probe::{HashPinnedCallObservation, probe_hash_pinned_call},
    qualify_provider_profile,
};
use pc_policy_core::invocation::{ConfigurationArtifactKind, load_active_configuration_artifact};
use pc_runtime_types::Digest;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{env, future::Future, path::PathBuf, time::Duration};
use tokio::time::{Instant, timeout};

#[cfg(test)]
#[path = "provider_probe_worker_tests.rs"]
mod tests;

// Renewable ownership is independent of the corpus's observation window. A
// crashed worker cannot hold a candidate for the whole (up to one hour) corpus.
const CLAIM_SECONDS: i32 = 30;
const RENEW_INTERVAL: Duration = Duration::from_secs(5);
const RENEW_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ProviderProbeWorker {
    source_directory: PathBuf,
    connections: ConnectionRegistry,
}
struct Candidate {
    observation_id: String,
    lease_token: String,
    provider_id: String,
    source_revision: i64,
    input_digest: String,
    configuration_digest: Digest,
    configuration_cbor: Vec<u8>,
    endpoint_secret_ref: String,
    chain_id: String,
}

async fn context(
    tx: &mut Transaction<'_, Postgres>,
    participant: &str,
    privacy: &str,
) -> Result<(), String> {
    // Bound every admission query, including context and the first lifecycle
    // fence. Active renewal retains its outer five-second deadline as well.
    sqlx::query("set transaction isolation level read committed")
        .execute(&mut **tx)
        .await
        .map_err(|_| "provider probe isolation rejected")?;
    sqlx::query(
        "select set_config('lock_timeout','2s',true),set_config('statement_timeout','3s',true)",
    )
    .execute(&mut **tx)
    .await
    .map_err(|_| "provider probe timeout rejected")?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true),openpc.assert_request_context(true)")
        .bind(participant).bind(privacy).execute(&mut **tx).await
        .map_err(|_| "provider probe context rejected")?;
    Ok(())
}

async fn candidate_fences(
    tx: &mut Transaction<'_, Postgres>,
    unclaimed: bool,
) -> Result<bool, String> {
    // The current-input view takes this lifecycle fence too. Acquire it before
    // all module/policy/row reads so a concurrent source owner cannot become a
    // reverse wait or an unrelated fatal candidate-read failure.
    if unclaimed {
        let acquired: bool = sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||openpc.current_participant_id()::text,0))")
            .fetch_one(&mut **tx).await.map_err(|_| "provider lifecycle fence unavailable")?;
        if !acquired {
            return Ok(false);
        }
    } else {
        sqlx::query("select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||openpc.current_participant_id()::text,0))")
            .execute(&mut **tx).await.map_err(|_| "provider lifecycle fence unavailable")?;
    }
    sqlx::query(
        "select pg_advisory_xact_lock_shared(hashtextextended('module-release-catalog',0))",
    )
    .execute(&mut **tx)
    .await
    .map_err(|_| "provider release fence unavailable")?;
    sqlx::query("select pg_advisory_xact_lock_shared(hashtextextended('module-admission:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0))")
        .execute(&mut **tx).await.map_err(|_| "provider module fence unavailable")?;
    sqlx::query("select pg_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0))")
        .execute(&mut **tx).await.map_err(|_| "provider policy fence unavailable")?;
    Ok(true)
}
fn digest(value: &str) -> Result<Digest, String> {
    Digest::parse(
        value
            .strip_prefix("sha256:")
            .ok_or("provider digest rejected")?,
    )
    .map_err(|_| "provider digest rejected".into())
}
impl ProviderProbeWorker {
    pub fn from_environment() -> Result<Option<Self>, String> {
        let Some(directory) = env::var_os("OPENPC_PROVIDER_SOURCE_DIRECTORY") else {
            return Ok(None);
        };
        let journal = env::var_os("OPENPC_PROVIDER_PROBE_JOURNAL_DIRECTORY")
            .ok_or("provider probe journal configuration missing")?;
        let connections = ConnectionRegistry::open(
            std::path::Path::new(&journal),
            "provider-qualification-worker",
            1024,
        )
        .map_err(|_| "provider probe journal rejected")?;
        Ok(Some(Self {
            source_directory: directory.into(),
            connections,
        }))
    }

    async fn claim(
        &self,
        pool: &PgPool,
        participant: &str,
        privacy: &str,
    ) -> Result<Option<Candidate>, String> {
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| "provider probe claim begin failed")?;
        context(&mut tx, participant, privacy).await?;
        if !candidate_fences(&mut tx, true).await? {
            tx.rollback()
                .await
                .map_err(|_| "provider claim rollback failed")?;
            return Ok(None);
        }
        // Lock the actual candidate before the observation row, also the order
        // used by publication and the public qualification owner.
        let row=sqlx::query(r#"
          select p.provider_profile_id::text,p.revision,p.behavior_fingerprint,
            p.endpoint_secret_ref,p.chain_id,c.runtime_configuration_input_id::text input_id,
            'sha256:'||encode(c.configuration_digest,'hex') configuration_digest
          from control.provider_profile p
          join control.module_installation i on i.participant_id=p.participant_id
            and i.privacy_domain_id=p.privacy_domain_id and i.state='ENABLED'
          join control.module_version v on v.module_version_id=i.module_version_id
            and v.module_id='pc.config.assets'
          join control.runtime_configuration_input_current_metadata c
            on c.module_installation_id=i.module_installation_id and c.active=true
          where p.participant_id=$1::text::uuid and p.privacy_domain_id=$2::text::uuid
            and p.state='REGISTERED'
            and not exists(select 1 from control.provider_probe_observation o
              where o.provider_profile_id=p.provider_profile_id and o.source_revision=p.revision
                and o.configuration_digest='sha256:'||encode(c.configuration_digest,'hex')
                and (o.state<>'RUNNING' or o.lease_until>clock_timestamp()))
            and 1=(select count(*) from control.module_installation ei
              join control.module_version ev on ev.module_version_id=ei.module_version_id
                and ev.module_id='pc.config.assets'
              join control.runtime_configuration_input_current_metadata ec on ec.module_installation_id=ei.module_installation_id
                and ec.active=true
              where ei.participant_id=p.participant_id and ei.privacy_domain_id=p.privacy_domain_id
                and ei.state='ENABLED')
          order by p.created_at,p.provider_profile_id for update of p skip locked limit 1
        "#).bind(participant).bind(privacy).fetch_optional(&mut *tx).await
            .map_err(|_| "provider probe candidate unavailable")?;
        let Some(row) = row else {
            tx.commit()
                .await
                .map_err(|_| "provider probe claim commit failed")?;
            return Ok(None);
        };
        let input_id: String = row.get("input_id");
        openpc_indexer_adapter::control_materialization::authorize_input(&mut tx, &input_id)
            .await?;
        let configuration_cbor: Vec<u8> =
            sqlx::query_scalar("select openpc.runtime_artifact_input_payload($1::text::uuid)")
                .bind(&input_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| "provider source materialization unavailable")?;
        let mut candidate = Candidate {
            observation_id: String::new(),
            lease_token: String::new(),
            provider_id: row.get("provider_profile_id"),
            source_revision: row.get("revision"),
            input_digest: row.get("behavior_fingerprint"),
            configuration_digest: digest(row.get("configuration_digest"))?,
            configuration_cbor,
            endpoint_secret_ref: row.get("endpoint_secret_ref"),
            chain_id: row.get("chain_id"),
        };
        let lease=sqlx::query(r#"
          insert into control.provider_probe_observation
            (participant_id,privacy_domain_id,provider_profile_id,source_revision,input_digest,
             configuration_digest,lease_token,lease_until)
          values($1::text::uuid,$2::text::uuid,$3::text::uuid,$4,$5,$6,uuidv7(),clock_timestamp()+make_interval(secs=>$7::integer))
          on conflict(provider_profile_id,source_revision,configuration_digest) do update
            set lease_token=uuidv7(),lease_until=clock_timestamp()+make_interval(secs=>$7::integer)
            where provider_probe_observation.state='RUNNING' and provider_probe_observation.lease_until<=clock_timestamp()
          returning observation_id::text,lease_token::text
        "#).bind(participant).bind(privacy).bind(&candidate.provider_id).bind(candidate.source_revision)
            .bind(&candidate.input_digest).bind(format!("sha256:{}",candidate.configuration_digest.as_str()))
            .bind(CLAIM_SECONDS)
            .fetch_one(&mut *tx).await.map_err(|_| "provider probe lease rejected")?;
        candidate.observation_id = lease.get("observation_id");
        candidate.lease_token = lease.get("lease_token");
        tx.commit()
            .await
            .map_err(|_| "provider probe lease commit failed")?;
        Ok(Some(candidate))
    }

    async fn observe(
        &self,
        pool: &PgPool,
        candidate: &Candidate,
        participant: &str,
        privacy: &str,
    ) -> Result<HashPinnedCallObservation, String> {
        let artifact = load_active_configuration_artifact(
            &candidate.configuration_cbor,
            &candidate.configuration_digest,
            &candidate.provider_id,
            ConfigurationArtifactKind::ProviderProfile,
            &digest(&candidate.input_digest)?,
        )
        .map_err(|_| "provider candidate artifact rejected")?;
        let profile = qualify_provider_profile(&artifact, &candidate.input_digest)
            .map_err(|_| "provider candidate profile rejected")?;
        if profile.chain_id != candidate.chain_id {
            return Err("provider candidate chain mismatch".into());
        }
        let prepared = provider_probe_source::prepare(
            &self.source_directory,
            &candidate.endpoint_secret_ref,
            &profile,
            participant,
            privacy,
            now_ms()?,
        )?;
        let prior = match self.connections.readback(&prepared.endpoint_id).await {
            Ok(record) => record.dispatcher_generation,
            Err(ConnectionError::NotInstalled) => 0,
            Err(_) => return Err("provider probe connection owner unavailable".into()),
        };
        let record = self
            .connections
            .install(&candidate.provider_id, prior, prepared.connection)
            .await
            .map_err(|_| "provider probe connection installation rejected")?;
        let remaining = prepared
            .valid_until_ms
            .checked_sub(now_ms()?)
            .ok_or("provider probe expired")?;
        let probe = probe_hash_pinned_call(
            &self.connections,
            &record,
            &prepared.plan,
            Instant::now() + Duration::from_millis(remaining),
        );
        let result = self
            .while_current(pool, participant, privacy, candidate, async {
                probe
                    .await
                    .map_err(|_| "provider live probe rejected".to_owned())
            })
            .await;
        // This off-path worker owns no protected dispatch. Release its socket
        // preparation after the observation; the Broker must prepare its own.
        self.connections
            .retire(&record.endpoint_id, record.dispatcher_generation)
            .await
            .map_err(|_| "provider probe connection retirement failed")?;
        result
    }

    pub async fn tick(
        &self,
        pool: &PgPool,
        participant: &str,
        privacy: &str,
    ) -> Result<bool, String> {
        let Some(candidate) = self.claim(pool, participant, privacy).await? else {
            return Ok(false);
        };
        let result = self.observe(pool, &candidate, participant, privacy).await;
        self.publish(pool, participant, privacy, &candidate, result)
            .await?;
        Ok(true)
    }

    /// Check the real candidate/configuration owner before the first exchange
    /// and throughout both the network work and the corpus repeat window.
    /// Dropping the probe on failure releases its connection lease before the
    /// caller retires the prepared connection. No failed renewal is retried.
    async fn while_current<T>(
        &self,
        pool: &PgPool,
        participant: &str,
        privacy: &str,
        candidate: &Candidate,
        probe: impl Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        self.renew(pool, participant, privacy, candidate).await?;
        tokio::pin!(probe);
        loop {
            tokio::select! {
                result = &mut probe => return result,
                () = tokio::time::sleep(RENEW_INTERVAL) => {
                    self.renew(pool, participant, privacy, candidate).await?;
                }
            }
        }
    }

    async fn renew(
        &self,
        pool: &PgPool,
        participant: &str,
        privacy: &str,
        candidate: &Candidate,
    ) -> Result<(), String> {
        timeout(RENEW_TIMEOUT, async {
            let mut tx = pool
                .begin()
                .await
                .map_err(|_| "provider renewal begin failed")?;
            context(&mut tx, participant, privacy).await?;
            candidate_fences(&mut tx, false).await?;
            // Same parent-before-observation lock order as claim/publication.
            let live = self.current_candidate(&mut tx, candidate).await?;
            if !live {
                return Err("provider observation candidate changed".to_owned());
            }
            let changed = sqlx::query(
                r#"
                update control.provider_probe_observation
                set lease_until=clock_timestamp()+make_interval(secs=>$3::integer)
                where observation_id=$1::text::uuid and lease_token=$2::text::uuid
                    and state='RUNNING' and lease_until>clock_timestamp()
            "#,
            )
            .bind(&candidate.observation_id)
            .bind(&candidate.lease_token)
            .bind(CLAIM_SECONDS)
            .execute(&mut *tx)
            .await
            .map_err(|_| "provider renewal persistence failed")?
            .rows_affected();
            if changed != 1 {
                return Err("provider observation lease changed".to_owned());
            }
            tx.commit()
                .await
                .map_err(|_| "provider renewal commit failed".to_owned())
        })
        .await
        .map_err(|_| "provider renewal timed out".to_owned())?
    }

    async fn current_candidate(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        candidate: &Candidate,
    ) -> Result<bool, String> {
        let live = sqlx::query(r#"select 1 from control.provider_profile p
          where p.provider_profile_id=$1::text::uuid and p.revision=$2 and p.state='REGISTERED'
            and p.behavior_fingerprint=$3 and p.endpoint_secret_ref=$5 and p.chain_id=$6
            and exists(select 1 from control.module_installation i
              join control.module_version v on v.module_version_id=i.module_version_id and v.module_id='pc.config.assets'
              join control.runtime_configuration_input_current_metadata c on c.module_installation_id=i.module_installation_id and c.active=true
              where i.participant_id=p.participant_id and i.privacy_domain_id=p.privacy_domain_id and i.state='ENABLED'
                and 'sha256:'||encode(c.configuration_digest,'hex')=$4)
            and 1=(select count(*) from control.module_installation i
              join control.module_version v on v.module_version_id=i.module_version_id and v.module_id='pc.config.assets'
              join control.runtime_configuration_input_current_metadata c on c.module_installation_id=i.module_installation_id and c.active=true
              where i.participant_id=p.participant_id and i.privacy_domain_id=p.privacy_domain_id and i.state='ENABLED')
          for update of p"#).bind(&candidate.provider_id).bind(candidate.source_revision)
            .bind(&candidate.input_digest).bind(format!("sha256:{}",candidate.configuration_digest.as_str()))
            .bind(&candidate.endpoint_secret_ref).bind(&candidate.chain_id)
            .fetch_optional(&mut **tx).await.map_err(|_| "provider observation candidate fence failed")?;
        Ok(live.is_some())
    }

    async fn publish(
        &self,
        pool: &PgPool,
        participant: &str,
        privacy: &str,
        candidate: &Candidate,
        result: Result<HashPinnedCallObservation, String>,
    ) -> Result<(), String> {
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| "provider observation begin failed")?;
        context(&mut tx, participant, privacy).await?;
        candidate_fences(&mut tx, false).await?;
        let live = self.current_candidate(&mut tx, candidate).await?;
        let result = if live {
            result
        } else {
            Err("provider observation candidate changed".into())
        };
        let observation = result
            .ok()
            .filter(|o| now_ms().is_ok_and(|now| o.connection().valid_until_ms > now));
        let (value, hash, until) = match &observation {
            Some(o) => (
                Some(serde_json::to_value(o).map_err(|_| "provider observation encoding failed")?),
                Some(format!(
                    "sha256:{}",
                    o.content_digest()
                        .map_err(|_| "provider observation digest failed")?
                        .as_str()
                )),
                Some(
                    i64::try_from(o.connection().valid_until_ms)
                        .map_err(|_| "provider observation validity rejected")?,
                ),
            ),
            None => (None, None, None),
        };
        let changed = sqlx::query(
            r#"update control.provider_probe_observation set
          state=case when $3::jsonb is null then 'FAILED' else 'OBSERVED' end,
          observation=$3,observation_digest=$4,valid_until=to_timestamp($5::bigint::double precision/1000),
          observed_revision=case when $3::jsonb is null then null else source_revision+1 end,
          last_error_code=case when $3::jsonb is null then 'PC-RUNTIME-3008' else null end,
          completed_at=clock_timestamp()
          where observation_id=$1::text::uuid and lease_token=$2::text::uuid and state='RUNNING'
            and lease_until>clock_timestamp()"#,
        )
        .bind(&candidate.observation_id)
        .bind(&candidate.lease_token)
        .bind(value)
        .bind(hash)
        .bind(until)
        .execute(&mut *tx)
        .await
        .map_err(|_| "provider observation persistence failed")?
        .rows_affected();
        if changed != 1 {
            // Another worker may have reclaimed an expired lease. This result
            // has no publication authority; leave that owner's work intact.
            tx.rollback()
                .await
                .map_err(|_| "provider lost lease rollback failed")?;
            return Ok(());
        }
        if observation.is_some() {
            let changed=sqlx::query("update control.provider_profile set state='SHADOW',qualification_observation_id=null,revision=revision+1,updated_at=clock_timestamp() where provider_profile_id=$1::text::uuid and revision=$2 and state='REGISTERED'")
                .bind(&candidate.provider_id).bind(candidate.source_revision).execute(&mut *tx).await
                .map_err(|_| "provider observed revision publication failed")?.rows_affected();
            if changed != 1 {
                return Err("provider observed revision changed".into());
            }
        }
        tx.commit()
            .await
            .map_err(|_| "provider observation commit failed".into())
    }
}
