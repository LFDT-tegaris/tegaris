//! Discovery starts at the verified ADS transport. It never activates a target.
use super::discovery_retry::{ObservationFailure, observe_with_retry};
use super::*;
use openpc_fleet_controller::ads_discovery::TargetDiscovery;
use sqlx::Acquire;
use tonic::Status;

pub(super) struct DiscoveryOwner {
    pub pool: PgPool,
    pub config: Config,
}

fn unavailable(_: impl std::fmt::Debug) -> Status {
    Status::failed_precondition("authenticated target discovery unavailable")
}

async fn required(tx: &mut Transaction<'_, Postgres>, target: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("select requires_authenticated_discovery from control.runtime_target where runtime_target_id=$1::text::uuid and participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id()")
        .bind(target).fetch_one(&mut **tx).await
}

impl DiscoveryOwner {
    async fn observe_once(
        &self,
        identity: &TargetIdentity,
        connection_id: &str,
        certificate_until_ms: u64,
    ) -> Result<(), ObservationFailure> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|error| ObservationFailure::database("acquire", error))?;
        let mut tx = connection
            .begin()
            .await
            .map_err(|error| ObservationFailure::database("begin", error))?;
        let result = async {
        set_context(&mut tx, &self.config)
            .await
            .map_err(|_| ObservationFailure::terminal("context"))?;
        if !required(&mut tx, &identity.target_id)
            .await
            .map_err(|error| ObservationFailure::database("target", error))?
        {
            return Ok(());
        }
        let certificate = format!("sha256:{}", identity.certificate_fingerprint.as_str());
        // Authority roots precede the generation fence and mutable target rows.
        let credential = sqlx::query("select credential_id::text,credential_epoch,principal_epoch from openpc.lock_runtime_discovery_authority($1::text::uuid,$2)")
            .bind(&identity.target_id).bind(&certificate).fetch_one(&mut *tx).await.map_err(|error| ObservationFailure::database("authority", error))?;
        sqlx::query(r#"insert into control.runtime_target_connection
          (runtime_target_id,participant_id,privacy_domain_id,connection_id,certificate_digest,credential_id,credential_epoch,principal_epoch,connected,observed_at,valid_until)
          select $1::text::uuid,openpc.current_participant_id(),openpc.current_privacy_domain_id(),$2::text::uuid,$3,$4::text::uuid,$5,$6,true,
           clock_timestamp(),least(clock_timestamp()+interval '15 seconds',to_timestamp($7::double precision/1000),credential.valid_until)
          from control.credential credential where credential.credential_id=$4::text::uuid and credential.participant_id=openpc.current_participant_id()
          on conflict(runtime_target_id) do update set connection_id=excluded.connection_id,certificate_digest=excluded.certificate_digest,
           credential_id=excluded.credential_id,credential_epoch=excluded.credential_epoch,principal_epoch=excluded.principal_epoch,
           connected=true,observed_at=excluded.observed_at,valid_until=excluded.valid_until"#)
            .bind(&identity.target_id).bind(connection_id).bind(&certificate)
            .bind(credential.get::<String,_>("credential_id")).bind(credential.get::<i64,_>("credential_epoch"))
            .bind(credential.get::<i64,_>("principal_epoch"))
            .bind(i64::try_from(certificate_until_ms).map_err(|_| ObservationFailure::terminal("certificate_validity"))?)
            .execute(&mut *tx).await.map_err(|error| ObservationFailure::database("connection", error))?;
        sqlx::query("update control.runtime_target set state='DISCOVERED',revision=revision+1,observed_at=clock_timestamp(),updated_at=clock_timestamp() where runtime_target_id=$1::text::uuid and participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id() and requires_authenticated_discovery and state='OFFLINE' and desired_generation_digest is null and active_generation_digest is null")
            .bind(&identity.target_id).execute(&mut *tx).await.map_err(|error| ObservationFailure::database("target_transition", error))?;
        Ok(())
        }.await;
        if let Err(error) = result {
            tx.rollback()
                .await
                .map_err(|error| ObservationFailure::database("rollback", error))?;
            return Err(error);
        }
        if let Err(error) = tx.commit().await {
            // SQLx queues rollback when commit fails. Flush it on this same
            // connection before any new attempt, including a COMMIT 40001.
            sqlx::Connection::ping(&mut *connection)
                .await
                .map_err(|error| ObservationFailure::database("rollback", error))?;
            return Err(ObservationFailure::database("commit", error));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl TargetDiscovery for DiscoveryOwner {
    async fn observe(
        &self,
        identity: &TargetIdentity,
        connection_id: &str,
        certificate_until_ms: u64,
    ) -> Result<(), Status> {
        observe_with_retry(
            certificate_until_ms,
            || self.observe_once(identity, connection_id, certificate_until_ms),
            || now_ms().ok(),
            tokio::time::sleep,
        ).await.map_err(|error| {
            eprintln!("{}", serde_json::json!({
                "level": "warn",
                "event": "runtime_discovery_observation_rejected",
                "targetId": identity.target_id,
                "connectionId": connection_id,
                "stage": error.stage,
                "sqlstate": error.sqlstate,
                "attempt": error.attempt,
                "disposition": if error.retryable() { "RETRIES_EXHAUSTED" } else { "FAIL_CLOSED" },
            }));
            unavailable(error)
        })
    }

    async fn disconnect(&self, identity: &TargetIdentity, connection_id: &str) {
        // The in-memory connection is already withdrawn. A failed SQL write
        // cannot restore it, and the durable observation expires independently.
        let _: WorkerResult<()> = async {
            let mut tx = self.pool.begin().await.map_err(|_| "discovery close unavailable")?;
            set_context(&mut tx, &self.config).await?;
            let changed = sqlx::query("update control.runtime_target_connection set connected=false where runtime_target_id=$1::text::uuid and connection_id=$2::text::uuid and participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id()")
                .bind(&identity.target_id).bind(connection_id).execute(&mut *tx).await.map_err(|_| "discovery close rejected")?.rows_affected();
            if changed == 1 {
                sqlx::query("update control.runtime_target set state='OFFLINE',revision=revision+1,updated_at=clock_timestamp() where runtime_target_id=$1::text::uuid and requires_authenticated_discovery and state='DISCOVERED' and desired_generation_digest is null and active_generation_digest is null")
                    .bind(&identity.target_id).execute(&mut *tx).await.map_err(|_| "discovery target close rejected")?;
            }
            tx.commit().await.map_err(|_| "discovery close commit rejected".into())
        }.await;
    }
}

/// Hold current credential/root locks across the real synchronous activation.
pub(super) struct ActivationDiscovery<'a> {
    transaction: Transaction<'a, Postgres>,
    connection_id: Option<String>,
    valid_until_ms: u64,
}

impl<'a> ActivationDiscovery<'a> {
    pub(super) async fn fence(
        pool: &'a PgPool,
        config: &Config,
        target: &str,
    ) -> WorkerResult<Self> {
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| "discovery activation fence unavailable")?;
        set_context(&mut tx, config).await?;
        if !required(&mut tx, target)
            .await
            .map_err(|_| "discovery target unavailable")?
        {
            return Ok(Self {
                transaction: tx,
                connection_id: None,
                valid_until_ms: 0,
            });
        }
        let observation = sqlx::query("select certificate_digest,connection_id::text from control.runtime_target_connection where runtime_target_id=$1::text::uuid and participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id() and connected")
            .bind(target).fetch_one(&mut *tx).await.map_err(|_| "discovery activation observation missing")?;
        let certificate: String = observation.get("certificate_digest");
        let connection_id: String = observation.get("connection_id");
        sqlx::query("select * from openpc.lock_runtime_discovery_authority($1::text::uuid,$2)")
            .bind(target)
            .bind(&certificate)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| "discovery activation authority rejected")?;
        let until: i64 = sqlx::query_scalar("select floor(extract(epoch from observation.valid_until)*1000)::bigint from control.runtime_target_connection observation where observation.runtime_target_id=$1::text::uuid and observation.connection_id=$2::text::uuid and observation.certificate_digest=$3 and openpc.runtime_target_discovery_current(openpc.current_participant_id(),openpc.current_privacy_domain_id(),observation.runtime_target_id)")
            .bind(target).bind(&connection_id).bind(&certificate).fetch_one(&mut *tx).await.map_err(|_| "discovery activation observation stale")?;
        Ok(Self {
            transaction: tx,
            connection_id: Some(connection_id),
            valid_until_ms: u64::try_from(until)
                .map_err(|_| "discovery activation expiry invalid")?,
        })
    }

    pub(super) fn activate<T>(
        &self,
        plane: &RuntimePlane,
        target: &str,
        action: impl FnOnce() -> WorkerResult<T>,
    ) -> WorkerResult<T> {
        let Some(connection) = &self.connection_id else {
            return action();
        };
        plane
            .ads
            .with_current_connection(target, connection, || {
                if now_ms()? >= self.valid_until_ms {
                    return Err("discovery activation expired".into());
                }
                action()
            })
            .map_err(|_| "discovery activation connection lost".to_owned())?
    }

    pub(super) async fn release(self) -> WorkerResult<()> {
        self.transaction
            .rollback()
            .await
            .map_err(|_| "discovery activation fence release failed".into())
    }
}
