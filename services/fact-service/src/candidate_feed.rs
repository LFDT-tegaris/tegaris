//! COM-017 reader custody. Reading candidate bytes is not provenance validation,
//! current source authorization, finality admission, or permission to sign facts.
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgPoolOptions};
use uuid::Uuid;

pub(crate) mod checkpoint;
mod closure;
mod material;
mod receipt;
pub(crate) mod reorg;
pub(crate) mod withdrawal;
pub use material::{CandidateMaterial, CandidateSourceMaterial};

#[derive(Debug, thiserror::Error)]
pub enum CandidateFeedError {
    #[error("FACT-CANDIDATE-STORE-IDENTITY")]
    StoreIdentity,
    #[error("FACT-CANDIDATE-WORKLOAD-AUTHENTICATION")]
    Authentication,
    #[error("FACT-CANDIDATE-SCOPE")]
    Scope,
    #[error("FACT-CANDIDATE-SEQUENCE-CONFLICT")]
    SequenceConflict,
    #[error("FACT-CANDIDATE-MATERIAL")]
    Material,
    #[error("FACT-CANDIDATE-LINEAGE:{0}")]
    Lineage(&'static str),
    #[error("FACT-CANDIDATE-DATABASE")]
    Database(#[from] sqlx::Error),
}

/// Supplied by the authenticated command owner, never resolved from an outbox
/// row, candidate payload, or caller-declared trust field.
pub struct CandidateReadScope {
    pub(crate) participant: Uuid,
    pub(crate) privacy: Uuid,
    pub(crate) operation: Uuid,
}
impl CandidateReadScope {
    pub fn new(
        participant: Uuid,
        privacy: Uuid,
        operation: Uuid,
    ) -> Result<Self, CandidateFeedError> {
        if [participant, privacy, operation]
            .iter()
            .any(|value| value.get_version_num() != 7)
        {
            return Err(CandidateFeedError::Scope);
        }
        Ok(Self {
            participant,
            privacy,
            operation,
        })
    }
}

/// Exact read-only database snapshot for one source partition. It cannot lock
/// or mutate the candidate owner's rows. Independent current authority must be
/// held separately through admission. Later withdrawal is a durable lifecycle
/// occurrence; protected reads consume the local signed generation and readiness.
pub struct CandidateFeedRead {
    transaction: Transaction<'static, Postgres>,
    scope: CandidateReadScope,
    partition: Uuid,
}

/// Candidate-controlled event bytes. This type intentionally contains no
/// "verified" or "trusted" flag and cannot authorize a fact-store mutation.
pub struct CandidateFeedEvent {
    pub event_id: Uuid,
    pub sequence: u64,
    pub event_type: String,
    pub schema_uri: String,
    pub payload_cbor: Vec<u8>,
    pub payload_digest: Vec<u8>,
    pub generation_id: Uuid,
    pub publication_state: Option<String>,
    pub generation_state: String,
}

#[derive(Clone)]
pub struct CandidateFeedReader {
    pool: PgPool,
}
impl CandidateFeedReader {
    pub(crate) async fn authenticate(
        &self,
        authenticator: &crate::workload_authority::FactWorkloadAuthenticator,
        participant: Uuid,
    ) -> Result<&Self, CandidateFeedError> {
        if self.pool.is_closed() {
            return Err(sqlx::Error::PoolClosed.into());
        }
        if authenticator.authenticate_peer(participant).await.is_err() {
            self.close().await;
            return Err(CandidateFeedError::Authentication);
        }
        Ok(self)
    }

    pub(crate) async fn locate(
        &self,
        scope: CandidateReadScope,
        candidate: Uuid,
    ) -> Result<Option<(Uuid, u64)>, CandidateFeedError> {
        let mut read = self.read_partition(scope, Uuid::now_v7()).await?;
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "select candidate_partition_id,outbox_sequence::text
          from candidate.fact_bridge_admission_v1 where participant_id=$1 and privacy_domain_id=$2
          and candidate_event_id=$3 limit 2",
        )
        .bind(read.scope.participant)
        .bind(read.scope.privacy)
        .bind(candidate)
        .fetch_all(&mut *read.transaction)
        .await?;
        read.close().await?;
        if rows.len() > 1 {
            return Err(CandidateFeedError::SequenceConflict);
        }
        rows.into_iter()
            .next()
            .map(|(partition, sequence)| {
                Ok((
                    partition,
                    sequence.parse().map_err(|_| CandidateFeedError::Material)?,
                ))
            })
            .transpose()
    }

    /// Deployment-only lazy pool. No network connection is created here and no
    /// session is retained after a read. The deployment owner authenticates the
    /// real workload before each acquisition; this constructor grants nothing.
    pub(crate) fn prepare(database_url: &str) -> Result<Self, CandidateFeedError> {
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .min_connections(0)
            .after_connect(|connection, _| Box::pin(async move {
                let identity: (String, String, bool, bool) = sqlx::query_as(
                    "select current_database(),current_user,rolsuper,rolbypassrls from pg_roles where rolname=current_user",
                ).fetch_one(connection).await?;
                if identity != ("openpc_candidate_index".into(),
                    "openpc_fact_bridge_reader".into(), false, false) {
                    return Err(sqlx::Error::Protocol("FACT-CANDIDATE-STORE-IDENTITY".into()));
                }
                Ok(())
            }))
            // Closing every returned session prevents stale idle connections
            // from surviving a credential/version change or failed next auth.
            .after_release(|_, _| Box::pin(async { Ok(false) }))
            .connect_lazy(database_url)?;
        Ok(Self { pool })
    }

    pub async fn connect(database_url: &str) -> Result<Self, CandidateFeedError> {
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(database_url)
            .await?;
        let identity: (String, String, bool, bool) = sqlx::query_as(
            "select current_database(),current_user,rolsuper,rolbypassrls from pg_roles where rolname=current_user",
        ).fetch_one(&pool).await?;
        if identity
            != (
                "openpc_candidate_index".into(),
                "openpc_fact_bridge_reader".into(),
                false,
                false,
            )
        {
            pool.close().await;
            return Err(CandidateFeedError::StoreIdentity);
        }
        Ok(Self { pool })
    }

    pub async fn read_partition(
        &self,
        scope: CandidateReadScope,
        partition: Uuid,
    ) -> Result<CandidateFeedRead, CandidateFeedError> {
        if partition.get_version_num() != 7 {
            return Err(CandidateFeedError::Scope);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query("set transaction isolation level repeatable read read only")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',true)")
            .bind(scope.participant).bind(scope.privacy).bind(scope.operation)
            .execute(&mut *transaction).await?;
        Ok(CandidateFeedRead {
            transaction,
            scope,
            partition,
        })
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.pool.is_closed()
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}
impl CandidateFeedRead {
    /// Consume every outbox event in sequence, including checkpoints and
    /// invalidations. A missing sequence never means confirmed absence.
    pub async fn event(
        &mut self,
        sequence: u64,
    ) -> Result<Option<CandidateFeedEvent>, CandidateFeedError> {
        if sequence == 0 {
            return Err(CandidateFeedError::Scope);
        }
        let rows = sqlx::query(
            "select event_id,outbox_sequence::text,event_type::text,schema_uri::text,
             event_payload_cbor,event_payload_digest,projection_generation_id,
             publication_state,generation_state::text
             from candidate.fact_bridge_admission_v1
             where participant_id=$1 and privacy_domain_id=$2 and candidate_partition_id=$3
               and outbox_sequence=$4::numeric and octet_length(event_payload_cbor)<=131072 limit 2",
        )
        .bind(self.scope.participant)
        .bind(self.scope.privacy)
        .bind(self.partition)
        .bind(sequence.to_string())
        .fetch_all(&mut *self.transaction)
        .await?;
        if rows.len() > 1 {
            return Err(CandidateFeedError::SequenceConflict);
        }
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        if row.try_get::<String, _>("outbox_sequence")? != sequence.to_string() {
            return Err(CandidateFeedError::SequenceConflict);
        }
        Ok(Some(CandidateFeedEvent {
            event_id: row.try_get("event_id")?,
            sequence,
            event_type: row.try_get("event_type")?,
            schema_uri: row.try_get("schema_uri")?,
            payload_cbor: row.try_get("event_payload_cbor")?,
            payload_digest: row.try_get("event_payload_digest")?,
            generation_id: row.try_get("projection_generation_id")?,
            publication_state: row.try_get("publication_state")?,
            generation_state: row.try_get("generation_state")?,
        }))
    }

    pub async fn close(self) -> Result<(), CandidateFeedError> {
        self.transaction.rollback().await?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
