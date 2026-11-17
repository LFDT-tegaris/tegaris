//! Verified consumption into the Control store. Participant association is a
//! transactionally derived effect of the Participant-owned database function.
use super::{Result, failure};
use crate::deployment_projection::{next_results, read_result, result_directory};
use openpc_multi_rpc::{
    deployment::{
        intent::PreparedDeploymentIntent,
        projection::{DeploymentProjection, PURPOSE, ProjectionExpectation},
    },
    submission_operation::SubmissionOwner,
};
use pc_policy_core::deployment_policy::AdmittedDeploymentPolicy;
use pc_runtime_types::{Digest, PurposeSigner};
use sqlx::{PgPool, Row};
use std::path::PathBuf;

const SOURCE: &str =
    include_str!("../../../control-api/src/configuration/deployment/result-source.sql");

pub(super) struct Consumer {
    directory: PathBuf,
    target_id: String,
    public_key: Vec<u8>,
    cursor: u64,
}
impl Consumer {
    pub(super) fn new(root: PathBuf, target: &str, agent_key: [u8; 32]) -> Result<Self> {
        Ok(Self {
            directory: result_directory(&root, target).map_err(|_| failure())?,
            target_id: target.into(),
            public_key: PurposeSigner::from_secret_bytes(PURPOSE, agent_key)
                .map_err(|_| failure())?
                .verifier()
                .sec1_bytes(),
            cursor: 0,
        })
    }
    pub(super) async fn tick(
        &mut self,
        pool: &PgPool,
        participant: &str,
        privacy: &str,
    ) -> Result<bool> {
        let files = next_results(&self.directory, self.cursor).map_err(|_| failure())?;
        let mut changed = false;
        for file in files {
            let bytes = match read_result(&file.path) {
                Ok(bytes) => bytes,
                // Producer superseded this snapshot during the directory scan.
                // Its newer file remains above the cursor for the next pass.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(failure()),
            };
            let envelope: pc_runtime_types::SignedEnvelope<DeploymentProjection> =
                serde_json::from_slice(&bytes).map_err(|_| failure())?;
            if envelope.claims.journal_sequence().map_err(|_| failure())? != file.sequence {
                return Err(failure());
            }
            changed |= consume(
                pool,
                &bytes,
                &self.public_key,
                &self.target_id,
                &file.command,
                participant,
                privacy,
            )
            .await?;
            // A failure cannot advance past an uncommitted result. Restarts
            // replay durable snapshots through the same database deduplication.
            self.cursor = file.sequence;
        }
        Ok(changed)
    }
}

pub async fn consume(
    pool: &PgPool,
    bytes: &[u8],
    public_key: &[u8],
    target: &str,
    command: &str,
    participant: &str,
    privacy: &str,
) -> Result<bool> {
    let mut tx = super::store::scoped(pool, participant, privacy).await?;
    let held=sqlx::query("select command_id from control.deployment_address_reservation where command_id=$1::text::uuid and participant_id=$2::text::uuid and privacy_domain_id=$3::text::uuid and state='HANDOFF' for update")
        .bind(command).bind(participant).bind(privacy).fetch_optional(&mut *tx).await.map_err(|_| failure())?;
    if held.is_none() {
        return Err(failure());
    }
    let row = sqlx::query(SOURCE)
        .bind(command)
        .bind(participant)
        .bind(privacy)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| "deployment result source rejected".to_owned())?;
    let string = |name| row.try_get::<String, _>(name).map_err(|_| failure());
    let digest = |name| Digest::parse(string(name)?).map_err(|_| failure());
    let expected = ProjectionExpectation {
        target_runtime_id: string("target_runtime_id")?,
        owner: SubmissionOwner {
            participant_id: participant.into(),
            privacy_domain_id: privacy.into(),
            actor_principal_id: string("execution_principal_id")?,
            workload_id: string("execution_workload_id")?,
        },
        command_id: command.into(),
        attempt_id: string("attempt_id")?,
        intent_digest: digest("intent_digest")?,
        preparation_digest: digest("preparation_digest")?,
        chain_id: string("chain_id")?,
        genesis_digest: digest("genesis_digest")?,
        transaction_hash: string("transaction_hash")?,
    };
    if expected.target_runtime_id != target {
        return Err("deployment result binding rejected".into());
    }
    let result = DeploymentProjection::verify(bytes, public_key, &expected)
        .map_err(|_| "deployment result signature rejected".to_owned())?;
    let publication: AdmittedDeploymentPolicy = serde_json::from_slice(
        &row.try_get::<Vec<u8>, _>("publication_bytes")
            .map_err(|_| failure())?,
    )
    .map_err(|_| failure())?;
    let prepared = PreparedDeploymentIntent::restore(
        &row.try_get::<Vec<u8>, _>("preparation_bytes")
            .map_err(|_| failure())?,
        &publication,
    )
    .map_err(|_| failure())?;
    result
        .verify_preparation(&prepared, &publication)
        .map_err(|_| "deployment result preparation rejected".to_owned())?;
    let sequence = result.claims().sequence().map_err(|_| failure())?;
    if let Some(prior) = row
        .try_get::<Option<String>, _>("sequence")
        .map_err(|_| failure())?
    {
        let prior = prior.parse::<u64>().map_err(|_| failure())?;
        if sequence <= prior {
            // Older signed snapshots cannot roll back newer invalidation.
            if sequence == prior
                && string("result_digest")? != format!("sha256:{}", result.digest().as_str())
            {
                return Err(failure());
            }
            tx.commit().await.map_err(|_| failure())?;
            return Ok(false);
        }
    }
    sqlx::query("insert into control.deployment_result(participant_id,privacy_domain_id,command_id,sequence,signed_bytes,result_digest) values($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::numeric,$5,$6)")
        .bind(participant).bind(privacy).bind(command).bind(sequence.to_string()).bind(bytes).bind(format!("sha256:{}",result.digest().as_str()))
        .execute(&mut *tx).await.map_err(|_| "deployment result persistence rejected".to_owned())?;
    super::result_event::emit(
        &mut tx,
        &expected,
        result.digest(),
        super::result_event::ResultKind::Journal(sequence),
    )
    .await?;
    tx.commit().await.map_err(|_| failure())?;
    Ok(true)
}
