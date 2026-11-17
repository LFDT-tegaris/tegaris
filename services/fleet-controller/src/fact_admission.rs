//! Fleet's durable original Fact admission inventory. Admission is consumed by
//! actual capsule assembly, but never replaces the live Fact authority lease.
use hmac::{Hmac, KeyInit, Mac};
use openpc_fact_service::consumer_profile::lock_installed_fact_consumer_profile;
use openpc_fact_service::{PolicyFactReader, VerifiedFactAdmissionDelivery};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;
mod delivery;
mod quarantine;
use delivery::{DeliveryClaim, DeliveryLease};

type Result<T> = std::result::Result<T, String>;
fn rejected() -> String {
    "Fleet Fact admission rejected".into()
}
fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
async fn context(
    tx: &mut Transaction<'_, Postgres>,
    participant: &str,
    privacy: &str,
) -> Result<()> {
    // Request context scopes SQL only. The installed workload key, verified
    // source value and commit function provide the independent write admission.
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-OPERATIONS_READ_OPERATION-V1',true)")
        .bind(participant).bind(privacy).execute(&mut **tx).await.map_err(|_| rejected())?;
    sqlx::query("set local statement_timeout='5s'")
        .execute(&mut **tx)
        .await
        .map_err(|_| rejected())?;
    Ok(())
}

pub struct FleetFactAdmissionConsumer {
    reader: PolicyFactReader,
    commit_key: [u8; 32],
    failure_signer: p256::ecdsa::SigningKey,
}
impl FleetFactAdmissionConsumer {
    pub fn new(
        reader: PolicyFactReader,
        commit_key: [u8; 32],
        failure_signer: p256::ecdsa::SigningKey,
    ) -> Self {
        Self {
            reader,
            commit_key,
            failure_signer,
        }
    }

    pub async fn tick(&self, control: &PgPool, participant: &str, privacy: &str) -> Result<u64> {
        let mut consumed = 0;
        for kind in ["CONTRACT_STATE_CALL", "RELATIONSHIP", "EXTERNAL_DECISION"] {
            let mut tx = control.begin().await.map_err(|_| rejected())?;
            context(&mut tx, participant, privacy).await?;
            let head: Option<String> = sqlx::query_scalar("select sequence::text from control.fleet_fact_admission_cursor where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and fact_type=$3")
                .bind(participant).bind(privacy).bind(kind).fetch_optional(&mut *tx).await.map_err(|_| rejected())?;
            tx.rollback().await.map_err(|_| rejected())?;
            let after = head
                .as_deref()
                .unwrap_or("0")
                .parse()
                .map_err(|_| rejected())?;
            let batch = self
                .reader
                .pending_admission_deliveries(participant, privacy, kind, after)
                .await
                .map_err(|_| rejected())?;
            for pending in batch {
                match self.claim_delivery(control, &pending).await? {
                    DeliveryClaim::Committed => continue,
                    DeliveryClaim::Blocked => break,
                    DeliveryClaim::Exhausted => {
                        self.quarantine_delivery(control, &pending).await?;
                        break;
                    }
                    DeliveryClaim::Leased(lease) => {
                        match self.reader.verify_admission_delivery(&pending).await {
                            Ok(event) => {
                                consumed += u64::from(self.commit(control, &event, &lease).await?)
                            }
                            Err(error) => {
                                self.fail_delivery(control, &pending, &lease, &error)
                                    .await?;
                                break;
                            }
                        }
                    }
                }
            }
        }
        Ok(consumed)
    }

    async fn commit(
        &self,
        control: &PgPool,
        event: &VerifiedFactAdmissionDelivery,
        lease: &DeliveryLease,
    ) -> Result<bool> {
        let mut tx = control.begin().await.map_err(|_| rejected())?;
        context(&mut tx, event.participant_id(), event.privacy_domain_id()).await?;
        let profile = lock_installed_fact_consumer_profile(
            &mut tx,
            event.participant_id(),
            event.privacy_domain_id(),
            "LS-FLEET-CONTROL",
        )
        .await
        .map_err(|_| rejected())?;
        if profile.profile_digest() != lease.profile_digest {
            return Err(rejected());
        }
        let material = serde_json::to_vec(&json!({
            "participantId":event.participant_id(), "privacyDomainId":event.privacy_domain_id(),
            "candidateId":event.candidate_id(), "generationId":event.generation_id(),
            "factType":event.fact_type(), "sequence":event.sequence().to_string(),
            "envelope":event.envelope(), "signedFactDigest":digest(&Sha256::digest(event.original_cose())),
            "factDigest":digest(event.fact_digest()), "consumerId":"LS-FLEET-CONTROL",
        })).map_err(|_| rejected())?;
        let (nonce, mac) = self.capability(
            b"OPENPC_FLEET_FACT_ADMISSION_V2",
            profile.profile_digest(),
            &material,
            lease.id,
        )?;
        let inserted =
            sqlx::query_scalar("select openpc.commit_fleet_fact_admission_v2($1,$2,$3,$4)")
                .bind(material)
                .bind(nonce.as_slice())
                .bind(mac)
                .bind(profile.profile_digest())
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| rejected())?;
        tx.commit().await.map_err(|_| rejected())?;
        Ok(inserted)
    }
}

/// Metadata admission is mandatory for Fleet assembly; the caller separately
/// verifies current signed publication, scope, finality and freshness afterward.
pub async fn require_admitted(
    control: &PgPool,
    participant: &str,
    privacy: &str,
    required: &[pc_policy_core::semantics::FactReference],
) -> Result<()> {
    if required.is_empty() || required.len() > 256 {
        return Err(rejected());
    }
    let mut tx = control.begin().await.map_err(|_| rejected())?;
    context(&mut tx, participant, privacy).await?;
    for fact in required {
        let present: bool = sqlx::query_scalar("select exists(select 1 from control.fleet_fact_admission_inbox i
            join control.fleet_fact_admission_cursor c using(participant_id,privacy_domain_id,fact_type)
            where i.participant_id=$1::text::uuid and i.privacy_domain_id=$2::text::uuid
            and i.candidate_id=$3::text::uuid and i.generation_id=$4::text::uuid and i.fact_digest=$5 and c.sequence>=i.sequence)")
            .bind(participant).bind(privacy).bind(&fact.candidate_id).bind(&fact.generation_id).bind(&fact.fact_digest)
            .fetch_one(&mut *tx).await.map_err(|_| rejected())?;
        if !present {
            return Err(rejected());
        }
    }
    tx.rollback().await.map_err(|_| rejected())?;
    Ok(())
}
