use super::*;
use openpc_fact_service::{FactStoreError, PendingFactAdmissionDelivery};
use serde_json::Value;

pub(super) struct DeliveryLease {
    pub id: Uuid,
    pub profile_digest: String,
}
pub(super) enum DeliveryClaim {
    Leased(DeliveryLease),
    Committed,
    Exhausted,
    Blocked,
}

impl FleetFactAdmissionConsumer {
    pub(super) fn capability(
        &self,
        purpose: &[u8],
        profile_digest: &str,
        material: &[u8],
        lease: Uuid,
    ) -> Result<([u8; 32], Vec<u8>)> {
        let mut nonce = [0_u8; 32];
        nonce[..16].copy_from_slice(lease.as_bytes());
        nonce[16..].copy_from_slice(Uuid::now_v7().as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.commit_key).map_err(|_| rejected())?;
        mac.update(purpose);
        let raw = profile_digest
            .strip_prefix("sha256:")
            .filter(|value| value.len() == 64)
            .ok_or_else(rejected)?;
        let bytes: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).map_err(|_| rejected()))
            .collect::<Result<_>>()?;
        mac.update(&bytes);
        mac.update(&Sha256::digest(material));
        mac.update(&nonce);
        Ok((nonce, mac.finalize().into_bytes().to_vec()))
    }

    pub(super) async fn claim_delivery(
        &self,
        control: &PgPool,
        event: &PendingFactAdmissionDelivery,
    ) -> Result<DeliveryClaim> {
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
        let lease = Uuid::now_v7();
        let material=serde_json::to_vec(&json!({"leaseId":lease,"event":{
            "participantId":event.participant_id(),"privacyDomainId":event.privacy_domain_id(),
            "candidateId":event.candidate_id(),"generationId":event.generation_id(),
            "factType":event.fact_type(),"sequence":event.sequence().to_string(),"eventId":event.event_id(),
            "consumerId":"LS-FLEET-CONTROL","envelope":event.envelope(),
            "envelopeDigest":digest(event.envelope_digest()),"dataDigest":digest(event.data_digest())
        }})).map_err(|_|rejected())?;
        let (nonce, mac) = self.capability(
            b"OPENPC_FLEET_FACT_DELIVERY_BEGIN_V1",
            profile.profile_digest(),
            &material,
            lease,
        )?;
        let result: Value =
            sqlx::query_scalar("select openpc.begin_fleet_fact_delivery($1,$2,$3,$4)")
                .bind(material)
                .bind(nonce.as_slice())
                .bind(mac)
                .bind(profile.profile_digest())
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| rejected())?;
        let result = match result.get("state").and_then(Value::as_str) {
            Some("LEASED")
                if result.get("leaseId").and_then(Value::as_str)
                    == Some(lease.to_string().as_str()) =>
            {
                DeliveryClaim::Leased(DeliveryLease {
                    id: lease,
                    profile_digest: profile.profile_digest().into(),
                })
            }
            Some("COMMITTED") => DeliveryClaim::Committed,
            Some("EXHAUSTED") => DeliveryClaim::Exhausted,
            Some("WAITING" | "BUSY" | "QUARANTINED") => DeliveryClaim::Blocked,
            _ => return Err(rejected()),
        };
        // An ambiguous COMMIT retains this lease in PostgreSQL. The next poll
        // sees BUSY or the original committed effect; it cannot create a new
        // identity, advance a cursor, or erase a consumed attempt.
        tx.commit().await.map_err(|_| rejected())?;
        Ok(result)
    }

    pub(super) async fn fail_delivery(
        &self,
        control: &PgPool,
        event: &PendingFactAdmissionDelivery,
        lease: &DeliveryLease,
        error: &FactStoreError,
    ) -> Result<()> {
        let outcome = match error {
            FactStoreError::Database(sqlx::Error::Database(error))
                if error
                    .code()
                    .is_some_and(|code| matches!(code.as_ref(), "53100" | "53200" | "53300")) =>
            {
                "CAPACITY_RELEASE"
            }
            FactStoreError::Database(sqlx::Error::RowNotFound) => "FAILED",
            FactStoreError::Database(_) => "UNAVAILABLE_RELEASE",
            _ => "FAILED",
        };
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
        let material=serde_json::to_vec(&json!({"participantId":event.participant_id(),"privacyDomainId":event.privacy_domain_id(),
            "eventId":event.event_id(),"leaseId":lease.id,"outcome":outcome,"problem":"PC-DATA-6005"})).map_err(|_|rejected())?;
        let (nonce, mac) = self.capability(
            b"OPENPC_FLEET_FACT_DELIVERY_FAIL_V1",
            profile.profile_digest(),
            &material,
            lease.id,
        )?;
        let state: String =
            sqlx::query_scalar("select openpc.fail_fleet_fact_delivery($1,$2,$3,$4)")
                .bind(material)
                .bind(nonce.as_slice())
                .bind(mac)
                .bind(profile.profile_digest())
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| rejected())?;
        tx.commit().await.map_err(|_| rejected())?;
        eprintln!(
            "FLEET_FACT_DELIVERY|event={}|outcome={outcome}|state={state}|problem=PC-DATA-6005",
            event.event_id()
        );
        Ok(())
    }
}
