use super::*;
use openpc_fact_service::PendingFactAdmissionDelivery;
use openpc_fact_service::consumer_profile::failure::{
    FactConsumerFailure, sign_fact_consumer_failure, verify_fact_consumer_failure,
};
use p256::pkcs8::EncodePublicKey;
use serde_json::Value;

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(rejected());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| rejected()))
        .collect()
}
impl FleetFactAdmissionConsumer {
    pub(super) async fn quarantine_delivery(
        &self,
        control: &PgPool,
        event: &PendingFactAdmissionDelivery,
    ) -> Result<()> {
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
        let spki = self
            .failure_signer
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| rejected())?;
        let spki = spki.as_bytes();
        let signer_id = digest(&Sha256::digest(spki));
        let material=serde_json::to_vec(&json!({"participantId":event.participant_id(),"privacyDomainId":event.privacy_domain_id(),"eventId":event.event_id(),"signerKeyId":signer_id})).map_err(|_|rejected())?;
        let (nonce, mac) = self.capability(
            b"OPENPC_FLEET_FACT_FAILURE_PREPARE_V1",
            profile.profile_digest(),
            &material,
            Uuid::now_v7(),
        )?;
        let prepared: Value =
            sqlx::query_scalar("select openpc.prepare_fleet_fact_quarantine($1,$2,$3,$4)")
                .bind(material)
                .bind(nonce.as_slice())
                .bind(mac)
                .bind(profile.profile_digest())
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| rejected())?;
        if prepared.get("state").and_then(Value::as_str) == Some("COMMITTED") {
            // This is historical no-effect readback. SQL retains the original
            // signed receipt/work-item identity; no new signature or event.
            tx.rollback().await.map_err(|_| rejected())?;
            return Ok(());
        }
        if prepared.get("state").and_then(Value::as_str) != Some("PREPARED")
            || unhex(
                prepared
                    .get("signerSpki")
                    .and_then(Value::as_str)
                    .ok_or_else(rejected)?,
            )? != spki
        {
            return Err(rejected());
        }
        let receipt: FactConsumerFailure =
            serde_json::from_value(prepared.get("claims").cloned().ok_or_else(rejected)?)
                .map_err(|_| rejected())?;
        let original=serde_json::to_vec(&json!({"participantId":event.participant_id(),"privacyDomainId":event.privacy_domain_id(),"eventId":event.event_id(),
            "candidateId":event.candidate_id(),"generationId":event.generation_id(),"factType":event.fact_type(),"sequence":event.sequence().to_string(),
            "consumerId":"LS-FLEET-CONTROL","envelope":event.envelope(),"envelopeDigest":digest(event.envelope_digest()),"dataDigest":digest(event.data_digest())})).map_err(|_|rejected())?;
        if receipt.participant_id != event.participant_id()
            || receipt.privacy_domain_id != event.privacy_domain_id()
            || receipt.event_id != event.event_id().to_string()
            || receipt.candidate_id != event.candidate_id()
            || receipt.generation_id != event.generation_id()
            || receipt.fact_type != event.fact_type()
            || receipt.sequence != event.sequence().to_string()
            || receipt.consumer_id != "LS-FLEET-CONTROL"
            || receipt.envelope_digest != digest(event.envelope_digest())
            || receipt.data_digest != digest(event.data_digest())
            || receipt.material_digest != digest(&Sha256::digest(&original))
            || receipt.current_profile_digest != profile.profile_digest()
            || receipt.signer_key_id != signer_id
        {
            return Err(rejected());
        }
        // Local P-256 signing has no external side effect. The source lock,
        // current trust fences, reservation, signature, real work item and
        // receipt outbox remain in one transaction; deferred SQL rejects an
        // unfinished reservation. An uncertain COMMIT is read back by event ID.
        let (payload, cose) =
            sign_fact_consumer_failure(&self.failure_signer, &receipt).map_err(|_| rejected())?;
        verify_fact_consumer_failure(spki, &receipt, &payload, &cose).map_err(|_| rejected())?;
        let material=serde_json::to_vec(&json!({"participantId":event.participant_id(),"privacyDomainId":event.privacy_domain_id(),"eventId":event.event_id(),"payload":raw_hex(&payload),"cose":raw_hex(&cose)})).map_err(|_|rejected())?;
        let (nonce, mac) = self.capability(
            b"OPENPC_FLEET_FACT_FAILURE_COMMIT_V1",
            profile.profile_digest(),
            &material,
            Uuid::now_v7(),
        )?;
        let item: Uuid =
            sqlx::query_scalar("select openpc.commit_fleet_fact_quarantine($1,$2,$3,$4)")
                .bind(material)
                .bind(nonce.as_slice())
                .bind(mac)
                .bind(profile.profile_digest())
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| rejected())?;
        if item.to_string() != receipt.work_item_id {
            return Err(rejected());
        }
        tx.commit().await.map_err(|_| rejected())?;
        eprintln!(
            "FLEET_FACT_QUARANTINE|event={}|work_item={item}|problem=PC-DATA-6005|ack=NONE",
            event.event_id()
        );
        Ok(())
    }
}
