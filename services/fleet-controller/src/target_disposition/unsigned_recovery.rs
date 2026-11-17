//! Historical verification for a fresh denial. No original permit is recovered
//! and no old confirmation is returned as current serving authority.
use super::*;
use pc_policy_core::runtime_wire::{Profile, Verifier};
use serde_json::Value;

impl TargetDispositionStore {
    pub fn with_identity_runtime_trust(mut self, spki: &[u8]) -> Result<Self> {
        Verifier::from_spki_der(spki).map_err(|_| unavailable())?;
        self.identity_runtime_trust = Some(spki.to_vec());
        Ok(self)
    }

    pub(super) async fn verify_unsigned_recovery(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        target: &str,
    ) -> Result<()> {
        let row=sqlx::query(r#"select a.binding,a.revision::text,a.admission_digest,
          d.delivery_digest,e.evidence_cbor,e.cose_sign1,o.activation_receipt,
          p.activation_proof,previous_delivery.signed_delivery,previous_ack.signed_acknowledgement
          from (select * from control.runtime_target_disposition_admission
           where participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id()
            and runtime_target_id=$1::text::uuid order by revision desc limit 1) a
          left join control.runtime_target_disposition_delivery d using(participant_id,privacy_domain_id,runtime_target_id,revision)
          left join control.configuration_work w on w.participant_id=a.participant_id and w.privacy_domain_id=a.privacy_domain_id
           and w.configuration_work_id::text=a.binding->'cause'->>'work_id'
          left join control.mutation_evidence e on e.participant_id=w.participant_id and e.privacy_domain_id=w.privacy_domain_id
           and e.operation_id=w.operation_id
          left join control.runtime_activation_observation o on o.participant_id=a.participant_id and o.privacy_domain_id=a.privacy_domain_id
           and o.runtime_target_id=a.runtime_target_id and substring(o.capsule_digest from 8)=a.binding->'source'->>'capsule_digest'
          left join control.runtime_target_disposition_admission p on p.participant_id=a.participant_id and p.privacy_domain_id=a.privacy_domain_id
           and p.runtime_target_id=a.runtime_target_id and p.revision=a.revision-1
          left join control.runtime_target_disposition_delivery previous_delivery on previous_delivery.participant_id=p.participant_id
           and previous_delivery.privacy_domain_id=p.privacy_domain_id and previous_delivery.runtime_target_id=p.runtime_target_id
           and previous_delivery.revision=p.revision
          left join control.runtime_target_disposition_acknowledgement previous_ack on previous_ack.participant_id=previous_delivery.participant_id
           and previous_ack.privacy_domain_id=previous_delivery.privacy_domain_id and previous_ack.runtime_target_id=previous_delivery.runtime_target_id
           and previous_ack.delivery_digest=previous_delivery.delivery_digest"#)
            .bind(target).fetch_optional(&mut **tx).await.map_err(database_error)?;
        let Some(row) = row else {
            return Ok(());
        };
        let binding: Value = row.try_get("binding").map_err(database_error)?;
        if binding["action"] != "Withdraw"
            || binding["cause"]["kind"] != "Activation"
            || row
                .try_get::<Option<String>, _>("delivery_digest")
                .map_err(database_error)?
                .is_some()
        {
            return Ok(());
        }
        let revision = supported_disposition_revision(
            &row.try_get::<String, _>("revision")
                .map_err(database_error)?,
        )?;
        let recoverable: bool = sqlx::query_scalar(
            "select openpc.runtime_unsigned_withdrawal_recoverable($1::text::uuid,$2,$3)",
        )
        .bind(target)
        .bind(i64::try_from(revision).map_err(|_| unavailable())?)
        .bind(
            row.try_get::<String, _>("admission_digest")
                .map_err(database_error)?,
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(database_error)?;
        if !recoverable {
            return Err(unavailable());
        }
        let identity =
            serde_json::from_value(binding["target"].clone()).map_err(|_| unavailable())?;
        let source =
            serde_json::from_value(binding["source"].clone()).map_err(|_| unavailable())?;
        let target_key = self
            .target_keys
            .lock()
            .map_err(|_| unavailable())?
            .get(target)
            .cloned()
            .ok_or_else(unavailable)?;
        let verifier = TargetDispositionVerifier::from_host_keys(
            identity,
            &self.control_signer.verifier().sec1_bytes(),
            &target_key,
        )
        .map_err(|_| unavailable())?;
        let wire: Vec<u8> = row.try_get("signed_delivery").map_err(database_error)?;
        let previous = verifier
            .verify_delivery(&wire, &source)
            .map_err(|_| unavailable())?;
        let ack: Vec<u8> = row
            .try_get("signed_acknowledgement")
            .map_err(database_error)?;
        verifier
            .verify_acknowledgement(&ack, &previous)
            .map_err(|_| unavailable())?;
        if previous.claims().action
            != pc_runtime_types::target_disposition::TargetDispositionAction::ConfirmActivation
            || previous.claims().source != source
            || previous.claims().revision.checked_add(1) != Some(revision)
            || binding["previous_delivery_digest"].as_str()
                != Some(previous.signed_digest().as_str())
        {
            return Err(unavailable());
        }
        let verifier = Verifier::from_spki_der(
            self.identity_runtime_trust
                .as_deref()
                .ok_or_else(unavailable)?,
        )
        .map_err(|_| unavailable())?;
        let authorization: Vec<u8> = row.try_get("evidence_cbor").map_err(database_error)?;
        let cose: Vec<u8> = row.try_get("cose_sign1").map_err(database_error)?;
        if verifier
            .verify(Profile::IdentityAssertion, &cose, 8192)
            .map_err(|_| unavailable())?
            != authorization
        {
            return Err(unavailable());
        }
        let receipt: Value = row.try_get("activation_receipt").map_err(database_error)?;
        let encoded = receipt["activationReceiptCoseHex"]
            .as_str()
            .ok_or_else(unavailable)?;
        if encoded.is_empty()
            || encoded.len() > 524288
            || !encoded.len().is_multiple_of(2)
            || !encoded
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(unavailable());
        }
        let signed = (0..encoded.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).map_err(|_| unavailable()))
            .collect::<Result<Vec<_>>>()?;
        let key = self
            .runtime_target_keys
            .lock()
            .map_err(|_| unavailable())?
            .get(target)
            .cloned()
            .ok_or_else(unavailable)?;
        let observed = openpc_runtime_agent::RuntimeWireVerifier::from_public_key_bytes(&key)
            .and_then(|v| v.verify_receipt(&signed))
            .map_err(|_| unavailable())?;
        let proof: Value = row.try_get("activation_proof").map_err(database_error)?;
        let until = proof["capsuleValidUntilNs"]
            .as_str()
            .ok_or_else(unavailable)?
            .parse::<u64>()
            .map_err(|_| unavailable())?;
        if observed.target_runtime_id != target
            || observed.status != 1
            || observed.reason_code != "ACTIVE_LOCAL"
            || observed.capsule_digest.as_str()
                != binding["source"]["capsule_digest"]
                    .as_str()
                    .ok_or_else(unavailable)?
            || observed.observed_at_ns >= until
            || proof["originalReceiptDigest"].as_str() != Some(Digest::of(&signed).as_str())
        {
            return Err(unavailable());
        }
        Ok(())
    }
}
