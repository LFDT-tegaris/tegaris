//! Recovery reads exact committed custody. These APIs never admit or sign.
use super::*;
use pc_runtime_types::target_disposition::TargetDispositionAction;

impl TargetDispositionStore {
    /// Lookup only, including after a process restart or uncertain publication.
    /// `Ok(false)` requires a verified original delivery awaiting its ACK. An
    /// absent, pending, withdrawn or unavailable head remains UNKNOWN/error.
    pub async fn lookup_fact_activation_confirmation(
        &self,
        original: OriginalTargetActivation<'_>,
        reader: &openpc_fact_service::PolicyFactReader,
        trust: TargetFactTrust<'_>,
    ) -> Result<bool> {
        self.lookup_fact_disposition(
            original,
            reader,
            trust,
            TargetDispositionAction::ConfirmActivation,
        )
        .await
    }

    /// Lookup of the original provably-unstarted restoration only. A Withdraw
    /// head is not authority to start a restoration from this recovery path.
    pub async fn lookup_fact_unstarted_restore(
        &self,
        original: OriginalTargetActivation<'_>,
        reader: &openpc_fact_service::PolicyFactReader,
        trust: TargetFactTrust<'_>,
    ) -> Result<bool> {
        self.lookup_fact_disposition(original, reader, trust, TargetDispositionAction::Restore)
            .await
    }

    async fn lookup_fact_disposition(
        &self,
        original: OriginalTargetActivation<'_>,
        reader: &openpc_fact_service::PolicyFactReader,
        trust: TargetFactTrust<'_>,
        action: TargetDispositionAction,
    ) -> Result<bool> {
        let current = self
            .current_for_installed_peer(original.peer)
            .await?
            .ok_or_else(unavailable)?;
        let bytes = current.signed_delivery.as_ref().ok_or_else(unavailable)?;
        let envelope: pc_runtime_types::SignedEnvelope<TargetDispositionDelivery> =
            serde_json::from_slice(bytes).map_err(|_| unavailable())?;
        if envelope.claims.action != action
            || envelope.claims.source.capsule_digest
                != original.capsule.digest().map_err(|_| unavailable())?
        {
            return Err(unavailable());
        }
        let target_key = self
            .target_keys
            .lock()
            .map_err(|_| unavailable())?
            .get(&original.peer.target_id)
            .cloned()
            .ok_or_else(unavailable)?;
        let verifier = TargetDispositionVerifier::from_host_keys(
            envelope.claims.target.clone(),
            &self.control_signer.verifier().sec1_bytes(),
            &target_key,
        )
        .map_err(|_| unavailable())?;
        let delivery = verifier
            .verify_delivery(bytes, &envelope.claims.source)
            .map_err(|_| unavailable())?;
        if delivery.claims().revision != current.revision
            || delivery.claims().committed_admission_digest != current.admission_digest
        {
            return Err(unavailable());
        }
        self.prepare_disposition_source(&original, DispositionSource::FactBound { reader, trust })
            .await?
            .revalidate_replay(self, &original, delivery.claims(), &current)
            .await?;
        match current.signed_acknowledgement {
            None => Ok(false),
            Some(bytes) => {
                verifier
                    .verify_acknowledgement(&bytes, &delivery)
                    .map_err(|_| unavailable())?;
                Ok(true)
            }
        }
    }
}
