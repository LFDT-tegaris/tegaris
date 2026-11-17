//! Non-invocation source reads share target evidence custody. Starting a read
//! consumes its persisted rate slot; failure or restart never refunds a send.
use super::*;

pub struct SourceReadEvidenceInput {
    pub request_digest: Digest,
    pub source_scope_digest: Digest,
    pub authority_binding_digest: Digest,
    pub valid_until_ns: u64,
    pub rate_window_ms: u32,
    pub maximum_requests: u32,
}

impl DecisionEvidenceStore {
    pub fn start_source_read(
        &self,
        active: &ActiveCapsuleLease<'_>,
        trace: &RequestTraceId,
        input: &SourceReadEvidenceInput,
        now_ns: u64,
    ) -> RuntimeResult<String> {
        active.revalidate(now_ns)?;
        let valid_until_ns = input.valid_until_ns.min(active.expires_at_ns());
        if active.capsule().target_runtime_id != self.target_id
            || now_ns >= valid_until_ns
            || !(1..=3_600_000).contains(&input.rate_window_ms)
            || !(1..=10_000).contains(&input.maximum_requests)
        {
            return Err(RuntimeError::InvalidInput);
        }
        let mut journal = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut next = journal.state()?.clone();
        if next.records.len() >= self.capacity {
            return Err(RuntimeError::EvidenceCapacity);
        }
        if next
            .records
            .values()
            .any(|r| r.trace_id.as_deref() == Some(trace.as_str()))
        {
            return Err(RuntimeError::Replay);
        }
        let window_ns = u64::from(input.rate_window_ms) * 1_000_000;
        let mut used = 0;
        for record in next.records.values() {
            let scope = match &record.status {
                DecisionEvidenceStatus::SourceReadStarted {
                    source_scope_digest,
                    ..
                }
                | DecisionEvidenceStatus::SourceReadReleased {
                    source_scope_digest,
                    ..
                } => source_scope_digest,
                _ => continue,
            };
            if scope == &input.source_scope_digest {
                let age = now_ns
                    .checked_sub(record.reserved_at_ns)
                    .ok_or(RuntimeError::ExpiredAuthorization)?;
                if age < window_ns {
                    used += 1;
                }
            }
        }
        if used >= input.maximum_requests {
            return Err(RuntimeError::BudgetExhausted);
        }
        let id = uuid::Uuid::now_v7().to_string();
        if next.records.contains_key(&id) {
            return Err(RuntimeError::Replay);
        }
        next.records.insert(
            id.clone(),
            DecisionEvidence {
                trace_id: Some(trace.as_str().into()),
                request_digest: input.request_digest.clone(),
                capsule_digest: active.capsule().digest()?,
                reserved_at_ns: now_ns,
                valid_until_ns,
                status: DecisionEvidenceStatus::SourceReadStarted {
                    source_scope_digest: input.source_scope_digest.clone(),
                    authority_binding_digest: input.authority_binding_digest.clone(),
                },
            },
        );
        // This path bypasses PDS. Include the proposed start and its completion
        // slot before any source send; existing admitted reads keep their slots.
        if journal.capacity_after(&next, self.capacity)?.critical() {
            return Err(RuntimeError::EvidenceCapacity);
        }
        journal.commit(next)?;
        Ok(id)
    }

    /// The same source authority must be revalidated immediately before this
    /// commit while the active capsule lease and Control row fences are held.
    pub fn release_source_read(
        &self,
        active: &ActiveCapsuleLease<'_>,
        evidence_id: &str,
        authority_binding_digest: &Digest,
        response: &[u8],
        now_ns: u64,
    ) -> RuntimeResult<()> {
        active.revalidate(now_ns)?;
        if response.is_empty() || response.len() > 131_072 {
            return Err(RuntimeError::InvalidInput);
        }
        let mut journal = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut next = journal.state()?.clone();
        let record = next
            .records
            .get_mut(evidence_id)
            .ok_or(RuntimeError::InvalidAuthorization)?;
        if record.capsule_digest != active.capsule().digest()?
            || active.capsule().target_runtime_id != self.target_id
            || now_ns < record.reserved_at_ns
            || now_ns >= record.valid_until_ns
        {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        let DecisionEvidenceStatus::SourceReadStarted {
            source_scope_digest,
            authority_binding_digest: admitted,
        } = &record.status
        else {
            return Err(RuntimeError::Replay);
        };
        if admitted != authority_binding_digest {
            return Err(RuntimeError::InvalidAuthorization);
        }
        record.status = DecisionEvidenceStatus::SourceReadReleased {
            source_scope_digest: source_scope_digest.clone(),
            authority_binding_digest: admitted.clone(),
            response_digest: Digest::of(response),
            released_at_ns: now_ns,
        };
        journal.commit(next)?;
        Ok(())
    }
}
