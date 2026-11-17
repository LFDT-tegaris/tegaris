//! Replay and attempt metadata share one durable commit. Raw provider bodies
//! remain with the response pipeline and are never written into this journal.
use pc_runtime_types::{
    DecisionEffect, Digest, LocalJournal, RuntimeError, RuntimeResult, canonical_bytes,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ReadAttemptStatus {
    /// Admission is durable. Provider contact/completion is not established;
    /// restart must not turn this record into an automatic provider retry.
    Admitted,
    /// The process ended without a committed outcome. This says nothing about
    /// provider receipt and never authorizes a resend or response release.
    Interrupted,
    Completed {
        effect: DecisionEffect,
        pc_code: String,
        evidence_digest: Digest,
        response_digest: Digest,
    },
    Failed {
        pc_code: String,
    },
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadAttemptMetadata {
    pub request_digest: Digest,
    pub decision_digest: Digest,
    pub generation_digest: Digest,
    pub provider_profile_id: String,
    pub capability_id: String,
    pub admitted_at_ms: u64,
    pub retain_until_ms: u64,
    pub status: ReadAttemptStatus,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokerJournal {
    pub version: u32,
    pub target_id: Option<String>,
    pub sequence: u64,
    pub consumed: BTreeMap<String, u64>,
    pub attempts: BTreeMap<String, ReadAttemptMetadata>,
}
impl BrokerJournal {
    pub fn empty(target_id: Option<String>) -> Self {
        Self {
            version: 1,
            target_id,
            sequence: 0,
            consumed: BTreeMap::new(),
            attempts: BTreeMap::new(),
        }
    }
    pub fn open(
        directory: &Path,
        target_id: &str,
        capacity: usize,
    ) -> RuntimeResult<LocalJournal<Self>> {
        if target_id.is_empty() || capacity == 0 {
            return Err(RuntimeError::InvalidInput);
        }
        let mut store =
            LocalJournal::open(directory, "broker", || Self::empty(Some(target_id.into())))?;
        let state = store.state()?;
        if state.version != 1
            || state.target_id.as_deref() != Some(target_id)
            || state.attempts.len() > capacity
            || state.consumed.len() > capacity
            || state.attempts.len() != state.consumed.len()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let mut capabilities = std::collections::BTreeSet::new();
        for (id, record) in &state.attempts {
            let sequence = id
                .strip_prefix("local-attempt-")
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .ok_or(RuntimeError::InvalidInput)?;
            if sequence == 0
                || sequence > state.sequence
                || id != &format!("local-attempt-{sequence:016x}")
                || !capabilities.insert(&record.capability_id)
                || record.provider_profile_id.is_empty()
                || record.admitted_at_ms >= record.retain_until_ms
                || state.consumed.get(&record.capability_id) != Some(&record.retain_until_ms)
            {
                return Err(RuntimeError::GenerationMismatch);
            }
            match &record.status {
                ReadAttemptStatus::Completed {
                    effect,
                    pc_code,
                    evidence_digest,
                    response_digest,
                } if *effect != DecisionEffect::AllowForward
                    || pc_code != "PC-RUNTIME-0000"
                    || *evidence_digest
                        != Digest::of(canonical_bytes(&(
                            id,
                            &record.request_digest,
                            response_digest,
                        ))?) =>
                {
                    return Err(RuntimeError::InvalidDigest);
                }
                ReadAttemptStatus::Failed { pc_code }
                    if !matches!(
                        pc_code.as_str(),
                        "PC-RUNTIME-3001"
                            | "PC-RUNTIME-3002"
                            | "PC-RUNTIME-3003"
                            | "PC-RUNTIME-3004"
                            | "PC-RUNTIME-3005"
                            | "PC-RUNTIME-3006"
                            | "PC-RUNTIME-3007"
                            | "PC-RUNTIME-3008"
                            | "PC-RUNTIME-3009"
                            | "PC-RUNTIME-3010"
                            | "PC-RUNTIME-3011"
                            | "PC-RUNTIME-3012"
                            | "PC-RUNTIME-3013"
                            | "PC-RUNTIME-3014"
                            | "PC-RUNTIME-3015"
                            | "PC-RUNTIME-3016"
                            | "PC-RUNTIME-3017"
                            | "PC-RUNTIME-3018"
                    ) =>
                {
                    return Err(RuntimeError::InvalidInput);
                }
                _ => {}
            }
        }
        let mut recovered = state.clone();
        let mut changed = false;
        for record in recovered.attempts.values_mut() {
            if record.status == ReadAttemptStatus::Admitted {
                record.status = ReadAttemptStatus::Interrupted;
                changed = true;
            }
        }
        if changed {
            store.commit(recovered)?;
        }
        Ok(store)
    }
}
