//! Semantic inputs for the governed Fact/candidate retirement boundary.
//!
//! Validation here proves shape and exact binding only. These types are not an
//! authorization capability, a public signed profile, or a durable attempt owner.
//! A target must authenticate the governed request with host-configured trust,
//! lock its durable attempt and source owners, and recheck live predicates before
//! any effect. In particular, no caller-supplied eligibility flag is accepted.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Digest, canonical_bytes};

const MAX_SELECTION_ROWS: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RetirementStore {
    #[serde(rename = "openpc_facts")]
    Facts,
    #[serde(rename = "openpc_candidate_index")]
    CandidateIndex,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementScope {
    pub participant_id: String,
    pub privacy_domain_id: String,
}

/// The generation and partition are part of the exact immutable selection.
/// `identity_digest` binds the existing source owner's complete identity; it does
/// not replace that owner's current publication, reorg or readiness checks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementSource {
    pub profile_id: String,
    pub generation_id: String,
    pub partition_id: String,
    pub identity_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FactPayloadSelection {
    pub candidate_id: String,
    pub fact_id: String,
    /// Immutable Fact identity allocation; never replace with the feed cursor.
    pub fact_delta_sequence: u64,
    pub candidate_feed_sequence: u64,
    pub payload_digest: Digest,
    pub payload_bytes: u64,
    pub signed_fact_digest: Digest,
    pub lineage_digest: Digest,
    pub checkpoint_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePayloadSelection {
    pub candidate_id: String,
    pub candidate_feed_sequence: u64,
    pub payload_digest: Digest,
    pub payload_bytes: u64,
    pub checkpoint_digest: Digest,
}

/// Only physical payload selections are represented. Independent outbox,
/// archive, normalized projection and signed-evidence copies are not implied.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "class", deny_unknown_fields)]
pub enum RetirementSelection {
    #[serde(rename = "ADMITTED_FACT")]
    Facts {
        source: RetirementSource,
        fact_generation_id: String,
        canonical_generation: u64,
        rows: Vec<FactPayloadSelection>,
    },
    #[serde(rename = "CANDIDATE_PROJECTION")]
    Candidates {
        source: RetirementSource,
        rows: Vec<CandidatePayloadSelection>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementGovernance {
    pub retention_policy_digest: Digest,
    pub archive_manifest_digest: Digest,
    pub archive_acknowledgement_digest: Digest,
    pub approval_digest: Digest,
    pub lifecycle_revision: u64,
    pub retention_not_before_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementAttempt {
    pub scope: RetirementScope,
    pub store: RetirementStore,
    pub business_intent_id: String,
    pub attempt_id: String,
    pub governance: RetirementGovernance,
    pub selection: RetirementSelection,
    pub selection_digest: Digest,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RetirementContractError {
    #[error("invalid retirement binding")]
    Binding,
    #[error("invalid or unbounded retirement selection")]
    Selection,
    #[error("retirement digest does not match its exact inputs")]
    Digest,
    #[error("retirement outcome does not match its attempt")]
    Outcome,
}

type Result<T> = std::result::Result<T, RetirementContractError>;

impl RetirementSelection {
    #[must_use]
    pub const fn store(&self) -> RetirementStore {
        match self {
            Self::Facts { .. } => RetirementStore::Facts,
            Self::Candidates { .. } => RetirementStore::CandidateIndex,
        }
    }

    /// Rows have a strict, unique feed order. Neither a retry nor a candidate
    /// rebuild is allowed to silently reorder or renumber an approved selection.
    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_SELECTION_ROWS).contains(&self.row_count()) {
            return Err(RetirementContractError::Selection);
        }
        let source = match self {
            Self::Facts {
                source,
                fact_generation_id,
                canonical_generation,
                rows,
            } => {
                identifier(fact_generation_id)?;
                // These two Fact allocations are NUMERIC(20,0), not BIGINT.
                positive_u64(*canonical_generation)?;
                let mut fact_ids = BTreeSet::new();
                let mut fact_sequences = BTreeSet::new();
                let mut candidates = BTreeSet::new();
                let mut previous = 0;
                for row in rows {
                    identifier(&row.fact_id)?;
                    positive_u64(row.fact_delta_sequence)?;
                    if !fact_ids.insert(&row.fact_id)
                        || !fact_sequences.insert(row.fact_delta_sequence)
                    {
                        return Err(RetirementContractError::Selection);
                    }
                    validate_row(
                        &row.candidate_id,
                        row.candidate_feed_sequence,
                        row.payload_bytes,
                        &row.payload_digest,
                        &row.checkpoint_digest,
                        &mut previous,
                        &mut candidates,
                    )?;
                    digest(&row.signed_fact_digest)?;
                    digest(&row.lineage_digest)?;
                }
                source
            }
            Self::Candidates { source, rows } => {
                let mut candidates = BTreeSet::new();
                let mut previous = 0;
                for row in rows {
                    validate_row(
                        &row.candidate_id,
                        row.candidate_feed_sequence,
                        row.payload_bytes,
                        &row.payload_digest,
                        &row.checkpoint_digest,
                        &mut previous,
                        &mut candidates,
                    )?;
                }
                source
            }
        };
        identifier(&source.profile_id)?;
        identifier(&source.generation_id)?;
        identifier(&source.partition_id)?;
        digest(&source.identity_digest)?;
        self.payload_bytes()?;
        Ok(())
    }

    /// Internal contract digest, not a signature or a replacement for the
    /// integration-owned signed wire profile. Scope is deliberately included.
    pub fn digest(&self, scope: &RetirementScope) -> Result<Digest> {
        self.validate()?;
        scope.validate()?;
        encode_digest(&("OPENPC_STORE_RETIREMENT_SELECTION_V1", scope, self))
    }

    #[must_use]
    pub fn row_count(&self) -> usize {
        match self {
            Self::Facts { rows, .. } => rows.len(),
            Self::Candidates { rows, .. } => rows.len(),
        }
    }

    pub fn payload_bytes(&self) -> Result<u64> {
        let total = match self {
            Self::Facts { rows, .. } => sum_sizes(rows.iter().map(|row| row.payload_bytes))?,
            Self::Candidates { rows, .. } => sum_sizes(rows.iter().map(|row| row.payload_bytes))?,
        };
        positive_sql_integer(total)?;
        Ok(total)
    }
}

impl RetirementScope {
    pub fn validate(&self) -> Result<()> {
        identifier(&self.participant_id)?;
        identifier(&self.privacy_domain_id)
    }
}

impl RetirementAttempt {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        identifier(&self.business_intent_id)?;
        identifier(&self.attempt_id)?;
        positive_sql_integer(self.governance.lifecycle_revision)?;
        positive_sql_integer(self.governance.retention_not_before_ms)?;
        for value in [
            &self.governance.retention_policy_digest,
            &self.governance.archive_manifest_digest,
            &self.governance.archive_acknowledgement_digest,
            &self.governance.approval_digest,
            &self.selection_digest,
        ] {
            digest(value)?;
        }
        if self.store != self.selection.store() {
            return Err(RetirementContractError::Binding);
        }
        if self.selection.digest(&self.scope)? != self.selection_digest {
            return Err(RetirementContractError::Digest);
        }
        Ok(())
    }

    /// Includes approval, archive, lifecycle revision and both business and
    /// attempt identities. An altered retry must conflict even if its rows match.
    pub fn digest(&self) -> Result<Digest> {
        self.validate()?;
        encode_digest(&("OPENPC_STORE_RETIREMENT_ATTEMPT_V1", self))
    }
}

/// These are claims awaiting the integration-owned outcome signature. A decoded
/// value alone must never settle a Control attempt or establish hold protection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementOutcome {
    pub attempt_digest: Digest,
    pub effect: RetirementEffect,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum RetirementEffect {
    Applied {
        retired_rows: u64,
        retired_payload_bytes: u64,
        retained_lineage_digest: Digest,
        outbox_event_digest: Digest,
    },
    RejectedNoEffect {
        rejection: RetirementRejection,
    },
    CancelledNoEffect {},
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetirementRejection {
    SourceChanged,
    GenerationChanged,
    ReorgFenced,
    CheckpointIncomplete,
    ReadinessProtected,
    PublicationProtected,
    ReferencesProtected,
    RetentionNotElapsed,
    ArchiveMismatch,
    GovernanceChanged,
}

impl RetirementOutcome {
    pub fn validate_for(&self, attempt: &RetirementAttempt) -> Result<()> {
        digest(&self.attempt_digest)?;
        if self.attempt_digest != attempt.digest()? {
            return Err(RetirementContractError::Outcome);
        }
        if let RetirementEffect::Applied {
            retired_rows,
            retired_payload_bytes,
            retained_lineage_digest,
            outbox_event_digest,
        } = &self.effect
        {
            if *retired_rows != attempt.selection.row_count() as u64
                || *retired_payload_bytes != attempt.selection.payload_bytes()?
            {
                return Err(RetirementContractError::Outcome);
            }
            digest(retained_lineage_digest)?;
            digest(outbox_event_digest)?;
        }
        Ok(())
    }
}

/// Absence, transport errors and uncertain commits cannot prove no effect.
/// Only the authenticated original terminal outcome may resolve the attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetirementReadback {
    Unknown,
    InProgress { attempt_digest: Digest },
    Terminal(RetirementOutcome),
}

fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(RetirementContractError::Binding);
    }
    Ok(())
}

fn positive_sql_integer(value: u64) -> Result<()> {
    if value == 0 || value > i64::MAX as u64 {
        return Err(RetirementContractError::Selection);
    }
    Ok(())
}

fn positive_u64(value: u64) -> Result<()> {
    if value == 0 {
        return Err(RetirementContractError::Selection);
    }
    Ok(())
}

fn sum_sizes(mut sizes: impl Iterator<Item = u64>) -> Result<u64> {
    sizes.try_fold(0_u64, |total, size| {
        total
            .checked_add(size)
            .ok_or(RetirementContractError::Selection)
    })
}

fn digest(value: &Digest) -> Result<()> {
    // Digest's general serde implementation permits an unchecked string. This
    // admission boundary requires exactly its lowercase canonical representation.
    match Digest::parse(value.as_str()) {
        Ok(parsed) if parsed == *value => Ok(()),
        _ => Err(RetirementContractError::Digest),
    }
}

fn encode_digest(value: &impl Serialize) -> Result<Digest> {
    canonical_bytes(value)
        .map(Digest::of)
        .map_err(|_| RetirementContractError::Digest)
}

fn validate_row<'a>(
    candidate_id: &'a str,
    sequence: u64,
    payload_bytes: u64,
    payload_digest: &Digest,
    checkpoint_digest: &Digest,
    previous: &mut u64,
    candidates: &mut BTreeSet<&'a str>,
) -> Result<()> {
    identifier(candidate_id)?;
    positive_sql_integer(sequence)?;
    positive_sql_integer(payload_bytes)?;
    digest(payload_digest)?;
    digest(checkpoint_digest)?;
    if sequence <= *previous || !candidates.insert(candidate_id) {
        return Err(RetirementContractError::Selection);
    }
    *previous = sequence;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> RetirementSource {
        RetirementSource {
            profile_id: "profile-1".into(),
            generation_id: "source-generation-1".into(),
            partition_id: "partition-1".into(),
            identity_digest: Digest::of(b"current source identity"),
        }
    }

    fn candidate_row(id: &str, feed: u64) -> CandidatePayloadSelection {
        CandidatePayloadSelection {
            candidate_id: id.into(),
            candidate_feed_sequence: feed,
            payload_digest: Digest::of(id.as_bytes()),
            payload_bytes: 40,
            checkpoint_digest: Digest::of(b"complete checkpoint"),
        }
    }

    fn candidate_selection() -> RetirementSelection {
        RetirementSelection::Candidates {
            source: source(),
            rows: vec![
                candidate_row("candidate-1", 20),
                candidate_row("candidate-2", 22),
            ],
        }
    }

    fn attempt(selection: RetirementSelection) -> RetirementAttempt {
        let scope = RetirementScope {
            participant_id: "participant-1".into(),
            privacy_domain_id: "privacy-1".into(),
        };
        RetirementAttempt {
            store: selection.store(),
            business_intent_id: "intent-1".into(),
            attempt_id: "attempt-1".into(),
            governance: RetirementGovernance {
                retention_policy_digest: Digest::of(b"policy"),
                archive_manifest_digest: Digest::of(b"manifest"),
                archive_acknowledgement_digest: Digest::of(b"acknowledgement"),
                approval_digest: Digest::of(b"approval"),
                lifecycle_revision: 9,
                retention_not_before_ms: 1_800_000_000_000,
            },
            selection_digest: selection.digest(&scope).unwrap(),
            scope,
            selection,
        }
    }

    fn fact_selection() -> RetirementSelection {
        RetirementSelection::Facts {
            source: source(),
            fact_generation_id: "fact-generation-1".into(),
            canonical_generation: u64::MAX,
            rows: vec![FactPayloadSelection {
                candidate_id: "candidate-1".into(),
                fact_id: "fact-1".into(),
                fact_delta_sequence: u64::MAX,
                candidate_feed_sequence: 20,
                payload_digest: Digest::of(b"payload"),
                payload_bytes: 40,
                signed_fact_digest: Digest::of(b"original COSE"),
                lineage_digest: Digest::of(b"lineage"),
                checkpoint_digest: Digest::of(b"checkpoint"),
            }],
        }
    }

    #[test]
    fn exact_roundtrip_preserves_distinct_fact_and_feed_allocations() {
        let original = attempt(fact_selection());
        let encoded = serde_json::to_vec(&original).unwrap();
        let restored: RetirementAttempt = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored, original);
        restored.validate().unwrap();
        let mut changed = restored.clone();
        let RetirementSelection::Facts { rows, .. } = &mut changed.selection else {
            panic!("Fact selection");
        };
        rows[0].fact_delta_sequence = rows[0].candidate_feed_sequence;
        assert_eq!(changed.validate(), Err(RetirementContractError::Digest));
        assert_eq!(original.digest().unwrap(), restored.digest().unwrap());
    }

    #[test]
    fn approval_archive_lifecycle_and_business_identity_are_replay_bindings() {
        let original = attempt(candidate_selection());
        let expected = original.digest().unwrap();
        let mutations: [fn(&mut RetirementAttempt); 7] = [
            |v| v.governance.approval_digest = Digest::of(b"successor approval"),
            |v| v.governance.archive_acknowledgement_digest = Digest::of(b"other ack"),
            |v| v.governance.archive_manifest_digest = Digest::of(b"other archive"),
            |v| v.governance.retention_policy_digest = Digest::of(b"other policy"),
            |v| v.governance.lifecycle_revision += 1,
            |v| v.business_intent_id = "other intent".into(),
            |v| v.attempt_id = "other attempt".into(),
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert_ne!(changed.digest().unwrap(), expected);
        }
    }

    #[test]
    fn selection_digest_binds_scope_and_source_generation() {
        let original = attempt(candidate_selection());
        let mut changed = original.clone();
        changed.scope.privacy_domain_id = "other privacy".into();
        assert_eq!(changed.validate(), Err(RetirementContractError::Digest));
        changed = original.clone();
        let RetirementSelection::Candidates { source, .. } = &mut changed.selection else {
            panic!("candidate selection");
        };
        source.generation_id = "successor generation".into();
        assert_eq!(changed.validate(), Err(RetirementContractError::Digest));
        changed = original;
        changed.store = RetirementStore::Facts;
        assert_eq!(changed.validate(), Err(RetirementContractError::Binding));
    }

    #[test]
    fn duplicate_identity_unordered_feed_and_unbounded_selection_are_rejected() {
        let bad_rows = [
            vec![],
            vec![candidate_row("same", 20), candidate_row("same", 21)],
            vec![candidate_row("one", 20), candidate_row("two", 20)],
            vec![candidate_row("one", 21), candidate_row("two", 20)],
            (0..=MAX_SELECTION_ROWS)
                .map(|index| candidate_row(&format!("candidate-{index}"), index as u64 + 1))
                .collect(),
        ];
        for rows in bad_rows {
            assert_eq!(
                RetirementSelection::Candidates {
                    source: source(),
                    rows
                }
                .validate(),
                Err(RetirementContractError::Selection)
            );
        }
        let mut selection = fact_selection();
        let RetirementSelection::Facts { rows, .. } = &mut selection else {
            panic!("Fact selection");
        };
        let mut duplicate = rows[0].clone();
        duplicate.candidate_id = "other-candidate".into();
        duplicate.candidate_feed_sequence += 1;
        rows.push(duplicate);
        assert_eq!(
            selection.validate(),
            Err(RetirementContractError::Selection)
        );
    }

    #[test]
    fn unchecked_digest_deserialization_and_authority_flags_are_rejected() {
        let original = attempt(candidate_selection());
        for malformed in ["z".repeat(64), "A".repeat(64), "a".repeat(63)] {
            let mut json = serde_json::to_value(&original).unwrap();
            json["governance"]["approval_digest"] = malformed.into();
            let parsed: RetirementAttempt = serde_json::from_value(json).unwrap();
            assert_eq!(parsed.validate(), Err(RetirementContractError::Digest));
        }
        for flag in [
            "eligible",
            "references_clear",
            "hold_free",
            "archive_verified",
        ] {
            let mut json = serde_json::to_value(&original).unwrap();
            json[flag] = true.into();
            assert!(serde_json::from_value::<RetirementAttempt>(json).is_err());
        }
    }

    #[test]
    fn zero_overflow_and_invalid_identity_cannot_reach_target_sql() {
        for bad in [0, i64::MAX as u64 + 1] {
            let mut row = candidate_row("candidate", bad);
            assert!(
                RetirementSelection::Candidates {
                    source: source(),
                    rows: vec![row.clone()]
                }
                .validate()
                .is_err()
            );
            row.candidate_feed_sequence = 1;
            row.payload_bytes = bad;
            assert!(
                RetirementSelection::Candidates {
                    source: source(),
                    rows: vec![row]
                }
                .validate()
                .is_err()
            );
        }
        for id in ["", " candidate", "candidate\0secret", "candidate\n"] {
            let mut changed = attempt(candidate_selection());
            changed.attempt_id = id.into();
            assert_eq!(changed.validate(), Err(RetirementContractError::Binding));
        }
    }

    #[test]
    fn outcomes_require_exact_attempt_and_exact_physical_effect() {
        let original = attempt(candidate_selection());
        let mut outcome = RetirementOutcome {
            attempt_digest: original.digest().unwrap(),
            effect: RetirementEffect::Applied {
                retired_rows: 2,
                retired_payload_bytes: 80,
                retained_lineage_digest: Digest::of(b"minimum immutable lineage"),
                outbox_event_digest: Digest::of(b"atomic original outcome event"),
            },
        };
        outcome.validate_for(&original).unwrap();
        let mut altered = original.clone();
        altered.attempt_id = "new attempt".into();
        assert_eq!(
            outcome.validate_for(&altered),
            Err(RetirementContractError::Outcome)
        );
        let RetirementEffect::Applied {
            retired_payload_bytes,
            ..
        } = &mut outcome.effect
        else {
            panic!("applied outcome");
        };
        *retired_payload_bytes = 0;
        assert_eq!(
            outcome.validate_for(&original),
            Err(RetirementContractError::Outcome)
        );
    }

    #[test]
    fn no_effect_outcomes_cannot_smuggle_effect_counts() {
        let original = attempt(candidate_selection());
        for effect in [
            RetirementEffect::CancelledNoEffect {},
            RetirementEffect::RejectedNoEffect {
                rejection: RetirementRejection::ReferencesProtected,
            },
        ] {
            let outcome = RetirementOutcome {
                attempt_digest: original.digest().unwrap(),
                effect,
            };
            outcome.validate_for(&original).unwrap();
            let mut value = serde_json::to_value(outcome).unwrap();
            value["effect"]["retired_rows"] = 1.into();
            assert!(serde_json::from_value::<RetirementOutcome>(value).is_err());
        }
    }
}
