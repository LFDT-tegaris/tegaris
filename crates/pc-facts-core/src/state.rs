use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateState {
    ObservedCandidate,
    ValidatedCandidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactLifecycleState {
    ObservedCandidate,
    ValidatedCandidate,
    Admitted,
    Provisional,
    Finalized,
    Stale,
    Invalidated,
    Reorged,
    Superseded,
    Quarantined,
    Retired,
}

impl FactLifecycleState {
    pub const ALL: [Self; 11] = [
        Self::ObservedCandidate,
        Self::ValidatedCandidate,
        Self::Admitted,
        Self::Provisional,
        Self::Finalized,
        Self::Stale,
        Self::Invalidated,
        Self::Reorged,
        Self::Superseded,
        Self::Quarantined,
        Self::Retired,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactReadinessState {
    NotAdmitted,
    Provisional,
    Ready,
    Stale,
    ReorgPending,
    Partial,
    Conflicting,
    Quarantined,
    Retired,
}

impl FactReadinessState {
    pub const ALL: [Self; 9] = [
        Self::NotAdmitted,
        Self::Provisional,
        Self::Ready,
        Self::Stale,
        Self::ReorgPending,
        Self::Partial,
        Self::Conflicting,
        Self::Quarantined,
        Self::Retired,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckpointState {
    Bootstrap,
    CatchingUp,
    Complete,
    GapBlocked,
    ReorgFenced,
    Quarantined,
    Recovering,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LineageAction {
    Admit,
    MarkProvisional,
    Finalize,
    MarkStale,
    Invalidate,
    MarkReorged,
    Supersede,
    Quarantine,
    Retire,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionOutcome {
    AdmittedProvisional,
    AdmittedFinalized,
    Rejected,
    Quarantined,
    IdempotentReplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactQueryOutcome {
    Present,
    AbsentConfirmed,
    Denied,
    Unknown,
    NotReady,
    Unavailable,
    Stale,
    Reorg,
    Partial,
    Conflicting,
    Tampered,
}

impl FactQueryOutcome {
    #[must_use]
    pub const fn is_positive(self) -> bool {
        matches!(self, Self::Present)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelationshipResult {
    MemberConfirmed,
    NonMemberConfirmed,
    Denied,
    Unresolved,
    NotCaughtUp,
    Stale,
    ReorgPending,
    Partial,
    Conflicting,
    Unavailable,
    Tampered,
    Retired,
}

impl RelationshipResult {
    pub const ALL: [Self; 12] = [
        Self::MemberConfirmed,
        Self::NonMemberConfirmed,
        Self::Denied,
        Self::Unresolved,
        Self::NotCaughtUp,
        Self::Stale,
        Self::ReorgPending,
        Self::Partial,
        Self::Conflicting,
        Self::Unavailable,
        Self::Tampered,
        Self::Retired,
    ];

    #[must_use]
    pub const fn narrows_authority(self) -> bool {
        matches!(self, Self::MemberConfirmed)
    }
}

#[must_use]
pub const fn replacement_is_admissible(
    predecessor: FactLifecycleState,
    invalidation_committed: bool,
    distinct_generation: bool,
    replacement_complete_fresh_finalized: bool,
) -> bool {
    invalidation_committed
        && distinct_generation
        && replacement_complete_fresh_finalized
        && matches!(predecessor, FactLifecycleState::Reorged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::is_positive_eligible;

    #[test]
    fn positive_fact_eligibility_is_exactly_finalized_and_ready() {
        let positives = FactLifecycleState::ALL
            .into_iter()
            .flat_map(|lifecycle| {
                FactReadinessState::ALL
                    .into_iter()
                    .map(move |readiness| (lifecycle, readiness))
            })
            .filter(|(lifecycle, readiness)| is_positive_eligible(*lifecycle, *readiness))
            .collect::<Vec<_>>();
        assert_eq!(
            positives,
            vec![(FactLifecycleState::Finalized, FactReadinessState::Ready)]
        );
    }

    #[test]
    fn relationship_positive_is_member_confirmed_only() {
        assert_eq!(
            RelationshipResult::ALL
                .into_iter()
                .filter(|result| result.narrows_authority())
                .collect::<Vec<_>>(),
            vec![RelationshipResult::MemberConfirmed]
        );
        assert!(!FactQueryOutcome::AbsentConfirmed.is_positive());
    }

    #[test]
    fn replacement_admissibility_exhausts_every_predecessor_and_guard_vector() {
        for predecessor in FactLifecycleState::ALL {
            for guard_vector in 0_u8..8 {
                let invalidation_committed = guard_vector & 0b001 != 0;
                let distinct_generation = guard_vector & 0b010 != 0;
                let replacement_complete_fresh_finalized = guard_vector & 0b100 != 0;
                let expected = predecessor == FactLifecycleState::Reorged && guard_vector == 0b111;

                assert_eq!(
                    replacement_is_admissible(
                        predecessor,
                        invalidation_committed,
                        distinct_generation,
                        replacement_complete_fresh_finalized,
                    ),
                    expected,
                    "unexpected FTR-010 result for {predecessor:?} guard vector {guard_vector:03b}",
                );
            }
        }
    }
}
