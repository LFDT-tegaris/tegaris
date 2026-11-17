use serde::{Deserialize, Serialize};

use crate::Digest;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TargetState {
    Offline,
    Discovered,
    Staging,
    Prepared,
    XdsPending,
    XdsAckedNotActive,
    Activating,
    ActiveMatched,
    ActiveMismatch,
    Nacked,
    Failed,
    RollingBack,
    RolledBack,
    Quarantined,
    Incompatible,
}

#[cfg(test)]
const ALL_TARGET_STATES: [TargetState; 15] = [
    TargetState::Offline,
    TargetState::Discovered,
    TargetState::Staging,
    TargetState::Prepared,
    TargetState::XdsPending,
    TargetState::XdsAckedNotActive,
    TargetState::Activating,
    TargetState::ActiveMatched,
    TargetState::ActiveMismatch,
    TargetState::Nacked,
    TargetState::Failed,
    TargetState::RollingBack,
    TargetState::RolledBack,
    TargetState::Quarantined,
    TargetState::Incompatible,
];

impl TargetState {
    /// Exact transitions from the authenticated generation state machine.
    #[must_use]
    pub const fn allows_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Offline, Self::Discovered)
                | (Self::Discovered, Self::Staging | Self::Quarantined)
                | (
                    Self::Staging,
                    Self::Prepared | Self::Failed | Self::Quarantined
                )
                | (
                    Self::Prepared,
                    Self::XdsPending | Self::Activating | Self::Failed
                )
                | (
                    Self::XdsPending,
                    Self::XdsAckedNotActive | Self::Nacked | Self::Failed
                )
                | (
                    Self::XdsAckedNotActive,
                    Self::Activating | Self::ActiveMismatch | Self::Failed
                )
                | (
                    Self::Activating,
                    Self::ActiveMatched | Self::ActiveMismatch | Self::Failed
                )
                | (
                    Self::ActiveMatched,
                    Self::Staging | Self::ActiveMismatch | Self::Offline | Self::RollingBack
                )
                | (
                    Self::ActiveMismatch | Self::Nacked | Self::Failed,
                    Self::Staging | Self::RollingBack | Self::Quarantined
                )
                | (
                    Self::RollingBack,
                    Self::RolledBack | Self::Failed | Self::Quarantined
                )
                | (Self::RolledBack, Self::Staging | Self::Offline)
                | (Self::Quarantined, Self::Discovered)
                | (Self::Incompatible, Self::Staging | Self::Quarantined)
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DesiredGeneration {
    pub occurrence_id: String,
    pub target_id: String,
    pub capsule_digest: Digest,
    pub xds_snapshot_digest: Digest,
    pub expected_previous_generation_digest: Option<Digest>,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreparedGeneration {
    pub desired: DesiredGeneration,
    pub artifact_set_digest: Digest,
    pub prepared_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivationToken {
    pub token_id: String,
    pub occurrence_id: String,
    pub target_id: String,
    pub capsule_digest: Digest,
    pub xds_version_digest: Digest,
    pub expected_previous_generation_digest: Option<Digest>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivationReceipt {
    pub receipt_id: String,
    pub occurrence_id: String,
    pub target_id: String,
    pub active_generation_digest: Digest,
    pub xds_version_digest: Digest,
    pub previous_generation_digest: Option<Digest>,
    pub journal_sequence: u64,
    pub activated_at_ms: u64,
    pub state: TargetState,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected(state: TargetState) -> &'static [TargetState] {
        match state {
            TargetState::Offline => &[TargetState::Discovered],
            TargetState::Discovered => &[TargetState::Staging, TargetState::Quarantined],
            TargetState::Staging => &[
                TargetState::Prepared,
                TargetState::Failed,
                TargetState::Quarantined,
            ],
            TargetState::Prepared => &[
                TargetState::XdsPending,
                TargetState::Activating,
                TargetState::Failed,
            ],
            TargetState::XdsPending => &[
                TargetState::XdsAckedNotActive,
                TargetState::Nacked,
                TargetState::Failed,
            ],
            TargetState::XdsAckedNotActive => &[
                TargetState::Activating,
                TargetState::ActiveMismatch,
                TargetState::Failed,
            ],
            TargetState::Activating => &[
                TargetState::ActiveMatched,
                TargetState::ActiveMismatch,
                TargetState::Failed,
            ],
            TargetState::ActiveMatched => &[
                TargetState::Staging,
                TargetState::ActiveMismatch,
                TargetState::Offline,
                TargetState::RollingBack,
            ],
            TargetState::ActiveMismatch | TargetState::Nacked | TargetState::Failed => &[
                TargetState::Staging,
                TargetState::RollingBack,
                TargetState::Quarantined,
            ],
            TargetState::RollingBack => &[
                TargetState::RolledBack,
                TargetState::Failed,
                TargetState::Quarantined,
            ],
            TargetState::RolledBack => &[TargetState::Staging, TargetState::Offline],
            TargetState::Quarantined => &[TargetState::Discovered],
            TargetState::Incompatible => &[TargetState::Staging, TargetState::Quarantined],
        }
    }

    #[test]
    fn exact_c17_transition_matrix_accepts_only_registered_edges() {
        for current in ALL_TARGET_STATES {
            for next in ALL_TARGET_STATES {
                assert_eq!(
                    current.allows_transition_to(next),
                    expected(current).contains(&next),
                    "unexpected transition {current:?} -> {next:?}"
                );
            }
        }
    }

    #[test]
    fn nacked_and_quarantined_states_cannot_transition_to_active_matched() {
        assert!(!TargetState::Nacked.allows_transition_to(TargetState::ActiveMatched));
        assert!(!TargetState::Quarantined.allows_transition_to(TargetState::ActiveMatched));
    }

    macro_rules! c04_state_case {
        ($name:ident, $state:expr) => {
            #[test]
            fn $name() {
                for next in ALL_TARGET_STATES {
                    assert_eq!(
                        $state.allows_transition_to(next),
                        expected($state).contains(&next),
                        "unexpected transition {:?} -> {next:?}",
                        $state
                    );
                }
            }
        };
    }

    c04_state_case!(c04_state_offline, TargetState::Offline);
    c04_state_case!(c04_state_discovered, TargetState::Discovered);
    c04_state_case!(c04_state_staging, TargetState::Staging);
    c04_state_case!(c04_state_prepared, TargetState::Prepared);
    c04_state_case!(c04_state_xds_pending, TargetState::XdsPending);
    c04_state_case!(
        c04_state_xds_acked_not_active,
        TargetState::XdsAckedNotActive
    );
    c04_state_case!(c04_state_activating, TargetState::Activating);
    c04_state_case!(c04_state_active_matched, TargetState::ActiveMatched);
    c04_state_case!(c04_state_active_mismatch, TargetState::ActiveMismatch);
    c04_state_case!(c04_state_nacked, TargetState::Nacked);
    c04_state_case!(c04_state_failed, TargetState::Failed);
    c04_state_case!(c04_state_rolling_back, TargetState::RollingBack);
    c04_state_case!(c04_state_rolled_back, TargetState::RolledBack);
    c04_state_case!(c04_state_quarantined, TargetState::Quarantined);
    c04_state_case!(c04_state_incompatible, TargetState::Incompatible);
}
