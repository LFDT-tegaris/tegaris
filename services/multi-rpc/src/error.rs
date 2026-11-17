use thiserror::Error;

// The authenticated twelve-row table includes conditions whose only current
// consumer is the exhaustive table proof; retaining those rows is mandatory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RpcCondition {
    ProfileMismatch,
    Denied,
    NoEligibleProvider,
    RateLimited,
    ReadUnavailable,
    Divergent,
    InvalidResponse,
    TrustDrift,
    WriteAmbiguity,
    ProhibitedWriteReplay,
    Partial,
    Reorg,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConditionMapping {
    pub(crate) locator: &'static str,
    pub(crate) code: &'static str,
    pub(crate) truth: &'static str,
    pub(crate) retryable: bool,
}

impl RpcCondition {
    pub(crate) const ALL: [Self; 12] = [
        Self::ProfileMismatch,
        Self::Denied,
        Self::NoEligibleProvider,
        Self::RateLimited,
        Self::ReadUnavailable,
        Self::Divergent,
        Self::InvalidResponse,
        Self::TrustDrift,
        Self::WriteAmbiguity,
        Self::ProhibitedWriteReplay,
        Self::Partial,
        Self::Reorg,
    ];

    pub(crate) const fn mapping(self) -> ConditionMapping {
        match self {
            Self::ProfileMismatch => mapping("RPC-COND-000", "PC-RUNTIME-3008", "FAILED", false),
            Self::Denied => mapping("RPC-COND-001", "PC-RUNTIME-3001", "DENIED", false),
            Self::NoEligibleProvider => {
                mapping("RPC-COND-002", "PC-RUNTIME-3002", "UNAVAILABLE", false)
            }
            Self::RateLimited => mapping("RPC-COND-003", "PC-OPS-9001", "RETRY_ELIGIBLE", true),
            Self::ReadUnavailable => {
                mapping("RPC-COND-004", "PC-RUNTIME-3003", "UNAVAILABLE", true)
            }
            Self::Divergent => mapping("RPC-COND-005", "PC-RUNTIME-3011", "CONFLICTING", false),
            Self::InvalidResponse => mapping("RPC-COND-006", "PC-RUNTIME-3009", "FAILED", false),
            Self::TrustDrift => mapping("RPC-COND-007", "PC-RUNTIME-3008", "FAILED", false),
            Self::WriteAmbiguity => {
                mapping("RPC-COND-008", "PC-RUNTIME-3005", "WRITE_AMBIGUITY", false)
            }
            Self::ProhibitedWriteReplay => {
                mapping("RPC-COND-009", "PC-RUNTIME-3007", "FAILED", false)
            }
            Self::Partial => mapping("RPC-COND-010", "PC-OPS-9004", "PARTIAL", false),
            Self::Reorg => mapping("RPC-COND-011", "PC-FACT-4003", "REORG", false),
        }
    }
}

const fn mapping(
    locator: &'static str,
    code: &'static str,
    truth: &'static str,
    retryable: bool,
) -> ConditionMapping {
    ConditionMapping {
        locator,
        code,
        truth,
        retryable,
    }
}

#[derive(Debug, Error)]
pub enum MultiRpcError {
    #[error("provider contract rejected: {0}")]
    Contract(&'static str),
    #[error("{code}: {truth}")]
    Condition {
        code: &'static str,
        truth: &'static str,
        retryable: bool,
    },
    #[error("durable journal rejected: {0}")]
    Journal(#[from] JournalError),
}

impl MultiRpcError {
    pub(crate) fn condition(condition: RpcCondition) -> Self {
        debug_assert_eq!(RpcCondition::ALL.len(), 12);
        let mapping = condition.mapping();
        Self::Condition {
            code: mapping.code,
            truth: mapping.truth,
            retryable: mapping.retryable,
        }
    }
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("journal I/O failed")]
    Io(#[from] std::io::Error),
    #[error("journal encoding failed")]
    Encoding(#[from] serde_json::Error),
    #[error("journal frame is truncated")]
    Truncated,
    #[error("journal frame exceeds the fixed maximum")]
    Oversized,
    #[error("journal domain or version is unknown")]
    UnknownVersion,
    #[error("journal sequence or digest chain is invalid")]
    Integrity,
    #[error("governed command already exists")]
    DuplicateCommand,
    #[error("governed command transition is forbidden")]
    ForbiddenTransition,
    #[error("governed command identity does not match")]
    IdentityMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn condition_table_is_exact_and_exhaustive() {
        let mappings = RpcCondition::ALL.map(RpcCondition::mapping);
        assert_eq!(mappings.len(), 12);
        assert_eq!(mappings[0].locator, "RPC-COND-000");
        assert_eq!(mappings[11].locator, "RPC-COND-011");
        assert_eq!(mappings[3].code, "PC-OPS-9001");
        assert!(mappings[3].retryable);
        assert_eq!(mappings[4].code, "PC-RUNTIME-3003");
        assert!(mappings[4].retryable);
        assert!(
            mappings
                .iter()
                .enumerate()
                .all(|(index, value)| value.locator == format!("RPC-COND-{index:03}"))
        );
        assert_eq!(
            mappings
                .iter()
                .map(|value| value.locator)
                .collect::<BTreeSet<_>>()
                .len(),
            12
        );
        assert!(
            mappings
                .iter()
                .filter(|value| value.retryable)
                .all(|value| matches!(value.locator, "RPC-COND-003" | "RPC-COND-004"))
        );
    }
}
