use thiserror::Error;

pub type RuntimeResult<T> = Result<T, RuntimeError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RuntimeError {
    #[error("PC-RUNTIME-3001 unavailable or invalid runtime input")]
    InvalidInput,
    #[error("PC-RUNTIME-3002 unknown or stale generation")]
    GenerationMismatch,
    #[error("PC-RUNTIME-3003 authorization denied")]
    Denied,
    #[error("PC-RUNTIME-3004 authorization envelope invalid")]
    InvalidAuthorization,
    #[error("PC-RUNTIME-3005 authorization envelope expired")]
    ExpiredAuthorization,
    #[error("PC-RUNTIME-3006 authorization replay")]
    Replay,
    #[error("PC-RUNTIME-3007 bounded replay store unavailable")]
    ReplayCapacity,
    #[error("PC-RUNTIME-3008 evidence admission unavailable")]
    EvidenceCapacity,
    #[error("PC-RUNTIME-3009 provider response withheld")]
    ResponseWithheld,
    #[error("PC-RUNTIME-3010 protected runtime unavailable")]
    RuntimeUnavailable,
    #[error("PC-RUNTIME-3011 conflicting route or provider")]
    ConflictingRoute,
    #[error("PC-RUNTIME-3012 write outcome ambiguous")]
    WriteAmbiguity,
    #[error("PC-RUNTIME-3013 invalid target transition")]
    InvalidTransition,
    #[error("PC-RUNTIME-3014 target identity rejected")]
    TargetIdentity,
    #[error("PC-RUNTIME-3015 exact xDS version quarantined")]
    XdsQuarantined,
    #[error("PC-RUNTIME-3016 invalid SHA-256 digest")]
    InvalidDigest,
    #[error("PC-RUNTIME-3017 canonical encoding failure")]
    CanonicalEncoding,
    #[error("PC-RUNTIME-3018 finite budget exhausted")]
    BudgetExhausted,
}

impl RuntimeError {
    /// Version-one local diagnostic identity, retained in the existing local
    /// journals and PDS/Broker compatibility objects. These numeric assignments
    /// are not public registry entries. Public adapters use public_error().
    #[must_use]
    pub const fn pc_code(&self) -> &'static str {
        match self {
            Self::InvalidInput => "PC-RUNTIME-3001",
            Self::GenerationMismatch => "PC-RUNTIME-3002",
            Self::Denied => "PC-RUNTIME-3003",
            Self::InvalidAuthorization => "PC-RUNTIME-3004",
            Self::ExpiredAuthorization => "PC-RUNTIME-3005",
            Self::Replay => "PC-RUNTIME-3006",
            Self::ReplayCapacity => "PC-RUNTIME-3007",
            Self::EvidenceCapacity => "PC-RUNTIME-3008",
            Self::ResponseWithheld => "PC-RUNTIME-3009",
            Self::RuntimeUnavailable => "PC-RUNTIME-3010",
            Self::ConflictingRoute => "PC-RUNTIME-3011",
            Self::WriteAmbiguity => "PC-RUNTIME-3012",
            Self::InvalidTransition => "PC-RUNTIME-3013",
            Self::TargetIdentity => "PC-RUNTIME-3014",
            Self::XdsQuarantined => "PC-RUNTIME-3015",
            Self::InvalidDigest => "PC-RUNTIME-3016",
            Self::CanonicalEncoding => "PC-RUNTIME-3017",
            Self::BudgetExhausted => "PC-RUNTIME-3018",
        }
    }

    /// Decode only a code emitted by the version-one local PDS/Broker owner.
    /// This must never interpret an upstream/provider or public-registry code.
    pub fn from_local_code(code: &str) -> Option<Self> {
        [
            Self::InvalidInput,
            Self::GenerationMismatch,
            Self::Denied,
            Self::InvalidAuthorization,
            Self::ExpiredAuthorization,
            Self::Replay,
            Self::ReplayCapacity,
            Self::EvidenceCapacity,
            Self::ResponseWithheld,
            Self::RuntimeUnavailable,
            Self::ConflictingRoute,
            Self::WriteAmbiguity,
            Self::InvalidTransition,
            Self::TargetIdentity,
            Self::XdsQuarantined,
            Self::InvalidDigest,
            Self::CanonicalEncoding,
            Self::BudgetExhausted,
        ]
        .into_iter()
        .find(|error| error.pc_code() == code)
    }

    /// the public error registry. A local owner failure never implies
    /// that a provider was contacted, or creates provider retry eligibility.
    pub const fn public_error(&self) -> PublicRuntimeError {
        match self {
            Self::Denied
            | Self::InvalidAuthorization
            | Self::ExpiredAuthorization
            | Self::TargetIdentity => {
                PublicRuntimeError::new("PC-RUNTIME-3001", -32001, 403, "DENIED", "Request denied")
            }
            Self::GenerationMismatch | Self::XdsQuarantined => PublicRuntimeError::new(
                "PC-RUNTIME-3004",
                -32004,
                412,
                "STALE",
                "Runtime generation is stale",
            ),
            Self::WriteAmbiguity => PublicRuntimeError::new(
                "PC-RUNTIME-3005",
                -32005,
                409,
                "WRITE_AMBIGUITY",
                "Write outcome is ambiguous",
            ),
            Self::BudgetExhausted => PublicRuntimeError::new(
                "PC-RUNTIME-3006",
                -32006,
                429,
                "FAILED",
                "Request budget exceeded",
            ),
            Self::Replay => PublicRuntimeError::new(
                "PC-RUNTIME-3007",
                -32007,
                409,
                "FAILED",
                "Request replay rejected",
            ),
            Self::InvalidDigest | Self::CanonicalEncoding => PublicRuntimeError::new(
                "PC-RUNTIME-3008",
                -32008,
                409,
                "FAILED",
                "Runtime profile mismatch",
            ),
            Self::ResponseWithheld => PublicRuntimeError::new(
                "PC-RUNTIME-3009",
                -32009,
                502,
                "FAILED",
                "Response integrity invalid",
            ),
            Self::EvidenceCapacity => PublicRuntimeError::new(
                "PC-RUNTIME-3010",
                -32010,
                503,
                "FAILED",
                "Evidence admission failed",
            ),
            Self::ConflictingRoute => PublicRuntimeError::new(
                "PC-RUNTIME-3011",
                -32011,
                409,
                "CONFLICTING",
                "Route is ambiguous",
            ),
            Self::InvalidInput => {
                PublicRuntimeError::new("PC-DATA-6002", -32600, 400, "FAILED", "Invalid Request")
            }
            Self::ReplayCapacity | Self::RuntimeUnavailable | Self::InvalidTransition => {
                PublicRuntimeError::new("PC-DATA-6005", -32603, 500, "FAILED", "Internal error")
            }
        }
    }
}

/// Safe closed projection. No detail string, upstream error or endpoint can be
/// copied into it. The caller supplies only separately validated correlation.
pub struct PublicRuntimeError {
    pub pc_code: &'static str,
    pub json_rpc_code: i32,
    pub http_status: i32,
    pub truth_state: &'static str,
    pub message: &'static str,
}
impl PublicRuntimeError {
    const fn new(
        pc_code: &'static str,
        json_rpc_code: i32,
        http_status: i32,
        truth_state: &'static str,
        message: &'static str,
    ) -> Self {
        Self {
            pc_code,
            json_rpc_code,
            http_status,
            truth_state,
            message,
        }
    }
}
