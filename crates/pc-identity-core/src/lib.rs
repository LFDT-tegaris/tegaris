#![forbid(unsafe_code)]

//! Identity-owned wire contracts and state machines for OpenPC R1.

mod credential;
mod mfa;
mod oidc;
mod principal;
mod recovery;
mod revocation;
mod session;
mod wire;

pub use credential::{
    WorkloadCredential, WorkloadCredentialContractType, WorkloadCredentialStatus,
};
pub use mfa::{MfaEvidence, MfaEvidenceContractType, MfaEvidenceStatus};
pub use oidc::{OidcAuthorization, OidcAuthorizationStatus};
pub use principal::{Principal, PrincipalAssurance, PrincipalContractType, PrincipalStatus};
pub use recovery::{RecoveryCase, RecoveryCaseContractType, RecoveryCaseStatus};
pub use revocation::{RevocationRecord, RevocationRecordContractType, RevocationRecordStatus};
pub use session::{SESSION_COOKIE_PROFILE, Session, SessionContractType, SessionStatus};
pub use wire::EntityMetadata;

/// Number of identity-owned contract types in the frozen I02 catalog.
pub const IDENTITY_CONTRACT_TYPE_COUNT: usize = 7;

/// Number of identity-owned states in the frozen I02 catalog.
pub const IDENTITY_STATE_COUNT: usize = 32;
