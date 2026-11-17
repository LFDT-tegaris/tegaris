#![forbid(unsafe_code)]

//! Participant, authority-envelope, assignment, delegation, and wallet contracts.

mod assignment;
mod delegation;
mod envelope;
mod participant;
mod wallet;
mod wire;

pub use assignment::{Assignment, AssignmentContractType, AssignmentStatus};
pub use delegation::{Delegation, DelegationContractType, DelegationStatus};
pub use envelope::{AuthorityEnvelope, AuthorityEnvelopeContractType, AuthorityEnvelopeStatus};
pub use participant::{Participant, ParticipantContractType, ParticipantStatus};
pub use wallet::{WalletBinding, WalletBindingContractType, WalletBindingStatus};
pub use wire::EntityMetadata;

/// Number of participant-owned contract types in the frozen I02 catalog.
pub const PARTICIPANT_CONTRACT_TYPE_COUNT: usize = 5;

/// Number of participant-owned states in the frozen I02 catalog.
pub const PARTICIPANT_STATE_COUNT: usize = 26;
