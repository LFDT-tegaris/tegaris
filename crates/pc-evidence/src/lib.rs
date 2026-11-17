#![forbid(unsafe_code)]

//! Evidence wire boundary reused by Fact Bridge without redefining signed semantics.

pub use pc_contracts::generated::openpc::evidence::v1 as wire;

pub const EVIDENCE_EXPORT_OPERATIONS: [&str; 3] =
    ["StartExport", "GetExport", "StreamExportReceipts"];

pub const RAW_PROTECTED_PAYLOAD_CAPTURE: &str = "FORBIDDEN";
pub const AUTHORITY_EFFECT: &str = "NONE_EVIDENCE_NEVER_GRANTS_PERMISSION";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_boundary_is_closed_and_non_authoritative() {
        assert_eq!(EVIDENCE_EXPORT_OPERATIONS.len(), 3);
        assert_eq!(RAW_PROTECTED_PAYLOAD_CAPTURE, "FORBIDDEN");
        assert_eq!(AUTHORITY_EFFECT, "NONE_EVIDENCE_NEVER_GRANTS_PERMISSION");
    }
}
