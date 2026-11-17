//! Local request correlation shared by transport, captured state and evidence.
//! It confers no authority and cannot be deserialized from workload metadata.

#[derive(Clone)]
pub struct RequestTraceId(String);
impl RequestTraceId {
    pub(crate) fn new() -> Self {
        Self(uuid::Uuid::now_v7().to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub(crate) fn valid(value: &str) -> bool {
        uuid::Uuid::parse_str(value)
            .is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == value)
    }
}
