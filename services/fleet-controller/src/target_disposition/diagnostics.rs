//! Bounded, per-installation diagnostic deduplication. It never changes source
//! validation, retry scheduling, signed custody or database effects.
use super::*;
use pc_runtime_types::target_disposition::TargetDispositionSource;
use std::collections::BTreeMap;

#[derive(Debug, Eq, PartialEq)]
struct Failure {
    class: &'static str,
    sqlstate: String,
    reason: &'static str,
    work: String,
    expiry: Option<u64>,
}

#[derive(Default)]
pub(super) struct SourceDiagnostics {
    previous: BTreeMap<(String, &'static str), Failure>,
}
impl SourceDiagnostics {
    fn changed(&mut self, target: &str, stage: &'static str, failure: Failure) -> bool {
        let key = (target.to_owned(), stage);
        if self.previous.get(&key) == Some(&failure) {
            return false;
        }
        if self.previous.len() >= 1024 && !self.previous.contains_key(&key) {
            self.previous.pop_first();
        }
        self.previous.insert(key, failure);
        true
    }
    pub(super) fn clear(&mut self, target: &str) {
        self.previous.retain(|(id, _), _| id != target);
    }
}

fn source_reason(message: &str) -> &'static str {
    match message {
        "TARGET-DISPOSITION-SOURCE-CONTEXT" => "source_context_or_expiry",
        "TARGET-DISPOSITION-WORKLOAD-AMBIGUOUS" => "workload_ambiguous",
        "TARGET-DISPOSITION-WORKLOAD-WITHDRAWN" => "workload_withdrawn",
        "TARGET-DISPOSITION-WORKLOAD-CREDENTIAL" => "workload_credential",
        "TARGET-DISPOSITION-SOURCE-OBSERVATION" => "original_observation",
        "TARGET-DISPOSITION-SOURCE-KIND" => "source_kind",
        "TARGET-DISPOSITION-SOURCE-RESTRICTED" => "source_restricted",
        "TARGET-DISPOSITION-SOURCE-WITHDRAWN" => "source_withdrawn",
        "TARGET-DISPOSITION-IDENTITY-EXPIRY" => "identity_expiry",
        "PC-DATA-6007" => "owner_busy",
        _ => "unavailable",
    }
}

impl TargetDispositionStore {
    pub(super) fn source_failure(
        &self,
        target: &str,
        source: &TargetDispositionSource,
        proof: &serde_json::Value,
        stage: &'static str,
        error: &sqlx::Error,
    ) {
        let (sqlstate, reason) = match error.as_database_error() {
            Some(db) => (
                db.code()
                    .filter(|code| safe_sqlstate(code))
                    .map_or_else(|| "none".to_owned(), |code| code.into_owned()),
                source_reason(db.message()),
            ),
            None => ("none".to_owned(), "unavailable"),
        };
        let expiry = proof
            .get("capsuleValidUntilNs")
            .and_then(|value| value.as_str())
            .and_then(|value| value.parse::<u64>().ok());
        let failure = Failure {
            class: database_error_class(error),
            sqlstate,
            reason,
            work: source.original_work_id.clone(),
            expiry,
        };
        let class = failure.class;
        let sqlstate = failure.sqlstate.clone();
        let changed = self
            .source_diagnostics
            .lock()
            .map(|mut state| state.changed(target, stage, failure))
            .unwrap_or(false);
        if changed {
            eprintln!(
                "{}",
                serde_json::json!({"level":"warn","event":"target_disposition_source_unavailable",
                "boundary":"target_disposition_sources","stage":stage,"target_id":target,
                "work_id":source.original_work_id,"capsule_id":source.runtime_configuration_generation_id,
                "capsule_valid_until_ns":expiry,"error_class":class,"sqlstate":sqlstate,"reason":reason,
                "retry_disposition":"WAIT_FOR_CURRENT_SOURCE_OR_FRESH_GOVERNED_CUSTODY"})
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn failure(work: &str) -> Failure {
        Failure {
            class: "database",
            sqlstate: "P0001".into(),
            reason: "source_context_or_expiry",
            work: work.into(),
            expiry: Some(100),
        }
    }
    #[test]
    fn source_diagnostics_keep_changes_and_recovery_without_repeated_noise() {
        let mut state = SourceDiagnostics::default();
        assert!(state.changed("target", "current_source_lock", failure("work1")));
        assert!(!state.changed("target", "current_source_lock", failure("work1")));
        assert!(state.changed("target", "current_source_lock", failure("work2")));
        state.clear("target");
        assert!(state.changed("target", "current_source_lock", failure("work2")));
    }
    #[test]
    fn source_diagnostics_are_bounded() {
        let mut state = SourceDiagnostics::default();
        for n in 0..1100 {
            state.changed(&n.to_string(), "current_source_lock", failure("work"));
        }
        assert_eq!(state.previous.len(), 1024);
    }
    #[test]
    fn source_diagnostics_reject_driver_message_prefixes_with_bound_inputs() {
        assert_eq!(
            source_reason("TARGET-DISPOSITION-SOURCE-CONTEXT"),
            "source_context_or_expiry"
        );
        for text in [
            "TARGET-DISPOSITION-secret-signed-input",
            "TARGET-DISPOSITION-SOURCE-CONTEXT secret",
            "secret-driver-query",
        ] {
            assert_eq!(source_reason(text), "unavailable");
        }
    }
}
