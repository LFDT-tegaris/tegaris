use serde::{Deserialize, Serialize};

use crate::{RuntimeError, RuntimeResult};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfiguration {
    pub evidence_critical_watermark: u8,
    pub evidence_export_retry_limit: u16,
    pub evidence_high_watermark: u8,
    pub evidence_local_spool_capacity: u64,
    pub provider_health_observation_window_ms: u64,
    pub provider_quarantine_on_fingerprint_drift: bool,
    pub provider_read_retry_limit: u8,
    pub provider_write_retry_after_attempt_start: u8,
    pub runtime_capsule_retained_active_generations: u8,
    pub runtime_decision_deadline_ms: u64,
    pub runtime_fail_closed_on_unknown_version: bool,
    pub runtime_local_artifact_capacity: u64,
    pub runtime_staged_generation_limit: u8,
}

impl RuntimeConfiguration {
    pub fn validate(&self) -> RuntimeResult<()> {
        if !(50..=98).contains(&self.evidence_high_watermark)
            || !(51..=99).contains(&self.evidence_critical_watermark)
            || self.evidence_high_watermark >= self.evidence_critical_watermark
            || self.evidence_export_retry_limit > 1000
            || self.evidence_local_spool_capacity == 0
            || !(5_000..=3_600_000).contains(&self.provider_health_observation_window_ms)
            || !self.provider_quarantine_on_fingerprint_drift
            || self.provider_read_retry_limit > 3
            || self.provider_write_retry_after_attempt_start != 0
            || !(2..=10).contains(&self.runtime_capsule_retained_active_generations)
            || self.runtime_decision_deadline_ms == 0
            || !self.runtime_fail_closed_on_unknown_version
            || self.runtime_local_artifact_capacity == 0
            || !(1..=10).contains(&self.runtime_staged_generation_limit)
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration() -> RuntimeConfiguration {
        RuntimeConfiguration {
            evidence_critical_watermark: 95,
            evidence_export_retry_limit: 20,
            evidence_high_watermark: 80,
            evidence_local_spool_capacity: 1024,
            provider_health_observation_window_ms: 60_000,
            provider_quarantine_on_fingerprint_drift: true,
            provider_read_retry_limit: 2,
            provider_write_retry_after_attempt_start: 0,
            runtime_capsule_retained_active_generations: 2,
            runtime_decision_deadline_ms: 20,
            runtime_fail_closed_on_unknown_version: true,
            runtime_local_artifact_capacity: 4096,
            runtime_staged_generation_limit: 2,
        }
    }

    #[test]
    fn exact_cross_constraints_are_fail_closed() {
        configuration().validate().unwrap();
        let mut invalid = configuration();
        invalid.evidence_high_watermark = invalid.evidence_critical_watermark;
        assert_eq!(invalid.validate(), Err(RuntimeError::InvalidInput));
        let mut retry = configuration();
        retry.provider_write_retry_after_attempt_start = 1;
        assert_eq!(retry.validate(), Err(RuntimeError::InvalidInput));
        let mut unknown = configuration();
        unknown.runtime_fail_closed_on_unknown_version = false;
        assert_eq!(unknown.validate(), Err(RuntimeError::InvalidInput));
    }

    #[test]
    fn unknown_json_field_is_rejected() {
        let mut value = serde_json::to_value(configuration()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), true.into());
        assert!(serde_json::from_value::<RuntimeConfiguration>(value).is_err());
    }
}
