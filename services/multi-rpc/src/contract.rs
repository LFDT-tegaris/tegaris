use pc_provider_api::{
    ProviderProfileV1, decode_provider_profile_pc_cbor, validate_provider_profile,
};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSettingsContract {
    pub health_observation_window_seconds: u16,
    pub quarantine_on_fingerprint_drift: bool,
    pub read_retry_limit: Option<u8>,
    pub write_retry_after_attempt_start: u8,
}

pub fn validate_provider_settings(value: &ProviderSettingsContract) -> Result<(), &'static str> {
    if !(5..=3600).contains(&value.health_observation_window_seconds)
        || !value.quarantine_on_fingerprint_drift
        || !matches!(value.read_retry_limit, Some(0..=3))
        || value.write_retry_after_attempt_start != 0
    {
        Err("frozen provider settings")
    } else {
        Ok(())
    }
}

pub fn qualify_provider_profile(
    profile_cbor: &[u8],
    expected_artifact_digest: &str,
) -> Result<ProviderProfileV1, crate::MultiRpcError> {
    let profile = decode_provider_profile_pc_cbor(profile_cbor)
        .map_err(|_| crate::MultiRpcError::Contract("provider profile PC-CBOR"))?;
    validate_provider_profile(&profile)
        .map_err(|_| crate::MultiRpcError::Contract("provider profile qualification"))?;
    let actual = Sha256::digest(profile_cbor);
    let actual = actual
        .iter()
        .fold(String::with_capacity(71), |mut value, byte| {
            use std::fmt::Write as _;
            if value.is_empty() {
                value.push_str("sha256:");
            }
            write!(value, "{byte:02x}").expect("writing to a string cannot fail");
            value
        });
    if actual != expected_artifact_digest {
        return Err(crate::MultiRpcError::Contract("provider profile digest"));
    }
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_provider_settings_are_closed() {
        let valid = ProviderSettingsContract {
            health_observation_window_seconds: 60,
            quarantine_on_fingerprint_drift: true,
            read_retry_limit: Some(3),
            write_retry_after_attempt_start: 0,
        };
        assert!(validate_provider_settings(&valid).is_ok());

        let mutations = [
            ProviderSettingsContract {
                read_retry_limit: None,
                ..valid.clone()
            },
            ProviderSettingsContract {
                health_observation_window_seconds: 4,
                ..valid.clone()
            },
            ProviderSettingsContract {
                quarantine_on_fingerprint_drift: false,
                ..valid.clone()
            },
            ProviderSettingsContract {
                read_retry_limit: Some(4),
                ..valid.clone()
            },
            ProviderSettingsContract {
                write_retry_after_attempt_start: 1,
                ..valid
            },
        ];
        for mutation in mutations {
            assert!(validate_provider_settings(&mutation).is_err());
        }
    }
}
