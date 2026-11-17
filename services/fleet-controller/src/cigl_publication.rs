//! CIGL source provenance at the publication owner. A configuration document
//! cannot fabricate the immutable public approval/receipt-backed source row.
use pc_policy_core::{
    cigl::settings::{CiglSettingsDefinition, ConfiguredCiglSettings},
    invocation::{ConfigurationArtifactKind, decode_active_invocation_configuration},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use sqlx::{Postgres, Row, Transaction};

pub mod profile_activation;
pub mod profile_invalidation;
pub mod profile_publication;
pub mod profile_store;
pub mod reviewed_profile;

#[cfg(test)]
#[path = "cigl_publication_tests.rs"]
mod tests;

#[derive(Clone)]
pub struct VerifiedCiglSettingsSources {
    configuration_digest: Digest,
}
impl VerifiedCiglSettingsSources {
    pub fn require_configuration(&self, configuration_digest: &Digest) -> RuntimeResult<()> {
        if &self.configuration_digest != configuration_digest {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }
}

/// The caller retains its current configuration/Participant authorization and
/// sets the real worker transaction's RLS scope. No readiness flags are accepted.
pub async fn verify_settings_sources(
    transaction: &mut Transaction<'_, Postgres>,
    participant_id: &str,
    privacy_domain_id: &str,
    configuration_bytes: &[u8],
    configuration_digest: &Digest,
) -> RuntimeResult<VerifiedCiglSettingsSources> {
    let configuration =
        decode_active_invocation_configuration(configuration_bytes, configuration_digest)?;
    let mut scopes = std::collections::BTreeSet::new();
    for advertised in configuration
        .resource_artifacts
        .iter()
        .filter(|a| a.artifact_kind == ConfigurationArtifactKind::CiglSettings)
    {
        let requested = ConfiguredCiglSettings::from_cbor(&advertised.payload_cbor)?;
        if !scopes.insert(pc_runtime_types::canonical_bytes(
            &requested.definition.scope,
        )?) || requested.settings_id != advertised.artifact_id
            || requested.participant_id != participant_id
            || requested.privacy_domain_id != privacy_domain_id
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let row = sqlx::query("select definition,definition_digest,publication_operation_id::text,publication_authority_digest
            from control.cigl_settings where cigl_settings_id=$1::text::uuid and participant_id=$2::text::uuid
             and privacy_domain_id=$3::text::uuid")
            .bind(&advertised.artifact_id).bind(participant_id).bind(privacy_domain_id)
            .fetch_optional(&mut **transaction).await.map_err(|_| RuntimeError::RuntimeUnavailable)?
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let text = |key| {
            row.try_get::<String, _>(key)
                .map_err(|_| RuntimeError::InvalidInput)
        };
        let digest = |key| {
            Digest::parse(
                text(key)?
                    .strip_prefix("sha256:")
                    .ok_or(RuntimeError::InvalidDigest)?,
            )
        };
        let definition = row
            .try_get::<serde_json::Value, _>("definition")
            .map_err(|_| RuntimeError::InvalidInput)?;
        let source = ConfiguredCiglSettings {
            settings_id: advertised.artifact_id.clone(),
            participant_id: participant_id.into(),
            privacy_domain_id: privacy_domain_id.into(),
            publication_operation_id: text("publication_operation_id")?,
            publication_authority_digest: digest("publication_authority_digest")?,
            definition_digest: digest("definition_digest")?,
            definition: serde_json::from_value::<CiglSettingsDefinition>(definition)
                .map_err(|_| RuntimeError::InvalidInput)?,
        };
        let payload = source.to_cbor()?;
        if advertised.payload_cbor != payload || advertised.artifact_digest != Digest::of(&payload)
        {
            return Err(RuntimeError::GenerationMismatch);
        }
    }
    Ok(VerifiedCiglSettingsSources {
        configuration_digest: configuration_digest.clone(),
    })
}
