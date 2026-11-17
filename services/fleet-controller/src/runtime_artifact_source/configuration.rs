//! Pure host configuration producer. Every trust field is verified again by the
//! initial installer; rendering never initializes or promotes an existing scope.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    participant_id: String,
    privacy_domain_id: String,
    source_owner_id: String,
    generation_id: String,
    source_file: PathBuf,
    journal_directory: PathBuf,
    retained_root_directory: PathBuf,
    signing_key_file: PathBuf,
    commit_key_file: PathBuf,
    database_password_file: PathBuf,
    fresh_scope: FreshScope,
    #[serde(default)]
    materialization_database: Option<retained_root::MaterializationDatabase>,
    #[serde(default)]
    archive_custody: Option<archive::Configuration>,
}

pub(super) fn render(bytes: &[u8]) -> RuntimeResult<Configuration> {
    if bytes.is_empty() || bytes.len() > 16384 {
        return Err(RuntimeError::InvalidInput);
    }
    let input: Input = serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidInput)?;
    input.fresh_scope.validate()?;
    let installation = SourceCustodyInstallation {
        participant_id: input.participant_id,
        privacy_domain_id: input.privacy_domain_id,
        source_owner_id: input.source_owner_id,
        source_file_binding: SourceCustodyInstallation::file_binding(&input.source_file)?,
    };
    installation.validate()?;
    for path in [
        &input.signing_key_file,
        &input.commit_key_file,
        &input.database_password_file,
    ] {
        SourceCustodyInstallation::file_binding(path)?;
    }
    if input.signing_key_file == input.commit_key_file {
        return Err(RuntimeError::InvalidAuthorization);
    }
    let mut root = SourceRootBinding::for_directories(
        input.generation_id,
        &input.journal_directory,
        &input.retained_root_directory,
    )?;
    if let Some(database) = input.materialization_database {
        root.consumer_profile = retained_root::MATERIALIZATION_PROFILE.into();
        root.database = Some(database);
        root.validate()?;
    }
    let role = RuntimeArtifactSourceWorker::installation_database_role(
        &installation.participant_id,
        &installation.privacy_domain_id,
    )?;
    Ok(Configuration {
        installation,
        source_file: input.source_file,
        journal_directory: input.journal_directory,
        signing_key_file: input.signing_key_file,
        commit_key_file: input.commit_key_file,
        retained_root: Some(RootConfiguration {
            directory: input.retained_root_directory,
            binding: root,
        }),
        database_role: Some(role),
        database_password_file: Some(input.database_password_file),
        fresh_scope: Some(input.fresh_scope),
        archive_custody: input.archive_custody,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_rendering_has_no_key_or_installation_effects() {
        let directory = crate::runtime_artifact_source::tests::Directory::new();
        let id = crate::runtime_artifact_source::tests::id;
        let input = serde_json::json!({
            "participant_id":id(1),"privacy_domain_id":id(2),"source_owner_id":id(3),"generation_id":id(4),
            "source_file":directory.0.join("source.cbor"),"journal_directory":directory.0.join("journal"),
            "retained_root_directory":directory.0.join("root"),"signing_key_file":directory.0.join("signing.key"),
            "commit_key_file":directory.0.join("commit.key"),"database_password_file":directory.0.join("database.password"),
            "fresh_scope":{"participant_display_name":"Source host","privacy_domain_name":"Source"},
        });
        let configuration = render(&serde_json::to_vec(&input).unwrap()).unwrap();
        assert_eq!(configuration.installation.participant_id, id(1));
        assert_eq!(
            configuration.retained_root.unwrap().binding.generation_id,
            id(4)
        );
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
        for (field, value) in [
            ("coverage", serde_json::json!("PROVEN")),
            (
                "participant_id",
                serde_json::json!("018F0000-0000-7000-8000-000000000001"),
            ),
            ("signing_key_file", serde_json::json!("relative.key")),
            (
                "retained_root_directory",
                input["journal_directory"].clone(),
            ),
        ] {
            let mut invalid = input.clone();
            invalid[field] = value;
            assert!(render(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
    }
}
