//! An archive is a distinct, installed consumer. Its possible plaintext use is
//! durable before release and remains unknown until the source worker verifies
//! the complete original encrypted custody in a separate committed transaction.
use super::*;
use hmac::Mac;
use materialization::{Materialization, Message, authenticator};
use std::{collections::BTreeMap, path::PathBuf};

#[path = "archive_format.rs"]
mod format;
#[path = "archive_readback.rs"]
mod readback;

pub(super) const REQUEST: &[u8] = b"OPENPC_RUNTIME_ARTIFACT_ARCHIVE_REQUEST_V1";
pub(super) const RESPONSE: &[u8] = b"OPENPC_RUNTIME_ARTIFACT_ARCHIVE_RESPONSE_V1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub database_role: String,
    pub stream_id: String,
    pub keys: BTreeMap<String, Digest>,
}

fn reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":._-".contains(&b))
}

pub(super) fn login(installation: &SourceCustodyInstallation) -> RuntimeResult<String> {
    Ok(installation::rooted_login(
        &installation.participant_id,
        &installation.privacy_domain_id,
    )?
    .replacen("openpc_rs_login_", "openpc_ra_login_", 1))
}

impl Binding {
    pub(super) fn validate(&self, installation: &SourceCustodyInstallation) -> RuntimeResult<()> {
        if self.database_role != login(installation)?
            || !reference(&self.stream_id)
            || self.keys.is_empty()
            || self.keys.len() > 64
            || self.keys.keys().any(|id| !reference(id))
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        for digest in self.keys.values() {
            Digest::parse(digest.as_str())?;
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Configuration {
    pub stream_id: String,
    pub database_password_file: PathBuf,
    pub keys: BTreeMap<String, PathBuf>,
}

pub(super) struct Custody {
    pub binding: Binding,
    pub keys: BTreeMap<String, [u8; 32]>,
}

impl Drop for Custody {
    fn drop(&mut self) {
        for key in self.keys.values_mut() {
            key.fill(0);
        }
    }
}

impl Configuration {
    pub(super) async fn install(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        installation: &SourceCustodyInstallation,
        root: &SourceRootBinding,
    ) -> SourceCustodyResult<()> {
        if root.consumer_profile != retained_root::MATERIALIZATION_PROFILE {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        let custody = self.open(installation)?;
        let password = std::fs::read(&self.database_password_file).map_err(control::unavailable)?;
        let password = std::str::from_utf8(&password).map_err(|_| RuntimeError::InvalidInput)?;
        if password.len() < 32
            || password.len() > 256
            || !password.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(RuntimeError::InvalidInput.into());
        }
        let profile = String::from_utf8(canonical_bytes(
            &serde_json::json!({"installation":installation,"root":root,"archive":custody.binding}),
        )?)
        .map_err(|_| RuntimeError::InvalidInput)?;
        for (template, second) in [
            (
                "CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L",
                password,
            ),
            ("GRANT openpc_control_worker TO %I", ""),
            ("COMMENT ON ROLE %I IS %L", profile.as_str()),
        ] {
            let statement: String =
                sqlx::query_scalar("select pg_catalog.format($1,$2::text,$3::text)")
                    .bind(template)
                    .bind(&custody.binding.database_role)
                    .bind(second)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(control::unavailable)?;
            sqlx::query(sqlx::AssertSqlSafe(statement))
                .execute(&mut **tx)
                .await
                .map_err(control::unavailable)?;
        }
        Ok(())
    }

    pub(super) fn open(&self, installation: &SourceCustodyInstallation) -> RuntimeResult<Custody> {
        use std::os::unix::fs::MetadataExt;
        SourceCustodyInstallation::file_binding(&self.database_password_file)?;
        let mut keys = BTreeMap::new();
        for (id, path) in &self.keys {
            SourceCustodyInstallation::file_binding(path)?;
            let metadata = std::fs::symlink_metadata(path).map_err(control::unavailable)?;
            if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.len() != 32 {
                return Err(RuntimeError::InvalidAuthorization);
            }
            keys.insert(id.clone(), worker::key(path)?);
        }
        let binding = Binding {
            database_role: login(installation)?,
            stream_id: self.stream_id.clone(),
            keys: keys
                .iter()
                .map(|(id, key)| (id.clone(), Digest::of(key)))
                .collect(),
        };
        binding.validate(installation)?;
        Ok(Custody { binding, keys })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub materialization: Materialization,
    pub stream_id: String,
}

impl Pending {
    pub(super) fn validate(&self) -> RuntimeResult<()> {
        self.materialization.validate()?;
        if !reference(&self.stream_id) {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Committed {
    pub pending_digest: Digest,
    pub input: ImportIdentity,
    pub stream_id: String,
    pub manifest_digest: Digest,
    pub custody_digest: Digest,
}

impl Committed {
    pub(super) fn validate(&self) -> RuntimeResult<()> {
        self.input.validate()?;
        if !reference(&self.stream_id) {
            return Err(RuntimeError::InvalidInput);
        }
        for digest in [
            &self.pending_digest,
            &self.manifest_digest,
            &self.custody_digest,
        ] {
            Digest::parse(digest.as_str())?;
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    version: u16,
    installation: SourceCustodyInstallation,
    binding: SourceRootBinding,
    archive: Pending,
}

impl RuntimeArtifactSourceCustody {
    pub(super) fn materialize_archive(
        &mut self,
        request: Message,
        key: &[u8; 32],
    ) -> RuntimeResult<Message> {
        authenticator(key, REQUEST, &request.wire)?
            .verify_slice(&request.mac)
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
        let challenge: Challenge =
            serde_json::from_slice(&request.wire).map_err(|_| RuntimeError::InvalidInput)?;
        challenge.archive.validate()?;
        let state = self.checked_state()?;
        let custody = self
            .archive
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        if challenge.version != 1
            || challenge.installation != self.installation
            || state.retained_root.as_ref() != Some(&challenge.binding)
            || challenge.binding.consumer_profile != retained_root::MATERIALIZATION_PROFILE
            || challenge.archive.stream_id != custody.binding.stream_id
            || challenge.archive.materialization.reader_role != custody.binding.database_role
            || self.denies(&challenge.archive.materialization.input.configuration_digest)?
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let history = state
            .history
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let input = &challenge.archive.materialization.input;
        if !history
            .imports(&self.history_signer)?
            .iter()
            .any(|(i, committed)| *committed && i == input)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let observation =
            history::Observation::ArchiveMaterializedOrUnknown(challenge.archive.clone());
        // A lost response can only reuse this exact original request. A new
        // transaction/request is not permission to repackage an unknown intent.
        if let Some((pending, _, _)) = history
            .archives(&self.history_signer)?
            .into_iter()
            .find(|(pending, _, _)| pending.materialization.input == *input)
        {
            if pending != challenge.archive {
                return Err(RuntimeError::Denied);
            }
        } else {
            self.record_observation(observation.clone())?;
        }
        let original = self
            .checked_state()?
            .history
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?
            .observation_original(&self.history_signer, &observation)?;
        let original_wire: String = original.iter().map(|byte| format!("{byte:02x}")).collect();
        let original: serde_json::Value =
            serde_json::from_slice(&original).map_err(|_| RuntimeError::InvalidInput)?;
        let wire = canonical_bytes(
            &serde_json::json!({"challenge":challenge,"observation":original,"original":original_wire,
            "root":self.retained_root.as_ref().ok_or(RuntimeError::InvalidAuthorization)?.original(self.checked_state()?)?}),
        )?;
        let mac = authenticator(key, RESPONSE, &wire)?
            .finalize()
            .into_bytes()
            .to_vec();
        Ok(Message { wire, mac })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Directory, id, installation};
    use super::*;

    fn setup(directory: &Directory) -> (RuntimeArtifactSourceCustody, Challenge) {
        let mut root = SourceRootBinding::for_directories(
            id(30),
            &directory.0.join("native"),
            &directory.0.join("root"),
        )
        .unwrap();
        root.consumer_profile = retained_root::MATERIALIZATION_PROFILE.into();
        root.database = Some(retained_root::MaterializationDatabase {
            system_identifier: "12345678".into(),
            database_oid: "16384".into(),
        });
        let mut owner = RuntimeArtifactSourceCustody::open_mode(
            &directory.0.join("native"),
            installation(),
            [7; 32],
            true,
            Some((&directory.0.join("root"), root.clone())),
        )
        .unwrap();
        let input = ImportIdentity {
            input_id: id(10),
            module_installation_id: id(11),
            module_configuration_generation_id: id(12),
            configuration_digest: Digest::of(b"archive original"),
        };
        owner
            .record_observation(history::Observation::ImportPending(input.clone()))
            .unwrap();
        owner
            .record_observation(history::Observation::ImportCommitted(input.clone()))
            .unwrap();
        owner.archive = Some(Custody {
            binding: Binding {
                database_role: login(&installation()).unwrap(),
                stream_id: "archive".into(),
                keys: BTreeMap::from([("key".into(), Digest::of([11; 32]))]),
            },
            keys: BTreeMap::from([("key".into(), [11; 32])]),
        });
        let challenge = Challenge {
            version: 1,
            installation: installation(),
            binding: root,
            archive: Pending {
                materialization: Materialization {
                    input,
                    reader_role: login(&installation()).unwrap(),
                    transaction_id: "12345".into(),
                    backend_id: "123:1000.000000".into(),
                    request_id: id(40),
                },
                stream_id: "archive".into(),
            },
        };
        (owner, challenge)
    }
    fn request(challenge: &Challenge) -> Message {
        let wire = canonical_bytes(challenge).unwrap();
        let mac = authenticator(&[8; 32], REQUEST, &wire)
            .unwrap()
            .finalize()
            .into_bytes()
            .to_vec();
        Message { wire, mac }
    }
    #[test]
    fn independent_decoder_checks_real_node_archive_wire_and_malformed_content() {
        use base64ct::{Base64, Encoding};
        let directory = Directory::new();
        let (owner, mut challenge) = setup(&directory);
        challenge.archive.materialization.input.configuration_digest =
            Digest::of(vec![0x93; 400_001]);
        let fixture = serde_json::json!({"format":true,"participant":installation().participant_id,"privacy":installation().privacy_domain_id,
            "input":challenge.archive.materialization.input.input_id,"module":challenge.archive.materialization.input.module_installation_id,
            "generation":challenge.archive.materialization.input.module_configuration_generation_id,"digest":challenge.archive.materialization.input.configuration_digest.as_str()});
        let output = std::process::Command::new("timeout")
            .current_dir(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .args([
                "--kill-after=2s",
                "15s",
                "node",
                "--import",
                "tsx",
                "tests/integration/identity/runtime-artifact-materialization-client.mjs",
            ])
            .env("OPENPC_RUNTIME_SOURCE_READ_TEST", fixture.to_string())
            .output()
            .unwrap();
        assert!(output.status.success(), "Node archive producer failed");
        let fixture: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let custody = owner.archive.as_ref().unwrap();
        let mut records = Vec::new();
        for segment in fixture["segments"].as_array().unwrap() {
            let bytes = Base64::decode_vec(segment["bytes"].as_str().unwrap()).unwrap();
            let header = &segment["header"];
            let digest = segment["objectDigest"].as_str().unwrap();
            records.extend(
                format::open_segment(&bytes, header, digest, custody).expect("exact Node segment"),
            );
            let mut corrupt = bytes.clone();
            corrupt[10] ^= 1;
            assert!(format::open_segment(&corrupt, header, digest, custody).is_err());
            let mut wrong = header.clone();
            wrong["streamId"] = serde_json::json!("foreign");
            assert!(format::open_segment(&bytes, &wrong, digest, custody).is_err());
        }
        format::verify_manifest(
            &fixture["manifest"],
            &records,
            &challenge.archive,
            &installation(),
        )
        .expect("exact Node archive");
        records.swap(0, 1);
        assert!(
            format::verify_manifest(
                &fixture["manifest"],
                &records,
                &challenge.archive,
                &installation()
            )
            .is_err()
        );
        records.swap(0, 1);
        records.pop();
        assert!(
            format::verify_manifest(
                &fixture["manifest"],
                &records,
                &challenge.archive,
                &installation()
            )
            .is_err()
        );
    }

    #[test]
    fn private_archive_pending_cannot_be_reclassified_repacked_or_completed_out_of_order() {
        let directory = Directory::new();
        let (mut owner, mut challenge) = setup(&directory);
        let initial =
            std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap();
        challenge.archive.stream_id = "wrong".into();
        assert!(owner.materialize(request(&challenge), &[8; 32]).is_err());
        challenge.archive.stream_id = "archive".into();
        challenge.archive.materialization.reader_role = "shared_worker".into();
        assert!(owner.materialize(request(&challenge), &[8; 32]).is_err());
        challenge.archive.materialization.reader_role = login(&installation()).unwrap();
        assert_eq!(
            initial,
            std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap()
        );
        let response = owner.materialize(request(&challenge), &[8; 32]).unwrap();
        authenticator(&[8; 32], RESPONSE, &response.wire)
            .unwrap()
            .verify_slice(&response.mac)
            .unwrap();
        let document: serde_json::Value = serde_json::from_slice(&response.wire).unwrap();
        let archived = owner
            .checked_state()
            .unwrap()
            .history
            .as_ref()
            .unwrap()
            .archives(&owner.history_signer)
            .unwrap();
        let expected: String = archived[0].1.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(document["original"].as_str(), Some(expected.as_str()));
        // The immutable signed native record uses its original typed field
        // ordering. A JSON value is not a byte-preserving substitute.
        assert_ne!(
            canonical_bytes(&document["observation"]).unwrap(),
            archived[0].1
        );
        assert!(owner.materialize(response, &[8; 32]).is_err()); // response reflection
        let pending =
            std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap();
        owner.materialize(request(&challenge), &[8; 32]).unwrap();
        assert_eq!(
            pending,
            std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap()
        );
        challenge.archive.materialization.transaction_id = "12346".into();
        assert_eq!(
            owner.materialize(request(&challenge), &[8; 32]).err(),
            Some(RuntimeError::Denied)
        );
        assert_eq!(
            pending,
            std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap()
        );
        let failed = Committed {
            pending_digest: Digest::of(b"not the original"),
            input: challenge.archive.materialization.input.clone(),
            stream_id: "archive".into(),
            manifest_digest: Digest::of(b"manifest"),
            custody_digest: Digest::of(b"custody"),
        };
        assert!(
            owner
                .record_observation(history::Observation::ArchiveCustodyCommitted(failed))
                .is_err()
        );
        assert_eq!(
            pending,
            std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap()
        );
        let admission = SourceDispositionAdmission {
            installation: installation(),
            disposition_id: id(51),
            operation_id: id(52),
            input_id: challenge.archive.materialization.input.input_id.clone(),
            configuration_digest: challenge
                .archive
                .materialization
                .input
                .configuration_digest
                .clone(),
            admission_receipt_digest: Digest::of(b"admission"),
            selection_digest: Digest::of(b"selection"),
        };
        assert_eq!(
            owner.begin_governed(admission.clone()).err(),
            Some(RuntimeError::Denied)
        );
        let completed = Committed {
            pending_digest: Digest::of(&archived[0].1),
            input: challenge.archive.materialization.input.clone(),
            stream_id: "archive".into(),
            manifest_digest: Digest::of(b"manifest"),
            custody_digest: Digest::of(b"custody"),
        };
        owner
            .record_observation(history::Observation::ArchiveCustodyCommitted(completed))
            .unwrap();
        // Even a complete archive cannot erase a separate generic plaintext use.
        let mut generic = challenge.archive.materialization.clone();
        generic.reader_role = "openpc_control_worker".into();
        owner
            .record_observation(history::Observation::MaterializedOrUnknown(generic))
            .unwrap();
        assert_eq!(
            owner.begin_governed(admission).err(),
            Some(RuntimeError::Denied)
        );
    }
}
