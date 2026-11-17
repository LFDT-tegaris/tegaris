//! A database reader receives bytes only after independent native custody has
//! recorded its transaction-bound materialization. A lost response, rejected
//! downstream publication or SQL rollback cannot remove that observation.
use super::*;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

#[path = "materialization_server.rs"]
mod server;
pub use server::MaterializationServer;

const REQUEST_PURPOSE: &[u8] = b"OPENPC_RUNTIME_ARTIFACT_MATERIALIZATION_REQUEST_V2";
const RESPONSE_PURPOSE: &[u8] = b"OPENPC_RUNTIME_ARTIFACT_MATERIALIZATION_RESPONSE_V2";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Materialization {
    pub input: ImportIdentity,
    pub(super) reader_role: String,
    pub(super) transaction_id: String,
    pub(super) backend_id: String,
    pub(super) request_id: String,
}

impl Materialization {
    pub(super) fn validate(&self) -> RuntimeResult<()> {
        self.input.validate()?;
        uuid(&self.request_id)?;
        if self.reader_role.is_empty()
            || self.reader_role.len() > 63
            || !self.reader_role.bytes().all(|byte| byte.is_ascii_graphic())
            || self.transaction_id.is_empty()
            || self.transaction_id.len() > 20
            || !self
                .transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_digit())
            || self
                .transaction_id
                .parse::<u64>()
                .ok()
                .is_none_or(|id| id == 0)
            || self.backend_id.is_empty()
            || self.backend_id.len() > 96
            || !self.backend_id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(RuntimeError::InvalidInput);
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
    materialization: Materialization,
}

/// Length-framed local transport. The database/native MAC authenticates the
/// exact wire, independently of socket access or a caller's claimed identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Message {
    pub wire: Vec<u8>,
    pub mac: Vec<u8>,
}

pub(super) fn authenticator(
    key: &[u8; 32],
    purpose: &[u8],
    wire: &[u8],
) -> RuntimeResult<Hmac<Sha256>> {
    if wire.is_empty() || wire.len() > 16384 {
        return Err(RuntimeError::InvalidInput);
    }
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| RuntimeError::InvalidInput)?;
    mac.update(purpose);
    mac.update(wire);
    Ok(mac)
}

impl RuntimeArtifactSourceCustody {
    pub(super) fn materialize(
        &mut self,
        request: Message,
        key: &[u8; 32],
    ) -> RuntimeResult<Message> {
        if authenticator(key, REQUEST_PURPOSE, &request.wire)?
            .verify_slice(&request.mac)
            .is_err()
        {
            return self.materialize_archive(request, key);
        }
        authenticator(key, REQUEST_PURPOSE, &request.wire)?
            .verify_slice(&request.mac)
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
        let challenge: Challenge =
            serde_json::from_slice(&request.wire).map_err(|_| RuntimeError::InvalidInput)?;
        challenge.materialization.validate()?;
        let state = self.checked_state()?;
        if challenge.version != 2
            || challenge.installation != self.installation
            || state.retained_root.as_ref() != Some(&challenge.binding)
            || challenge.binding.consumer_profile != retained_root::MATERIALIZATION_PROFILE
            || self.denies(&challenge.materialization.input.configuration_digest)?
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let history = state
            .history
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        if !history
            .imports(&self.history_signer)?
            .iter()
            .any(|(input, committed)| *committed && *input == challenge.materialization.input)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let original = match history
            .materialization_original(&self.history_signer, &challenge.materialization.input)?
        {
            Some(original) => original,
            None => {
                let observation =
                    history::Observation::MaterializedOrUnknown(challenge.materialization.clone());
                // The first possible use and root advance are fsynced before
                // any response. One permanent original suffices for this exact
                // input; ordinary polling must not consume history capacity.
                self.record_observation(observation.clone())?;
                self.checked_state()?
                    .history
                    .as_ref()
                    .ok_or(RuntimeError::InvalidAuthorization)?
                    .observation_original(&self.history_signer, &observation)?
            }
        };
        let original: serde_json::Value =
            serde_json::from_slice(&original).map_err(|_| RuntimeError::InvalidInput)?;
        let root = self
            .retained_root
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        // No release permit is reused: every response authenticates this fresh
        // challenge and current retained root after all checks above.
        let wire = canonical_bytes(&serde_json::json!({
            "challenge": challenge,
            "observation": original,
            "root": root.original(self.checked_state()?)?,
        }))?;
        let mac = authenticator(key, RESPONSE_PURPOSE, &wire)?
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

    fn input() -> ImportIdentity {
        ImportIdentity {
            input_id: id(10),
            module_installation_id: id(11),
            module_configuration_generation_id: id(12),
            configuration_digest: Digest::of(b"read source"),
        }
    }

    fn challenge(binding: &SourceRootBinding) -> Message {
        let wire = canonical_bytes(&Challenge {
            version: 2,
            installation: installation(),
            binding: binding.clone(),
            materialization: Materialization {
                input: input(),
                reader_role: "actual_database_reader".into(),
                transaction_id: "12345".into(),
                backend_id: "123:1000000000.000000".into(),
                request_id: id(40),
            },
        })
        .unwrap();
        let mac = authenticator(&[8; 32], REQUEST_PURPOSE, &wire)
            .unwrap()
            .finalize()
            .into_bytes()
            .to_vec();
        Message { wire, mac }
    }

    fn setup(directory: &Directory, v2: bool) -> (RuntimeArtifactSourceCustody, SourceRootBinding) {
        let native = directory.0.join("native");
        let retained = directory.0.join("retained");
        let mut binding = SourceRootBinding::for_directories(id(30), &native, &retained).unwrap();
        if v2 {
            binding.consumer_profile = retained_root::MATERIALIZATION_PROFILE.into();
            binding.database = Some(retained_root::MaterializationDatabase {
                system_identifier: "123456789".into(),
                database_oid: "16384".into(),
            });
        }
        let mut owner = RuntimeArtifactSourceCustody::open_mode(
            &native,
            installation(),
            [7; 32],
            true,
            Some((&retained, binding.clone())),
        )
        .unwrap();
        owner
            .record_observation(history::Observation::ImportPending(input()))
            .unwrap();
        owner
            .record_observation(history::Observation::ImportCommitted(input()))
            .unwrap();
        (owner, binding)
    }

    fn admission() -> SourceDispositionAdmission {
        SourceDispositionAdmission {
            installation: installation(),
            disposition_id: id(50),
            operation_id: id(51),
            input_id: input().input_id,
            configuration_digest: input().configuration_digest,
            admission_receipt_digest: Digest::of(b"admitted"),
            selection_digest: Digest::of(b"selected"),
        }
    }

    #[test]
    fn fresh_generic_reads_reuse_only_the_permanent_possible_use_original() {
        let directory = Directory::new();
        let (mut owner, binding) = setup(&directory, true);
        let first = owner.materialize(challenge(&binding), &[8; 32]).unwrap();
        let first: serde_json::Value = serde_json::from_slice(&first.wire).unwrap();
        let original =
            std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap();
        for attempt in 100..200 {
            let mut request: Challenge = serde_json::from_slice(&challenge(&binding).wire).unwrap();
            request.materialization.request_id = id(attempt);
            request.materialization.reader_role = format!("different_reader_{attempt}");
            request.materialization.transaction_id = attempt.to_string();
            let wire = canonical_bytes(&request).unwrap();
            let mac = authenticator(&[8; 32], REQUEST_PURPOSE, &wire)
                .unwrap()
                .finalize()
                .into_bytes()
                .to_vec();
            let response = owner.materialize(Message { wire, mac }, &[8; 32]).unwrap();
            authenticator(&[8; 32], RESPONSE_PURPOSE, &response.wire)
                .unwrap()
                .verify_slice(&response.mac)
                .unwrap();
            let response: serde_json::Value = serde_json::from_slice(&response.wire).unwrap();
            assert_ne!(response["challenge"], first["challenge"]);
            assert_eq!(response["observation"], first["observation"]);
        }
        assert_eq!(
            std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap(),
            original
        );
        assert_eq!(
            owner.begin_governed(admission()).err(),
            Some(RuntimeError::Denied)
        );
    }

    #[test]
    fn interrupted_first_materialization_reconciles_the_actual_durable_boundary() {
        for pending in [
            "retained/runtime-artifact-source-root.next",
            "native/runtime-artifact-source.next",
        ] {
            let directory = Directory::new();
            let (mut owner, binding) = setup(&directory, true);
            let original =
                std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap();
            let root = std::fs::read(
                directory
                    .0
                    .join("retained/runtime-artifact-source-root.json"),
            )
            .unwrap();
            // Real create_new refusal before/after retained-root advancement;
            // shared LocalJournal tests separately cover fsync failure itself.
            std::fs::write(directory.0.join(pending), b"interrupted original").unwrap();
            assert!(owner.materialize(challenge(&binding), &[8; 32]).is_err());
            assert!(owner.materialize(challenge(&binding), &[8; 32]).is_err());
            assert_eq!(
                std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap(),
                original
            );
            let root_advanced = std::fs::read(
                directory
                    .0
                    .join("retained/runtime-artifact-source-root.json"),
            )
            .unwrap()
                != root;
            drop(owner);
            let restarted = RuntimeArtifactSourceCustody::open_mode(
                &directory.0.join("native"),
                installation(),
                [7; 32],
                false,
                Some((&directory.0.join("retained"), binding.clone())),
            );
            if pending.starts_with("retained/") {
                assert!(!root_advanced);
                // No byte-release response existed before the root advanced.
                // The shared journal validates/fsyncs the prior committed file
                // and removes only its never-acknowledged staging file. A
                // recovered first release still needs a durable use original.
                let mut restarted = restarted.unwrap();
                assert_eq!(
                    std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap(),
                    original
                );
                let response = restarted
                    .materialize(challenge(&binding), &[8; 32])
                    .unwrap();
                authenticator(&[8; 32], RESPONSE_PURPOSE, &response.wire)
                    .unwrap()
                    .verify_slice(&response.mac)
                    .unwrap();
                assert_ne!(
                    std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap(),
                    original
                );
                assert_eq!(
                    restarted.begin_governed(admission()).err(),
                    Some(RuntimeError::Denied)
                );
            } else {
                // Once the root advances, reopening the older source state
                // must stay denied rather than replaying or erasing the attempt.
                assert!(root_advanced);
                assert!(restarted.is_err());
            }
        }
    }

    #[test]
    fn lost_response_and_rejected_publication_remain_consumed_after_restart() {
        let directory = Directory::new();
        let (mut owner, binding) = setup(&directory, true);
        let response = owner.materialize(challenge(&binding), &[8; 32]).unwrap();
        authenticator(&[8; 32], RESPONSE_PURPOSE, &response.wire)
            .unwrap()
            .verify_slice(&response.mac)
            .unwrap();
        // No database publication or downstream effect ever commits.
        drop(response);
        assert_eq!(
            owner.begin_governed(admission()).err(),
            Some(RuntimeError::Denied)
        );
        let original =
            std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap();
        drop(owner);
        let mut owner = RuntimeArtifactSourceCustody::open_mode(
            &directory.0.join("native"),
            installation(),
            [7; 32],
            false,
            Some((&directory.0.join("retained"), binding.clone())),
        )
        .unwrap();
        owner.materialize(challenge(&binding), &[8; 32]).unwrap();
        assert_eq!(
            std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap(),
            original
        );
        assert_eq!(
            owner.begin_governed(admission()).err(),
            Some(RuntimeError::Denied)
        );
    }

    #[test]
    fn legacy_forged_foreign_and_denied_requests_release_no_permit() {
        let directory = Directory::new();
        let (mut owner, binding) = setup(&directory, false);
        assert!(owner.materialize(challenge(&binding), &[8; 32]).is_err());
        let directory = Directory::new();
        let (mut owner, binding) = setup(&directory, true);
        let before =
            std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap();
        let mut forged = challenge(&binding);
        forged.mac[0] ^= 1;
        assert!(owner.materialize(forged, &[8; 32]).is_err());
        let mut foreign = binding.clone();
        foreign.generation_id = id(99);
        assert!(owner.materialize(challenge(&foreign), &[8; 32]).is_err());
        assert_eq!(
            std::fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap(),
            before
        );
        owner.begin_governed(admission()).unwrap();
        assert!(owner.materialize(challenge(&binding), &[8; 32]).is_err());
    }
}
