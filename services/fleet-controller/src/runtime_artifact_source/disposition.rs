//! The irreversible native denial is issued only after its Control admission
//! has committed and this installed source's complete history proves non-use.
//! This is one custody dimension, never retention or physical-delete authority.
use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceNonUse {
    profile: String,
    binding: SourceRootBinding,
    input: ImportIdentity,
    pending_digest: Digest,
    committed_digest: Digest,
    history_sequence: u64,
    history_head_digest: Digest,
    retained_head_digest: Digest,
    consumers: Vec<SourceConsumerBoundary>,
}

impl SourceNonUse {
    pub(super) fn validate(
        &self,
        admission: &SourceDispositionAdmission,
        root: Option<&SourceRootBinding>,
    ) -> RuntimeResult<()> {
        self.input.validate()?;
        if self.profile != "openpc:runtime-artifact-source-non-use:v1"
            || root != Some(&self.binding)
            || self.binding.consumer_profile != retained_root::MATERIALIZATION_PROFILE
            || self.input.input_id != admission.input_id
            || self.input.configuration_digest != admission.configuration_digest
            || !(2..=MAX_DENIALS as u64).contains(&self.history_sequence)
            || self.consumers != SourceConsumerBoundary::INSTALLED
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        for digest in [
            &self.pending_digest,
            &self.committed_digest,
            &self.history_head_digest,
            &self.retained_head_digest,
        ] {
            Digest::parse(digest.as_str())?;
        }
        Ok(())
    }
}

impl RuntimeArtifactSourceCustody {
    /// Called only by reconciliation while the same scoped Control transaction
    /// owns the lifecycle/source fences. No caller supplies the proof or a
    /// readiness flag. The independent root must have preceded every import;
    /// legacy/pending/used/unknown custody cannot burn first-issue permission.
    pub(super) fn begin_governed(
        &mut self,
        admission: SourceDispositionAdmission,
    ) -> RuntimeResult<FirstDenial> {
        admission.validate()?;
        let state = self.checked_state()?;
        let binding = state
            .retained_root
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let history = state
            .history
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        history.validate(&self.installation, &self.history_signer)?;
        history.require_consumer_profile(&self.history_signer)?;
        let (input, pending_digest, committed_digest, history_sequence, history_head_digest) =
            history.non_use(&self.history_signer, &admission)?;
        let root = self
            .retained_root
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let proof = SourceNonUse {
            profile: "openpc:runtime-artifact-source-non-use:v1".into(),
            binding: binding.clone(),
            input,
            pending_digest,
            committed_digest,
            history_sequence,
            history_head_digest,
            retained_head_digest: Digest::of(canonical_bytes(&root.original(state)?)?),
            consumers: SourceConsumerBoundary::INSTALLED.to_vec(),
        };
        proof.validate(&admission, Some(binding))?;
        self.begin_with_custody(admission, Some(proof))
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::{Directory, id, installation};
    use super::*;
    use std::fs;

    fn input() -> ImportIdentity {
        ImportIdentity {
            input_id: id(10),
            module_installation_id: id(11),
            module_configuration_generation_id: id(12),
            configuration_digest: Digest::of(b"independent imported artifact"),
        }
    }

    fn admission() -> SourceDispositionAdmission {
        SourceDispositionAdmission {
            installation: installation(),
            disposition_id: id(20),
            operation_id: id(21),
            input_id: input().input_id,
            configuration_digest: input().configuration_digest,
            admission_receipt_digest: Digest::of(b"original committed governance"),
            selection_digest: Digest::of(b"exact selection"),
        }
    }

    fn rooted(directory: &Directory) -> (RuntimeArtifactSourceCustody, SourceRootBinding) {
        let native = directory.0.join("native");
        let retained = directory.0.join("retained");
        let mut binding = SourceRootBinding::for_directories(id(30), &native, &retained).unwrap();
        // Native proof mechanics only. Production installation must also
        // authenticate the V2 materialization boundary and its actual grants.
        binding.consumer_profile = retained_root::MATERIALIZATION_PROFILE.into();
        binding.database = Some(retained_root::MaterializationDatabase {
            system_identifier: "123456789".into(),
            database_oid: "16384".into(),
        });
        let owner = RuntimeArtifactSourceCustody::open_mode(
            &native,
            installation(),
            [7; 32],
            true,
            Some((&retained, binding.clone())),
        )
        .unwrap();
        (owner, binding)
    }

    fn import(owner: &mut RuntimeArtifactSourceCustody) {
        owner
            .record_observation(history::Observation::ImportPending(input()))
            .unwrap();
        owner
            .record_observation(history::Observation::ImportCommitted(input()))
            .unwrap();
    }

    pub(in crate::runtime_artifact_source) fn control_wire(database: bool) {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let directory = Directory::new();
        let (mut owner, _) = rooted(&directory);
        import(&mut owner);
        let permit = owner.begin_governed(admission()).unwrap();
        let first = owner.finish(permit).unwrap();
        let next_input = ImportIdentity {
            input_id: id(42),
            configuration_digest: Digest::of(b"independent second source wire"),
            ..input()
        };
        owner
            .record_observation(history::Observation::ImportPending(next_input.clone()))
            .unwrap();
        owner
            .record_observation(history::Observation::ImportCommitted(next_input.clone()))
            .unwrap();
        let next = SourceDispositionAdmission {
            disposition_id: id(43),
            operation_id: id(44),
            input_id: next_input.input_id,
            configuration_digest: next_input.configuration_digest,
            ..admission()
        };
        let permit = owner.begin_governed(next).unwrap();
        let second = owner.finish(permit).unwrap();
        let signed: SignedEnvelope<SourceDenial> = serde_json::from_slice(&second).unwrap();
        assert_eq!(signed.claims.sequence, 2);
        assert_eq!(
            signed.claims.previous_denial_digest,
            Some(Digest::of(&first))
        );
        for wire in [first, second] {
            let fixture =
                serde_json::json!({"wire":wire,"publicKey":owner.signer.verifier().sec1_bytes()});
            let mut child = Command::new("timeout")
                .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
                .args([
                    "--kill-after=2s",
                    "30s",
                    "node",
                    "tests/integration/identity/runtime-artifact-denial-wire.mjs",
                    if database { "postgres" } else { "pure" },
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&serde_json::to_vec(&fixture).unwrap())
                .unwrap();
            let result = child.wait_with_output().unwrap();
            assert!(
                result.status.success(),
                "native wire consumer failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            print!("{}", String::from_utf8_lossy(&result.stdout));
        }
    }

    #[test]
    fn source_denial_wire_matches_control_consumer() {
        control_wire(false);
    }

    #[test]
    fn rooted_original_non_use_is_bound_to_signed_denial_and_restart() {
        let directory = Directory::new();
        let (mut owner, binding) = rooted(&directory);
        import(&mut owner);
        let permit = owner.begin_governed(admission()).unwrap();
        let wire = owner.finish(permit).unwrap();
        let signed: SignedEnvelope<SourceDenial> = serde_json::from_slice(&wire).unwrap();
        assert_eq!(signed.claims.version, 2);
        let proof = signed.claims.custody.unwrap();
        assert_eq!(proof.input, input());
        assert_eq!(proof.history_sequence, 2);
        assert_eq!(proof.consumers, SourceConsumerBoundary::INSTALLED);
        proof.validate(&admission(), Some(&binding)).unwrap();
        let before = fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap();
        drop(owner);
        let mut owner = RuntimeArtifactSourceCustody::open_mode(
            &directory.0.join("native"),
            installation(),
            [7; 32],
            false,
            Some((&directory.0.join("retained"), binding)),
        )
        .unwrap();
        owner
            .require_control_custody(&[(admission(), Some(wire))])
            .unwrap();
        assert!(owner.begin_governed(admission()).is_err());
        assert!(owner.denies(&input().configuration_digest).unwrap());
        assert_eq!(
            fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap(),
            before
        );
    }

    #[test]
    fn legacy_missing_pending_alias_and_wrong_identity_never_burn_issuance() {
        let legacy = Directory::new();
        let mut owner =
            RuntimeArtifactSourceCustody::initialize(&legacy.0, installation(), [7; 32]).unwrap();
        import(&mut owner);
        assert!(owner.begin_governed(admission()).is_err());
        assert!(!owner.denies(&input().configuration_digest).unwrap());
        let old_root = Directory::new();
        let binding = SourceRootBinding::for_directories(
            id(30),
            &old_root.0.join("native"),
            &old_root.0.join("retained"),
        )
        .unwrap();
        let mut prior = RuntimeArtifactSourceCustody::open_mode(
            &old_root.0.join("native"),
            installation(),
            [7; 32],
            true,
            Some((&old_root.0.join("retained"), binding)),
        )
        .unwrap();
        import(&mut prior);
        assert!(prior.begin_governed(admission()).is_err());
        assert!(!prior.denies(&input().configuration_digest).unwrap());
        let directory = Directory::new();
        let (mut owner, _) = rooted(&directory);
        assert!(owner.begin_governed(admission()).is_err());
        owner
            .record_observation(history::Observation::ImportPending(input()))
            .unwrap();
        assert!(owner.begin_governed(admission()).is_err());
        owner
            .record_observation(history::Observation::ImportCommitted(input()))
            .unwrap();
        for changed in [
            SourceDispositionAdmission {
                input_id: id(99),
                ..admission()
            },
            SourceDispositionAdmission {
                configuration_digest: Digest::of(b"wrong"),
                ..admission()
            },
            SourceDispositionAdmission {
                installation: SourceCustodyInstallation {
                    source_owner_id: id(99),
                    ..installation()
                },
                ..admission()
            },
        ] {
            assert!(owner.begin_governed(changed).is_err());
        }
        let alias = ImportIdentity {
            input_id: id(98),
            module_configuration_generation_id: id(97),
            ..input()
        };
        owner
            .record_observation(history::Observation::ImportPending(alias.clone()))
            .unwrap();
        owner
            .record_observation(history::Observation::ImportCommitted(alias))
            .unwrap();
        assert!(owner.begin_governed(admission()).is_err());
        assert!(!owner.denies(&input().configuration_digest).unwrap());
        assert!(owner.checked_state().unwrap().entries.is_empty());
    }

    #[test]
    fn every_consumed_or_unknown_boundary_protects_the_original_even_after_rollback() {
        for boundary in SourceConsumerBoundary::INSTALLED {
            let directory = Directory::new();
            let (mut owner, _) = rooted(&directory);
            import(&mut owner);
            owner
                .record_observation(history::Observation::ConsumedOrUnknown(SourceConsumerUse {
                    configuration_digest: input().configuration_digest,
                    consumer_id: "actual-native-owner".into(),
                    target_id: Some(id(40)),
                    original_id: id(41),
                    boundary: Some(boundary),
                }))
                .unwrap();
            let original =
                fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap();
            assert_eq!(
                owner.begin_governed(admission()).err(),
                Some(RuntimeError::Denied)
            );
            assert!(owner.checked_state().unwrap().entries.is_empty());
            assert_eq!(
                fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap(),
                original
            );
        }
    }

    #[test]
    fn incomplete_or_foreign_proof_and_unknown_original_cannot_be_reissued() {
        let directory = Directory::new();
        let (mut owner, binding) = rooted(&directory);
        import(&mut owner);
        let permit = owner.begin_governed(admission()).unwrap();
        let mut proof = permit.0.custody.clone().unwrap();
        proof.consumers.pop();
        assert!(proof.validate(&admission(), Some(&binding)).is_err());
        let mut proof = permit.0.custody.clone().unwrap();
        proof.binding.generation_id = id(99);
        assert!(proof.validate(&admission(), Some(&binding)).is_err());
        assert!(owner.begin_governed(admission()).is_err());
        let before = fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap();
        drop(permit);
        drop(owner);
        let mut owner = RuntimeArtifactSourceCustody::open_mode(
            &directory.0.join("native"),
            installation(),
            [7; 32],
            false,
            Some((&directory.0.join("retained"), binding)),
        )
        .unwrap();
        assert!(owner.begin_governed(admission()).is_err());
        assert!(owner.denies(&input().configuration_digest).unwrap());
        assert!(
            owner.checked_state().unwrap().entries[0]
                .signed_denial
                .is_none()
        );
        assert_eq!(
            fs::read(directory.0.join("native/runtime-artifact-source.json")).unwrap(),
            before
        );
    }
}
