//! Serialized consumer of the existing work queue and controller custody journal.
use super::*;
use openpc_fleet_controller::cigl_publication::{
    profile_store::{self, CompilationWork},
    reviewed_profile::InstalledAnalysisSources,
};
use pc_policy_core::cigl::profile::publication::PURPOSE;
use pc_runtime_types::{RuntimeError, RuntimeResult};

fn target_key(target: &str) -> RuntimeResult<Vec<u8>> {
    let path = env::var_os("OPENPC_CIGL_ANALYSIS_TARGET_KEYS_FILE")
        .ok_or(RuntimeError::InvalidAuthorization)?;
    let bytes = fs::read(path).map_err(|_| RuntimeError::InvalidAuthorization)?;
    target_key_from_bytes(target, &bytes)
}

fn target_key_from_bytes(target: &str, bytes: &[u8]) -> RuntimeResult<Vec<u8>> {
    if bytes.len() > 65_536 {
        return Err(RuntimeError::BudgetExhausted);
    }
    let keys: BTreeMap<String, String> =
        serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidAuthorization)?;
    if keys.iter().any(|(id, key)| {
        !uuid::Uuid::parse_str(id)
            .is_ok_and(|parsed| parsed.get_version_num() == 7 && parsed.to_string() == *id)
            || key.len() != 66
            || !(key.starts_with("02") || key.starts_with("03"))
            || !key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return Err(RuntimeError::InvalidAuthorization);
    }
    let key = keys.get(target).ok_or(RuntimeError::InvalidAuthorization)?;
    (0..key.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&key[i..i + 2], 16).map_err(|_| RuntimeError::InvalidAuthorization)
        })
        .collect()
}

pub(super) struct InstalledCustody {
    pub(super) capsule: RuntimeCapsule,
    artifacts: BTreeMap<Digest, Vec<u8>>,
    invocation: Arc<openpc_runtime_agent::invocation_custody::InvocationArtifactAdmission>,
    pub(super) activation_token: Vec<u8>,
    pub(super) activation_receipt: Vec<u8>,
}
pub(super) struct InstalledSources {
    custody: InstalledCustody,
    target_key: Vec<u8>,
}
impl InstalledSources {
    pub(super) fn borrowed(&self) -> InstalledAnalysisSources<'_> {
        InstalledAnalysisSources {
            capsule: &self.custody.capsule,
            artifacts: &self.custody.artifacts,
            invocation: &self.custody.invocation,
            target_verification_key: &self.target_key,
        }
    }
    pub(super) fn activation_proof(self) -> (Vec<u8>, Vec<u8>) {
        (
            self.custody.activation_token,
            self.custody.activation_receipt,
        )
    }
}
impl InstalledCustody {
    pub(super) fn configuration(
        &self,
    ) -> RuntimeResult<pc_policy_core::invocation::ActiveInvocationConfigurationV1> {
        let (bytes, _) = self
            .invocation
            .analysis_source_bytes(&self.capsule, &self.artifacts)?;
        decode_active_invocation_configuration(bytes, &Digest::of(bytes))
    }
}

/// Analysis additionally requires its installed target key. Ordinary transport
/// restoration reads the same authenticated custody without claiming analysis.
pub(super) fn load_installed_sources(
    config: &Config,
    target: &str,
    capsule_digest: &Digest,
) -> RuntimeResult<InstalledSources> {
    let key = target_key(target)?;
    Ok(InstalledSources {
        custody: load_installed_custody(config, target, capsule_digest)?,
        target_key: key,
    })
}

pub(super) fn load_installed_custody(
    config: &Config,
    target: &str,
    capsule_digest: &Digest,
) -> RuntimeResult<InstalledCustody> {
    let owners = prior_governed_owners(config, target, Some(capsule_digest))
        .map_err(|_| RuntimeError::InvalidAuthorization)?
        .ok_or(RuntimeError::InvalidAuthorization)?;
    let stable = Digest::of(b"OpenPC R1 runtime primary registry v1");
    let fleet = RuntimeWireSigner::from_secret_bytes(config.fleet_key)?;
    // Read one authenticated committed snapshot without taking the live
    // target's writer lock or creating any replacement journal/cache.
    let directory = Path::new("/runtime/agent").join(target);
    if !directory.is_dir() {
        return Err(RuntimeError::GenerationMismatch);
    }
    let (capsule, artifacts, activation_token, activation_receipt) =
        RuntimeAgent::read_canonical_activation(
            &CapsuleTrust {
                target_id: target.to_owned(),
                fleet_id: "openpc-local-runtime-fleet".into(),
                fleet_signer_id: "openpc-local-fleet-signer".into(),
                agent_signer_id: "openpc-local-agent-signer".into(),
                contract_set_manifest_digest: stable.clone(),
                schema_registry_digest: stable.clone(),
                cose_purpose_registry_digest: stable,
                complete_component_set_digest: Digest::of(
                    b"OpenPC R1 runtime complete component set v1",
                ),
            },
            &fleet.verifier().public_key_bytes(),
            &RuntimeWireSigner::from_secret_bytes(config.agent_key)?
                .verifier()
                .public_key_bytes(),
            &directory,
            Some(capsule_digest),
            &GovernedOrBootstrapAdmission {
                governed: observed_admission("identity", owners.identity),
            },
            |capsule, artifacts, token, receipt| {
                Ok((
                    capsule.clone(),
                    owners
                        .invocation
                        .analysis_source_snapshot(capsule, artifacts)?,
                    token.to_vec(),
                    receipt.to_vec(),
                ))
            },
        )?;
    Ok(InstalledCustody {
        capsule,
        artifacts,
        invocation: owners.invocation,
        activation_token,
        activation_receipt,
    })
}

async fn compile(pool: &PgPool, config: &Config, work: &CompilationWork) -> RuntimeResult<()> {
    let sources = load_installed_sources(config, &work.target_runtime_id, &work.capsule_digest)?;
    let signer = PurposeSigner::from_secret_bytes(PURPOSE, config.fleet_key)?;
    profile_store::compile_and_commit(pool, work, &sources.borrowed(), &signer).await
}

pub(super) async fn tick(pool: &PgPool, config: &Config) -> WorkerResult<()> {
    let work = profile_store::claim_next(
        pool,
        &config.participant_id,
        &config.privacy_domain_id,
        &config.worker_id,
    )
    .await
    .map_err(|_| "CIGL compilation claim unavailable")?;
    if let Some(work) = work
        && let Err(error) = compile(pool, config, &work).await
    {
        eprintln!(
            "{{\"boundary\":\"cigl_profile_compilation\",\"pc_code\":\"{}\"}}",
            error.pc_code()
        );
        profile_store::fail_or_retry(pool, &work, error)
            .await
            .map_err(|_| "CIGL compilation result unavailable")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn analysis_requires_an_exact_valid_installed_target_key() {
        let target = "018f0000-0000-7000-8000-000000000301";
        assert_eq!(
            target_key_from_bytes(target, b"{}"),
            Err(RuntimeError::InvalidAuthorization)
        );
        let key = format!("02{}", "01".repeat(32));
        let encoded = serde_json::to_vec(&BTreeMap::from([(target, key)])).unwrap();
        assert_eq!(target_key_from_bytes(target, &encoded).unwrap().len(), 33);
        assert_eq!(
            target_key_from_bytes("018f0000-0000-7000-8000-000000000302", &encoded),
            Err(RuntimeError::InvalidAuthorization)
        );
        let malformed = serde_json::to_vec(&BTreeMap::from([(target, "04")])).unwrap();
        assert_eq!(
            target_key_from_bytes(target, &malformed),
            Err(RuntimeError::InvalidAuthorization)
        );
    }
}
