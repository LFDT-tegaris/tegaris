//! Local transport for the existing signed RuntimeActivationAck. Only the
//! serving target publishes; Fleet verifies exact generation and fresh time.
use openpc_runtime_agent::{RuntimeActivationAck, RuntimeAgent, RuntimeWireVerifier};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const FILE: &str = "request-observed.cose";
const MAX_BYTES: usize = 4096;
pub const FRESHNESS_NS: u64 = 15_000_000_000;

/// Called only by the running protected target, with its exclusively owned
/// RuntimeAgent. No supplied digest or readiness flag can create an ACK.
pub fn publish(
    directory: &Path,
    agent: &RuntimeAgent,
    protected_class_set: &Digest,
    now_ns: u64,
) -> RuntimeResult<()> {
    let Some(bytes) = agent.observed_active_ack(protected_class_set, now_ns)? else {
        return clear(directory);
    };
    if bytes.len() > MAX_BYTES {
        return Err(RuntimeError::BudgetExhausted);
    }
    let pending = directory.join("request-observed.cose.next");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&pending)
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    fs::rename(&pending, directory.join(FILE)).map_err(|_| RuntimeError::RuntimeUnavailable)?;
    sync(directory)
}

pub fn clear(directory: &Path) -> RuntimeResult<()> {
    match fs::remove_file(directory.join(FILE)) {
        Ok(()) => sync(directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RuntimeError::RuntimeUnavailable),
    }
}

fn sync(directory: &Path) -> RuntimeResult<()> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| RuntimeError::RuntimeUnavailable)
}

/// Missing or expired evidence is pending, never matched. Invalid signed
/// material remains an error instead of being treated as a retryable absence.
pub fn read(
    directory: &Path,
    agent_public_key: &[u8],
    target: &str,
    agent_signer_id: &str,
    capsule: &Digest,
    generation: u64,
    now_ns: u64,
) -> RuntimeResult<Option<RuntimeActivationAck>> {
    let file = match File::open(directory.join(FILE)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(RuntimeError::RuntimeUnavailable),
    };
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    if bytes.len() > MAX_BYTES {
        return Err(RuntimeError::BudgetExhausted);
    }
    let ack = RuntimeWireVerifier::from_public_key_bytes(agent_public_key)?.verify_ack(&bytes)?;
    if ack.target_runtime_id != target
        || ack.signer_id != agent_signer_id
        || ack.status != 1
        || ack.reason_code != "REQUEST_OBSERVED"
        || ack.acknowledged_at_ns > now_ns
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    if ack.capsule_digest != *capsule
        || ack.generation != generation
        || now_ns.saturating_sub(ack.acknowledged_at_ns) >= FRESHNESS_NS
    {
        return Ok(None);
    }
    Ok(Some(ack))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpc_runtime_agent::RuntimeWireSigner;

    #[test]
    fn observed_ack_requires_exact_target_generation_signer_and_fresh_time() {
        let root = std::env::var_os("OPENPC_TEST_TMP_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("runtime-observation-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        let signer = RuntimeWireSigner::from_secret_bytes([53; 32]).unwrap();
        let public = signer.verifier().public_key_bytes();
        let digest = Digest::of("actual capsule");
        let ack = RuntimeActivationAck {
            ack_id: uuid::Uuid::now_v7().to_string(),
            target_runtime_id: "target".into(),
            capsule_digest: digest.clone(),
            generation: 2,
            status: 1,
            reason_code: "REQUEST_OBSERVED".into(),
            acknowledged_at_ns: 100,
            agent_sequence: 2,
            signer_id: "agent".into(),
        };
        let read = |now, generation, digest: &Digest| {
            super::read(&root, &public, "target", "agent", digest, generation, now)
        };
        assert!(read(101, 2, &digest).unwrap().is_none());
        fs::write(root.join(FILE), signer.sign_ack(&ack).unwrap()).unwrap();
        assert_eq!(read(101, 2, &digest).unwrap(), Some(ack.clone()));
        assert!(read(100 + FRESHNESS_NS, 2, &digest).unwrap().is_none());
        assert!(read(101, 3, &digest).unwrap().is_none());
        assert!(
            read(101, 2, &Digest::of("other capsule"))
                .unwrap()
                .is_none()
        );
        assert!(read(99, 2, &digest).is_err());
        let mut wrong = ack.clone();
        wrong.target_runtime_id = "another target".into();
        fs::write(root.join(FILE), signer.sign_ack(&wrong).unwrap()).unwrap();
        assert!(read(101, 2, &digest).is_err());
        let foreign = RuntimeWireSigner::from_secret_bytes([54; 32]).unwrap();
        fs::write(root.join(FILE), foreign.sign_ack(&ack).unwrap()).unwrap();
        assert!(read(101, 2, &digest).is_err());
        OpenOptions::new()
            .write(true)
            .open(root.join(FILE))
            .unwrap()
            .set_len((MAX_BYTES + 1) as u64)
            .unwrap();
        assert_eq!(read(101, 2, &digest), Err(RuntimeError::BudgetExhausted));
        clear(&root).unwrap();
        clear(&root).unwrap();
        assert!(read(101, 2, &digest).unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }
}
