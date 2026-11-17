//! Denial of one authenticated expired effect. This never confirms activation,
//! restores serving, renews authority or reconstructs first-issue capability.
use super::*;
use pc_runtime_types::target_disposition::TargetDispositionAction;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{io::Read, os::unix::fs::MetadataExt};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct OperatorBundle {
    intent_bytes_hex: String,
    capsule_hex: String,
    token_hex: String,
    receipt_hex: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OperatorPurpose {
    Initial,
    Handover,
    CredentialHandover,
}
impl OperatorPurpose {
    fn intent(self) -> &'static str {
        match self {
            Self::Initial => "EXPIRED_OBSERVED_DENIAL_V1",
            Self::Handover => "EXPIRED_OBSERVED_UNSIGNED_DENIAL_HANDOVER_V1",
            Self::CredentialHandover => "EXPIRED_OBSERVED_CREDENTIAL_DENIAL_HANDOVER_V1",
        }
    }
    fn request_domain(self) -> &'static [u8] {
        match self {
            Self::Initial => b"OPENPC_EXPIRED_ACTIVATION_OPERATOR_REQUEST_V1",
            Self::Handover => b"OPENPC_EXPIRED_UNSIGNED_DENIAL_HANDOVER_REQUEST_V1",
            Self::CredentialHandover => b"OPENPC_EXPIRED_CREDENTIAL_DENIAL_HANDOVER_REQUEST_V1",
        }
    }
    fn proof_domain(self) -> &'static [u8] {
        match self {
            Self::Initial => b"OPENPC_EXPIRED_ACTIVATION_DENIAL_V1",
            Self::Handover => b"OPENPC_EXPIRED_UNSIGNED_DENIAL_HANDOVER_V1",
            Self::CredentialHandover => b"OPENPC_EXPIRED_CREDENTIAL_DENIAL_HANDOVER_V1",
        }
    }
}

struct ExpiredDenialIntent<'a> {
    pub intent: &'a Value,
    pub bytes: &'a [u8],
    pub digest: &'a str,
    purpose: OperatorPurpose,
    certificate_until_ms: u64,
}

impl TargetDispositionStore {
    /// The target's TLS identity is necessary but insufficient. Only the host
    /// operator has the installation MAC key; ordinary targets cannot request
    /// a new admission. The installed controller retains its source owner.
    pub(crate) async fn deny_expired_operator(
        &self,
        extensions: &http::Extensions,
        fleet: &crate::FleetController,
        bytes: &[u8],
        nonce: &[u8],
        signature: &[u8],
    ) -> Result<Digest> {
        self.expired_operator(
            extensions,
            fleet,
            bytes,
            nonce,
            signature,
            OperatorPurpose::Initial,
        )
        .await
    }

    pub(crate) async fn handover_unsigned_expired_operator(
        &self,
        extensions: &http::Extensions,
        fleet: &crate::FleetController,
        bytes: &[u8],
        nonce: &[u8],
        signature: &[u8],
    ) -> Result<Digest> {
        self.expired_operator(
            extensions,
            fleet,
            bytes,
            nonce,
            signature,
            OperatorPurpose::Handover,
        )
        .await
    }

    pub(crate) async fn handover_expired_credential_operator(
        &self,
        extensions: &http::Extensions,
        fleet: &crate::FleetController,
        bytes: &[u8],
        nonce: &[u8],
        signature: &[u8],
    ) -> Result<Digest> {
        self.expired_operator(
            extensions,
            fleet,
            bytes,
            nonce,
            signature,
            OperatorPurpose::CredentialHandover,
        )
        .await
    }

    async fn expired_operator(
        &self,
        extensions: &http::Extensions,
        fleet: &crate::FleetController,
        bytes: &[u8],
        nonce: &[u8],
        signature: &[u8],
        purpose: OperatorPurpose,
    ) -> Result<Digest> {
        let (peer, certificate_until_ms) =
            crate::runtime_tls::authenticated_target(extensions, fleet)
                .map_err(|_| unavailable())?;
        if bytes.is_empty()
            || bytes.len() > 128 * 1024
            || nonce.len() != 32
            || signature.len() != 32
        {
            return Err(unavailable());
        }
        if purpose == OperatorPurpose::Initial {
            verify_operator_mac(&self.commit_key, bytes, nonce, signature)?;
        } else {
            operator_mac_for(purpose, &self.commit_key, bytes, nonce)?
                .verify_slice(signature)
                .map_err(|_| unavailable())?;
        }

        let bundle: OperatorBundle = serde_json::from_slice(bytes).map_err(|_| unavailable())?;
        let intent_bytes = decode(&bundle.intent_bytes_hex, 16_384)?;
        let intent: Value = serde_json::from_slice(&intent_bytes).map_err(|_| unavailable())?;
        if intent["purpose"] != purpose.intent()
            || intent["custody"]["runtimeTargetId"] != peer.target_id
        {
            return Err(unavailable());
        }
        require_operator_window(&intent)?;
        require_receiver_seal(&intent["custody"])?;
        let mut checked = self.pool.begin().await.map_err(|_| unavailable())?;
        self.context(&mut checked).await?;
        let matches:bool=sqlx::query_scalar("select current_user::text=$1 and session_user::text=$1 and current_database()=$2 and host(inet_server_addr())=$3 and (select oid::text from pg_database where datname=current_database())=$4 and current_setting('role')='none' and pg_has_role(current_user,'openpc_control_worker','USAGE') and not pg_has_role(current_user,'openpc_control_owner','USAGE') and not exists(select 1 from pg_roles where rolname=current_user and (rolsuper or rolbypassrls))")
            .bind(intent["custody"]["databaseRole"].as_str().ok_or_else(unavailable)?)
            .bind(intent["custody"]["databaseName"].as_str().ok_or_else(unavailable)?)
            .bind(intent["custody"]["databaseServerAddress"].as_str().ok_or_else(unavailable)?)
            .bind(intent["custody"]["databaseOid"].as_str().ok_or_else(unavailable)?)
            .fetch_one(&mut *checked).await.map_err(|_| unavailable())?;
        checked.rollback().await.map_err(|_| unavailable())?;
        if !matches {
            return Err(unavailable());
        }
        let capsule =
            openpc_runtime_agent::RuntimeCapsule::decode(&decode(&bundle.capsule_hex, 64 * 1024)?)
                .map_err(|_| unavailable())?;
        let token = decode(&bundle.token_hex, 16 * 1024)?;
        let receipt = decode(&bundle.receipt_hex, 16 * 1024)?;
        let artifacts = std::collections::BTreeMap::new();
        let digest = format!("sha256:{}", Digest::of(&intent_bytes).as_str());
        let pending = self
            .begin_expired_activation_denial(
                OriginalTargetActivation {
                    peer: &peer,
                    capsule: &capsule,
                    signed_token: &token,
                    signed_receipt: &receipt,
                    artifacts: &artifacts,
                },
                ExpiredDenialIntent {
                    intent: &intent,
                    bytes: &intent_bytes,
                    digest: &digest,
                    purpose,
                    certificate_until_ms,
                },
            )
            .await?;
        // No retry/reconstruction after this capability is consumed. Stored
        // delivery bytes, rather than a fresh signature, own later readback.
        let delivery = self.sign_committed_withdrawal(pending).await?;
        Ok(Digest::of(&delivery))
    }

    async fn begin_expired_activation_denial(
        &self,
        original: OriginalTargetActivation<'_>,
        request: ExpiredDenialIntent<'_>,
    ) -> Result<PendingTargetDisposition> {
        let OriginalTargetActivation {
            peer,
            capsule,
            signed_token,
            signed_receipt,
            ..
        } = original;
        if request.bytes.len() > 16_384
            || request.digest != format!("sha256:{}", Digest::of(request.bytes).as_str())
            || serde_json::from_slice::<Value>(request.bytes).map_err(|_| unavailable())?
                != *request.intent
            || request.intent["purpose"] != request.purpose.intent()
        {
            return Err(unavailable());
        }
        let bootstrap = if request.purpose == OperatorPurpose::CredentialHandover {
            let transition: crate::runtime_target::disposition::ExpiredDenialCredentialTransition =
                serde_json::from_value(request.intent["credentialTransition"].clone())
                    .map_err(|_| unavailable())?;
            let binding = self
                .bootstrap_for_expired_credential_denial(
                    peer,
                    capsule,
                    &transition.rotation_operation_id,
                )
                .await?;
            if binding.credential_predecessor.as_ref() != Some(&transition.predecessor_target)
                || binding.target.credential_id != transition.successor_credential_id
            {
                return Err(unavailable());
            }
            binding
        } else {
            if request.intent.get("credentialTransition").is_some() {
                return Err(unavailable());
            }
            self.bootstrap_for_activation(peer, capsule).await?
        };
        let target_key = self
            .runtime_target_keys
            .lock()
            .map_err(|_| unavailable())?
            .get(&peer.target_id)
            .cloned()
            .ok_or_else(unavailable)?;
        let token = self
            .runtime_control
            .verify_activation_token(signed_token)
            .map_err(|_| unavailable())?;
        let receipt = openpc_runtime_agent::RuntimeWireVerifier::from_public_key_bytes(&target_key)
            .and_then(|v| v.verify_receipt(signed_receipt))
            .map_err(|_| unavailable())?;
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| unavailable())?
                .as_nanos(),
        )
        .map_err(|_| unavailable())?;
        // The authentic receipt timestamp is used solely to verify ORIGINAL
        // custody. Actual wall time independently requires expiry for denial.
        restore_custody::require_original_custody(
            capsule,
            &token,
            &receipt,
            &bootstrap.source,
            &peer.target_id,
            receipt.observed_at_ns,
        )?;
        if capsule.hard_expiry_ns > now
            || capsule.previous_capsule_digest.is_none()
            || receipt.signer_id != "openpc-local-agent-signer"
            || request.intent["custody"]["occurrenceId"] != token.occurrence_id
        {
            return Err(unavailable());
        }
        if request.purpose != OperatorPurpose::Initial {
            let handover: crate::runtime_target::disposition::ExpiredUnsignedDenialHandover =
                serde_json::from_value(request.intent["handover"].clone())
                    .map_err(|_| unavailable())?;
            if handover.abandoned_revision != handover.floor.observed_revision
                || handover.abandoned_admission_digest != handover.floor.observed_admission_digest
                || handover.floor.installed_revision.checked_add(1)
                    != Some(handover.abandoned_revision)
                || handover.floor.original_receipt_wire_digest != Digest::of(signed_receipt)
                || request.intent["custody"]["deliveryDigest"]
                    != format!(
                        "sha256:{}",
                        handover.floor.installed_delivery_digest.as_str()
                    )
            {
                return Err(unavailable());
            }
        } else if request.intent.get("handover").is_some() {
            return Err(unavailable());
        }
        let issued_ms = request.intent["issuedAtMs"]
            .as_u64()
            .ok_or_else(unavailable)?;
        let expires_ms = request.intent["expiresAtMs"]
            .as_u64()
            .ok_or_else(unavailable)?;
        let worker = request.intent["custody"]["workerId"]
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 256)
            .ok_or_else(unavailable)?
            .to_owned();
        let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
        let prepared: Result<(TargetDispositionDelivery,u64)> = async {
        self.context(&mut tx).await?;
        self.lock_fact_disposition_roots(&mut tx,&peer.target_id).await?;
        let identity = self.bootstrap_identity(&mut tx,peer).await?;
        if identity != bootstrap.target { return Err(unavailable()); }
        let credential_until:i64=sqlx::query_scalar("select floor(extract(epoch from valid_until)*1000)::bigint from control.credential where participant_id=openpc.current_participant_id() and credential_id=$1::text::uuid")
            .bind(&identity.credential_id).fetch_one(&mut *tx).await.map_err(|_|unavailable())?;
        let effective_expires=effective_operator_expiry(expires_ms,request.certificate_until_ms,credential_until,issued_ms)?;

        let transaction: String = sqlx::query_scalar("select pg_current_xact_id()::text")
            .fetch_one(&mut *tx).await.map_err(|_| unavailable())?;
        let proof = json!({"version":1,"transactionId":transaction,
            "intent":request.intent,"intentBytesHex":hex_bytes(request.bytes),"intentDigest":request.digest,
            "source":bootstrap.source,"target":identity,"capsuleGeneration":capsule.generation,
            "capsuleNotBeforeNs":capsule.not_before_ns.to_string(),"capsuleExpiresAtNs":capsule.hard_expiry_ns.to_string(),
            "observedAtNs":receipt.observed_at_ns.to_string(),"receiptWireDigest":Digest::of(signed_receipt),
            "tokenDigest":Digest::of(signed_token)});
        let wire = canonical_bytes(&proof).map_err(|_| unavailable())?;
        let mut nonce=[0u8;32];
        nonce[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        nonce[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        let mut mac=<Hmac<Sha256> as KeyInit>::new_from_slice(&self.commit_key).map_err(|_| unavailable())?;
        mac.update(request.purpose.proof_domain());mac.update(&Sha256::digest(&wire));mac.update(&nonce);
            let query=match request.purpose {
                OperatorPurpose::Initial=>"select binding,admission_digest from openpc.begin_expired_activation_denial($1,$2,$3)",
                OperatorPurpose::Handover=>"select binding,admission_digest from openpc.begin_expired_denial_handover($1,$2,$3)",
                OperatorPurpose::CredentialHandover=>"select binding,admission_digest from openpc.begin_expired_credential_denial_handover($1,$2,$3)",
            };
            let row = sqlx::query(query)
            .bind(wire).bind(nonce.as_slice()).bind(mac.finalize().into_bytes().as_slice())
            .fetch_one(&mut *tx).await.map_err(database_error)?;
        let mut binding:Value=row.try_get("binding").map_err(|_| unavailable())?;
        let digest:String=row.try_get("admission_digest").map_err(|_| unavailable())?;
        let digest=Digest::parse(digest.strip_prefix("sha256:").ok_or_else(unavailable)?).map_err(|_| unavailable())?;
        if Digest::of(canonical_bytes(&binding).map_err(|_| unavailable())?)!=digest { return Err(unavailable()); }
        binding.as_object_mut().ok_or_else(unavailable)?.insert("committed_admission_digest".into(),json!(digest));
        let claims:TargetDispositionDelivery=serde_json::from_value(binding).map_err(|_| unavailable())?;
        claims.validate().map_err(|_| unavailable())?;
        if claims.action!=TargetDispositionAction::Withdraw || claims.target!=identity || claims.source!=bootstrap.source {
            return Err(unavailable());
        }
        require_operator_window(request.intent)?;
        Ok((claims,effective_expires))
        }.await;
        let (claims, effective_expires) = match prepared {
            Ok(claims) => claims,
            Err(error) => {
                if tx.rollback().await.is_err() {
                    return Err(format!("{error}; denial admission rollback unconfirmed"));
                }
                return Err(error);
            }
        };
        let permit = issuance::FirstIssuePermit::commit_new(tx, None, claims.clone())
            .await?
            .with_operator_window(issued_ms, effective_expires);
        Ok(PendingTargetDisposition {
            claims,
            first_issue: Some(permit),
            worker,
        })
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode(text: &str, maximum: usize) -> Result<Vec<u8>> {
    if text.is_empty()
        || text.len() > maximum * 2
        || !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(unavailable());
    }
    (0..text.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&text[n..n + 2], 16).map_err(|_| unavailable()))
        .collect()
}

// The capability cannot outlive either independently checked credential bound.
fn effective_operator_expiry(
    intent_until: u64,
    tls_until: u64,
    credential_until: i64,
    issued: u64,
) -> Result<u64> {
    let until = intent_until
        .min(tls_until)
        .min(u64::try_from(credential_until).map_err(|_| unavailable())?);
    if until <= issued {
        return Err(unavailable());
    }
    Ok(until)
}

fn require_operator_window(intent: &Value) -> Result<()> {
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| unavailable())?
            .as_millis(),
    )
    .map_err(|_| unavailable())?;
    require_operator_window_at(intent, now)
}

fn require_operator_window_at(intent: &Value, now: u64) -> Result<()> {
    let issued = intent["issuedAtMs"].as_u64().ok_or_else(unavailable)?;
    let expires = intent["expiresAtMs"].as_u64().ok_or_else(unavailable)?;
    let id = intent["requestId"].as_str().ok_or_else(unavailable)?;
    if uuid::Uuid::parse_str(id).is_err()
        || issued > now
        || expires <= now
        || expires
            .checked_sub(issued)
            .is_none_or(|v| v == 0 || v > 120_000)
    {
        return Err(unavailable());
    }
    Ok(())
}

fn require_receiver_seal(custody: &Value) -> Result<()> {
    let path = std::path::Path::new("/run/openpc-maintenance/installation.json");
    let metadata = std::fs::symlink_metadata(path).map_err(|_| unavailable())?;
    let parent = std::fs::symlink_metadata(path.parent().ok_or_else(unavailable)?)
        .map_err(|_| unavailable())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o444
        || parent.file_type().is_symlink()
        || parent.uid() != 0
        || parent.mode() & 0o022 != 0
    {
        return Err(unavailable());
    }
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").map_err(|_| unavailable())?;
    let mut covering = Vec::new();
    for line in mounts.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() > 5 && path.starts_with(f[4]) {
            covering.push((f[4], f[5]));
        }
    }
    let depth = covering
        .iter()
        .map(|(p, _)| p.len())
        .max()
        .ok_or_else(unavailable)?;
    let effective: Vec<_> = covering
        .into_iter()
        .filter(|(p, _)| p.len() == depth)
        .collect();
    if effective.len() != 1
        || effective[0].0 != "/run/openpc-maintenance"
        || !effective[0].1.split(',').any(|v| v == "ro")
    {
        return Err(unavailable());
    }
    let file = std::fs::File::open(path).map_err(|_| unavailable())?;
    let opened = file.metadata().map_err(|_| unavailable())?;
    if opened.len() > 16384
        || (opened.dev(), opened.ino(), opened.uid(), opened.mode())
            != (
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.mode(),
            )
    {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    file.take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() as u64 != opened.len() {
        return Err(unavailable());
    }
    let seal: Value = serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
    let mut expected = serde_json::Map::new();
    for key in [
        "schemaVersion",
        "installationId",
        "vmBootId",
        "sourceRevision",
        "controllerImageId",
        "executableDigest",
        "databaseName",
        "databaseRole",
        "workerRole",
        "databaseInstallationId",
        "databaseServerAddress",
        "databaseOid",
        "workerId",
        "participantId",
        "privacyDomainId",
    ] {
        expected.insert(key.into(), custody[key].clone());
    }
    if seal != Value::Object(expected)
        || custody["workerRole"] != "openpc_control_worker"
        || std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|_| unavailable())?
            .trim()
            != custody["vmBootId"].as_str().ok_or_else(unavailable)?
    {
        return Err(unavailable());
    }
    let mut exe = std::fs::File::open("/proc/self/exe").map_err(|_| unavailable())?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = exe.read(&mut buffer).map_err(|_| unavailable())?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    if custody["executableDigest"] != format!("sha256:{}", hex_bytes(&hash.finalize())) {
        return Err(unavailable());
    }
    Ok(())
}

fn operator_mac(key: &[u8], bytes: &[u8], nonce: &[u8]) -> Result<Hmac<Sha256>> {
    operator_mac_for(OperatorPurpose::Initial, key, bytes, nonce)
}
fn operator_mac_for(
    purpose: OperatorPurpose,
    key: &[u8],
    bytes: &[u8],
    nonce: &[u8],
) -> Result<Hmac<Sha256>> {
    if bytes.is_empty() || bytes.len() > 128 * 1024 || nonce.len() != 32 {
        return Err(unavailable());
    }
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| unavailable())?;
    mac.update(purpose.request_domain());
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(&Sha256::digest(bytes));
    mac.update(nonce);
    Ok(mac)
}
fn verify_operator_mac(key: &[u8], bytes: &[u8], nonce: &[u8], signature: &[u8]) -> Result<()> {
    if signature.len() != 32 {
        return Err(unavailable());
    }
    operator_mac(key, bytes, nonce)?
        .verify_slice(signature)
        .map_err(|_| unavailable())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operator_mac_binds_payload_nonce_key_and_domain() {
        let key = [19u8; 32];
        let body = b"original operator intent";
        let nonce = [71u8; 32];
        let mac = operator_mac(&key, body, &nonce)
            .unwrap()
            .finalize()
            .into_bytes();
        assert!(verify_operator_mac(&key, body, &nonce, &mac).is_ok());
        for (k, b, n) in [
            (&[20u8; 32][..], &body[..], &nonce[..]),
            (&key[..], &b"changed operator intent"[..], &nonce[..]),
            (&key[..], &body[..], &[72u8; 32][..]),
        ] {
            assert!(verify_operator_mac(k, b, n, &mac).is_err());
        }
        assert!(verify_operator_mac(&key, body, &nonce, &[]).is_err());
        assert!(verify_operator_mac(&key, body, &[], &mac).is_err());
        assert!(verify_operator_mac(&key, &[], &nonce, &mac).is_err());
        let mut other = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
        other.update(b"OPENPC_EXPIRED_ACTIVATION_DENIAL_V1");
        other.update(&Sha256::digest(body));
        other.update(&nonce);
        assert!(verify_operator_mac(&key, body, &nonce, &other.finalize().into_bytes()).is_err());
    }
    #[test]
    fn original_and_handover_operator_requests_cannot_cross_domains() {
        let key = [93u8; 32];
        let nonce = [94u8; 32];
        let body = b"exact sealed bytes";
        let old = operator_mac_for(OperatorPurpose::Initial, &key, body, &nonce)
            .unwrap()
            .finalize()
            .into_bytes();
        let new = operator_mac_for(OperatorPurpose::Handover, &key, body, &nonce)
            .unwrap()
            .finalize()
            .into_bytes();
        assert!(
            operator_mac_for(OperatorPurpose::Handover, &key, body, &nonce)
                .unwrap()
                .verify_slice(&old)
                .is_err()
        );
        assert!(verify_operator_mac(&key, body, &nonce, &new).is_err());
        assert!(
            operator_mac_for(OperatorPurpose::Handover, &key, body, &nonce)
                .unwrap()
                .verify_slice(&new)
                .is_ok()
        );
        assert_ne!(
            OperatorPurpose::Initial.proof_domain(),
            OperatorPurpose::Handover.proof_domain()
        );
        assert_ne!(
            OperatorPurpose::Handover.request_domain(),
            OperatorPurpose::Handover.proof_domain()
        );
    }
    #[test]
    fn three_operator_purposes_have_disjoint_authenticated_domains() {
        let purposes = [
            OperatorPurpose::Initial,
            OperatorPurpose::Handover,
            OperatorPurpose::CredentialHandover,
        ];
        let key = [83u8; 32];
        let nonce = [84u8; 32];
        let body = b"same pending observed denial";
        for (i, purpose) in purposes.iter().enumerate() {
            let signed = operator_mac_for(*purpose, &key, body, &nonce)
                .unwrap()
                .finalize()
                .into_bytes();
            for (j, other) in purposes.iter().enumerate() {
                assert_eq!(
                    operator_mac_for(*other, &key, body, &nonce)
                        .unwrap()
                        .verify_slice(&signed)
                        .is_ok(),
                    i == j
                );
                if i != j {
                    assert_ne!(purpose.intent(), other.intent());
                    assert_ne!(purpose.proof_domain(), other.proof_domain());
                }
                assert_ne!(purpose.request_domain(), other.proof_domain());
            }
        }
    }
    #[test]
    fn operator_capability_ends_at_the_earliest_independent_credential_bound() {
        assert_eq!(
            effective_operator_expiry(5000, 7000, 9000, 1000).unwrap(),
            5000
        );
        assert_eq!(
            effective_operator_expiry(7000, 5000, 9000, 1000).unwrap(),
            5000
        );
        assert_eq!(
            effective_operator_expiry(7000, 9000, 5000, 1000).unwrap(),
            5000
        );
        for (intent, tls, credential) in [
            (1000, 7000, 9000),
            (7000, 1000, 9000),
            (7000, 9000, 1000),
            (7000, 9000, -1),
        ] {
            assert!(effective_operator_expiry(intent, tls, credential, 1000).is_err());
        }
    }
    #[test]
    fn operator_window_excludes_expired_future_and_extended_requests() {
        let mut i = json!({"requestId":"018f0000-0000-7000-8000-000000000101","issuedAtMs":1000,"expiresAtMs":121000});
        assert!(require_operator_window_at(&i, 1000).is_ok());
        assert!(require_operator_window_at(&i, 120999).is_ok());
        assert!(require_operator_window_at(&i, 999).is_err());
        assert!(require_operator_window_at(&i, 121000).is_err());
        i["expiresAtMs"] = json!(121001);
        assert!(require_operator_window_at(&i, 1000).is_err());
        i["expiresAtMs"] = json!(1000);
        assert!(require_operator_window_at(&i, 1000).is_err());
        i["expiresAtMs"] = json!(2000);
        i["requestId"] = json!("foreign");
        assert!(require_operator_window_at(&i, 1000).is_err());
    }
    #[test]
    fn raw_artifacts_are_bounded_and_bundle_rejects_unknown_fields() {
        assert_eq!(decode("00ff", 2).unwrap(), vec![0, 255]);
        for value in ["", "0", "0F", "gg", "000000"] {
            assert!(decode(value, 2).is_err());
        }
        let mut value =
            json!({"intentBytesHex":"00","capsuleHex":"00","tokenHex":"00","receiptHex":"00"});
        assert!(serde_json::from_value::<OperatorBundle>(value.clone()).is_ok());
        value["authority"] = json!("caller-controlled");
        assert!(serde_json::from_value::<OperatorBundle>(value).is_err());
    }
}
