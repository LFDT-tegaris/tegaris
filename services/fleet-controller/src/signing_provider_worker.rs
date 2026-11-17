//! Dispatch only the external signing-provider lifecycle operations owned by DU-PC-CONTROL.
//! Reservation commits before network I/O. A dispatched attempt is only reconciled by lookup.
#[path = "signing_provider_denial.rs"]
mod denial;

use reqwest::{Certificate, Client, Identity, Url, tls::Version};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{env, fs, time::Duration};

type Result<T> = std::result::Result<T, String>;
fn failure() -> String {
    "signing provider queue unavailable".into()
}
fn exact(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|v| v.len() == fields.len() && fields.iter().all(|k| v.contains_key(*k)))
}
fn bounded_text(value: &Value, max: usize) -> bool {
    value
        .as_str()
        .is_some_and(|v| !v.is_empty() && v.len() <= max && v.bytes().all(|b| b >= 32 && b != 127))
}
fn nanos(value: &Value) -> bool {
    value.as_str().is_some_and(|v| {
        v.parse::<u64>()
            .is_ok_and(|n| n % 1000 == 0 && n.to_string() == v)
    })
}
fn hex_value(value: &Value, size: usize) -> bool {
    value.as_str().is_some_and(|v| {
        v.len() == size * 2
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn fingerprint(value: &Value) -> bool {
    value
        .as_str()
        .and_then(|v| v.strip_prefix("sha256:"))
        .is_some_and(|v| hex_value(&Value::String(v.into()), 32))
}
fn identifier(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 36
            && s.as_bytes()[14] == b'7'
            && matches!(s.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
            && s.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
    })
}
fn reference(value: &Value, version: &Value) -> bool {
    let (Some(r), Some(v)) = (value.as_str(), version.as_str()) else {
        return false;
    };
    r.starts_with("secret://")
        && r.len() <= 331
        && !v.is_empty()
        && v.len() <= 96
        && !["latest", "current"].contains(&v.to_ascii_lowercase().as_str())
        && r.ends_with(&format!("#{v}"))
        && r.matches('#').count() == 1
        && r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~:/#".contains(&b))
}
const COMMON: &[&str] = &[
    "participantId",
    "privacyDomainId",
    "workloadCredentialId",
    "environmentId",
    "secretClass",
    "purpose",
    "reference",
    "version",
    "callerWorkloadCredentialId",
    "attemptId",
    "operationId",
    "method",
    "rotationId",
];
fn request_valid(request: &Value, participant: &str, privacy: &str, credential: &str) -> bool {
    let mut fields = COMMON.to_vec();
    match request["method"].as_str() {
        Some("PREPARE") => {
            if request.get("expectedFingerprint").is_some() {
                fields.push("expectedFingerprint");
            }
        }
        Some("DISTRIBUTE" | "REVOKE" | "RETIRE") => fields.push("expectedFingerprint"),
        _ => return false,
    }
    exact(request, &fields)
        && request["participantId"] == participant
        && request["privacyDomainId"] == privacy
        && request["callerWorkloadCredentialId"] == credential
        && request["secretClass"] == "SECRET-SIGNING-KEY"
        && request["purpose"] == "pc.cose.control-business-transition.v1"
        && [
            "participantId",
            "privacyDomainId",
            "workloadCredentialId",
            "callerWorkloadCredentialId",
            "attemptId",
            "operationId",
            "rotationId",
        ]
        .iter()
        .all(|k| identifier(&request[k]))
        && bounded_text(&request["environmentId"], 160)
        && reference(&request["reference"], &request["version"])
        && ((request["method"] == "PREPARE" && request.get("expectedFingerprint").is_none())
            || fingerprint(&request["expectedFingerprint"]))
}
/// Reject unknown/credential fields before retaining the observation. Binding and outcome
/// interpretation remain with the lifecycle owner, after this durable write.
fn observation_valid(value: &Value) -> bool {
    if !exact(
        value,
        &[
            "schemaVersion",
            "providerId",
            "attemptId",
            "operationId",
            "requestDigest",
            "method",
            "recordedAtNs",
            "outcome",
            "reason",
            "descriptor",
            "resultHex",
        ],
    ) || value["schemaVersion"] != 1
        || !identifier(&value["attemptId"])
        || !identifier(&value["operationId"])
        || !fingerprint(&value["requestDigest"])
        || !nanos(&value["recordedAtNs"])
        || !value["providerId"].as_str().is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 128
                && s.as_bytes()[0].is_ascii_lowercase()
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        })
        || !matches!(
            value["method"].as_str(),
            Some("PREPARE" | "DISTRIBUTE" | "REVOKE" | "RETIRE")
        )
        || !value["resultHex"].is_null()
    {
        return false;
    }
    match value["outcome"].as_str() {
        Some("SUCCEEDED") if value["reason"].is_null() && !value["descriptor"].is_null() => {}
        Some("REJECTED")
            if matches!(
                value["reason"].as_str(),
                Some(
                    "KEY_NOT_FOUND"
                        | "REVOKED"
                        | "EXPIRED"
                        | "WRONG_SCOPE"
                        | "FINGERPRINT_MISMATCH"
                        | "INVALID_REQUEST"
                        | "ATTEMPT_CONFLICT"
                        | "NOT_APPLIED"
                )
            ) => {}
        _ => return false,
    }
    let d = &value["descriptor"];
    d.is_null()
        || (exact(
            d,
            &[
                "participantId",
                "privacyDomainId",
                "workloadCredentialId",
                "environmentId",
                "secretClass",
                "purpose",
                "reference",
                "version",
                "algorithm",
                "publicKeySpkiHex",
                "fingerprint",
                "validFromNs",
                "validUntilNs",
                "state",
                "revokedAtNs",
                "retiredAtNs",
            ],
        ) && ["participantId", "privacyDomainId", "workloadCredentialId"]
            .iter()
            .all(|k| identifier(&d[k]))
            && bounded_text(&d["environmentId"], 160)
            && d["secretClass"] == "SECRET-SIGNING-KEY"
            && d["purpose"] == "pc.cose.control-business-transition.v1"
            && reference(&d["reference"], &d["version"])
            && d["algorithm"] == "ES256"
            && hex_value(&d["publicKeySpkiHex"], 91)
            && fingerprint(&d["fingerprint"])
            && nanos(&d["validFromNs"])
            && nanos(&d["validUntilNs"])
            && matches!(d["state"].as_str(), Some("ACTIVE" | "REVOKED" | "RETIRED"))
            && (d["revokedAtNs"].is_null() || nanos(&d["revokedAtNs"]))
            && (d["retiredAtNs"].is_null() || nanos(&d["retiredAtNs"])))
}

fn observation_matches(request: &Value, value: &Value) -> bool {
    if !observation_valid(value) {
        return false;
    }
    let Ok(encoded) = pc_runtime_types::canonical_bytes(request) else {
        return false;
    };
    let mut preimage = b"pc.control.signing-provider-request.v1\0".to_vec();
    preimage.extend(encoded);
    let digest = Sha256::digest(preimage)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if ["attemptId", "operationId", "method"]
        .iter()
        .any(|k| value[k] != request[k])
        || value["requestDigest"] != format!("sha256:{digest}")
    {
        return false;
    }
    let d = &value["descriptor"];
    if d.is_null() {
        return value["outcome"] == "REJECTED";
    }
    if [
        "participantId",
        "privacyDomainId",
        "workloadCredentialId",
        "environmentId",
        "secretClass",
        "purpose",
        "reference",
        "version",
    ]
    .iter()
    .any(|k| d[k] != request[k])
        || (request.get("expectedFingerprint").is_some()
            && request["expectedFingerprint"] != d["fingerprint"])
    {
        return false;
    }
    let Some(encoded) = d["publicKeySpkiHex"].as_str() else {
        return false;
    };
    if !encoded.starts_with("3059301306072a8648ce3d020106082a8648ce3d03010703420004") {
        return false;
    }
    // observation_valid established exact ASCII hex length before any byte indexing.
    let public = (0..91)
        .map(|i| u8::from_str_radix(&encoded[i * 2..i * 2 + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>();
    let Ok(public) = public else {
        return false;
    };
    if p256::ecdsa::VerifyingKey::from_sec1_bytes(&public[26..]).is_err() {
        return false;
    }
    let fingerprint = Sha256::digest(&public)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if d["fingerprint"] != format!("sha256:{fingerprint}") {
        return false;
    }
    let number = |v: &Value| v.as_str().and_then(|v| v.parse::<u64>().ok());
    let (Some(valid_from), Some(valid_until)) =
        (number(&d["validFromNs"]), number(&d["validUntilNs"]))
    else {
        return false;
    };
    if valid_from >= valid_until
        || (d["state"] == "ACTIVE" && (!d["revokedAtNs"].is_null() || !d["retiredAtNs"].is_null()))
        || (d["state"] != "ACTIVE" && d["revokedAtNs"].is_null())
        || ((d["state"] == "RETIRED") != !d["retiredAtNs"].is_null())
        || (!d["retiredAtNs"].is_null() && number(&d["retiredAtNs"]) < number(&d["revokedAtNs"]))
    {
        return false;
    }
    if value["outcome"] == "REJECTED" {
        return true;
    }
    match request["method"].as_str() {
        Some("REVOKE") => d["state"] == "REVOKED",
        Some("RETIRE") => d["state"] == "RETIRED",
        Some("PREPARE" | "DISTRIBUTE") => {
            let number = |v: &Value| v.as_str().and_then(|v| v.parse::<u64>().ok());
            match (
                number(&value["recordedAtNs"]),
                number(&d["validFromNs"]),
                number(&d["validUntilNs"]),
            ) {
                (Some(at), Some(from), Some(until)) => {
                    d["state"] == "ACTIVE" && from <= at && at < until
                }
                _ => false,
            }
        }
        _ => false,
    }
}

pub struct SigningProviderWorker {
    client: Client,
    origin: Url,
    credential: String,
}
impl SigningProviderWorker {
    pub fn from_environment() -> Result<Self> {
        let get = |name| env::var(name).map_err(|_| failure());
        let read = |name| fs::read(get(name)?).map_err(|_| failure());
        let origin =
            Url::parse(&get("CONTROL_WORKER_SIGNING_PROVIDER_URL")?).map_err(|_| failure())?;
        if origin.scheme() != "https"
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(failure());
        }
        let mut identity = read("CONTROL_WORKER_SIGNING_PROVIDER_CERT_FILE")?;
        identity.extend(read("CONTROL_WORKER_SIGNING_PROVIDER_KEY_FILE")?);
        let tls_identity = Identity::from_pem(&identity).map_err(|_| failure())?;
        identity.fill(0);
        let client = Client::builder()
            .identity(tls_identity)
            .tls_certs_only([Certificate::from_pem(&read(
                "CONTROL_WORKER_SIGNING_PROVIDER_CA_FILE",
            )?)
            .map_err(|_| failure())?])
            .tls_version_min(Version::TLS_1_3)
            .tls_version_max(Version::TLS_1_3)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| failure())?;
        let credential = get("CONTROL_WORKER_SIGNING_CREDENTIAL_ID")?;
        if !identifier(&Value::String(credential.clone())) {
            return Err(failure());
        }
        Ok(Self {
            client,
            origin,
            credential,
        })
    }
    async fn exchange(&self, request: &Value, dispatch: bool) -> Result<Option<Value>> {
        let path = if dispatch {
            "/v1/business-signing/requests".into()
        } else {
            format!(
                "/v1/business-signing/attempts/{}",
                request["attemptId"].as_str().ok_or_else(failure)?
            )
        };
        let url = self.origin.join(&path).map_err(|_| failure())?;
        let builder = if dispatch {
            self.client
                .post(url)
                .header("content-type", "application/json")
                .body(pc_runtime_types::canonical_bytes(request).map_err(|_| failure())?)
        } else {
            self.client.get(url)
        };
        let mut response = builder.send().await.map_err(|_| failure())?;
        if response.status() != 200
            || !response
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .is_some_and(|h| h.starts_with("application/json"))
        {
            return Err(failure());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| failure())? {
            if body.len() + chunk.len() > 262144 {
                return Err(failure());
            }
            body.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&body).map_err(|_| failure())?;
        let observed = if dispatch {
            value
        } else {
            if exact(&value, &["state", "attemptId"])
                && value["state"] == "ABSENT"
                && value["attemptId"] == request["attemptId"]
            {
                return Ok(None);
            }
            if !exact(&value, &["state", "observation"]) || value["state"] != "OBSERVED" {
                return Err(failure());
            }
            value["observation"].clone()
        };
        if !observation_matches(request, &observed) {
            return Err(failure());
        }
        Ok(Some(observed))
    }
    pub async fn tick(&self, pool: &PgPool, participant: &str, privacy: &str) -> Result<bool> {
        let mut tx = pool.begin().await.map_err(|_| failure())?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',true)")
            .bind(participant).bind(privacy).execute(&mut *tx).await.map_err(|_|failure())?;
        let selected=sqlx::query("select a.attempt_id::text,a.request,a.request_digest,a.state from control.signing_provider_attempt a join control.signing_rotation_command c on c.participant_id=a.participant_id and c.privacy_domain_id=a.privacy_domain_id and c.operation_id=a.operation_id join control.signing_key_rotation r on r.participant_id=a.participant_id and r.privacy_domain_id=a.privacy_domain_id and r.rotation_id=a.rotation_id where a.participant_id=$1::text::uuid and a.privacy_domain_id=$2::text::uuid and a.request->>'callerWorkloadCredentialId'=$3 and a.request->>'method' in ('PREPARE','DISTRIBUTE','REVOKE','RETIRE') and a.state in ('READY','DISPATCHING') and (c.state='ACCEPTED' or (c.state='WRITE_AMBIGUITY' and a.state='DISPATCHING')) and ((r.revision=a.from_revision and r.state=a.from_state) or (r.state='RECOVERING' and r.recovery_from_revision=a.from_revision and r.recovery_from_state=a.from_state)) order by (a.state='READY') desc,a.created_at limit 1")
            .bind(participant).bind(privacy).bind(&self.credential).fetch_optional(&mut *tx).await.map_err(|_|failure())?;
        let Some(row) = selected else {
            tx.commit().await.map_err(|_| failure())?;
            return Ok(false);
        };
        let id: String = row.try_get("attempt_id").map_err(|_| failure())?;
        // Take retained authority roots before the provider-attempt lock. An expired or
        // revoked actor prevents new dispatch; an already dispatched attempt still reconciles.
        if row.try_get::<String, _>("state").map_err(|_| failure())? == "READY" {
            let live: bool = sqlx::query_scalar("select coalesce((openpc.signing_attempt_authority_status($1::text::uuid)->>'unchangedLive')::boolean,false)")
                .bind(&id).fetch_one(&mut *tx).await.map_err(|_| failure())?;
            if !live {
                let completed =
                    denial::fail_before_dispatch(&mut tx, participant, privacy, &id).await?;
                tx.commit().await.map_err(|_| failure())?;
                return Ok(completed);
            }
        }
        let claimed = sqlx::query("select request,request_digest,state from control.signing_provider_attempt a where a.attempt_id=$1::text::uuid and a.state in ('READY','DISPATCHING') and not exists(select 1 from control.signing_rotation_command recovery where recovery.participant_id=a.participant_id and recovery.privacy_domain_id=a.privacy_domain_id and recovery.original_operation_id=a.operation_id and recovery.state='ACCEPTED') for update skip locked")
            .bind(&id).fetch_optional(&mut *tx).await.map_err(|_| failure())?;
        let Some(row) = claimed else {
            tx.commit().await.map_err(|_| failure())?;
            return Ok(false);
        };
        let request: Value = row.try_get("request").map_err(|_| failure())?;
        let stored_digest: Vec<u8> = row.try_get("request_digest").map_err(|_| failure())?;
        let mut preimage = b"pc.control.signing-provider-request.v1\0".to_vec();
        preimage.extend(pc_runtime_types::canonical_bytes(&request).map_err(|_| failure())?);
        if !request_valid(&request, participant, privacy, &self.credential)
            || request["attemptId"] != id
            || Sha256::digest(preimage).as_slice() != stored_digest
        {
            return Err(failure());
        }
        let dispatch = row.try_get::<String, _>("state").map_err(|_| failure())? == "READY";
        if dispatch {
            let valid:bool=sqlx::query_scalar("select exists(select 1 from control.credential c join control.principal p using(participant_id,principal_id) where c.participant_id=$1::text::uuid and c.credential_id=$2::text::uuid and c.kind='WORKLOAD_MTLS' and c.state='ACTIVE' and p.kind='WORKLOAD' and p.state='ACTIVE' and c.valid_from<=clock_timestamp() and (c.valid_until is null or c.valid_until>clock_timestamp()))")
                .bind(participant).bind(&self.credential).fetch_one(&mut *tx).await.map_err(|_|failure())?;
            if !valid {
                return Err(failure());
            }
            sqlx::query("update control.signing_provider_attempt set state='DISPATCHING' where attempt_id=$1::text::uuid").bind(&id).execute(&mut *tx).await.map_err(|_|failure())?;
        }
        tx.commit().await.map_err(|_| failure())?;
        // A second claimant can only look up the durable attempt, never repeat the POST.
        let observation = match self.exchange(&request, dispatch).await {
            Ok(Some(v)) => v,
            _ => {
                let mut tx = pool.begin().await.map_err(|_| failure())?;
                sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,$3::text::uuid,'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',true)")
                    .bind(participant).bind(privacy).bind(request["operationId"].as_str().ok_or_else(failure)?)
                    .execute(&mut *tx).await.map_err(|_|failure())?;
                sqlx::query("select openpc.record_signing_ambiguity($1::text::uuid)")
                    .bind(&id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| failure())?;
                tx.commit().await.map_err(|_| failure())?;
                return Ok(false);
            }
        };
        let observation_digest =
            Sha256::digest(pc_runtime_types::canonical_bytes(&observation).map_err(|_| failure())?)
                .to_vec();
        let mut tx = pool.begin().await.map_err(|_| failure())?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,$3::text::uuid,'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',true)")
            .bind(participant).bind(privacy).bind(request["operationId"].as_str().ok_or_else(failure)?)
            .execute(&mut *tx).await.map_err(|_|failure())?;
        let updated=sqlx::query("update control.signing_provider_attempt set state='OBSERVED',observation=$2,observation_digest=$3 where attempt_id=$1::text::uuid and state='DISPATCHING'")
            .bind(&id).bind(&observation).bind(&observation_digest).execute(&mut *tx).await.map_err(|_|failure())?;
        if updated.rows_affected() != 1 {
            let prior:Option<Vec<u8>>=sqlx::query_scalar("select observation_digest from control.signing_provider_attempt where attempt_id=$1::text::uuid").bind(&id).fetch_one(&mut *tx).await.map_err(|_|failure())?;
            if prior.as_ref() != Some(&observation_digest) {
                return Err(failure());
            }
        }
        tx.commit().await.map_err(|_| failure())?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_rejects_signing_or_other_workload_requests_before_dispatch() {
        let participant = "018f0000-0000-7000-8000-000000000101";
        let privacy = "018f0000-0000-7000-8000-000000000201";
        let credential = "018f0000-0000-7000-8000-000000000198";
        let request = serde_json::json!({"participantId":participant,"privacyDomainId":privacy,"workloadCredentialId":"018f0000-0000-7000-8000-000000000195","environmentId":"local","secretClass":"SECRET-SIGNING-KEY","purpose":"pc.cose.control-business-transition.v1","reference":"secret://local/control-business-evidence#2","version":"2","callerWorkloadCredentialId":credential,"attemptId":"018f0000-0000-7000-8000-000000000301","operationId":"018f0000-0000-7000-8000-000000000302","method":"PREPARE","rotationId":"018f0000-0000-7000-8000-000000000303"});
        assert!(request_valid(&request, participant, privacy, credential));
        for (field, value) in [
            ("method", "SIGN_RECEIPT"),
            ("method", "PROVE"),
            (
                "callerWorkloadCredentialId",
                "018f0000-0000-7000-8000-000000000195",
            ),
            ("privacyDomainId", participant),
            (
                "reference",
                "secret://local/control-business-evidence#latest",
            ),
            ("purpose", "pc.identity.auth-context.v1"),
        ] {
            let mut invalid = request.clone();
            invalid[field] = Value::String(value.into());
            assert!(
                !request_valid(&invalid, participant, privacy, credential),
                "{field}"
            );
        }
        let mut invalid = request;
        invalid["privateKey"] = Value::String("undeclared".into());
        assert!(!request_valid(&invalid, participant, privacy, credential));
    }
    #[test]
    fn provider_result_is_bound_before_it_becomes_immutable() {
        let request = serde_json::json!({"attemptId":"018f0000-0000-7000-8000-000000000301","operationId":"018f0000-0000-7000-8000-000000000302","method":"PREPARE"});
        let mut preimage = b"pc.control.signing-provider-request.v1\0".to_vec();
        preimage.extend(pc_runtime_types::canonical_bytes(&request).unwrap());
        let digest = Sha256::digest(preimage)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let observed = serde_json::json!({"schemaVersion":1,"providerId":"local.fixture","attemptId":request["attemptId"],"operationId":request["operationId"],"requestDigest":format!("sha256:{digest}"),"method":"PREPARE","recordedAtNs":"1789150000000000000","outcome":"REJECTED","reason":"NOT_APPLIED","descriptor":null,"resultHex":null});
        assert!(observation_matches(&request, &observed));
        for (field, value) in [
            ("operationId", request["attemptId"].clone()),
            ("attemptId", request["operationId"].clone()),
            ("method", Value::String("REVOKE".into())),
            (
                "requestDigest",
                Value::String(format!("sha256:{}", "ab".repeat(32))),
            ),
        ] {
            let mut wrong = observed.clone();
            wrong[field] = value;
            assert!(observation_valid(&wrong));
            assert!(!observation_matches(&request, &wrong));
        }
    }
    #[test]
    fn provider_observation_rejects_untrusted_fields_before_storage() {
        let observation = serde_json::json!({"schemaVersion":1,"providerId":"local.fixture","attemptId":"018f0000-0000-7000-8000-000000000301","operationId":"018f0000-0000-7000-8000-000000000302","requestDigest":format!("sha256:{}","ab".repeat(32)),"method":"PREPARE","recordedAtNs":"1789150000000000000","outcome":"REJECTED","reason":"NOT_APPLIED","descriptor":null,"resultHex":null});
        assert!(observation_valid(&observation));
        for field in ["privateKey", "accessToken", "password"] {
            let mut invalid = observation.clone();
            invalid[field] = Value::String("undeclared".into());
            assert!(!observation_valid(&invalid));
        }
        let mut invalid = observation.clone();
        invalid["reason"] = Value::String("arbitrary provider body".into());
        assert!(!observation_valid(&invalid));
        let mut invalid = observation;
        invalid["resultHex"] = Value::String("deadbeef".into());
        assert!(!observation_valid(&invalid));
    }
}
