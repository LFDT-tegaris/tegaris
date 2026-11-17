//! Installed TEST secret-recipient admission through the pinned TLS owner. No
//! candidate database session or file read is allowed before initial publication.
//! A response is not Fact action authority; all existing business fences remain.
use super::{DeploymentInput, read};
use openpc_multi_rpc::provider_connection::{
    DestinationPolicy, EndpointDescriptor, LocalTlsMaterial, NetworkRange, ProviderConnection,
    Resolution,
};
use pc_runtime_types::Digest;
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgConnection};
use std::{net::IpAddr, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

const PATH: &str = "/internal/v1/secrets/fact-candidate";
const FAILURE: &str = "fact installed secret recipient unavailable";
const OBSERVATION_PATH: &str = "/internal/v1/operations/secret-resolution";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationsObserverInput {
    endpoint: EndpointDescriptor,
    addresses: Vec<IpAddr>,
    allowed_ranges: Vec<String>,
    private_network_ranges: Vec<String>,
    server_certificate_digest: Digest,
    association_id: Uuid,
    consumer_instance_id: Uuid,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChallengeReply {
    version: u8,
    challenge_id: Uuid,
    key1: u32,
    key2: u32,
    issued_at_ms: u64,
    valid_until_ms: u64,
    consumer_started_at_ms: u64,
}
impl ChallengeReply {
    fn validate(&self, now: u64) -> Result<(), String> {
        if self.version != 1
            || self.challenge_id.get_version_num() != 7
            || self.key1 > i32::MAX as u32
            || self.key2 > i32::MAX as u32
            || self.consumer_started_at_ms == 0
            || self.consumer_started_at_ms > self.issued_at_ms
            || self.issued_at_ms > now
            || self.valid_until_ms <= now
            || self.valid_until_ms > 9_007_199_254_740_991
            || self.valid_until_ms.saturating_sub(self.issued_at_ms) > 30_000
        {
            return Err(FAILURE.into());
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ObservationReply {
    version: u8,
    observation_id: Uuid,
    source_digest: String,
    valid_until_ms: u64,
}
impl ObservationReply {
    fn validate(&self, challenge: &ChallengeReply, now: u64) -> Result<(), String> {
        if self.version != 1
            || self.observation_id != challenge.challenge_id
            || !digest(&self.source_digest)
            || self.valid_until_ms > challenge.valid_until_ms
            || self.valid_until_ms <= now
        {
            return Err(FAILURE.into());
        }
        Ok(())
    }
}

struct InstalledTransport<'a> {
    endpoint: &'a EndpointDescriptor,
    addresses: &'a [IpAddr],
    allowed_ranges: &'a [String],
    private_network_ranges: &'a [String],
    certificate: &'a Digest,
}

/// One bounded read-only proof session, separate from all business pools. It
/// retains no read result/secret bytes and has a server-enforced 30-second idle
/// timeout. Dropping/replacing this instance closes its original connection.
pub(super) struct ObservedSecretUse {
    connection: PgConnection,
    valid_until_ms: u64,
}
impl ObservedSecretUse {
    pub(super) fn fresh(&self, now: u64) -> bool {
        now.checked_add(5000)
            .is_some_and(|deadline| deadline < self.valid_until_ms)
    }
    pub(super) async fn close(mut self) -> Result<(), String> {
        let rollback = sqlx::query("rollback").execute(&mut self.connection).await;
        let closed = self.connection.close().await;
        if rollback.is_err() || closed.is_err() {
            return Err(FAILURE.into());
        }
        Ok(())
    }
}

fn probe_query(participant: Uuid, privacy: Uuid, key1: u32, key2: u32) -> Result<String, String> {
    if participant.get_version_num() != 7
        || privacy.get_version_num() != 7
        || key1 > i32::MAX as u32
        || key2 > i32::MAX as u32
    {
        return Err(FAILURE.into());
    }
    Ok(format!(
        "select pg_advisory_xact_lock({key1},{key2}),exists(select 1 from candidate.fact_bridge_admission_v1 where participant_id='{participant}'::uuid and privacy_domain_id='{privacy}'::uuid limit 1) from (select openpc.assert_request_context(true)) context where openpc.current_participant_id()='{participant}'::uuid and openpc.current_privacy_domain_id()='{privacy}'::uuid and current_setting('transaction_read_only')='on' and current_setting('transaction_isolation')='repeatable read' and current_setting('row_security')='on' and current_user='openpc_fact_bridge_reader' and current_database()='openpc_candidate_index'"
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecretRecipientInput {
    endpoint: EndpointDescriptor,
    addresses: Vec<IpAddr>,
    allowed_ranges: Vec<String>,
    private_network_ranges: Vec<String>,
    server_certificate_digest: Digest,
    signed_binding_digest: String,
    installation_digest: String,
    generation: String,
    workload_credential_id: Uuid,
    workload_credential_epoch: String,
    reference: String,
    version: String,
    #[serde(default)]
    operations_observer: Option<OperationsObserverInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reply {
    version: u8,
    signed_binding_digest: String,
    installation_digest: String,
    generation: String,
    participant_id: Uuid,
    privacy_domain_id: Uuid,
    workload_credential_id: Uuid,
    workload_credential_epoch: String,
    valid_until_ms: u64,
}
fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn integer(value: &str, positive: bool) -> bool {
    value
        .parse::<u64>()
        .is_ok_and(|n| n.to_string() == value && (!positive || n > 0))
}
impl SecretRecipientInput {
    pub(super) fn has_operations_observer(&self) -> bool {
        self.operations_observer.is_some()
    }

    /// Observe use of the actual mounted credential after normal workload and
    /// recipient admission. No caller can supply a checked/readiness flag.
    pub(super) async fn observe_use(
        &self,
        input: &DeploymentInput,
    ) -> Result<ObservedSecretUse, String> {
        self.validate(input)?;
        let observer = self.operations_observer.as_ref().ok_or(FAILURE)?;
        if observer.endpoint.path != OBSERVATION_PATH
            || observer.addresses.is_empty()
            || observer.addresses.len() > 16
            || observer.allowed_ranges.len() > 16
            || observer.private_network_ranges.len() > 16
            || Digest::parse(observer.server_certificate_digest.as_str()).as_ref()
                != Ok(&observer.server_certificate_digest)
            || observer.association_id.get_version_num() != 7
            || observer.consumer_instance_id.get_version_num() != 7
        {
            return Err(FAILURE.into());
        }
        let connection = Self::connection_for(
            input,
            InstalledTransport {
                endpoint: &observer.endpoint,
                addresses: &observer.addresses,
                allowed_ranges: &observer.allowed_ranges,
                private_network_ranges: &observer.private_network_ranges,
                certificate: &observer.server_certificate_digest,
            },
        )?;
        let request = serde_json::json!({ "phase":"CHALLENGE", "associationId":observer.association_id,
            "consumerInstanceId":observer.consumer_instance_id });
        let bytes = connection
            .post_json(
                serde_json::to_vec(&request).map_err(|_| FAILURE)?,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .map_err(|_| FAILURE)?;
        let challenge: ChallengeReply = serde_json::from_slice(&bytes).map_err(|_| FAILURE)?;
        challenge.validate(openpc_multi_rpc::provider_probe_source::now_ms()?)?;
        let query = probe_query(
            input.participant_id,
            input.privacy_domain_id,
            challenge.key1,
            challenge.key2,
        )?;
        let database_url = super::database_url(&input.candidate_database_url_file)?;
        let mut database =
            tokio::time::timeout(Duration::from_secs(5), PgConnection::connect(&database_url))
                .await
                .map_err(|_| FAILURE)?
                .map_err(|_| FAILURE)?;
        let observed = async {
            sqlx::query("begin isolation level repeatable read read only").execute(&mut database).await.map_err(|_| FAILURE)?;
            sqlx::query("set local idle_in_transaction_session_timeout='30s'").execute(&mut database).await.map_err(|_| FAILURE)?;
            sqlx::query("set local statement_timeout='5s'").execute(&mut database).await.map_err(|_| FAILURE)?;
            sqlx::query("set local row_security=on").execute(&mut database).await.map_err(|_| FAILURE)?;
            sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',true)")
                .bind(input.participant_id).bind(input.privacy_domain_id).bind(challenge.challenge_id).execute(&mut database).await.map_err(|_| FAILURE)?;
            let (pid,started): (i32,String) = sqlx::query_as("select pg_backend_pid(),extract(epoch from backend_start)::text from pg_stat_activity where pid=pg_backend_pid()")
                .fetch_one(&mut database).await.map_err(|_| FAILURE)?;
            // Fetching the row completes the actual RLS-scoped candidate view
            // read. Keep its transaction and lock open for independent inspection.
            // Audited exact probe text: probe_query interpolates only typed UUIDv7
            // values and bounded u32 lock keys, never an arbitrary SQL fragment.
            // The independent observer verifies this precise wire text.
            sqlx::query(sqlx::AssertSqlSafe(query.as_str())).fetch_one(&mut database).await.map_err(|_| FAILURE)?;
            let request=serde_json::json!({"phase":"OBSERVE","associationId":observer.association_id,
                "consumerInstanceId":observer.consumer_instance_id,
                "challengeId":challenge.challenge_id,"backendPid":pid,"backendStart":started});
            let bytes=connection.post_json(serde_json::to_vec(&request).map_err(|_| FAILURE)?,Instant::now()+Duration::from_secs(5)).await.map_err(|_| FAILURE)?;
            let observation: ObservationReply=serde_json::from_slice(&bytes).map_err(|_| FAILURE)?;
            observation.validate(&challenge, openpc_multi_rpc::provider_probe_source::now_ms()?)?;
            Ok(observation.valid_until_ms)
        }.await;
        match observed {
            Ok(valid_until_ms) => Ok(ObservedSecretUse {
                connection: database,
                valid_until_ms,
            }),
            Err(failure) => {
                if database.close().await.is_err() {
                    eprintln!("OPS_SECRET_OBSERVATION_CLEANUP|UNKNOWN");
                }
                Err(failure)
            }
        }
    }
    fn validate(&self, input: &DeploymentInput) -> Result<(), String> {
        if self.endpoint.path != PATH
            || self.addresses.is_empty()
            || self.addresses.len() > 16
            || !digest(&self.signed_binding_digest)
            || !digest(&self.installation_digest)
            || !integer(&self.generation, true)
            || !integer(&self.workload_credential_epoch, false)
            || self.workload_credential_id.get_version_num() != 7
            || self.reference.len() > 512
            || !self.reference.starts_with("secret://test-memory-resolver/")
            || self.version.is_empty()
            || self.version.len() > 128
            || !self.reference.ends_with(&format!("#{}", self.version))
            || input.candidate_database_url_file.to_str() != Some("/fact-bridge/candidate-url")
            || Digest::parse(self.server_certificate_digest.as_str()).as_ref()
                != Ok(&self.server_certificate_digest)
        {
            return Err(FAILURE.into());
        }
        Ok(())
    }
    fn connection(&self, input: &DeploymentInput) -> Result<ProviderConnection, String> {
        self.validate(input)?;
        Self::connection_for(
            input,
            InstalledTransport {
                endpoint: &self.endpoint,
                addresses: &self.addresses,
                allowed_ranges: &self.allowed_ranges,
                private_network_ranges: &self.private_network_ranges,
                certificate: &self.server_certificate_digest,
            },
        )
    }
    fn connection_for(
        input: &DeploymentInput,
        transport: InstalledTransport<'_>,
    ) -> Result<ProviderConnection, String> {
        let ranges = |values: &[String]| {
            values
                .iter()
                .map(|v| NetworkRange::parse(v).map_err(|_| FAILURE))
                .collect::<Result<Vec<_>, _>>()
        };
        let now = openpc_multi_rpc::provider_probe_source::now_ms()?;
        let endpoint = transport
            .endpoint
            .prepare(
                &DestinationPolicy {
                    allowed_ranges: ranges(transport.allowed_ranges)?,
                    private_network_ranges: ranges(transport.private_network_ranges)?,
                    allow_ip_endpoint: false,
                },
                Resolution {
                    addresses: transport.addresses.to_vec(),
                    resolved_at_ms: now,
                    valid_until_ms: now.checked_add(30_000).ok_or(FAILURE)?,
                    generation: now,
                },
            )
            .map_err(|_| FAILURE)?;
        ProviderConnection::prepare(
            endpoint,
            LocalTlsMaterial {
                roots: input
                    .root_der_files
                    .iter()
                    .map(|p| read(p, 65536).map(Into::into))
                    .collect::<Result<_, _>>()?,
                client_chain: input
                    .client_chain_der_files
                    .iter()
                    .map(|p| read(p, 65536).map(Into::into))
                    .collect::<Result<_, _>>()?,
                client_key: read(&input.client_key_der_file, 16384)?
                    .try_into()
                    .map_err(|_| FAILURE)?,
                expected_server_certificate: transport.certificate.clone(),
            },
            2048,
            4096,
        )
        .map_err(|_| FAILURE.into())
    }
    fn verify_reply(
        &self,
        reply: Reply,
        participant: Uuid,
        privacy: Uuid,
        now: u64,
    ) -> Result<(), String> {
        if reply.version != 1
            || reply.signed_binding_digest != self.signed_binding_digest
            || reply.installation_digest != self.installation_digest
            || reply.generation != self.generation
            || reply.participant_id != participant
            || reply.privacy_domain_id != privacy
            || reply.workload_credential_id != self.workload_credential_id
            || reply.workload_credential_epoch != self.workload_credential_epoch
            || reply.valid_until_ms <= now
            || reply.valid_until_ms > 9_007_199_254_740_991
        {
            return Err(FAILURE.into());
        }
        Ok(())
    }
    pub(super) async fn authorize(
        &self,
        input: &DeploymentInput,
        publish: bool,
    ) -> Result<(), String> {
        let connection = self.connection(input)?;
        let request = self.request(input.participant_id, input.privacy_domain_id, publish)?;
        let bytes = connection
            .post_json(request, Instant::now() + Duration::from_secs(5))
            .await
            .map_err(|_| FAILURE)?;
        let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| FAILURE)?;
        self.verify_reply(
            reply,
            input.participant_id,
            input.privacy_domain_id,
            openpc_multi_rpc::provider_probe_source::now_ms()?,
        )
    }
    fn request(&self, participant: Uuid, privacy: Uuid, publish: bool) -> Result<Vec<u8>, String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Expected<'a> {
            signed_binding_digest: &'a str,
            installation_digest: &'a str,
            generation: &'a str,
            participant_id: Uuid,
            privacy_domain_id: Uuid,
            workload_credential_id: Uuid,
            workload_credential_epoch: &'a str,
        }
        #[derive(Serialize)]
        struct Request<'a> {
            operation: &'static str,
            reference: &'a str,
            version: &'a str,
            expected: Expected<'a>,
        }
        serde_json::to_vec(&Request {
            operation: if publish { "PUBLISH" } else { "CHECK" },
            reference: &self.reference,
            version: &self.version,
            expected: Expected {
                signed_binding_digest: &self.signed_binding_digest,
                installation_digest: &self.installation_digest,
                generation: &self.generation,
                participant_id: participant,
                privacy_domain_id: privacy,
                workload_credential_id: self.workload_credential_id,
                workload_credential_epoch: &self.workload_credential_epoch,
            },
        })
        .map_err(|_| FAILURE.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn fixture() -> (SecretRecipientInput, Value, Uuid, Uuid) {
        let participant = Uuid::now_v7();
        let privacy = Uuid::now_v7();
        let credential = Uuid::now_v7();
        let input: SecretRecipientInput = serde_json::from_value(json!({
            "endpoint": {"endpoint_id":"secret-recipient", "normalized_uri":"https://secrets.test:3443/internal/v1/secrets/fact-candidate", "reference_identity":"secrets.test", "port":3443, "path":PATH,
                "dns_policy_ref":"test-exact", "tls_policy_ref":"test-mtls", "credential_ref":"urn:openpc:workload:test", "egress_policy_ref":"test-exact", "endpoint_generation":1},
            "addresses":["127.0.0.1"], "allowed_ranges":["127.0.0.1/32"], "private_network_ranges":["127.0.0.1/32"],
            "server_certificate_digest":"11".repeat(32), "signed_binding_digest":format!("sha256:{}", "22".repeat(32)),
            "installation_digest":format!("sha256:{}", "33".repeat(32)), "generation":"1", "workload_credential_id":credential,
            "workload_credential_epoch":"2", "reference":"secret://test-memory-resolver/fact/candidate-reader#v1", "version":"v1"
        })).unwrap();
        let reply = json!({"version":1,"signedBindingDigest":input.signed_binding_digest,"installationDigest":input.installation_digest,
            "generation":"1","participantId":participant,"privacyDomainId":privacy,"workloadCredentialId":credential,
            "workloadCredentialEpoch":"2","validUntilMs":2000});
        (input, reply, participant, privacy)
    }
    #[test]
    fn observation_requires_bounded_original_challenge_and_exact_response() {
        let value = json!({"version":1,"challengeId":Uuid::now_v7(),"key1":12,"key2":34,
            "issuedAtMs":2000,"validUntilMs":32000,"consumerStartedAtMs":1000});
        let challenge: ChallengeReply = serde_json::from_value(value.clone()).unwrap();
        assert!(challenge.validate(2000).is_ok());
        for (field, changed) in [
            ("version", json!(2)),
            ("challengeId", json!(Uuid::nil())),
            ("key1", json!(2147483648_u32)),
            ("key2", json!(2147483648_u32)),
            ("issuedAtMs", json!(2001)),
            ("consumerStartedAtMs", json!(0)),
            ("consumerStartedAtMs", json!(2001)),
            ("validUntilMs", json!(2000)),
            ("validUntilMs", json!(32001)),
            ("validUntilMs", json!(9_007_199_254_740_992_u64)),
        ] {
            let mut changed_value = value.clone();
            changed_value[field] = changed;
            assert!(
                serde_json::from_value::<ChallengeReply>(changed_value)
                    .unwrap()
                    .validate(2000)
                    .is_err()
            );
        }
        let mut extra = value.clone();
        extra["checked"] = json!(true);
        assert!(serde_json::from_value::<ChallengeReply>(extra).is_err());
        let response = json!({"version":1,"observationId":challenge.challenge_id,
            "sourceDigest":format!("sha256:{}","11".repeat(32)),"validUntilMs":31000});
        assert!(
            serde_json::from_value::<ObservationReply>(response.clone())
                .unwrap()
                .validate(&challenge, 2000)
                .is_ok()
        );
        for (field, changed) in [
            ("version", json!(2)),
            ("observationId", json!(Uuid::now_v7())),
            ("sourceDigest", json!("checked")),
            ("validUntilMs", json!(32001)),
            ("validUntilMs", json!(2000)),
        ] {
            let mut changed_value = response.clone();
            changed_value[field] = changed;
            assert!(
                serde_json::from_value::<ObservationReply>(changed_value)
                    .unwrap()
                    .validate(&challenge, 2000)
                    .is_err()
            );
        }
    }

    #[test]
    fn observation_query_rejects_noncanonical_scope_and_lock_keys() {
        let participant = Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap();
        let privacy = Uuid::parse_str("018f0000-0000-7000-8000-000000000002").unwrap();
        let query = probe_query(participant, privacy, 12, 34).unwrap();
        // Shared exact-query protocol vector with the independent TS observer.
        assert_eq!(
            Digest::of(query.as_bytes()).as_str(),
            "59936925501ac93bd98e1f45d01a45856597644816481e2ee9386014d8f9dde0"
        );
        assert!(query.len() < 1024);
        assert!(query.contains("pg_advisory_xact_lock(12,34)"));
        assert!(query.contains("candidate.fact_bridge_admission_v1"));
        assert!(query.contains("current_setting('transaction_read_only')='on'"));
        assert!(query.contains("current_setting('transaction_isolation')='repeatable read'"));
        assert!(query.contains("openpc.assert_request_context(true)"));
        assert!(probe_query(Uuid::nil(), privacy, 12, 34).is_err());
        assert!(probe_query(participant, Uuid::nil(), 12, 34).is_err());
        assert!(probe_query(participant, privacy, u32::MAX, 34).is_err());
        assert!(probe_query(participant, privacy, 12, u32::MAX).is_err());
    }

    #[test]
    fn response_requires_exact_installed_identity_scope_and_live_deadline() {
        let (input, reply, participant, privacy) = fixture();
        assert!(
            input
                .verify_reply(
                    serde_json::from_value(reply.clone()).unwrap(),
                    participant,
                    privacy,
                    1000
                )
                .is_ok()
        );
        for (field, value) in [
            ("version", json!(2)),
            (
                "signedBindingDigest",
                json!(format!("sha256:{}", "44".repeat(32))),
            ),
            (
                "installationDigest",
                json!(format!("sha256:{}", "44".repeat(32))),
            ),
            ("generation", json!("2")),
            ("participantId", json!(Uuid::now_v7())),
            ("privacyDomainId", json!(Uuid::now_v7())),
            ("workloadCredentialId", json!(Uuid::now_v7())),
            ("workloadCredentialEpoch", json!("3")),
            ("validUntilMs", json!(1000)),
            ("validUntilMs", json!(9_007_199_254_740_992_u64)),
        ] {
            let mut changed = reply.clone();
            changed[field] = value;
            assert!(
                input
                    .verify_reply(
                        serde_json::from_value(changed).unwrap(),
                        participant,
                        privacy,
                        1000
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn publication_and_check_send_all_installed_pins_before_any_side_effect() {
        let (input, reply, participant, privacy) = fixture();
        for publish in [true, false] {
            let request: Value =
                serde_json::from_slice(&input.request(participant, privacy, publish).unwrap())
                    .unwrap();
            assert_eq!(
                request["operation"],
                if publish { "PUBLISH" } else { "CHECK" }
            );
            assert_eq!(request["reference"], input.reference);
            assert_eq!(request["version"], input.version);
            let expected = request["expected"].as_object().unwrap();
            assert_eq!(expected.len(), 7);
            for name in [
                "signedBindingDigest",
                "installationDigest",
                "generation",
                "participantId",
                "privacyDomainId",
                "workloadCredentialId",
                "workloadCredentialEpoch",
            ] {
                assert_eq!(expected[name], reply[name]);
            }
        }
    }
    #[test]
    fn unknown_success_flags_and_duplicate_response_fields_are_rejected() {
        let (_, mut reply, _, _) = fixture();
        reply["startupAllowed"] = json!(true);
        assert!(serde_json::from_value::<Reply>(reply).is_err());
        assert!(serde_json::from_str::<Reply>(r#"{"version":1,"version":1}"#).is_err());
    }
    #[test]
    fn pins_reject_noncanonical_digests_and_epoch_strings() {
        for value in [
            "",
            "sha256:aa",
            &format!("sha256:{}", "AA".repeat(32)),
            &"11".repeat(32),
        ] {
            assert!(!digest(value));
        }
        for value in ["", "01", "+1", "-1", "18446744073709551616"] {
            assert!(!integer(value, false));
        }
        assert!(integer("0", false));
        assert!(!integer("0", true));
        assert!(integer("18446744073709551615", true));
    }
}
