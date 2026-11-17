//! Exact expired confirmation custody for durable ACK recovery only. This read
//! cannot sign, issue, restore, or satisfy ReadCurrent's source admission.
use super::*;
use pc_runtime_types::target_disposition::{TargetDispositionAction, TargetDispositionIdentity};
use serde_json::{Value, json};

pub struct HistoricalTargetConfirmation {
    pub revision: u64,
    pub admission_digest: Digest,
    pub signed_delivery: Vec<u8>,
    pub signed_acknowledgement: Option<Vec<u8>>,
}

pub(super) struct VerifiedHistoricalRecord {
    pub confirmation: HistoricalTargetConfirmation,
    pub observed: openpc_runtime_agent::TargetActivationReceipt,
    pub source: pc_runtime_types::target_disposition::TargetDispositionSource,
}

fn stored_digest(value: String) -> Result<Digest> {
    Digest::parse(value.strip_prefix("sha256:").ok_or_else(unavailable)?).map_err(|_| unavailable())
}

impl TargetDispositionStore {
    pub async fn original_confirmation(
        &self,
        extensions: &http::Extensions,
        fleet: &crate::FleetController,
    ) -> Result<HistoricalTargetConfirmation> {
        let (peer, _) = crate::runtime_tls::authenticated_target(extensions, fleet)
            .map_err(|_| unavailable())?;
        self.original_confirmation_for_peer(&peer).await
    }

    async fn original_confirmation_for_peer(
        &self,
        peer: &crate::TargetIdentity,
    ) -> Result<HistoricalTargetConfirmation> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        self.context(&mut tx).await?;
        sqlx::query("select openpc.assert_runtime_target_disposition_owner()")
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        // The actual Identity owner locks the current credential/principal.
        // Its result must still equal the original signed target identity.
        let identity = self
            .bootstrap_identity(&mut tx, peer)
            .await
            .map_err(|_| "historical confirmation identity unavailable".to_owned())?;
        let locked: bool = sqlx::query_scalar("select pg_try_advisory_xact_lock_shared(hashtextextended('runtime-target-disposition:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text||':'||($1::text::uuid)::text,0))")
            .bind(&peer.target_id).fetch_one(&mut *tx).await.map_err(database_error)?;
        if !locked {
            return Err(TARGET_DISPOSITION_BUSY.into());
        }
        // Start at the latest head, then join its exact original. A newer
        // unsigned head, withdrawal or restoration cannot expose an older one.
        let row = sqlx::query(r#"select a.revision::text,a.binding,a.activation_proof,a.admission_digest,
          d.claims,d.signed_delivery,d.delivery_digest,k.signed_acknowledgement,
          o.activation_receipt,o.activation_receipt_digest,
          jsonb_build_object('runtime_configuration_input_id',i.runtime_configuration_input_id::text,
            'configuration_digest',encode(i.configuration_digest,'hex'),
            'module_installation_id',i.module_installation_id::text,
            'module_configuration_generation_id',i.module_configuration_generation_id::text,
            'runtime_configuration_generation_id',w.runtime_configuration_generation_id::text,
            'capsule_digest',substring(o.capsule_digest from 8),
            'xds_version_digest',substring(w.xds_version_digest from 8),
            'predecessor_capsule_digest',substring(w.predecessor_digest from 8),
            'original_work_id',w.configuration_work_id::text,'original_operation_id',w.operation_id::text,
            'original_execution_attempt_id',w.execution_attempt_id::text) original_source
          from (select * from control.runtime_target_disposition_admission
            where participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id()
             and runtime_target_id=$1::text::uuid order by revision desc limit 1) a
          join control.runtime_target_disposition_delivery d using(participant_id,privacy_domain_id,runtime_target_id,revision)
          left join control.runtime_target_disposition_acknowledgement k
            using(participant_id,privacy_domain_id,runtime_target_id,delivery_digest)
          join control.configuration_work w on w.participant_id=a.participant_id and w.privacy_domain_id=a.privacy_domain_id
            and w.runtime_target_id=a.runtime_target_id and w.configuration_work_id::text=a.binding->'source'->>'original_work_id'
          join control.runtime_activation_observation o on o.participant_id=w.participant_id and o.privacy_domain_id=w.privacy_domain_id
            and o.configuration_work_id=w.configuration_work_id and o.operation_id=w.operation_id
            and o.execution_attempt_id=w.execution_attempt_id and o.runtime_target_id=w.runtime_target_id
            and o.runtime_configuration_generation_id=w.runtime_configuration_generation_id
            and o.generation_digest=w.generation_digest and o.xds_version_digest=w.xds_version_digest
            and o.activation_receipt_digest=w.result_receipt_digest
          join control.runtime_configuration_input i on i.participant_id=w.participant_id and i.privacy_domain_id=w.privacy_domain_id
            and i.configuration_digest=decode(substring(w.configuration_digest from 8),'hex')
          where a.binding->>'action'='ConfirmActivation' and a.restoration_proof is null
            and w.work_kind='RUNTIME_ACTIVATION' and w.state='COMPLETED' and w.completed_at is not null
            and w.execution_started_at is not null and w.execution_attempt_id is not null and w.result_event_id is not null
            and w.policy_generation_digest='sha256:'||(a.activation_proof->>'policyGenerationDigest')
          for share of w,i nowait"#)
            .bind(&peer.target_id).fetch_one(&mut *tx).await.map_err(|error| {
                if matches!(error,sqlx::Error::RowNotFound) { "historical confirmation original row unavailable".into() }
                else { database_error(error) }
            })?;
        let result = self.verify_historical_confirmation(&row, &identity)?;
        // Same held Identity/target fences through the read. ACK is a separate
        // transaction and independently rechecks Identity, latest head and CAS.
        if self.bootstrap_identity(&mut tx, peer).await? != identity {
            return Err(unavailable());
        }
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }

    fn verify_historical_confirmation(
        &self,
        row: &sqlx::postgres::PgRow,
        identity: &TargetDispositionIdentity,
    ) -> Result<HistoricalTargetConfirmation> {
        Ok(self
            .verify_historical_confirmation_record(row, identity)?
            .confirmation)
    }

    pub(super) fn verify_historical_confirmation_record(
        &self,
        row: &sqlx::postgres::PgRow,
        identity: &TargetDispositionIdentity,
    ) -> Result<VerifiedHistoricalRecord> {
        let binding: Value = row.try_get("binding").map_err(database_error)?;
        let proof: Value = row.try_get("activation_proof").map_err(database_error)?;
        let source: Value = row.try_get("original_source").map_err(database_error)?;
        let claims: TargetDispositionDelivery =
            serde_json::from_value(row.try_get("claims").map_err(database_error)?)
                .map_err(|_| unavailable())?;
        let revision = row
            .try_get::<String, _>("revision")
            .map_err(database_error)?
            .parse::<u64>()
            .map_err(|_| unavailable())?;
        let admission = stored_digest(row.try_get("admission_digest").map_err(database_error)?)?;
        let wire: Vec<u8> = row.try_get("signed_delivery").map_err(database_error)?;
        let acknowledgement: Option<Vec<u8>> = row
            .try_get("signed_acknowledgement")
            .map_err(database_error)?;
        let target_key = self
            .target_keys
            .lock()
            .map_err(|_| unavailable())?
            .get(&identity.target_id)
            .cloned()
            .ok_or_else(unavailable)?;
        let verifier = TargetDispositionVerifier::from_host_keys(
            identity.clone(),
            &self.control_signer.verifier().sec1_bytes(),
            &target_key,
        )
        .map_err(|_| unavailable())?;
        let verified = verifier
            .verify_delivery(&wire, &claims.source)
            .map_err(|_| "historical confirmation delivery signature rejected".to_owned())?;
        let until_text = proof
            .get("capsuleValidUntilNs")
            .and_then(Value::as_str)
            .ok_or_else(unavailable)?;
        let until = until_text.parse::<u64>().map_err(|_| unavailable())?;
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| unavailable())?
                .as_nanos(),
        )
        .map_err(|_| unavailable())?;
        let receipt: Value = row.try_get("activation_receipt").map_err(database_error)?;
        let receipt_digest = stored_digest(
            row.try_get("activation_receipt_digest")
                .map_err(database_error)?,
        )?;
        let encoded = receipt
            .get("activationReceiptCoseHex")
            .and_then(Value::as_str)
            .ok_or_else(unavailable)?;
        if encoded.is_empty()
            || encoded.len() > 524288
            || !encoded.len().is_multiple_of(2)
            || !encoded
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(unavailable());
        }
        let signed_receipt = (0..encoded.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).map_err(|_| unavailable()))
            .collect::<Result<Vec<_>>>()?;
        let runtime_key = self
            .runtime_target_keys
            .lock()
            .map_err(|_| unavailable())?
            .get(&identity.target_id)
            .cloned()
            .ok_or_else(unavailable)?;
        let observed =
            openpc_runtime_agent::RuntimeWireVerifier::from_public_key_bytes(&runtime_key)
                .and_then(|v| v.verify_receipt(&signed_receipt))
                .map_err(|_| "historical confirmation activation signature rejected".to_owned())?;
        let mut expected = binding.clone();
        expected
            .as_object_mut()
            .ok_or_else(unavailable)?
            .insert("committed_admission_digest".into(), json!(admission));
        let checks = [
            (
                "delivery",
                verified.claims() == &claims
                    && claims.action == TargetDispositionAction::ConfirmActivation
                    && claims.target == *identity
                    && claims.revision == revision
                    && claims.committed_admission_digest == admission
                    && Digest::of(&wire)
                        == stored_digest(row.try_get("delivery_digest").map_err(database_error)?)?,
            ),
            (
                "source",
                serde_json::to_value(&claims.source).map_err(|_| unavailable())? == source
                    && proof.get("source") == Some(&source)
                    && binding.get("source") == Some(&source),
            ),
            (
                "proof identity",
                proof.get("target")
                    == Some(&serde_json::to_value(identity).map_err(|_| unavailable())?)
                    && proof.get("targetId").and_then(Value::as_str)
                        == Some(identity.target_id.as_str())
                    && proof.get("capsuleDigest").and_then(Value::as_str)
                        == Some(claims.source.capsule_digest.as_str()),
            ),
            (
                "expiry",
                until != 0 && until.to_string() == until_text && until <= now,
            ),
            (
                "admission commitment",
                Digest::of(
                    canonical_bytes(&json!({"binding":binding,"activationProof":proof}))
                        .map_err(|_| unavailable())?,
                ) == admission,
            ),
            (
                "claim binding",
                serde_json::to_value(&claims).map_err(|_| unavailable())? == expected,
            ),
            (
                "observation commitment",
                Digest::of(canonical_bytes(&receipt).map_err(|_| unavailable())?) == receipt_digest,
            ),
            (
                "original receipt",
                proof.get("originalReceiptDigest").and_then(Value::as_str)
                    == Some(Digest::of(&signed_receipt).as_str())
                    && observed.target_runtime_id == identity.target_id
                    && observed.capsule_digest == claims.source.capsule_digest
                    && observed.status == 1
                    && observed.reason_code == "ACTIVE_LOCAL"
                    && observed.observed_at_ns < until,
            ),
        ];
        if let Some((boundary, _)) = checks.iter().find(|(_, valid)| !valid) {
            return Err(format!("historical confirmation {boundary} rejected"));
        }
        if let Some(ack) = &acknowledgement {
            verifier
                .verify_acknowledgement(ack, &verified)
                .map_err(|_| unavailable())?;
        }
        Ok(VerifiedHistoricalRecord {
            confirmation: HistoricalTargetConfirmation {
                revision,
                admission_digest: admission,
                signed_delivery: wire,
                signed_acknowledgement: acknowledgement,
            },
            observed,
            source: claims.source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpc_runtime_agent::RuntimeWireSigner;
    use pc_runtime_types::PURPOSE_ACTIVATION_RECEIPT_V1;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::{collections::BTreeMap, fs, path::Path, sync::Arc};

    fn key(root: &Path, name: &str) -> [u8; 32] {
        let text = fs::read_to_string(root.join("secrets").join(format!("{name}.txt"))).unwrap();
        let text = text.trim();
        assert_eq!(text.len(), 64);
        std::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
    }

    async fn retained_installation() -> (
        std::path::PathBuf,
        sqlx::PgPool,
        crate::TargetIdentity,
        TargetDispositionStore,
        [u8; 32],
    ) {
        let root =
            std::path::PathBuf::from(std::env::var("OPENPC_EXPIRED_CONFIRMATION_ROOT").unwrap());
        let input: Value = serde_json::from_slice(
            &fs::read(root.join("evidence/runtime-bootstrap/policy-set-input.json")).unwrap(),
        )
        .unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(
                PgConnectOptions::new()
                    .host("127.0.0.1")
                    .port(55432)
                    .database("openpc_control")
                    .username("openpc_local_control_worker")
                    .password(
                        fs::read_to_string(
                            root.join("secrets/control_worker_runtime_db_password.txt"),
                        )
                        .unwrap()
                        .trim(),
                    ),
            )
            .await
            .unwrap();
        let peer = crate::runtime_tls::target_identity_from_pem(
            &fs::read(root.join("data/runtime-bootstrap/runtime/tls/ads-client.pem")).unwrap(),
        )
        .unwrap();
        let store = TargetDispositionStore::from_host_installation(
            pool.clone(),
            input["participantId"].as_str().unwrap().into(),
            input["privacyDomainId"].as_str().unwrap().into(),
            key(&root, "fleet_controller_signing_secret"),
            key(&root, "runtime_target_disposition_key"),
            BTreeMap::new(),
        )
        .unwrap();
        let agent = key(&root, "runtime_agent_signing_secret");
        store
            .register_host_target_key(
                &peer.target_id,
                &PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, agent)
                    .unwrap()
                    .verifier()
                    .sec1_bytes(),
            )
            .unwrap();
        store
            .register_host_runtime_target_key(
                &peer.target_id,
                &RuntimeWireSigner::from_secret_bytes(agent)
                    .unwrap()
                    .verifier()
                    .public_key_bytes(),
            )
            .unwrap();
        (root, pool, peer, store, agent)
    }

    #[tokio::test]
    #[ignore = "requires a completed original expired public activation; read-only, no seeded business state or ACK"]
    async fn postgres_expired_original_confirmation_preserves_custody_and_denies_foreign_peer() {
        let (root, pool, peer, store, agent) = retained_installation().await;
        let first = store.original_confirmation_for_peer(&peer).await.unwrap();
        let again = store.original_confirmation_for_peer(&peer).await.unwrap();
        assert_eq!(first.revision, again.revision);
        assert_eq!(first.admission_digest, again.admission_digest);
        assert_eq!(first.signed_delivery, again.signed_delivery);
        assert_eq!(first.signed_acknowledgement, again.signed_acknowledgement);
        assert!(store.current_for_installed_peer(&peer).await.is_err());
        let mut foreign = peer.clone();
        foreign.certificate_fingerprint = Digest::of("foreign certificate");
        assert!(
            store
                .original_confirmation_for_peer(&foreign)
                .await
                .is_err()
        );
        let mut foreign = peer.clone();
        foreign.target_id = uuid::Uuid::now_v7().to_string();
        assert!(
            store
                .original_confirmation_for_peer(&foreign)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .original_confirmation_for_peer(&peer)
                .await
                .unwrap()
                .signed_delivery,
            first.signed_delivery
        );
        // Exercise the same TLS/gRPC service as the packaged target. Direct
        // SQL verification alone cannot establish transport reachability.
        let tls_root = root.join("data/runtime-bootstrap/runtime/tls");
        let fleet = Arc::new(
            crate::FleetController::new(
                key(&root, "fleet_controller_signing_secret"),
                &PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, agent)
                    .unwrap()
                    .verifier()
                    .sec1_bytes(),
                30_000,
            )
            .unwrap(),
        );
        fleet.register_target(peer.clone(), &peer).unwrap();
        let tls = crate::runtime_tls::server_config(
            &fs::read(root.join("secrets/runtime_ads_server_cert.pem")).unwrap(),
            &fs::read(root.join("secrets/runtime_ads_server_key.pem")).unwrap(),
            &fs::read(root.join("secrets/identity_mtls_ca.pem")).unwrap(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(crate::serve_ads(
            crate::ads::AdsService::new(fleet).with_target_disposition(Arc::new(store)),
            listener,
            tls,
            async {
                let _ = stopped.await;
            },
        ));
        use crate::target_disposition_transport::{
            ReadDispositionRequest, ReadOriginalConfirmationResponse,
        };
        use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
        let channel = Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name("control-worker")
                    .ca_certificate(Certificate::from_pem(
                        fs::read(tls_root.join("ads-ca.pem")).unwrap(),
                    ))
                    .identity(Identity::from_pem(
                        fs::read(tls_root.join("ads-client.pem")).unwrap(),
                        fs::read(tls_root.join("ads-client.key")).unwrap(),
                    )),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut grpc = tonic::client::Grpc::new(channel);
        grpc.ready().await.unwrap();
        let challenge = vec![71; 32];
        let mut request = tonic::Request::new(ReadDispositionRequest {
            challenge: challenge.clone(),
        });
        request.set_timeout(std::time::Duration::from_secs(4));
        let response: tonic::Response<ReadOriginalConfirmationResponse> = grpc
            .unary(
                request,
                http::uri::PathAndQuery::from_static(
                    "/openpc.internal.runtime.v1.TargetDispositionService/ReadOriginalConfirmation",
                ),
                tonic_prost::ProstCodec::default(),
            )
            .await
            .unwrap();
        let response = response.into_inner();
        assert_eq!(response.challenge, challenge);
        assert_eq!(response.signed_delivery, first.signed_delivery);
        assert_eq!(
            response.signed_acknowledgement,
            first.signed_acknowledgement.unwrap_or_default()
        );
        drop(grpc);
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
        pool.close().await;
    }

    async fn renewal_snapshot(store: &TargetDispositionStore, target: &str) -> Value {
        let mut tx = store.pool.begin().await.unwrap();
        store.context(&mut tx).await.unwrap();
        let snapshot: Value = sqlx::query_scalar(r#"select jsonb_build_object(
          'target',(select to_jsonb(t) from control.runtime_target t where runtime_target_id=$1::text::uuid),
          'work',(select jsonb_agg(to_jsonb(w) order by configuration_work_id) from control.configuration_work w where configuration_work_id in
            ('01a0dce3-fc5b-787b-ac18-2c173d3ca1a0','01a0dd90-4a0a-7dc0-98cb-159824f79d0e')),
          'admission',(select jsonb_agg(to_jsonb(a) order by revision) from control.runtime_target_disposition_admission a where runtime_target_id=$1::text::uuid),
          'delivery',(select jsonb_agg(to_jsonb(d) order by revision) from control.runtime_target_disposition_delivery d where runtime_target_id=$1::text::uuid),
          'ack',(select jsonb_agg(to_jsonb(k) order by delivery_digest) from control.runtime_target_disposition_acknowledgement k where runtime_target_id=$1::text::uuid),
          'observation',(select jsonb_agg(to_jsonb(o) order by runtime_activation_observation_id) from control.runtime_activation_observation o where configuration_work_id in
            ('01a0dce3-fc5b-787b-ac18-2c173d3ca1a0','01a0dd90-4a0a-7dc0-98cb-159824f79d0e'))
        )"#).bind(target).fetch_one(&mut *tx).await.unwrap();
        tx.rollback().await.unwrap();
        snapshot
    }

    #[tokio::test]
    #[ignore = "requires the retained terminal failed renewal; admission-only denial, no signing or replay"]
    async fn postgres_terminal_renewal_denial_preserves_original_effects() {
        let (_, pool, peer, store, _) = retained_installation().await;
        let before = renewal_snapshot(&store, &peer.target_id).await;
        assert_eq!(before["target"]["state"], "FAILED");
        assert_eq!(before["target"]["revision"], 10);
        let works = before["work"].as_array().unwrap();
        assert_eq!(works.len(), 2);
        let failed = works
            .iter()
            .find(|w| w["configuration_work_id"] == "01a0dd90-4a0a-7dc0-98cb-159824f79d0e")
            .unwrap();
        assert_eq!(failed["state"], "FAILED");
        assert_eq!(failed["attempt_count"], 3);
        assert!(failed["execution_attempt_id"].is_null());
        assert!(failed["execution_started_at"].is_null());
        assert_eq!(
            failed["result_receipt_digest"],
            "sha256:4e7c059d90197fff68e51aad5eb2a76e94266ad51c8aca26ced3a11679674f1d"
        );
        let completed = works
            .iter()
            .find(|w| w["configuration_work_id"] == "01a0dce3-fc5b-787b-ac18-2c173d3ca1a0")
            .unwrap();
        assert_eq!(completed["state"], "COMPLETED");
        assert_eq!(
            completed["result_receipt_digest"],
            "sha256:57a4e1cf5d7518fcb3c33b17b5afc6017ec914d0678d1b7524efc32d614ff023"
        );
        for field in ["admission", "delivery", "ack", "observation"] {
            assert_eq!(
                before[field].as_array().unwrap().len(),
                1,
                "original {field}"
            );
        }
        assert_eq!(before["admission"][0]["revision"], 1);
        // The corrected decoder must not change the exact contention retry
        // signal. Hold only the existing transaction-scoped target fence.
        let mut lock = pool.begin().await.unwrap();
        store.context(&mut lock).await.unwrap();
        sqlx::query("select pg_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text||':'||($1::text::uuid)::text,0))")
            .bind(&peer.target_id).execute(&mut *lock).await.unwrap();
        let busy = store
            .begin_activation_withdrawal(
                &peer.target_id,
                "01a0dd90-4a0a-7dc0-98cb-159824f79d0e",
                "local-control-worker-1",
                &peer.certificate_fingerprint,
                1,
            )
            .await;
        assert!(matches!(busy, Err(error) if error == super::super::TARGET_DISPOSITION_BUSY));
        lock.rollback().await.unwrap();
        let result = store
            .begin_activation_withdrawal(
                &peer.target_id,
                "01a0dd90-4a0a-7dc0-98cb-159824f79d0e",
                "local-control-worker-1",
                &peer.certificate_fingerprint,
                1,
            )
            .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("terminal cause admitted"),
        };
        let after = renewal_snapshot(&store, &peer.target_id).await;
        assert!(
            before == after,
            "terminal diagnostic changed original state or bytes"
        );
        assert_eq!(
            error,
            "target disposition owner unavailable [admission:cause_unavailable:P0001]"
        );
        println!(
            "OPENPC_WITHDRAWAL_DIAGNOSTIC|admission|cause_unavailable|original-state-and-bytes-unchanged"
        );
        pool.close().await;
    }
}
