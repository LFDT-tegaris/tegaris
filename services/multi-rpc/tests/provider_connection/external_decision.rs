use super::*;
use openpc_multi_rpc::external_decision::*;
use serde_json::{Value, json};
use std::sync::atomic::AtomicBool;

#[tokio::test]
async fn external_observation_is_typed_scoped_bounded_idempotent_and_cancelable() {
    let certs = Certificates::new();
    for (index, mode) in [
        "true",
        "false",
        "wrong-scope",
        "wrong-version",
        "wrong-request",
        "expired",
        "malformed",
        "raw-error",
        "retry",
        "cancel",
        "timeout",
    ]
    .into_iter()
    .enumerate()
    {
        let requests = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let captured = requests.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel = cancelled.clone();
        let peer=Provider::start_with_handler(certs.server_config("server"),move |wire| {
            let start=wire.windows(4).position(|v|v==b"\r\n\r\n").unwrap()+4;
            let bytes=wire[start..].to_vec();
            let input:Value=serde_json::from_slice(&bytes).unwrap();
            let count={ let mut all=captured.lock().unwrap(); all.push(bytes); all.len() };
            assert_eq!(input["method"],"acquireObservation");
            assert!(input["context"]["deadlineAt"].as_str().unwrap().contains('T'));
            assert_eq!(input["context"]["cancellation"]["mode"],"NO_NEW_EFFECT_AFTER_CANCELLATION");
            if mode=="retry" && count==1 { return b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(); }
            let request:ExternalDecisionRequestV1=serde_json::from_value(input["request"].clone()).unwrap();
            let mut observation=ExternalDecisionObservationV1 {
                request_digest:request.digest().unwrap(),source_occurrence:request.source_occurrence,
                participant_id:request.participant_id,privacy_domain_id:request.privacy_domain_id,
                provider_id:request.provider_id,provider_version:request.provider_version,
                provider_configuration_digest:request.provider_configuration_digest,condition:request.condition,
                satisfied:mode!="false",observed_at_ms:now(),expires_at_ms:now()+2000,response_digest:Digest::of([]),
            };
            match mode {
                "wrong-scope"=>observation.privacy_domain_id=uuid::Uuid::now_v7().to_string(),
                "wrong-version"=>observation.provider_version="2.0.0".into(),
                "wrong-request"=>observation.request_digest=Digest::of(b"other"),
                "expired"=>observation.expires_at_ms=now()-1,
                "cancel"=>cancel.store(true,Ordering::Release),
                _=>(),
            }
            observation.response_digest=observation.response_digest().unwrap();
            let mut value=serde_json::to_value(observation).unwrap();
            if mode=="malformed" { value["satisfied"]=json!("true"); }
            if mode=="raw-error" { value=json!({"privateToken":"never return this"}); }
            let body=serde_json::to_vec(&value).unwrap();
            let mut response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
            response.extend(body);response
        },if mode=="timeout" { Duration::from_millis(150) } else { Duration::ZERO }).await;
        let registry = ConnectionRegistry::open(
            &certs.path.join(format!("external-{index}")),
            "external-owner",
            1,
        )
        .unwrap();
        registry
            .install(
                "provider-1",
                0,
                connection_generation(&certs, peer.port, 1, 1),
            )
            .await
            .unwrap();
        let record = registry.readback("endpoint-1").await.unwrap();
        let lease = registry
            .acquire("provider-1", "endpoint-1", record.dispatcher_generation)
            .unwrap();
        let request = ExternalDecisionRequestV1 {
            participant_id: uuid::Uuid::now_v7().to_string(),
            privacy_domain_id: uuid::Uuid::now_v7().to_string(),
            provider_id: "provider-1".into(),
            provider_version: "1.0.0".into(),
            provider_configuration_digest: Digest::of(b"signed-profile"),
            source_occurrence: Digest::of(b"source-occurrence"),
            condition: "eligible".into(),
            input_digest: Digest::of(b"scoped-input"),
        };
        let authority = Digest::of(b"actual-test-authority");
        let scope = Digest::of(b"scope");
        let occurrence = uuid::Uuid::now_v7().to_string();
        let access = vec!["ACCESS-STANDARD".into()];
        let context = AdapterCallContextV1 {
            authorization_digest: &authority,
            profile_digest: &request.provider_configuration_digest,
            scope_digest: &scope,
            authorization_context_id: &occurrence,
            authorization_context_epoch: 1,
            access_class_ids: &access,
            occurrence_id: &occurrence,
            audit_correlation_id: &occurrence,
            deadline: Instant::now() + Duration::from_secs(2),
            profile_timeout_ms: if mode == "timeout" { 40 } else { 1500 },
            maximum_age_ms: 5000,
            cancelled: &cancelled,
            revalidate: &|| true,
        };
        let result = acquire_observation(&lease, &request, &context).await;
        if matches!(mode, "true" | "false" | "retry") {
            let result = result.unwrap();
            assert_eq!(result.observation().satisfied, mode != "false");
            assert_eq!(result.request_digest(), &request.digest().unwrap());
        } else {
            let error = result.err().unwrap();
            assert!(!error.to_string().contains("private"));
        }
        {
            let actual = requests.lock().unwrap();
            if mode == "retry" {
                assert_eq!(actual.len(), 2);
                assert_eq!(actual[0], actual[1]);
            } else {
                assert!(actual.len() <= 1, "{mode}");
            }
        }
        cancelled.store(true, Ordering::Release);
        let before = peer.contacts();
        assert!(
            acquire_observation(&lease, &request, &context)
                .await
                .is_err()
        );
        assert_eq!(peer.contacts(), before);
    }
}
