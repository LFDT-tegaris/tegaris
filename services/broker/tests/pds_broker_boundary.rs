// The target-local owner is not deployed by this component test. Unauthenticated
// requests must stay denied; synthetic authority records are not PDS acceptance.
use openpc_broker::{BrokerService, ProviderOutcome, ProviderTransport, ReadLaw};
use openpc_pds::{EvaluationInput, IdentityAssertionEvidence, PolicyDecisionService};
use pc_runtime_types::{
    ContractInvocation, DecisionEffect, Digest, ProviderResponse, RequestClass, RuntimeBindings,
    RuntimeRequest, Transport,
};

struct Provider {
    calls: usize,
}

impl ProviderTransport for Provider {
    fn send(&mut self, request: &RuntimeRequest, _attempt_id: &str) -> ProviderOutcome {
        self.calls += 1;
        let body = br#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#.to_vec();
        ProviderOutcome::Response(ProviderResponse {
            request_id: request.request_id.clone(),
            response_digest: Digest::of(&body),
            anchor_digest: Digest::of("anchor"),
            body,
            complete: true,
        })
    }

    fn reconcile(&mut self, _signed_transaction_hash: &Digest) -> Option<ProviderResponse> {
        None
    }
}

fn digest(value: &str) -> Digest {
    Digest::of(value)
}

fn request() -> RuntimeRequest {
    let mut calldata = vec![0x12, 0x34, 0x56, 0x78];
    calldata.extend_from_slice(&[0_u8; 31]);
    calldata.push(7);
    let mut request = RuntimeRequest {
        visibility: None,
        deployment: None,
        request_id: "request-1".into(),
        method: "eth_call".into(),
        params_digest: digest("params"),
        transport: Transport::Http,
        batch_index: 0,
        request_digest: digest("placeholder"),
        class: RequestClass::Read,
        received_at_ms: 100,
        deadline_at_ms: 200,
        response_budget_bytes: 1024,
        invocation: Some(ContractInvocation {
            chain_id: "1".into(),
            network_id: "mainnet".into(),
            genesis_digest: digest("genesis"),
            contract_address: [1; 20],
            proxy_address: None,
            implementation_address: None,
            code_digest: digest("code"),
            implementation_code_digest: None,
            abi_digest: digest("abi"),
            calldata,
            nested_calls: Vec::new(),
        }),
    };
    request.request_digest = request.computed_digest().unwrap();
    request
}

fn bindings() -> RuntimeBindings {
    RuntimeBindings {
        participant_id: "participant-1".into(),
        privacy_domain_id: "privacy-1".into(),
        workload_id: "workload-1".into(),
        target_id: "target-1".into(),
        active_generation_digest: digest("generation"),
        observed_generation_digest: digest("generation"),
        policy_generation_digest: digest("policy"),
        expected_policy_generation_digest: digest("policy"),
        fact_generation_digest: digest("facts"),
        expected_fact_generation_digest: digest("facts"),
        route_profile_digest: digest("route"),
        expected_route_profile_digest: digest("route"),
        eligible_provider_profile_ids: vec!["provider-1".into()],
        provider_profile_digest: digest("provider"),
        expected_provider_profile_digest: digest("provider"),
    }
}

#[test]
fn absent_runtime_owner_never_mints_a_capability_or_contacts_a_provider() {
    for class in [RequestClass::Read, RequestClass::Write] {
        let pds = PolicyDecisionService::new([21; 32], 25).unwrap();
        let broker = BrokerService::new(&pds.capability_verifier_sec1(), 8).unwrap();
        let mut request = request();
        request.class = class;
        if class == RequestClass::Write {
            request.method = "eth_sendRawTransaction".into();
        }
        request.request_digest = request.computed_digest().unwrap();
        let decision = pds
            .evaluate(&EvaluationInput {
                request: request.clone(),
                identity_assertion: IdentityAssertionEvidence {
                    payload_cbor: vec![],
                    cose_sign1: vec![],
                },
            })
            .unwrap();
        assert_eq!(decision.effect, DecisionEffect::DenyTerminal);
        assert!(decision.capability.is_none());
        let mut provider = Provider { calls: 0 };
        assert!(
            broker
                .dispatch(
                    &request,
                    &bindings(),
                    &decision,
                    111,
                    &digest("anchor"),
                    ReadLaw {
                        same_route_retries: 0,
                        parity_failover: false
                    },
                    &mut provider,
                    None
                )
                .is_err()
        );
        assert_eq!(provider.calls, 0);
    }
}
