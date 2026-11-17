//! Composed policy/provider component regression. Identity input is deliberately
//! a test double here; real signed identity/currentness is tested by runtime.
use super::*;
use openpc_multi_rpc::{
    cigl::{
        analysis::{AnalysisSources, analyze_signed_method},
        authorization::{SignedMethodContext, evaluate_signed_method_profile},
        observer::{ObservationScope, observe_signed},
    },
    governed_write::submission_params_digest,
    route_witness::{ChainAnchor, ChainAnchorBindings, VerifiedChainAnchor},
};
use pc_policy_core::{
    cigl::{CallKind, TraceLimits, grants::*, profile::*},
    contract_policy::{
        AdmittedArgumentRule, AdmittedContractPolicy, compile_admitted_contract_policies,
    },
    invocation::*,
    rpc_policy::{RpcEffect, RpcRule, RpcSurfacePolicy},
};
use pc_runtime_types::{RequestClass, RuntimeError, RuntimeRequest, RuntimeResult, Transport};
use serde_json::{Value, json};

const TENANT: &str = "018f0000-0000-7000-8000-000000000101";
const PRIVACY: &str = "018f0000-0000-7000-8000-000000000201";
const ROOT: &str = "018f0000-0000-7000-8000-000000000701";
const CHILD: &str = "018f0000-0000-7000-8000-000000000703";
const BINDING: &str = "018f0000-0000-7000-8000-000000000704";
const SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

#[path = "cigl_review.rs"]
mod review_tests;

struct Subjects(ValidatedInvocationAuthorization);
impl pc_policy_core::cigl::program::CurrentStateEvidence for Subjects {
    fn read(
        &self,
        _: &pc_policy_core::cigl::program::StateValueReference,
    ) -> RuntimeResult<ArgumentValue> {
        Err(RuntimeError::RuntimeUnavailable)
    }
}
impl CurrentInteractionSubjects for Subjects {
    fn invocation_authorization(&self) -> RuntimeResult<&ValidatedInvocationAuthorization> {
        Ok(&self.0)
    }
    fn participant_id(&self) -> &str {
        &self.0.facts().participant_id
    }
    fn privacy_domain_id(&self) -> &str {
        &self.0.facts().privacy_domain_id
    }
    fn require_current(&self, _: u64) -> RuntimeResult<()> {
        Ok(())
    }
    fn matches(&self, subject: &GrantSubject) -> RuntimeResult<bool> {
        Ok(match subject {
            GrantSubject::Role { id } => self.0.facts().roles.contains(id),
            _ => false,
        })
    }
}
fn prefixed(digest: Digest) -> String {
    format!("sha256:{}", digest.as_str())
}
fn calldata(amount: u8) -> Vec<u8> {
    let mut data = SELECTOR.to_vec();
    data.extend([0; 12]);
    data.extend([0x22; 20]);
    data.extend([0; 31]);
    data.push(amount);
    data
}
fn method(id: &str, address: u8, rpc: &RpcSurfacePolicy) -> AdmittedContractPolicy {
    AdmittedContractPolicy {
        asset_id: id.into(),
        runtime_binding_id: Some(
            if id == ROOT {
                "018f0000-0000-7000-8000-000000000702"
            } else {
                BINDING
            }
            .into(),
        ),
        transaction_policy: None,
        policy_version: "1".into(),
        tenant_id: TENANT.into(),
        privacy_domain_id: PRIVACY.into(),
        chain_id: "1".into(),
        network_id: "fixture".into(),
        genesis_digest: prefixed(Digest::of("genesis")),
        contract_address: deployment_fixture::hex(&[address; 20]),
        proxy_address: None,
        implementation_address: None,
        code_digest: prefixed(Digest::of([0x60, if id == ROOT { 0 } else { 1 }])),
        implementation_code_digest: None,
        abi_digest: prefixed(Digest::of("abi")),
        canonical_signature: "transfer(address,uint256)".into(),
        selector: deployment_fixture::hex(&SELECTOR),
        canonical_abi: json!([{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[],"stateMutability":if id==ROOT {"nonpayable"} else {"view"}}]),
        effect: if id == ROOT { "WRITE" } else { "READ" }.into(),
        required_roles: vec![
            if id == ROOT {
                "root-role"
            } else {
                "child-role"
            }
            .into(),
        ],
        approval_requirement: "NONE".into(),
        mfa_requirement: "NONE".into(),
        rpc_method_policy_digest: prefixed(rpc.digest().unwrap()),
        nested_call_set_digest: prefixed(Digest::of([])),
        named_set_count: 0,
        rules: vec![AdmittedArgumentRule {
            parameter_path: "inputs[1]".into(),
            operand_type: "INTEGER".into(),
            operator: "LTE".into(),
            values: vec!["100".into()],
        }],
    }
}

#[tokio::test]
async fn cigl_composition_enforces_installed_root_nested_constraints_shared_grants_and_revalidation()
 {
    let certs = Certificates::new();
    let signer = pc_policy_core::runtime_wire::Signer::from_secret_bytes([87; 32]).unwrap();
    let generation = Digest::of("generation");
    let route = Digest::of("route");
    let block = Digest::of("block");
    let limits = TraceLimits {
        max_depth: 16,
        max_frames: 32,
        max_response_bytes: 100_000,
        timeout_ms: 5000,
    };
    for mode in [
        "ok",
        "root-role",
        "child-role",
        "deny",
        "missing-grant",
        "wrong-surface",
        "wrong-subject",
        "wrong-caller",
        "typed-argument",
        "code-drift",
        "stale-configuration",
        "revoke-after-match",
        "nested-approval",
        "nested-step-up",
        "value",
    ] {
        let rpc = RpcSurfacePolicy {
            schema_version: "1.0.0".into(),
            participant_id: TENANT.into(),
            privacy_domain_id: PRIVACY.into(),
            rules: vec![
                RpcRule {
                    method: "eth_sendRawTransaction".into(),
                    effect: RpcEffect::Allow,
                    required_roles: vec!["rpc-writer".into()],
                },
                RpcRule {
                    method: "eth_call".into(),
                    effect: RpcEffect::Allow,
                    required_roles: vec!["rpc-reader".into()],
                },
            ],
        };
        let definition = MethodProfileDefinition {
            schema_version: "1.0".into(),
            profile_id: "018f0000-0000-7000-8000-000000000801".into(),
            revision: 1,
            participant_id: TENANT.into(),
            privacy_domain_id: PRIVACY.into(),
            root_contract_method_policy_id: ROOT.into(),
            analysis_digest: Digest::of("analysis component fixture"),
            program: None,
            limits,
            interactions: vec![MethodInteractionRule {
                interaction_id: "nested".into(),
                caller: if mode == "wrong-caller" {
                    CallerConstraint::Exact {
                        address: [0x99; 20],
                    }
                } else {
                    CallerConstraint::RootExecution {}
                },
                call_kind: if mode == "value" {
                    CallKind::Call
                } else {
                    CallKind::Staticcall
                },
                contract_method_policy_id: CHILD.into(),
                maximum_value: [0; 32],
            }],
        };
        let profile_digest = definition.digest().unwrap();
        let mut grants = InteractionGrantSet {
            profile_id: definition.profile_id.clone(),
            profile_revision: 1,
            profile_digest: profile_digest.clone(),
            participant_id: TENANT.into(),
            privacy_domain_id: PRIVACY.into(),
            status: GrantStatus::Active,
            grants: vec![InteractionGrant {
                grant_id: "shared-allow".into(),
                runtime_binding_id: BINDING.into(),
                selector: SELECTOR,
                subject: GrantSubject::Role {
                    id: "child-role".into(),
                },
                surface: InteractionSurface::RawSubmission,
                effect: GrantEffect::Allow,
                status: GrantStatus::Active,
            }],
        };
        match mode {
            "deny" => {
                let mut deny = grants.grants[0].clone();
                deny.grant_id = "shared-deny".into();
                deny.effect = GrantEffect::Deny;
                grants.grants.push(deny);
            }
            "missing-grant" => grants.grants.clear(),
            "wrong-surface" => grants.grants[0].surface = InteractionSurface::EthCall,
            "wrong-subject" => grants.grants[0].subject = GrantSubject::User { id: "actor".into() },
            _ => {}
        }
        let mut root = method(ROOT, 0x35, &rpc);
        root.nested_call_set_digest = prefixed(profile_digest.clone());
        let mut child = method(CHILD, 0x33, &rpc);
        if mode == "nested-approval" {
            child.approval_requirement = "MAKER_CHECKER".into();
        }
        if mode == "nested-step-up" {
            child.mfa_requirement = "WEBAUTHN".into();
        }
        let bundle =
            compile_admitted_contract_policies(&[root, child], &[rpc], &generation, "workload")
                .unwrap()
                .unwrap();
        let mut configuration = decode_active_invocation_configuration(
            &bundle.configuration_cbor,
            &bundle.configuration_digest,
        )
        .unwrap();
        let configured = ConfiguredMethodProfile { definition, grants };
        let payload = configured.to_cbor().unwrap();
        configuration
            .resource_artifacts
            .push(ConfigurationArtifactV1 {
                artifact_id: configured.definition.profile_id.clone(),
                artifact_kind: ConfigurationArtifactKind::CiglProfile,
                artifact_digest: Digest::of(&payload),
                payload_cbor: payload,
            });
        let configuration = encode_active_invocation_configuration(&configuration).unwrap();
        let configuration_digest = Digest::of(&configuration);
        let profiles = ValidatedMethodProfile::load_active(
            &configuration,
            &configuration_digest,
            &bundle.policy_cbor,
            &bundle.policy_digest,
            &ActiveInvocationScope {
                policy_generation_digest: &generation,
                tenant_id: TENANT,
                privacy_domain_id: PRIVACY,
                workload_id: "workload",
            },
        )
        .unwrap();
        let transaction = deployment_fixture::signed(Some([0x35; 20]), &calldata(50));
        let (_, invocation) = resolve_contract_invocation(
            &bundle.policies,
            "eth_sendRawTransaction",
            [0x35; 20],
            calldata(50),
        )
        .unwrap();
        let mut request = RuntimeRequest {
            visibility: None,
            deployment: None,
            invocation: Some(invocation),
            request_id: "1".into(),
            method: "eth_sendRawTransaction".into(),
            params_digest: submission_params_digest(&transaction).unwrap(),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of("pending"),
            class: RequestClass::Write,
            received_at_ms: now(),
            deadline_at_ms: now() + 20_000,
            response_budget_bytes: 1024,
        };
        request.request_digest = request.computed_digest().unwrap();
        let actor = deployment_fixture::hex(transaction.signer());
        let block_rpc = format!("0x{}", block.as_str());
        let provider=Provider::start_with_handler(certs.server_config("server"),move|bytes| {
            let offset=bytes.windows(4).position(|v|v==b"\r\n\r\n").unwrap()+4;let request:Value=serde_json::from_slice(&bytes[offset..]).unwrap();
            let result=match request["method"].as_str().unwrap() {
                "eth_getBlockByNumber"=>json!({"hash":block_rpc,"number":"0x10","stateRoot":format!("0x{}",Digest::of("state").as_str()),"gasLimit":"0x1c9c380","baseFeePerGas":"0x1"}),
                "eth_getCode"=>if request["params"][0]==deployment_fixture::hex(&[0x35;20]) {json!("0x6000")} else {json!(if mode=="code-drift" {"0x6002"} else {"0x6001"})},
                "debug_traceCall"=>if request["params"][2].get("tracer").is_some() {
                    json!({"type":"CALL","from":actor,"to":deployment_fixture::hex(&[0x35;20]),"input":deployment_fixture::hex(&calldata(50)),"value":"0x0","gas":"0x186a0","gasUsed":"0x1000","calls":[{"type":if mode=="value" {"CALL"} else {"STATICCALL"},"from":deployment_fixture::hex(&[0x35;20]),"to":deployment_fixture::hex(&[0x33;20]),"input":deployment_fixture::hex(&calldata(if mode=="typed-argument" {101} else {50})),"value":if mode=="value" {"0x1"} else {"0x0"},"gas":"0x3e8","gasUsed":"0x1"}]})
                } else {json!({"failed":false,"gas":4096,"returnValue":"","structLogs":[{"pc":0,"op":if mode=="value" {"CALL"} else {"STATICCALL"},"gas":10000,"gasCost":100,"depth":1},{"pc":0,"op":"STOP","gas":999,"gasCost":0,"depth":2},{"pc":1,"op":"STOP","gas":9000,"gasCost":0,"depth":1}]})},
                _=>panic!("CIGL must never submit"),
            };
            let body=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"result":result})).unwrap();let mut response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();response.extend(body);response
        },Duration::ZERO).await;
        let registry =
            ConnectionRegistry::open(&certs.path.join(format!("method-{mode}")), "target-1", 1)
                .unwrap();
        let record = registry
            .install(
                "provider-1",
                0,
                ProviderConnection::prepare(
                    prepared(provider.port),
                    certs.material("server"),
                    4096,
                    200_000,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let connection = registry
            .acquire("provider-1", "endpoint-1", record.dispatcher_generation)
            .unwrap();
        let material = ChainAnchor {
            chain_environment_id: "chain-1".into(),
            chain_id: 1,
            block_number: 16,
            block_hash: block.clone(),
            state_root: Digest::of("state"),
            canonical_generation: 1,
            observed_at_ns: now() * 1_000_000,
        };
        let anchor = VerifiedChainAnchor::verify(
            &signer.verifier(),
            &material.sign(&signer).unwrap(),
            &ChainAnchorBindings {
                chain_environment_id: "chain-1",
                chain_id: 1,
                canonical_generation: 1,
                maximum_age_ns: 30_000_000_000,
            },
            now() * 1_000_000,
        )
        .unwrap();
        let observation = observe_signed(
            &connection,
            &request,
            &transaction,
            &anchor,
            &ObservationScope {
                profile_digest: &profile_digest,
                route_witness_set_digest: &route,
            },
            limits,
            Instant::now() + Duration::from_secs(10),
            &|| Ok(()),
        )
        .await
        .unwrap();
        let mut roles = vec!["rpc-writer".into(), "root-role".into(), "child-role".into()];
        roles.retain(|r| r != mode);
        let subjects = Subjects(
            ValidatedInvocationAuthorization::try_new(InvocationAuthorization {
                participant_id: TENANT.into(),
                privacy_domain_id: PRIVACY.into(),
                workload_id: "workload".into(),
                actor_principal_id: "actor".into(),
                roles,
                approval: None,
                webauthn: None,
            })
            .unwrap(),
        );
        let checks = AtomicUsize::new(0);
        let revalidate = || {
            let count = checks.fetch_add(1, Ordering::SeqCst);
            if mode == "revoke-after-match" && count > 0 {
                Err(RuntimeError::Denied)
            } else {
                Ok(())
            }
        };
        let changed = Digest::of("stale");
        let context = SignedMethodContext {
            connection: &record,
            request: &request,
            transaction: &transaction,
            anchor: &anchor,
            configuration_digest: if mode == "stale-configuration" {
                &changed
            } else {
                &configuration_digest
            },
            policy_artifact_digest: &bundle.policy_digest,
            policy_generation_digest: &generation,
            route_witness_set_digest: &route,
        };
        let sources = AnalysisSources {
            configuration_bytes: &configuration,
            policy_bytes: &bundle.policy_cbor,
            root_contract_method_policy_id: ROOT,
            observation_context_digest: &profile_digest,
        };
        let analysis =
            analyze_signed_method(&observation, &sources, &subjects, &context, &|| Ok(()));
        if matches!(mode, "root-role" | "stale-configuration") {
            assert!(analysis.is_err(), "analysis {mode}");
        } else {
            let analysis = analysis.unwrap();
            let document = analysis.document();
            assert_eq!(document.interactions.len(), 1);
            assert_eq!(document.interactions[0].ordinal, 1);
            assert_eq!(document.interactions[0].parent, 0);
            assert_eq!(document.root_contract_method_policy_id, ROOT);
            assert_eq!(
                document.unresolved_count(),
                usize::from(mode == "code-drift")
            );
            assert_ne!(analysis.digest().unwrap(), Digest::of([]));
            let wire = serde_json::to_value(document).unwrap();
            assert!(wire["interactions"][0].get("input").is_none());
            assert!(wire["interactions"][0].get("messageValue").is_none());
            assert!(wire.get("rawTransaction").is_none());
            // A current root may inspect the denied child/grant and propose
            // remediation. Successful analysis is deliberately non-granting.
            let denied = AtomicUsize::new(0);
            assert!(
                analyze_signed_method(&observation, &sources, &subjects, &context, &|| {
                    if denied.fetch_add(1, Ordering::SeqCst) == 0 {
                        Ok(())
                    } else {
                        Err(RuntimeError::Denied)
                    }
                })
                .is_err()
            );
            assert_eq!(denied.load(Ordering::SeqCst), 2);
            if mode == "ok" {
                let methods = ValidatedInvocationPolicy::load_active(
                    &configuration,
                    &configuration_digest,
                    &bundle.policy_cbor,
                    &bundle.policy_digest,
                    &ActiveInvocationScope {
                        policy_generation_digest: &generation,
                        tenant_id: TENANT,
                        privacy_domain_id: PRIVACY,
                        workload_id: "workload",
                    },
                )
                .unwrap();
                let root = methods
                    .iter()
                    .find(|m| m.configured_identity().unwrap().contract_method_policy_id() == ROOT)
                    .unwrap();
                review_tests::assert_exact_review(document, &configuration, &bundle.policy_cbor);
                let index =
                    pc_policy_core::cigl::analysis::MethodAnalysisIndex::new(root, &methods)
                        .unwrap();
                use pc_policy_core::cigl::analysis::{MethodResolution, UnresolvedReason};
                for (kind, target, input, reason) in [
                    (
                        CallKind::Staticcall,
                        [0x44; 20],
                        calldata(50),
                        UnresolvedReason::UnregisteredMethod,
                    ),
                    (
                        CallKind::Call,
                        [0x33; 20],
                        vec![0; 3],
                        UnresolvedReason::MissingSelector,
                    ),
                    (
                        CallKind::Create,
                        [0x33; 20],
                        calldata(50),
                        UnresolvedReason::UnsupportedCallKind,
                    ),
                ] {
                    assert_eq!(
                        index.resolve(kind, target, &input, |_| Ok(Digest::of([0x60, 1]))),
                        MethodResolution::Unresolved { reason }
                    );
                }
                let mut ambiguous = methods.clone();
                ambiguous.push(
                    methods
                        .iter()
                        .find(|m| {
                            m.selector() == SELECTOR && m.exposed_contract_address() == [0x33; 20]
                        })
                        .unwrap()
                        .clone(),
                );
                let index =
                    pc_policy_core::cigl::analysis::MethodAnalysisIndex::new(root, &ambiguous)
                        .unwrap();
                assert_eq!(
                    index.resolve(CallKind::Staticcall, [0x33; 20], &calldata(50), |_| Ok(
                        Digest::of([0x60, 1])
                    )),
                    MethodResolution::Unresolved {
                        reason: UnresolvedReason::AmbiguousMethod
                    }
                );
                let mut invalid = document.clone();
                invalid.interactions[0].parent = 1;
                assert!(invalid.validate().is_err());
                invalid = document.clone();
                invalid.interactions[0].depth = 2;
                assert!(invalid.validate().is_err());
                invalid = document.clone();
                invalid.interactions[0].ordinal = 2;
                assert!(invalid.validate().is_err());
                assert!(
                    serde_json::from_value::<pc_policy_core::cigl::analysis::MethodAnalysisV1>(
                        json!({"framePaths":[]})
                    )
                    .is_err()
                );
            }
        }
        let result = evaluate_signed_method_profile(
            &observation,
            &profiles[0],
            &subjects,
            &subjects,
            &context,
            &revalidate,
        );
        if mode == "ok" {
            let decision = result.unwrap();
            assert_eq!(decision.interaction_count(), 1);
            assert_ne!(decision.digest().unwrap(), Digest::of([]));
            assert_eq!(checks.load(Ordering::SeqCst), 2);
        } else {
            assert!(result.is_err(), "{mode}");
        }
        assert_eq!(provider.contacts(), 6);
    }
}
