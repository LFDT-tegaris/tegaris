use pc_policy_core::{EvaluationInput, evaluate, normalize, pc_cbor_1, pc_cbor_1_digest};
use serde::Serialize;
use serde_json::Value;
use std::io::{self, Read};

#[path = "openpc-policy-evaluator/cigl_analysis_command.rs"]
mod cigl_analysis_command;
#[path = "openpc-policy-evaluator/cigl_command.rs"]
mod cigl_command;
#[path = "openpc-policy-evaluator/cigl_profile_command.rs"]
mod cigl_profile_command;
#[path = "openpc-policy-evaluator/deployment_intent_command.rs"]
mod deployment_intent_command;
#[path = "openpc-policy-evaluator/deployment_projection_command.rs"]
mod deployment_projection_command;
#[path = "openpc-policy-evaluator/deployment_rejection_command.rs"]
mod deployment_rejection_command;
#[path = "openpc-policy-evaluator/native_value_command.rs"]
mod native_value_command;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output {
    evaluator_identity: String,
    truth_state: pc_policy_core::TruthState,
    permissions: Vec<String>,
    obligations: Vec<String>,
    conflicts: Vec<String>,
    explanation_codes: Vec<String>,
    input_digest: String,
    result_digest: String,
    input_bytes: String,
    result_bytes: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let mut source = String::new();
    io::stdin()
        .read_to_string(&mut source)
        .expect("read evaluator input");
    let document: Value = serde_json::from_str(&source).expect("valid policy core input");
    if document.get("command").and_then(Value::as_str) == Some("MODULE_LIFECYCLE_SIMULATION") {
        let result = serde_json::from_value::<pc_policy_core::module_lifecycle::Input>(
            document.get("value").cloned().unwrap_or(Value::Null),
        )
        .map_err(|_| "module input rejected".to_owned())
        .and_then(|input| pc_policy_core::module_lifecycle::simulate(&input));
        println!(
            "{}",
            result.unwrap_or_else(|_| serde_json::json!({"code":"PC-MODULE-7003"}))
        );
        return;
    }
    if document.get("command").and_then(Value::as_str) == Some("READ_CIGL_PROFILE") {
        println!(
            "{}",
            cigl_profile_command::execute(document.get("value").cloned().unwrap_or(Value::Null))
                .unwrap_or_else(|_| serde_json::json!({"code":"PC-POLICY-2003"}))
        );
        return;
    }
    if let Some(command @ ("READ_CIGL_ANALYSIS" | "REVIEW_CIGL_ANALYSIS")) =
        document.get("command").and_then(Value::as_str)
    {
        println!(
            "{}",
            (if command == "READ_CIGL_ANALYSIS" {
                cigl_analysis_command::execute
            } else {
                cigl_analysis_command::review
            })(document.get("value").cloned().unwrap_or(Value::Null))
            .unwrap_or_else(|_| serde_json::json!({"code":"PC-POLICY-2003"}))
        );
        return;
    }
    if let Some(
        command @ ("VALIDATE_CIGL_SETTINGS"
        | "ENCODE_CIGL_SETTINGS_SOURCE"
        | "VALIDATE_CIGL_GRANT"
        | "VALIDATE_CIGL_DEPENDENCIES"),
    ) = document.get("command").and_then(Value::as_str)
    {
        let result = cigl_command::execute(
            command,
            document.get("value").cloned().unwrap_or(Value::Null),
        );
        println!(
            "{}",
            result.unwrap_or_else(|_| serde_json::json!({"code":"PC-POLICY-2003"}))
        );
        return;
    }
    if let Some(
        command @ ("ENCODE_NATIVE_VALUE_AUTHORIZATION" | "READ_NATIVE_VALUE_AUTHORIZATION"),
    ) = document.get("command").and_then(Value::as_str)
    {
        println!(
            "{}",
            native_value_command::execute(
                command,
                document.get("value").cloned().unwrap_or(Value::Null)
            )
            .unwrap_or_else(|_| serde_json::json!({"code":"PC-POLICY-2003"}))
        );
        return;
    }
    if let Some(command @ ("READ_DEPLOYMENT_PROJECTION" | "READ_DEPLOYMENT_REJECTION")) =
        document.get("command").and_then(Value::as_str)
    {
        println!(
            "{}",
            (if command == "READ_DEPLOYMENT_REJECTION" {
                deployment_rejection_command::execute
            } else {
                deployment_projection_command::execute
            })(document.get("value").cloned().unwrap_or(Value::Null))
            .unwrap_or_else(|_| serde_json::json!({"code":"PC-POLICY-2003"}))
        );
        return;
    }
    if let Some(
        command @ ("PREPARE_DEPLOYMENT_INTENT"
        | "READ_DEPLOYMENT_INTENT"
        | "BIND_DEPLOYMENT_RESERVATION"),
    ) = document.get("command").and_then(Value::as_str)
    {
        println!(
            "{}",
            deployment_intent_command::execute(
                command,
                document.get("value").cloned().unwrap_or(Value::Null)
            )
            .unwrap_or_else(|_| serde_json::json!({"code":"PC-POLICY-2003"}))
        );
        return;
    }
    if document.get("command").and_then(Value::as_str) == Some("DEPLOYMENT_SIMULATION") {
        let result = document
            .get("value")
            .cloned()
            .ok_or_else(|| "simulation input missing".to_owned())
            .and_then(|value| {
                serde_json::from_value::<
                    openpc_multi_rpc::deployment::simulation::DeploymentSimulationInput,
                >(value)
                .map_err(|_| "simulation input rejected".to_owned())
            })
            .and_then(|value| {
                let evaluation = openpc_multi_rpc::deployment::simulation::evaluate(&value)?;
                Ok(serde_json::json!({
                    "identity": "PC-DEPLOYMENT-SIMULATION-1/PC-CBOR-1",
                    "authority": "SIMULATION_ONLY", "evaluation": evaluation,
                }))
            });
        println!(
            "{}",
            result.unwrap_or_else(|_| serde_json::json!({"code":"PC-POLICY-2003"}))
        );
        return;
    }
    if document.get("command").and_then(Value::as_str) == Some("VISIBILITY_SIMULATION") {
        let result = serde_json::from_value::<
            pc_policy_core::visibility_policy::VisibilitySimulationInput,
        >(document.get("value").cloned().unwrap_or(Value::Null))
        .map_err(|_| "visibility simulation input rejected".to_owned())
        .and_then(|input| {
            pc_policy_core::visibility_policy::evaluate_visibility_simulation(&input)
        });
        println!(
            "{}",
            match result {
                Ok(evaluation) =>
                    serde_json::json!({"identity":"PC-VISIBILITY-SIMULATION-1/PC-CBOR-1", "authority":"SIMULATION_ONLY", "evaluation":evaluation}),
                Err(_) => serde_json::json!({"code":"PC-POLICY-2003"}),
            }
        );
        return;
    }
    if document.get("command").and_then(Value::as_str) == Some("CONTRACT_SIMULATION") {
        let result = document
            .get("value")
            .cloned()
            .ok_or_else(|| "simulation input missing".to_owned())
            .and_then(|value| {
                serde_json::from_value::<
                        pc_policy_core::contract_simulation::ContractSimulationInput,
                    >(value)
                    .map_err(|_| "simulation input rejected".to_owned())
            })
            .and_then(|value| {
                let evaluation =
                    pc_policy_core::contract_simulation::evaluate_contract_simulation(&value)?;
                Ok(serde_json::json!({
                    "identity": "PC-CONTRACT-SIMULATION-1/PC-CBOR-1",
                    "authority": "SIMULATION_ONLY",
                    "evaluation": evaluation,
                }))
            });
        println!(
            "{}",
            result.unwrap_or_else(|_| serde_json::json!({"code":"PC-POLICY-2003"}))
        );
        return;
    }
    if document.get("command").and_then(Value::as_str) == Some("INDEXER_SIMULATION") {
        let result =
            serde_json::from_value::<pc_policy_core::indexer_policy::IndexerSimulationInput>(
                document.get("value").cloned().unwrap_or(Value::Null),
            )
            .map_err(|_| "source simulation input rejected".to_owned())
            .and_then(|input| pc_policy_core::indexer_policy::evaluate_indexer_simulation(&input));
        println!(
            "{}",
            match result {
                Ok(evaluation) => serde_json::json!({
                    "identity": "PC-INDEXER-SIMULATION-1/PC-CBOR-1",
                    "authority": "SIMULATION_ONLY", "evaluation": evaluation,
                }),
                Err(_) => serde_json::json!({"code":"PC-POLICY-2003"}),
            }
        );
        return;
    }
    if document.get("command").and_then(Value::as_str) == Some("COMPILE_SEMANTICS") {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct CompileInput {
            document: pc_policy_core::semantics::PolicySemanticDocument,
            admitted: Vec<pc_policy_core::contract_policy::AdmittedContractPolicy>,
            #[serde(default)]
            deployments: Vec<pc_policy_core::deployment_policy::AdmittedDeploymentPolicy>,
            #[serde(default)]
            indexer_inputs: Vec<pc_policy_core::indexer_policy::IndexerCompilationInput>,
            #[serde(default)]
            visibility_inputs: Vec<pc_policy_core::visibility_policy::AdmittedVisibilityResource>,
            workload_id: String,
        }
        let result = document
            .get("value")
            .cloned()
            .ok_or_else(|| "compile input missing".to_owned())
            .and_then(|value| {
                serde_json::from_value::<CompileInput>(value)
                    .map_err(|_| "compile input rejected".to_owned())
            })
            .and_then(|value| {
                pc_policy_core::contract_simulation::compile_document_with_visibility(
                    &value.document,
                    &value.admitted,
                    &value.deployments,
                    &value.indexer_inputs,
                    &value.visibility_inputs,
                    &value.workload_id,
                    &value.document.digest()?,
                )
            });
        let output = match result {
            Ok(compiled) => serde_json::json!({
                "identity": "PC-CONTRACT-COMPILER-1/PC-CBOR-1",
                "configurationBytes": hex(&compiled.configuration_cbor),
                "configurationDigest": compiled.configuration_digest.as_str(),
                "policyBytes": hex(&compiled.policy_cbor),
                "policyDigest": compiled.policy_digest.as_str(),
            }),
            Err(_) => serde_json::json!({"code":"PC-POLICY-2003"}),
        };
        println!("{output}");
        return;
    }
    if matches!(
        document.get("command").and_then(Value::as_str),
        Some("SEMANTICS" | "DECODE_SEMANTICS")
    ) {
        let result = document
            .get("value")
            .cloned()
            .ok_or_else(|| "policy semantic document missing".to_owned())
            .and_then(|value| {
                if document.get("command").and_then(Value::as_str) == Some("DECODE_SEMANTICS") {
                    let bytes: Vec<u8> = serde_json::from_value(value)
                        .map_err(|_| "semantic bytes rejected".to_owned())?;
                    pc_policy_core::semantics::PolicySemanticDocument::decode(&bytes)
                } else {
                    serde_json::from_value::<pc_policy_core::semantics::PolicySemanticDocument>(
                        value,
                    )
                    .map_err(|_| "policy semantic document rejected".to_owned())
                }
            })
            .and_then(|value| {
                value.validate()?;
                Ok(value)
            });
        let output = match result {
            Ok(value) => serde_json::json!({
                "identity": "PC-POLICY-SEMANTICS-1/PC-CBOR-1",
                "document": value,
                "bytes": hex(&pc_cbor_1(&value)),
                "digest": hex(&pc_cbor_1_digest(&value)),
            }),
            Err(_) => serde_json::json!({"code": "PC-POLICY-2003"}),
        };
        println!("{output}");
        return;
    }
    if document.get("command").and_then(Value::as_str) == Some("DIGEST") {
        let value = document.get("value").expect("digest value");
        println!(
            "{}",
            serde_json::json!({
                "identity": "PC-CBOR-1",
                "digest": hex(&pc_cbor_1_digest(value)),
                "bytes": hex(&pc_cbor_1(value)),
            })
        );
        return;
    }
    let input: EvaluationInput = serde_json::from_value(document).expect("valid evaluator input");
    let input = normalize(&input);
    let input_bytes = pc_policy_core::pc_cbor_1(&input);
    let result = evaluate(&input);
    let result_bytes = pc_policy_core::pc_cbor_1(&result);
    let output = Output {
        evaluator_identity: result.evaluator_identity,
        truth_state: result.truth_state,
        permissions: result.permissions,
        obligations: result.obligations,
        conflicts: result.conflicts,
        explanation_codes: result.explanation_codes,
        input_digest: hex(&result.input_digest),
        result_digest: hex(&result.result_digest),
        input_bytes: hex(&input_bytes),
        result_bytes: hex(&result_bytes),
    };
    println!(
        "{}",
        serde_json::to_string(&output).expect("serialize evaluator output")
    );
}
