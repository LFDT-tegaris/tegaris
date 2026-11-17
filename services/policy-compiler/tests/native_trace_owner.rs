use pc_policy_core::{EvaluationInput, TruthState, evaluate, pc_cbor_1};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf};

const R8_CORPUS_ROOT_COMMITMENT: &str =
    "860ad27f51fc4178dda85e043f54451e7acdbc70963148631af2d69fd37b98fd";

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.to_string(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => {
            let mut fields = values.iter().collect::<Vec<_>>();
            fields.sort_by_key(|(key, _)| *key);
            format!(
                "{{{}}}",
                fields
                    .into_iter()
                    .map(|(key, value)| format!("{}:{}", json!(key), canonical_json(value)))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn sha256(value: &str) -> String {
    sha256_bytes(value.as_bytes())
}

fn sha256_bytes(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn bytes(value: &Value) -> Vec<u8> {
    let hex = value.as_str().expect("digest string");
    assert_eq!(hex.len(), 64);
    (0..32)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.get(name).unwrap_or_else(|| panic!("missing {name}"))
}

fn validate(
    record: &Value,
    raw_record: &str,
    commitment: &Value,
    oracle: &Value,
) -> Result<bool, String> {
    if field(record, "schemaVersion") != "2.0"
        || field(record, "targetSectionId") != "MOD-POLICY"
        || field(record, "declaredOwner") != "crates/pc-policy-core/src/evaluator.rs"
        || field(record, "declaredRuntime") != "RUST_NATIVE"
        || field(record, "behaviorKind") != "NATIVE_POLICY_EVALUATION"
    {
        return Err("owner/runtime substitution".to_owned());
    }
    let mut preimage = record.as_object().expect("record object").clone();
    preimage.remove("schemaVersion");
    let claimed = preimage
        .remove("recordDigest")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or("missing record digest")?;
    if sha256(&canonical_json(&Value::Object(preimage))) != claimed {
        return Err("semantic record authentication".to_owned());
    }
    if field(commitment, "traceId") != field(record, "traceId")
        || field(commitment, "recordDigest").as_str() != Some(claimed.as_str())
        || field(commitment, "rawRecordSha256").as_str() != Some(sha256(raw_record).as_str())
        || field(commitment, "semanticInputDigest") != field(record, "semanticInputDigest")
        || field(commitment, "concreteInputDigest") != field(record, "concreteInputDigest")
        || field(commitment, "oracleDigest") != field(oracle, "oracleDigest")
        || field(oracle, "traceId") != field(record, "traceId")
        || field(oracle, "semanticRecordDigest").as_str() != Some(claimed.as_str())
    {
        return Err("rooted record commitment".to_owned());
    }
    let authority = field(record, "authority");
    let product = field(record, "productInput");
    let authority_record_sha256s =
        std::iter::once(field(field(authority, "requirement"), "recordSha256"))
            .chain(
                ["decisions", "sources", "claims"]
                    .into_iter()
                    .flat_map(|name| field(authority, name).as_array().unwrap())
                    .map(|item| field(item, "recordSha256")),
            )
            .chain(std::iter::once(field(
                field(authority, "closure"),
                "recordSha256",
            )))
            .cloned()
            .collect::<Vec<_>>();
    let components = json!({
        "authorityRecordSha256s": authority_record_sha256s,
        "requirementDigest": field(product, "requirementDigest"),
        "decisionDigests": field(product, "decisionDigests"),
        "sourceDigests": field(product, "sourceDigests"),
        "claimDigests": field(product, "claimDigests"),
        "negativeBehaviorDigest": field(product, "negativeBehaviorDigest"),
        "closureDigest": field(product, "closureDigest"),
    });
    if field(commitment, "componentDigestsSha256").as_str()
        != Some(sha256(&canonical_json(&components)).as_str())
    {
        return Err("component digest commitment".to_owned());
    }
    let sources = field(field(record, "authority"), "sources")
        .as_array()
        .ok_or("sources")?;
    let dispositions = sources
        .iter()
        .map(|source| field(source, "normativity").as_str().unwrap_or_default())
        .collect::<std::collections::BTreeSet<_>>();
    if dispositions.len() != 1 {
        return Err("mixed semantic dispositions".to_owned());
    }
    let accepted = match dispositions.first().copied() {
        Some("IMPLEMENTATION_REQUIREMENT") => true,
        Some("OPEN_EVIDENCE_GATE_NOT_READY_FOR_IMPLEMENTATION")
        | Some("NEGATIVE_ORACLE_EXCLUDED_BEHAVIOR") => false,
        _ => return Err("unknown semantic disposition".to_owned()),
    };
    let assertion = field(record, "productAssertion");
    if field(assertion, "outcome")
        != if accepted {
            "ACCEPTED"
        } else {
            "REJECTED_FAIL_CLOSED"
        }
        || field(assertion, "authorityEffect")
            != if accepted {
                "R1_AUTHORITY_BOUND"
            } else {
                "NONE"
            }
        || field(assertion, "zeroEffectRequired") != !accepted
    {
        return Err("caller assertion does not follow semantic record".to_owned());
    }
    Ok(accepted)
}

struct AuthenticatedCorpusRow {
    record: Value,
    raw_record: String,
    commitment: Value,
    oracle: Value,
}

fn authenticated_corpus() -> Vec<AuthenticatedCorpusRow> {
    let generated =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policies/modules/generated");
    let manifest_bytes = fs::read(generated.join("module-trace-corpus-manifest.json"))
        .expect("read rooted corpus manifest");
    let mut manifest: Value =
        serde_json::from_slice(&manifest_bytes).expect("valid corpus manifest");
    assert_eq!(field(&manifest, "schemaVersion"), "2.0");
    assert_eq!(
        field(&manifest, "corpusId"),
        "OPENPC-I03-TRACE-SEMANTIC-CORPUS-R8"
    );
    let claimed_root = manifest
        .as_object_mut()
        .unwrap()
        .remove("rootCommitmentSha256")
        .and_then(|value| value.as_str().map(str::to_owned))
        .expect("root commitment");
    assert_eq!(claimed_root, R8_CORPUS_ROOT_COMMITMENT);
    assert_eq!(sha256(&canonical_json(&manifest)), claimed_root);
    let frozen = field(&manifest, "frozenAuthoritySources");
    for (name, expected) in [
        (
            "sourceUnits",
            "3fbd1d00639aeb3fb1f568942e89ae505b7ac1cf45b2c4aa2faea2c74e70dd29",
        ),
        (
            "decisions",
            "397c0becca904297e172141d8bfe18712b255b05d0bd1b3f0f187da15680aae1",
        ),
        (
            "claimCeilings",
            "b9c866b671a06d475fd601a85ecb75789baca0da8e7356fe7b96dd1195fb0858",
        ),
        (
            "requirements",
            "e49a27645e39168fdc6b3aad94cea40de0db496d99bb7b6140595d744fcbcafd",
        ),
        (
            "closures",
            "3fed5ae229aca36f2cd9a48f866ae4918e63310c68026578a7becdeb74932f07",
        ),
    ] {
        assert_eq!(field(frozen, name), expected, "frozen authority {name}");
    }
    let catalog_bytes = fs::read(generated.join("module-trace-authority-catalog.json"))
        .expect("read authority catalog");
    let oracle_bytes = fs::read(generated.join("module-trace-behavior-oracles.jsonl"))
        .expect("read behavior oracles");
    let corpus_bytes = fs::read(generated.join("module-trace-semantic-corpus.jsonl"))
        .expect("read semantic corpus");
    assert_eq!(
        field(&manifest, "authorityCatalogFileSha256")
            .as_str()
            .unwrap(),
        sha256_bytes(&catalog_bytes)
    );
    assert_eq!(
        field(&manifest, "behaviorOracleFileSha256")
            .as_str()
            .unwrap(),
        sha256_bytes(&oracle_bytes)
    );
    assert_eq!(
        field(&manifest, "corpusFileSha256").as_str().unwrap(),
        sha256_bytes(&corpus_bytes)
    );
    let oracle_values = String::from_utf8(oracle_bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("valid oracle"))
        .collect::<Vec<_>>();
    assert_eq!(
        field(&manifest, "orderedOracleDigestAggregateSha256")
            .as_str()
            .unwrap(),
        sha256(
            &oracle_values
                .iter()
                .map(|oracle| field(oracle, "oracleDigest").as_str().unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        )
    );
    let oracles = oracle_values
        .into_iter()
        .map(|oracle| {
            (
                field(&oracle, "traceId").as_str().unwrap().to_owned(),
                oracle,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let commitments = field(&manifest, "recordCommitments")
        .as_array()
        .expect("record commitments");
    let corpus = String::from_utf8(corpus_bytes).unwrap();
    let lines = corpus.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 5_470);
    assert_eq!(commitments.len(), lines.len());
    let rows = lines
        .into_iter()
        .zip(commitments)
        .map(|(line, commitment)| {
            let record: Value = serde_json::from_str(line).expect("valid semantic record");
            let trace_id = field(&record, "traceId").as_str().unwrap().to_owned();
            AuthenticatedCorpusRow {
                record,
                raw_record: line.to_owned(),
                commitment: commitment.clone(),
                oracle: oracles.get(&trace_id).expect("trace oracle").clone(),
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        field(&manifest, "orderedRecordDigestAggregateSha256")
            .as_str()
            .unwrap(),
        sha256(
            &rows
                .iter()
                .map(|row| field(&row.record, "recordDigest").as_str().unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        )
    );
    rows
}

fn evaluation_input(record: &Value) -> EvaluationInput {
    let product = field(record, "productInput");
    let owner_input = field(product, "ownerInput");
    assert_eq!(field(owner_input, "kind"), "NATIVE_POLICY_EVALUATION_INPUT");
    let authority = field(record, "authority");
    let concrete = bytes(field(record, "concreteInputDigest"));
    let semantic = bytes(field(record, "semanticInputDigest"));
    let decision = bytes(&field(product, "decisionDigests").as_array().unwrap()[0]);
    let source = bytes(&field(product, "sourceDigests").as_array().unwrap()[0]);
    let claim = bytes(&field(product, "claimDigests").as_array().unwrap()[0]);
    let negative = bytes(field(product, "negativeBehaviorDigest"));
    let closure = bytes(field(product, "closureDigest"));
    let trace_id = field(record, "traceId").as_str().unwrap();
    let requirement_id = field(field(authority, "requirement"), "requirementId")
        .as_str()
        .unwrap();
    let all_obligations = ["decisionDigests", "sourceDigests", "claimDigests"]
        .into_iter()
        .flat_map(|name| field(product, name).as_array().unwrap().iter())
        .map(|value| value.as_str().unwrap().to_owned())
        .chain([
            field(product, "negativeBehaviorDigest")
                .as_str()
                .unwrap()
                .to_owned(),
            field(product, "closureDigest").as_str().unwrap().to_owned(),
        ])
        .collect::<Vec<_>>();
    let mut wire = json!({
        "evaluatorVersion": "PC-POLICY-EVALUATOR-1",
        "profileId": field(owner_input, "profileId"),
        "platformTerminalDeny": false,
        "participantEnvelopeAllows": true,
        "assignmentAllows": true,
        "epochs": {"platform":"1","currentPlatform":"1","participant":"2","currentParticipant":"2","authority":"3","currentAuthority":"3","delegation":"4","currentDelegation":"4","assignment":"5","currentAssignment":"5","credential":"6","currentCredential":"6"},
        "identities": {"participantId":format!("participant:{requirement_id}"),"currentParticipantId":format!("participant:{requirement_id}"),"privacyDomainId":format!("privacy:{trace_id}"),"currentPrivacyDomainId":format!("privacy:{trace_id}"),"actorId":format!("actor:{trace_id}"),"currentActorId":format!("actor:{trace_id}"),"workloadId":format!("workload:{trace_id}"),"currentWorkloadId":format!("workload:{trace_id}"),"walletId":format!("wallet:{trace_id}"),"currentWalletId":format!("wallet:{trace_id}"),"assignmentId":format!("assignment:{trace_id}"),"currentAssignmentId":format!("assignment:{trace_id}")},
        "request": {"actionIntentId":field(owner_input,"actionIntentId"),"currentActionIntentId":field(owner_input,"actionIntentId"),"scopeDigest":bytes(field(owner_input,"scopeDigest")),"currentScopeDigest":bytes(field(owner_input,"scopeDigest")),"resourceId":format!("policy:{trace_id}"),"currentResourceId":format!("policy:{trace_id}"),"resourceDigest":bytes(field(owner_input,"resourceDigest")),"currentResourceDigest":bytes(field(owner_input,"resourceDigest"))},
        "simulation": {"scenarioId":field(owner_input,"scenarioId"),"currentScenarioId":field(owner_input,"scenarioId"),"requestId":trace_id,"currentRequestId":trace_id,"chainId":format!("trace:{requirement_id}"),"currentChainId":format!("trace:{requirement_id}"),"routeDigest":bytes(field(owner_input,"routeDigest")),"currentRouteDigest":bytes(field(owner_input,"routeDigest")),"requestedDisclosureCapabilities":["RESULT","EXPLANATION"],"currentDisclosureCapabilities":["RESULT","EXPLANATION"]},
        "versions": {"participantEnvelopeDigest":source,"currentParticipantEnvelopeDigest":source,"policyVersionDigest":semantic,"currentPolicyVersionDigest":semantic,"policyReleaseDigest":decision,"currentPolicyReleaseDigest":decision,"policyGenerationDigest":bytes(field(owner_input,"policyGenerationDigest")),"currentPolicyGenerationDigest":bytes(field(owner_input,"policyGenerationDigest")),"factGenerationDigest":concrete,"currentFactGenerationDigest":concrete,"providerGenerationDigest":decision,"currentProviderGenerationDigest":decision,"checkpointGenerationDigest":source,"currentCheckpointGenerationDigest":source,"dependencyClosureDigest":claim,"currentDependencyClosureDigest":claim,"schemaDigest":bytes(field(owner_input,"schemaDigest")),"currentSchemaDigest":bytes(field(owner_input,"schemaDigest")),"typeRegistryDigest":semantic,"currentTypeRegistryDigest":semantic,"moduleManifestSetDigest":claim,"currentModuleManifestSetDigest":claim,"stackProfileDigest":negative,"currentStackProfileDigest":negative},
        "completeness": {"selectorDigest":bytes(field(owner_input,"selectorDigest")),"currentSelectorDigest":bytes(field(owner_input,"selectorDigest")),"windowDigest":closure,"currentWindowDigest":closure,"obligationDigest":claim,"currentObligationDigest":claim,"selectorComplete":true,"windowComplete":true,"obligationComplete":true,"factComplete":true,"checkpointComplete":true,"providerComplete":true,"moduleManifestComplete":true,"routeComplete":true,"disclosureComplete":true,"compatibilityComplete":true,"complete":true},
        "contributions": [{"moduleId":format!("pc.trace.{trace_id}"),"moduleVersion":"1.0.0","manifestDigest":concrete,"family":requirement_id,"priority":1,"effect":"ALLOW","permissions":[format!("permission:{requirement_id}")],"obligations":all_obligations,"visibility":"AUTHORIZED_ONLY","inputType":"POLICY-REQUEST","outputType":"POLICY-DECISION","schemaDigest":bytes(field(owner_input,"schemaDigest")),"capabilityId":format!("capability:{trace_id}"),"providerId":format!("provider:{requirement_id}"),"generationDigest":bytes(field(owner_input,"policyGenerationDigest")),"selectorDigest":bytes(field(owner_input,"selectorDigest")),"existenceRule":"AUTHORIZED_ONLY","payloadRule":"REDACTED","terminalLayer":"MODULE","broaderDelegation":false,"unsupportedSemantics":false,"futureDependency":false,"missingBridge":false,"terminal":false}]
    });
    match field(product, "mutation").as_str().unwrap() {
        "NONE" => {}
        "INCOMPLETE_INPUT" => wire["completeness"]["complete"] = json!(false),
        "AUTHORITY_EPOCH_STALE" => wire["epochs"]["currentAuthority"] = json!("4"),
        "PLATFORM_TERMINAL_DENY" => wire["platformTerminalDeny"] = json!(true),
        "UNSUPPORTED_SEMANTICS" => wire["contributions"][0]["unsupportedSemantics"] = json!(true),
        "RESOURCE_SUBSTITUTION" => {
            wire["request"]["currentResourceId"] = json!("policy:substituted")
        }
        "PROVIDER_GENERATION_STALE" => {
            wire["versions"]["currentProviderGenerationDigest"] = json!(vec![255_u8; 32])
        }
        "DISCLOSURE_MISMATCH" => {
            wire["simulation"]["currentDisclosureCapabilities"] = json!(["RESULT"])
        }
        "OBLIGATION_INCOMPLETE" => wire["completeness"]["obligationComplete"] = json!(false),
        mutation => panic!("unexpected native mutation {mutation}"),
    }
    serde_json::from_value(wire).expect("complete native evaluation input")
}

#[test]
fn every_rust_declared_trace_executes_in_the_native_owner_from_authenticated_semantics() {
    let mut executed = 0_usize;
    for row in authenticated_corpus() {
        if field(&row.record, "declaredRuntime") != "RUST_NATIVE" {
            continue;
        }
        let expected_success = validate(&row.record, &row.raw_record, &row.commitment, &row.oracle)
            .expect("authenticated Rust semantic record");
        let input = evaluation_input(&row.record);
        let before = pc_cbor_1(&input);
        let result = evaluate(&input);
        assert_eq!(
            pc_cbor_1(&input),
            before,
            "native evaluator mutated trace input"
        );
        assert_eq!(result.truth_state == TruthState::Success, expected_success);
        executed += 1;
    }
    assert_eq!(
        executed, 2_619,
        "exact Rust-owned trace denominator changed"
    );
}

#[test]
fn native_semantic_record_rejects_assertion_owner_and_authority_tampering() {
    let row = authenticated_corpus()
        .into_iter()
        .find(|row| field(&row.record, "declaredRuntime") == "RUST_NATIVE")
        .expect("native record");
    let record = row.record;
    let rejected = |record: &Value| {
        validate(
            record,
            &serde_json::to_string(record).unwrap(),
            &row.commitment,
            &row.oracle,
        )
        .is_err()
    };
    let mut assertion = record.clone();
    assertion["productAssertion"]["outcome"] =
        if field(field(&record, "productAssertion"), "outcome") == "ACCEPTED" {
            json!("REJECTED_FAIL_CLOSED")
        } else {
            json!("ACCEPTED")
        };
    assert!(rejected(&assertion));
    let mut runtime = record.clone();
    runtime["declaredRuntime"] = json!("TYPESCRIPT");
    assert!(rejected(&runtime));
    let mut requirement = record.clone();
    requirement["authority"]["requirement"]["statement"] = json!("substituted requirement");
    let mut rehashed_requirement = requirement.as_object().unwrap().clone();
    rehashed_requirement.remove("schemaVersion");
    rehashed_requirement.remove("recordDigest");
    requirement["recordDigest"] = json!(sha256(&canonical_json(&Value::Object(
        rehashed_requirement
    ))));
    assert!(rejected(&requirement));
    let mut decision = record.clone();
    decision["authority"]["decisions"][0]["selectedResult"][0] = json!("substituted decision");
    assert!(rejected(&decision));
    let mut source_unit = record.clone();
    source_unit["authority"]["sources"][0]["statement"] = json!("substituted source");
    assert!(rejected(&source_unit));
    let mut claim = record;
    claim["authority"]["claims"][0]["rule"] = json!("substituted claim");
    assert!(rejected(&claim));
}
