//! Complete provider-result validation before any protected bytes are released.
use openpc_multi_rpc::route_witness::ChainAnchor;
use pc_policy_core::{
    fact_condition::FactCondition, invocation::InvocationAuthorization, semantics::FactReference,
    visibility_policy::*,
};
use pc_runtime_types::{RuntimeError, RuntimeRequest, RuntimeResult, VisibilityReadQuery};
use serde_json::{Map, Value};

pub(crate) struct ReadResponseContext<'a> {
    pub request: &'a RuntimeRequest,
    pub resource: &'a AdmittedVisibilityResource,
    pub resources: &'a [AdmittedVisibilityResource],
    pub policies: &'a [VisibilityPolicy],
    pub required_facts: &'a [FactReference],
    pub authorization: &'a InvocationAuthorization,
    pub anchor: &'a ChainAnchor,
    pub decision: &'a VisibilityDecision,
}

pub(crate) fn filter(
    context: ReadResponseContext<'_>,
    body: &[u8],
    condition: impl Fn(&FactCondition, u64, u64) -> RuntimeResult<bool>,
) -> RuntimeResult<Vec<u8>> {
    let c = &context;
    if body.is_empty() || body.len() as u64 > c.request.response_budget_bytes {
        return Err(deny());
    }
    let mut envelope = openpc_multi_rpc::parse_strict_json(body, 16).map_err(|_| deny())?;
    let object = envelope.as_object_mut().ok_or_else(deny)?;
    if object.len() != 3
        || object.get("jsonrpc") != Some(&Value::String("2.0".into()))
        || crate::request_decode::request_id(object.get("id").ok_or_else(deny)?)
            .map_err(|_| deny())?
            != c.request.request_id
    {
        return Err(deny());
    }
    let result = object.get_mut("result").ok_or_else(deny)?;
    let read = c.request.visibility.as_ref().ok_or_else(deny)?;
    let binding = c.resource.contract_binding.as_ref().ok_or_else(deny)?;
    match &read.query {
        VisibilityReadQuery::Transaction { hash } => {
            let transaction = result.as_object_mut().ok_or_else(deny)?;
            validate_transaction(transaction)?;
            anchored(transaction, c.anchor)?;
            if text(transaction, "hash")? != hash
                || !text(transaction, "to")?.eq_ignore_ascii_case(&binding.contract_address)
                || transaction
                    .get("chainId")
                    .is_some_and(|value| quantity(value).ok() != Some(c.anchor.chain_id))
            {
                return Err(deny());
            }
            for key in transaction.keys() {
                if !c.resource.available_fields.contains(key) {
                    return Err(deny());
                }
            }
            transaction.retain(|field, _| {
                c.decision.fields.contains(field)
                    && c.decision.dimensions.contains(&if matches!(
                        field.as_str(),
                        "input" | "value" | "accessList"
                    ) {
                        VisibilityDimension::Payload
                    } else {
                        VisibilityDimension::Metadata
                    })
            });
            if transaction.is_empty() {
                return Err(deny());
            }
        }
        VisibilityReadQuery::Receipt { hash } => {
            if !c.decision.whole_receipt {
                return Err(deny());
            }
            let receipt = result.as_object().ok_or_else(deny)?;
            validate_receipt(receipt)?;
            anchored(receipt, c.anchor)?;
            if text(receipt, "transactionHash")? != hash
                || !text(receipt, "to")?.eq_ignore_ascii_case(&binding.contract_address)
            {
                return Err(deny());
            }
            let allowed = [
                "transactionHash",
                "transactionIndex",
                "blockHash",
                "blockNumber",
                "from",
                "to",
                "cumulativeGasUsed",
                "gasUsed",
                "contractAddress",
                "logs",
                "logsBloom",
                "status",
                "root",
                "effectiveGasPrice",
                "type",
                "blobGasUsed",
                "blobGasPrice",
            ];
            if receipt.keys().any(|key| !allowed.contains(&key.as_str()))
                || ![
                    "from",
                    "cumulativeGasUsed",
                    "gasUsed",
                    "contractAddress",
                    "logs",
                    "logsBloom",
                ]
                .iter()
                .all(|key| receipt.contains_key(*key))
                || (receipt.contains_key("status") == receipt.contains_key("root"))
            {
                return Err(deny());
            }
            let logs = receipt["logs"].as_array().ok_or_else(deny)?;
            validate_logs(
                c,
                logs,
                Some((hash, quantity(&receipt["transactionIndex"])?)),
                &condition,
            )?;
        }
        VisibilityReadQuery::Logs { topics, .. } => {
            if ![
                VisibilityDimension::Existence,
                VisibilityDimension::Metadata,
                VisibilityDimension::Payload,
            ]
            .iter()
            .all(|d| c.decision.dimensions.contains(d))
                || !c
                    .resource
                    .available_fields
                    .iter()
                    .all(|field| c.decision.fields.contains(field))
            {
                return Err(deny());
            }
            let logs = result.as_array().ok_or_else(deny)?;
            for log in logs {
                let returned = log["topics"].as_array().ok_or_else(deny)?;
                if returned.len() < topics.len()
                    || topics
                        .iter()
                        .zip(returned)
                        .any(|(expected, actual)| actual.as_str() != Some(expected))
                {
                    return Err(deny());
                }
            }
            *result = Value::Array(validate_logs(c, logs, None, &condition)?);
        }
    }
    openpc_multi_rpc::rfc8785_canonical_bytes(&envelope).map_err(|_| deny())
}

fn validate_logs(
    c: &ReadResponseContext<'_>,
    logs: &[Value],
    receipt: Option<(&str, u64)>,
    condition: &impl Fn(&FactCondition, u64, u64) -> RuntimeResult<bool>,
) -> RuntimeResult<Vec<Value>> {
    if logs.len() > 4096 {
        return Err(deny());
    }
    let mut previous = None;
    let mut visible = Vec::new();
    for log in logs {
        let log = log.as_object().ok_or_else(deny)?;
        if log.len() != 9
            || ![
                "address",
                "topics",
                "data",
                "blockNumber",
                "transactionHash",
                "transactionIndex",
                "blockHash",
                "logIndex",
                "removed",
            ]
            .iter()
            .all(|key| log.contains_key(*key))
            || log["removed"] != false
        {
            return Err(deny());
        }
        anchored(log, c.anchor)?;
        hex(&log["transactionHash"], Some(32), false)?;
        let tx = quantity(&log["transactionIndex"])?;
        let index = quantity(&log["logIndex"])?;
        if previous.is_some_and(|(prior_tx, prior_index)| prior_tx > tx || prior_index >= index) {
            return Err(deny());
        }
        previous = Some((tx, index));
        if let Some((hash, receipt_index)) = receipt
            && (text(log, "transactionHash")? != hash || tx != receipt_index)
        {
            return Err(deny());
        }
        let topics = log["topics"]
            .as_array()
            .filter(|topics| !topics.is_empty() && topics.len() <= 4)
            .ok_or_else(deny)?;
        let topic = topics[0].as_str().ok_or_else(deny)?;
        let mut resources = c.resources.iter().filter(|resource| {
            let VisibilitySelector::Event {
                event_signature, ..
            } = &resource.selector
            else {
                return false;
            };
            resource.contract_binding.as_ref().is_some_and(|binding| {
                log["address"]
                    .as_str()
                    .is_some_and(|address| address.eq_ignore_ascii_case(&binding.contract_address))
                    && binding.chain_id == c.anchor.chain_id.to_string()
                    && pc_policy_core::contract_policy::event_topic(
                        &binding.canonical_abi,
                        event_signature,
                    )
                    .as_deref()
                        == Ok(topic)
            })
        });
        let resource = resources.next().ok_or_else(deny)?;
        if resources.next().is_some()
            || resource.participant_id != c.authorization.participant_id
            || resource.privacy_domain_id != c.authorization.privacy_domain_id
        {
            return Err(deny());
        }
        if receipt.is_none() && resource.selector != c.resource.selector {
            return Err(deny());
        }
        let binding = resource.contract_binding.as_ref().ok_or_else(deny)?;
        let VisibilitySelector::Event {
            event_signature, ..
        } = &resource.selector
        else {
            return Err(deny());
        };
        pc_policy_core::contract_policy::validate_event_payload(
            &binding.canonical_abi,
            event_signature,
            topics,
            &log["data"],
        )
        .map_err(|_| deny())?;
        let unavailable = std::cell::Cell::new(false);
        let decision = evaluate_visibility(
            c.policies,
            c.required_facts,
            &VisibilityRequest {
                selector: &resource.selector,
                mode: VisibilityMode::Static,
                subject: &VisibilitySubject::Workload {
                    workload_id: c.authorization.workload_id.clone(),
                },
                purpose: "EVENT_READ",
                roles: &c.authorization.roles,
            },
            |fact| match condition(fact, tx, index) {
                Ok(permitted) => permitted,
                Err(_) => {
                    unavailable.set(true);
                    false
                }
            },
        );
        if unavailable.get() {
            return Err(deny());
        }
        let permitted = match decision {
            Err(RuntimeError::Denied) => false,
            Err(_) => return Err(deny()),
            Ok(decision) => {
                [
                    VisibilityDimension::Existence,
                    VisibilityDimension::Metadata,
                    VisibilityDimension::Payload,
                ]
                .iter()
                .all(|d| decision.dimensions.contains(d))
                    && resource
                        .available_fields
                        .iter()
                        .all(|field| decision.fields.contains(field))
            }
        };
        if permitted {
            visible.push(Value::Object(log.clone()));
        } else if receipt.is_some() {
            // A standard receipt is atomic. Event queries may return only
            // complete visible records, with no hidden count or placeholder.
            return Err(deny());
        }
    }
    Ok(visible)
}
fn anchored(value: &Map<String, Value>, anchor: &ChainAnchor) -> RuntimeResult<()> {
    if quantity(value.get("blockNumber").ok_or_else(deny)?)? != anchor.block_number
        || text(value, "blockHash")? != format!("0x{}", anchor.block_hash.as_str())
    {
        return Err(deny());
    }
    quantity(value.get("transactionIndex").ok_or_else(deny)?)?;
    Ok(())
}
fn text<'a>(value: &'a Map<String, Value>, key: &str) -> RuntimeResult<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(deny)
}
fn quantity(value: &Value) -> RuntimeResult<u64> {
    let v = value
        .as_str()
        .and_then(|v| v.strip_prefix("0x"))
        .filter(|v| !v.is_empty() && (v.len() == 1 || !v.starts_with('0')))
        .ok_or_else(deny)?;
    u64::from_str_radix(v, 16).map_err(|_| deny())
}
fn deny() -> RuntimeError {
    RuntimeError::ResponseWithheld
}

fn hex(value: &Value, exact_bytes: Option<usize>, quantity: bool) -> RuntimeResult<()> {
    let digits = value
        .as_str()
        .and_then(|v| v.strip_prefix("0x"))
        .ok_or_else(deny)?;
    if !digits
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || (quantity
            && (digits.is_empty()
                || digits.len() > 64
                || (digits.len() > 1 && digits.starts_with('0'))))
        || (!quantity && !digits.len().is_multiple_of(2))
        || exact_bytes.is_some_and(|size| digits.len() != size * 2)
    {
        return Err(deny());
    }
    Ok(())
}
fn validate_transaction(transaction: &Map<String, Value>) -> RuntimeResult<()> {
    for key in [
        "hash",
        "blockHash",
        "blockNumber",
        "transactionIndex",
        "from",
        "to",
        "gas",
        "input",
        "nonce",
        "value",
    ] {
        if !transaction.contains_key(key) {
            return Err(deny());
        }
    }
    for (key, value) in transaction {
        match key.as_str() {
            "hash" | "blockHash" | "r" | "s" => hex(value, Some(32), false)?,
            "from" | "to" => hex(value, Some(20), false)?,
            "input" => hex(value, None, false)?,
            "accessList" => {
                let entries = value
                    .as_array()
                    .filter(|entries| entries.len() <= 1024)
                    .ok_or_else(deny)?;
                let mut total_keys = 0usize;
                for entry in entries {
                    let entry = entry
                        .as_object()
                        .filter(|entry| entry.len() == 2)
                        .ok_or_else(deny)?;
                    hex(entry.get("address").ok_or_else(deny)?, Some(20), false)?;
                    let keys = entry
                        .get("storageKeys")
                        .and_then(Value::as_array)
                        .ok_or_else(deny)?;
                    total_keys = total_keys
                        .checked_add(keys.len())
                        .filter(|count| *count <= 4096)
                        .ok_or_else(deny)?;
                    for key in keys {
                        hex(key, Some(32), false)?;
                    }
                }
            }
            "blockNumber"
            | "transactionIndex"
            | "chainId"
            | "gas"
            | "gasPrice"
            | "maxFeePerGas"
            | "maxPriorityFeePerGas"
            | "nonce"
            | "type"
            | "value"
            | "v"
            | "yParity" => hex(value, None, true)?,
            _ => return Err(deny()),
        }
    }
    Ok(())
}
fn validate_receipt(receipt: &Map<String, Value>) -> RuntimeResult<()> {
    for (key, value) in receipt {
        match key.as_str() {
            "transactionHash" | "blockHash" | "root" => hex(value, Some(32), false)?,
            "from" | "to" => hex(value, Some(20), false)?,
            "contractAddress" if value.is_null() => {}
            "contractAddress" => hex(value, Some(20), false)?,
            "logsBloom" => hex(value, Some(256), false)?,
            "status" if value == "0x0" || value == "0x1" => {}
            "logs" if value.is_array() => {}
            "blockNumber" | "transactionIndex" | "cumulativeGasUsed" | "gasUsed"
            | "effectiveGasPrice" | "type" | "blobGasUsed" | "blobGasPrice" => {
                hex(value, None, true)?
            }
            _ => return Err(deny()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_policy_core::rpc_policy::RpcEffect;
    use pc_runtime_types::{Digest, RequestClass, Transport, VisibilityRead};
    use serde_json::json;
    #[test]
    fn visibility_transaction_validates_access_list_addresses_and_storage_words() {
        let transaction = json!({"hash":format!("0x{}","11".repeat(32)),"blockHash":format!("0x{}","22".repeat(32)),"blockNumber":"0x10","transactionIndex":"0x0","from":format!("0x{}","33".repeat(20)),"to":format!("0x{}","44".repeat(20)),"gas":"0x5208","input":"0x","nonce":"0x1","value":"0x0","accessList":[{"address":format!("0x{}","55".repeat(20)),"storageKeys":[format!("0x{}","66".repeat(32))]}]});
        validate_transaction(transaction.as_object().unwrap()).unwrap();
        let mut malformed = transaction.clone();
        malformed["accessList"][0]["storageKeys"][0] = json!("0x01");
        assert!(validate_transaction(malformed.as_object().unwrap()).is_err());
        malformed = transaction;
        malformed["accessList"][0]["secret"] = json!("unauthorized");
        assert!(validate_transaction(malformed.as_object().unwrap()).is_err());
    }
    fn fixture(
        selector: VisibilitySelector,
    ) -> (
        AdmittedVisibilityResource,
        VisibilityPolicy,
        InvocationAuthorization,
    ) {
        let resource = AdmittedVisibilityResource {
            state_output_types: None,
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            selector,
            available_fields: vec!["inputs[0]".into()],
            contract_binding: Some(VisibilityContractBinding {
                chain_id: "1".into(),
                network_id: "test".into(),
                genesis_digest: format!("sha256:{}", Digest::of("genesis").as_str()),
                contract_address: format!("0x{}", "12".repeat(20)),
                code_digest: format!("sha256:{}", Digest::of("code").as_str()),
                abi_digest: format!("sha256:{}", Digest::of("abi").as_str()),
                canonical_abi: json!([{"type":"event","name":"Changed","anonymous":false,"inputs":[{"name":"value","type":"uint256","indexed":false}]}]),
            }),
        };
        let actor = InvocationAuthorization {
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            workload_id: "urn:openpc:workload:018f0000-0000-7000-8000-000000000191".into(),
            actor_principal_id: "018f0000-0000-7000-8000-000000000192".into(),
            roles: vec!["reader".into()],
            approval: None,
            webauthn: None,
        };
        let policy = VisibilityPolicy {
            policy_id: "018f0000-0000-7000-8000-000000000193".into(),
            selector: resource.selector.clone(),
            mode: VisibilityMode::Static,
            effect: RpcEffect::Allow,
            subject: VisibilitySubject::Workload {
                workload_id: actor.workload_id.clone(),
            },
            purpose: "EVENT_READ".into(),
            required_roles: actor.roles.clone(),
            dimensions: vec![
                VisibilityDimension::Existence,
                VisibilityDimension::Metadata,
                VisibilityDimension::Payload,
            ],
            fields: resource.available_fields.clone(),
            conditions: vec![],
        };
        (resource, policy, actor)
    }
    #[test]
    fn visibility_receipt_is_unchanged_or_wholly_withheld_and_logs_have_exact_order_and_binding() {
        let id = "018f0000-0000-7000-8000-000000000194";
        let (event, policy, actor) = fixture(VisibilitySelector::Event {
            runtime_binding_id: id.into(),
            binding_revision: "1".into(),
            abi_digest: format!("sha256:{}", Digest::of("abi").as_str()),
            event_signature: "Changed(uint256)".into(),
        });
        let mut receipt_resource = event.clone();
        receipt_resource.selector = VisibilitySelector::Receipt {
            runtime_binding_id: id.into(),
            binding_revision: "1".into(),
        };
        receipt_resource.available_fields.clear();
        let anchor = ChainAnchor {
            chain_environment_id: "test".into(),
            chain_id: 1,
            block_number: 16,
            block_hash: Digest::of("block"),
            state_root: Digest::of("state"),
            canonical_generation: 1,
            observed_at_ns: 100,
        };
        let hash = format!("0x{}", "44".repeat(32));
        let topic = pc_policy_core::contract_policy::event_topic(
            &event.contract_binding.as_ref().unwrap().canonical_abi,
            "Changed(uint256)",
        )
        .unwrap();
        let log = json!({"address":event.contract_binding.as_ref().unwrap().contract_address,"topics":[topic],"data":format!("0x{}","00".repeat(32)),"blockNumber":"0x10","blockHash":format!("0x{}",anchor.block_hash.as_str()),"transactionHash":hash,"transactionIndex":"0x0","logIndex":"0x1","removed":false});
        let result = json!({"transactionHash":hash,"transactionIndex":"0x0","blockHash":log["blockHash"],"blockNumber":"0x10","from":format!("0x{}","34".repeat(20)),"to":log["address"],"cumulativeGasUsed":"0x1","gasUsed":"0x1","contractAddress":null,"logs":[log],"logsBloom":format!("0x{}","00".repeat(256)),"status":"0x1"});
        let mut request = RuntimeRequest {
            request_id: "1".into(),
            method: "eth_getTransactionReceipt".into(),
            params_digest: Digest::of("params"),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of([]),
            class: RequestClass::Read,
            received_at_ms: 1,
            deadline_at_ms: 1000,
            response_budget_bytes: 16384,
            invocation: None,
            deployment: None,
            visibility: Some(VisibilityRead {
                runtime_binding_id: id.into(),
                binding_digest: receipt_resource
                    .contract_binding
                    .as_ref()
                    .unwrap()
                    .digest()
                    .unwrap(),
                block_number: 16,
                query: VisibilityReadQuery::Receipt { hash },
            }),
        };
        request.request_digest = request.computed_digest().unwrap();
        let decision = VisibilityDecision {
            dimensions: policy.dimensions.iter().copied().collect(),
            fields: Default::default(),
            whole_receipt: true,
        };
        let run = |result: Value, policies: &[VisibilityPolicy]| {
            let body =
                serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":result})).unwrap();
            filter(
                ReadResponseContext {
                    request: &request,
                    resource: &receipt_resource,
                    resources: std::slice::from_ref(&event),
                    policies,
                    required_facts: &[],
                    authorization: &actor,
                    anchor: &anchor,
                    decision: &decision,
                },
                &body,
                |_, _, _| Ok(false),
            )
        };
        let output = run(result.clone(), std::slice::from_ref(&policy)).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&output).unwrap()["result"],
            result
        );
        let mut denied = policy.clone();
        denied.effect = RpcEffect::Deny;
        assert_eq!(run(result.clone(), &[policy.clone(), denied]), Err(deny()));
        for case in 0..7 {
            let mut changed = result.clone();
            match case {
                0 => changed["logs"][0]["removed"] = json!(true),
                1 => changed["logs"][0]["address"] = json!(format!("0x{}", "99".repeat(20))),
                2 => {
                    changed["logs"][0]["transactionHash"] = json!(format!("0x{}", "99".repeat(32)))
                }
                3 => changed["logs"][0]["blockHash"] = json!(format!("0x{}", "99".repeat(32))),
                4 => changed["logs"].as_array_mut().unwrap().push(log.clone()),
                5 => changed["logs"][0]["data"] = json!("0x00"),
                _ => changed["logs"][0]["secret"] = json!("hidden"),
            }
            assert_eq!(
                run(changed, std::slice::from_ref(&policy)),
                Err(deny()),
                "case {case}"
            );
        }
        let mut event_request = request.clone();
        event_request.method = "eth_getLogs".into();
        event_request.visibility.as_mut().unwrap().query = VisibilityReadQuery::Logs {
            event_signature: "Changed(uint256)".into(),
            topics: vec![topic],
        };
        event_request.request_digest = event_request.computed_digest().unwrap();
        let event_decision = VisibilityDecision {
            fields: event.available_fields.iter().cloned().collect(),
            whole_receipt: false,
            ..decision
        };
        let mut conditional = policy.clone();
        let fact = FactReference {
            candidate_id: "membership".into(),
            generation_id: "generation".into(),
            fact_digest: format!("sha256:{}", Digest::of("fact").as_str()),
        };
        conditional
            .conditions
            .push(FactCondition::ExternalObservation {
                fact: fact.clone(),
                provider_id: "predicate".into(),
                provider_version: "1".into(),
                provider_configuration_digest: Digest::of("provider"),
                request_digest: Digest::of("predicate request"),
                condition: "PERMITTED".into(),
            });
        let run_events = |logs: Value, condition_result: RuntimeResult<bool>| {
            filter(
                ReadResponseContext {
                    request: &event_request,
                    resource: &event,
                    resources: std::slice::from_ref(&event),
                    policies: std::slice::from_ref(&conditional),
                    required_facts: std::slice::from_ref(&fact),
                    authorization: &actor,
                    anchor: &anchor,
                    decision: &event_decision,
                },
                &serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":logs})).unwrap(),
                |_, _, _| condition_result.clone(),
            )
        };
        let hidden = run_events(json!([log]), Ok(false)).unwrap();
        assert_eq!(
            hidden,
            run_events(json!([]), Ok(false)).unwrap(),
            "a known hidden event has the same response as absence"
        );
        assert!(
            run_events(json!([log]), Err(deny())).is_err(),
            "unresolved Facts cannot fabricate an empty result"
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&run_events(json!([log]), Ok(true)).unwrap()).unwrap()
                ["result"],
            json!([log])
        );
    }
}
