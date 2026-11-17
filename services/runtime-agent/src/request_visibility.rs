//! Closed standard visibility requests, bound to installed resource identities.
use super::*;
use pc_policy_core::visibility_policy::{AdmittedVisibilityResource, VisibilitySelector};
use pc_runtime_types::{RequestClass, VisibilityRead, VisibilityReadQuery};

impl DecodedProtectedRequest {
    pub(crate) fn decode_visibility(
        body: &[u8],
        resources: &[AdmittedVisibilityResource],
        limits: RequestDecodeLimits<'_>,
        received_at_ms: u64,
    ) -> RuntimeResult<Option<Self>> {
        let value = strict_json_rpc_envelope(body, limits.maximum_request_bytes)?;
        let method = value["method"].as_str().ok_or(RuntimeError::InvalidInput)?;
        if !matches!(
            method,
            "eth_getTransactionByHash" | "eth_getTransactionReceipt" | "eth_getLogs"
        ) {
            return Ok(None);
        }
        if received_at_ms == 0
            || !(1..=60_000).contains(&limits.timeout_ms)
            || !(1..=16 * 1024 * 1024).contains(&limits.maximum_response_bytes)
            || !valid_block_selector(limits.block_selector)
        {
            return Err(RuntimeError::InvalidInput);
        }
        let height = u64::from_str_radix(&limits.block_selector[2..], 16)
            .map_err(|_| RuntimeError::InvalidInput)?;
        let params = value["params"]
            .as_array()
            .filter(|p| p.len() == 1)
            .ok_or(RuntimeError::InvalidInput)?;
        let mut choices = Vec::new();
        for resource in resources {
            let Some(binding) = &resource.contract_binding else {
                continue;
            };
            let query = match (&resource.selector, method) {
                (VisibilitySelector::Transaction { .. }, "eth_getTransactionByHash") => {
                    VisibilityReadQuery::Transaction {
                        hash: hash(&params[0])?,
                    }
                }
                (VisibilitySelector::Receipt { .. }, "eth_getTransactionReceipt") => {
                    VisibilityReadQuery::Receipt {
                        hash: hash(&params[0])?,
                    }
                }
                (
                    VisibilitySelector::Event {
                        event_signature, ..
                    },
                    "eth_getLogs",
                ) => {
                    let filter = params[0].as_object().ok_or(RuntimeError::InvalidInput)?;
                    if filter.len() != 4
                        || !["address", "fromBlock", "toBlock", "topics"]
                            .iter()
                            .all(|k| filter.contains_key(*k))
                    {
                        return Err(RuntimeError::InvalidInput);
                    }
                    if filter["fromBlock"] != limits.block_selector
                        || filter["toBlock"] != limits.block_selector
                    {
                        return Err(RuntimeError::InvalidAuthorization);
                    }
                    if filter["address"]
                        .as_str()
                        .map(str::to_ascii_lowercase)
                        .as_deref()
                        != Some(&binding.contract_address.to_ascii_lowercase())
                    {
                        continue;
                    }
                    let topics = filter["topics"]
                        .as_array()
                        .filter(|t| !t.is_empty() && t.len() <= 4)
                        .ok_or(RuntimeError::InvalidInput)?;
                    let topics = topics.iter().map(hash).collect::<RuntimeResult<Vec<_>>>()?;
                    if topics[0]
                        != pc_policy_core::contract_policy::event_topic(
                            &binding.canonical_abi,
                            event_signature,
                        )
                        .map_err(|_| RuntimeError::InvalidInput)?
                    {
                        continue;
                    }
                    VisibilityReadQuery::Logs {
                        event_signature: event_signature.clone(),
                        topics,
                    }
                }
                _ => continue,
            };
            choices.push(VisibilityRead {
                runtime_binding_id: resource.selector.resource_id().into(),
                binding_digest: binding.digest()?,
                block_number: height,
                query,
            });
        }
        if choices.len() != 1 {
            return Err(RuntimeError::Denied);
        }
        let mut request = RuntimeRequest {
            request_id: request_id(&value["id"])?,
            method: method.into(),
            params_digest: Digest::of(
                openpc_multi_rpc::rfc8785_canonical_bytes(&value["params"])
                    .map_err(|_| RuntimeError::InvalidInput)?,
            ),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of([]),
            class: RequestClass::Read,
            received_at_ms,
            deadline_at_ms: received_at_ms
                .checked_add(limits.timeout_ms)
                .ok_or(RuntimeError::InvalidInput)?,
            response_budget_bytes: limits.maximum_response_bytes,
            invocation: None,
            deployment: None,
            visibility: choices.pop(),
        };
        request.request_digest = request.computed_digest()?;
        Ok(Some(Self {
            request,
            body: body.to_vec(),
            signed_transaction: None,
            deployment: None,
            call_sender: None,
            call_block_selector: None,
        }))
    }
}
fn hash(value: &Value) -> RuntimeResult<String> {
    let value = value.as_str().ok_or(RuntimeError::InvalidInput)?;
    if value.len() != 66 || bytes(value, 32)?.len() != 32 {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn visibility_request_requires_one_admitted_binding_and_binds_hash_without_submission_authority()
     {
        let resource:AdmittedVisibilityResource=serde_json::from_value(json!({
            "participantId":"participant","privacyDomainId":"privacy",
            "selector":{"kind":"TRANSACTION","runtimeBindingId":"018f0000-0000-7000-8000-000000000191","bindingRevision":"1"},
            "availableFields":["hash"],"contractBinding":{
                "chainId":"1","networkId":"test","genesisDigest":format!("sha256:{}",Digest::of("genesis").as_str()),
                "contractAddress":format!("0x{}","11".repeat(20)),"codeDigest":format!("sha256:{}",Digest::of("code").as_str()),
                "abiDigest":format!("sha256:{}",Digest::of("abi").as_str()),"canonicalAbi":[]
            }
        })).unwrap();
        let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":[format!("0x{}","22".repeat(32))]});
        let decode = |body: &Value, resources: &[AdmittedVisibilityResource]| {
            DecodedProtectedRequest::decode_visibility(
                &serde_json::to_vec(body).unwrap(),
                resources,
                RequestDecodeLimits {
                    maximum_request_bytes: 2048,
                    maximum_response_bytes: 4096,
                    timeout_ms: 1000,
                    block_selector: "0x10",
                },
                100,
            )
        };
        let decoded = decode(&body, std::slice::from_ref(&resource))
            .unwrap()
            .unwrap();
        assert_eq!(decoded.request.class, RequestClass::Read);
        assert!(decoded.request.invocation.is_none());
        assert!(decoded.signed_transaction.is_none());
        decoded.request.validate_digest().unwrap();
        assert!(decode(&body, &[]).is_err());
        assert!(decode(&body, &[resource.clone(), resource.clone()]).is_err());
        let mut absent = resource.clone();
        absent.contract_binding = None;
        assert!(decode(&body, &[absent]).is_err());
        let mut changed = decoded.request.clone();
        changed.visibility.as_mut().unwrap().query = VisibilityReadQuery::Receipt {
            hash: format!("0x{}", "22".repeat(32)),
        };
        assert!(changed.validate_digest().is_err());
        for params in [
            json!(["0x22"]),
            json!([]),
            json!([body["params"][0], "latest"]),
            json!([null]),
        ] {
            let mut invalid = body.clone();
            invalid["params"] = params;
            assert!(decode(&invalid, std::slice::from_ref(&resource)).is_err());
        }
    }
}
