//! Strict workload JSON-RPC decoding under admitted invocation authority.
//! Request bytes provide the target and calldata only; the resolved chain, code,
//! ABI and proxy bindings always come from the installed policy generation.

use openpc_multi_rpc::route_witness::VerifiedChainAnchor;
use pc_policy_core::invocation::{ValidatedInvocationPolicy, resolve_contract_invocation};
use pc_runtime_types::{Digest, RuntimeError, RuntimeRequest, RuntimeResult, Transport};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
#[path = "request_deployment.rs"]
mod deployment;
#[path = "request_visibility.rs"]
mod visibility;
pub use deployment::DecodedDeployment;
pub(crate) use deployment::deployment_rpc_body;

#[derive(Clone, Copy)]
pub struct RequestDecodeLimits<'a> {
    pub maximum_request_bytes: usize,
    pub maximum_response_bytes: u64,
    pub timeout_ms: u64,
    /// Exact route-owner-selected JSON block selector, such as `0x10`.
    /// `latest` is an alias for this admitted anchor, never a provider selector.
    /// A caller cannot choose `pending` or another anchor.
    pub block_selector: &'a str,
}

/// Immutable request data captured at the decoder boundary. Keeping the bytes
/// and their policy-resolved request together prevents a later Broker adapter
/// from pairing an allowed request with a different provider body.
pub struct DecodedProtectedRequest {
    request: RuntimeRequest,
    body: Vec<u8>,
    signed_transaction: Option<openpc_multi_rpc::signed_transaction::SignedTransaction>,
    deployment: Option<DecodedDeployment>,
    call_sender: Option<[u8; 20]>,
    call_block_selector: Option<String>,
}
impl DecodedProtectedRequest {
    pub fn decode(
        body: &[u8],
        policies: &[ValidatedInvocationPolicy],
        limits: RequestDecodeLimits<'_>,
        received_at_ms: u64,
    ) -> RuntimeResult<Self> {
        let envelope = strict_json_rpc_envelope(body, limits.maximum_request_bytes)?;
        let call_sender = if envelope["method"] == "eth_call" {
            envelope["params"][0]
                .get("from")
                .map(|value| address(value.as_str().ok_or(RuntimeError::InvalidInput)?))
                .transpose()?
        } else {
            None
        };
        let (request, signed_transaction) = if let Some(signed) =
            signed_submission_identity(&envelope)?
        {
            let destination = *signed.destination().ok_or(RuntimeError::Denied)?;
            let (class, invocation) = resolve_contract_invocation(
                policies,
                "eth_sendRawTransaction",
                destination,
                signed.data().to_vec(),
            )?;
            if class != pc_runtime_types::RequestClass::Write
                || invocation.chain_id != signed.chain_id().to_string()
                || !(1..=pc_policy_core::transaction_policy::MAX_TRANSACTION_DEADLINE_MS)
                    .contains(&limits.timeout_ms)
                || signed.data().len() > pc_policy_core::transaction_policy::MAX_CALLDATA_BYTES
                || signed.access_list_size().0
                    > pc_policy_core::transaction_policy::MAX_ACCESS_LIST_ADDRESSES
                || signed.access_list_size().1
                    > pc_policy_core::transaction_policy::MAX_ACCESS_LIST_STORAGE_KEYS
                || received_at_ms == 0
                || limits.maximum_response_bytes == 0
                || limits.maximum_response_bytes > 16 * 1024 * 1024
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            let mut request = RuntimeRequest {
                visibility: None,
                deployment: None,
                request_id: request_id(envelope.get("id").ok_or(RuntimeError::InvalidInput)?)?,
                method: "eth_sendRawTransaction".into(),
                params_digest: openpc_multi_rpc::governed_write::submission_params_digest(&signed)?,
                transport: Transport::Http,
                batch_index: 0,
                request_digest: Digest::of([]),
                class,
                received_at_ms,
                deadline_at_ms: received_at_ms
                    .checked_add(limits.timeout_ms)
                    .ok_or(RuntimeError::InvalidInput)?,
                response_budget_bytes: limits.maximum_response_bytes,
                invocation: Some(invocation),
            };
            request.request_digest = request.computed_digest()?;
            (request, Some(signed))
        } else {
            (
                decode_call(envelope, policies, limits, received_at_ms)?,
                None,
            )
        };
        let call_block_selector =
            (request.method == "eth_call").then(|| limits.block_selector.to_owned());
        Ok(Self {
            request,
            body: body.to_vec(),
            signed_transaction,
            deployment: None,
            call_sender,
            call_block_selector,
        })
    }
    pub fn request(&self) -> &RuntimeRequest {
        &self.request
    }
    pub fn deployment(&self) -> Option<&DecodedDeployment> {
        self.deployment.as_ref()
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn signed_transaction(
        &self,
    ) -> Option<&openpc_multi_rpc::signed_transaction::SignedTransaction> {
        self.signed_transaction.as_ref()
    }
    pub(crate) fn call_sender(&self) -> Option<&[u8; 20]> {
        self.call_sender.as_ref()
    }

    /// Convert the admitted block-number selector to the exact signed hash for
    /// provider contact. This transformation owns the outgoing bytes: a reorg
    /// between selection and dispatch cannot silently retarget a number read.
    /// The caller still retains the canonical-generation and provider leases.
    pub(crate) fn hash_pinned_provider_body(
        &self,
        anchor: &VerifiedChainAnchor,
    ) -> RuntimeResult<Vec<u8>> {
        let anchor = anchor.anchor();
        if let Some(read) = &self.request.visibility {
            if read.block_number != anchor.block_number {
                return Err(RuntimeError::InvalidAuthorization);
            }
            let mut value = openpc_multi_rpc::parse_strict_json(&self.body, 8)
                .map_err(|_| RuntimeError::InvalidInput)?;
            if matches!(
                read.query,
                pc_runtime_types::VisibilityReadQuery::Logs { .. }
            ) {
                let filter = value["params"][0]
                    .as_object_mut()
                    .ok_or(RuntimeError::InvalidInput)?;
                filter.remove("fromBlock");
                filter.remove("toBlock");
                filter.insert(
                    "blockHash".into(),
                    Value::String(format!("0x{}", anchor.block_hash.as_str())),
                );
            }
            return openpc_multi_rpc::rfc8785_canonical_bytes(&value)
                .map_err(|_| RuntimeError::InvalidInput);
        }
        if let Some(signed) = &self.signed_transaction {
            if self.request.method != "eth_sendRawTransaction"
                || self.request.class != pc_runtime_types::RequestClass::Write
                || signed.chain_id() != anchor.chain_id
                || self
                    .request
                    .invocation
                    .as_ref()
                    .is_some_and(|invocation| invocation.chain_id != signed.chain_id().to_string())
                || (self.request.invocation.is_none() && self.deployment.is_none())
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            return openpc_multi_rpc::rfc8785_canonical_bytes(
                &openpc_multi_rpc::parse_strict_json(&self.body, 8)
                    .map_err(|_| RuntimeError::InvalidInput)?,
            )
            .map_err(|_| RuntimeError::InvalidInput);
        }
        let invocation = self
            .request
            .invocation
            .as_ref()
            .ok_or(RuntimeError::Denied)?;
        if self.request.method != "eth_call"
            || self.request.class != pc_runtime_types::RequestClass::Read
            || invocation.chain_id != anchor.chain_id.to_string()
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let mut value = openpc_multi_rpc::parse_strict_json(&self.body, 8)
            .map_err(|_| RuntimeError::InvalidInput)?;
        let params = value
            .get_mut("params")
            .and_then(Value::as_array_mut)
            .filter(|p| p.len() == 2)
            .ok_or(RuntimeError::InvalidInput)?;
        let pinned = serde_json::json!({"blockHash": format!("0x{}", anchor.block_hash.as_str()), "requireCanonical": true});
        let selected = format!("0x{:x}", anchor.block_number);
        if self.call_block_selector.as_deref() != Some(selected.as_str())
            || (params[1] != Value::String(selected)
                && params[1] != Value::String("latest".into())
                && params[1] != pinned)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        params[1] = pinned;
        openpc_multi_rpc::rfc8785_canonical_bytes(&value).map_err(|_| RuntimeError::InvalidInput)
    }
}

pub fn decode_protected_json_rpc(
    body: &[u8],
    policies: &[ValidatedInvocationPolicy],
    limits: RequestDecodeLimits<'_>,
    received_at_ms: u64,
) -> RuntimeResult<RuntimeRequest> {
    let value = strict_json_rpc_envelope(body, limits.maximum_request_bytes)?;
    decode_call(value, policies, limits, received_at_ms)
}

fn decode_call(
    value: Value,
    policies: &[ValidatedInvocationPolicy],
    limits: RequestDecodeLimits<'_>,
    received_at_ms: u64,
) -> RuntimeResult<RuntimeRequest> {
    if limits.maximum_response_bytes == 0
        || limits.maximum_response_bytes > 16 * 1024 * 1024
        || !(1..=60_000).contains(&limits.timeout_ms)
        || received_at_ms == 0
        || !valid_block_selector(limits.block_selector)
    {
        return Err(RuntimeError::InvalidInput);
    }
    let object = value.as_object().ok_or(RuntimeError::InvalidInput)?;
    let id = object.get("id").ok_or(RuntimeError::InvalidInput)?;
    let request_id = request_id(id)?;
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .filter(|method| !method.is_empty() && method.len() <= 128)
        .ok_or(RuntimeError::InvalidInput)?;
    // This decoder implements only the bounded single-call shape. In particular,
    // an admitted write policy cannot reinterpret a call object as a signed
    // transaction. Other forms belong to their own complete lifecycle owners.
    if method != "eth_call" {
        return Err(RuntimeError::Denied);
    }
    let params = object
        .get("params")
        .and_then(Value::as_array)
        .filter(|params| params.len() == 2)
        .ok_or(RuntimeError::InvalidInput)?;
    let call = params[0].as_object().ok_or(RuntimeError::InvalidInput)?;
    if !call.contains_key("data")
        || !call.contains_key("to")
        || call
            .keys()
            .any(|key| !matches!(key.as_str(), "data" | "to" | "from"))
    {
        return Err(RuntimeError::InvalidInput);
    }
    if let Some(sender) = call.get("from") {
        address(sender.as_str().ok_or(RuntimeError::InvalidInput)?)?;
    }
    let target_address = address(
        call.get("to")
            .and_then(Value::as_str)
            .ok_or(RuntimeError::InvalidInput)?,
    )?;
    let calldata = bytes(
        call.get("data")
            .and_then(Value::as_str)
            .ok_or(RuntimeError::InvalidInput)?,
        262_144,
    )?;
    let hash_selector = params[1].as_object().is_some_and(|selector| {
        selector.len() == 2
            && selector.get("requireCanonical") == Some(&Value::Bool(true))
            && selector
                .get("blockHash")
                .and_then(Value::as_str)
                .is_some_and(|hash| bytes(hash, 32).is_ok_and(|bytes| bytes.len() == 32))
    });
    if params[1] != Value::String(limits.block_selector.into())
        && params[1] != Value::String("latest".into())
        && !hash_selector
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    let (class, invocation) =
        resolve_contract_invocation(policies, method, target_address, calldata)?;
    let params_bytes = openpc_multi_rpc::rfc8785_canonical_bytes(&Value::Array(params.clone()))
        .map_err(|_| RuntimeError::InvalidInput)?;
    let deadline_at_ms = received_at_ms
        .checked_add(limits.timeout_ms)
        .ok_or(RuntimeError::InvalidInput)?;
    let mut request = RuntimeRequest {
        visibility: None,
        deployment: None,
        request_id,
        method: method.into(),
        params_digest: Digest::of(params_bytes),
        transport: Transport::Http,
        batch_index: 0,
        request_digest: Digest::of([]),
        class,
        received_at_ms,
        deadline_at_ms,
        response_budget_bytes: limits.maximum_response_bytes,
        invocation: Some(invocation),
    };
    request.request_digest = request.computed_digest()?;
    Ok(request)
}

/// Return only the canonical JSON-RPC scalar from a strictly parsed request
/// envelope. This is safe to retain before generation and policy lookup so a
/// later governed denial can preserve request correlation without reflecting
/// arbitrary caller bytes.
pub(crate) fn request_id_from_body(
    body: &[u8],
    maximum_request_bytes: usize,
) -> RuntimeResult<String> {
    let value = strict_json_rpc_envelope(body, maximum_request_bytes)?;
    request_id(
        value
            .as_object()
            .and_then(|object| object.get("id"))
            .ok_or(RuntimeError::InvalidInput)?,
    )
}

/// The same exact signed identity parser serves new admission and prior-outcome
/// binding. It grants no invocation permission and resolves no current policy.
pub(crate) fn signed_submission_identity(
    envelope: &Value,
) -> RuntimeResult<Option<openpc_multi_rpc::signed_transaction::SignedTransaction>> {
    if envelope.get("method").and_then(Value::as_str) != Some("eth_sendRawTransaction") {
        return Ok(None);
    }
    request_id(envelope.get("id").ok_or(RuntimeError::InvalidInput)?)?;
    let params = envelope
        .get("params")
        .and_then(Value::as_array)
        .filter(|v| v.len() == 1)
        .ok_or(RuntimeError::InvalidInput)?;
    let raw = bytes(
        params[0].as_str().ok_or(RuntimeError::InvalidInput)?,
        pc_policy_core::transaction_policy::MAX_RAW_TRANSACTION_BYTES,
    )?;
    openpc_multi_rpc::signed_transaction::SignedTransaction::decode(&raw)
        .map(Some)
        .map_err(|_| RuntimeError::InvalidInput)
}

pub(crate) fn strict_json_rpc_envelope(
    body: &[u8],
    maximum_request_bytes: usize,
) -> RuntimeResult<Value> {
    if body.is_empty()
        || body.len() > maximum_request_bytes
        || maximum_request_bytes > 16 * 1024 * 1024
    {
        return Err(RuntimeError::InvalidInput);
    }
    let value =
        openpc_multi_rpc::parse_strict_json(body, 8).map_err(|_| RuntimeError::InvalidInput)?;
    let object = exact_object(&value, &["id", "jsonrpc", "method", "params"])?;
    if object.get("jsonrpc") != Some(&Value::String("2.0".into())) {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(value)
}

fn exact_object<'a>(value: &'a Value, names: &[&str]) -> RuntimeResult<&'a Map<String, Value>> {
    let object = value.as_object().ok_or(RuntimeError::InvalidInput)?;
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != names.iter().copied().collect()
    {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(object)
}

pub(crate) fn request_id(value: &Value) -> RuntimeResult<String> {
    match value {
        Value::String(value) if !value.is_empty() && value.chars().count() <= 128 => {}
        Value::Number(value) if value.as_u64().is_some_and(|id| id <= 9_007_199_254_740_991) => {}
        _ => return Err(RuntimeError::InvalidInput),
    }
    let bytes =
        openpc_multi_rpc::rfc8785_canonical_bytes(value).map_err(|_| RuntimeError::InvalidInput)?;
    String::from_utf8(bytes).map_err(|_| RuntimeError::InvalidInput)
}

fn valid_block_selector(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("0x") else {
        return false;
    };
    !hex.is_empty()
        && hex.len() <= 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && (hex == "0" || !hex.starts_with('0'))
}

fn address(value: &str) -> RuntimeResult<[u8; 20]> {
    let digits = value.strip_prefix("0x").ok_or(RuntimeError::InvalidInput)?;
    let bytes = bytes(&format!("0x{}", digits.to_ascii_lowercase()), 20)?;
    bytes.try_into().map_err(|_| RuntimeError::InvalidInput)
}

fn bytes(value: &str, maximum_bytes: usize) -> RuntimeResult<Vec<u8>> {
    let digits = value.strip_prefix("0x").ok_or(RuntimeError::InvalidInput)?;
    if digits.is_empty()
        || !digits.len().is_multiple_of(2)
        || digits.len() / 2 > maximum_bytes
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RuntimeError::InvalidInput);
    }
    (0..digits.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&digits[index..index + 2], 16)
                .map_err(|_| RuntimeError::InvalidInput)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_policy_core::invocation::{
        AbiType, ApprovalRequirement, InvocationPolicy, ValidatedInvocationPolicy,
    };
    use pc_runtime_types::RequestClass;

    fn policies() -> Vec<ValidatedInvocationPolicy> {
        policies_for("eth_call", RequestClass::Read)
    }
    fn policies_for(method: &str, class: RequestClass) -> Vec<ValidatedInvocationPolicy> {
        vec![
            ValidatedInvocationPolicy::try_new(InvocationPolicy {
                method_required_roles: None,
                nested_call_set_digest: None,
                rpc_denied: false,
                tenant_id: "participant".into(),
                privacy_domain_id: "privacy".into(),
                workload_id: "workload".into(),
                policy_version: "1".into(),
                policy_artifact_digest: Digest::of("policy"),
                policy_generation_digest: Digest::of("generation"),
                active: true,
                rpc_method: method.into(),
                request_class: class,
                chain_id: "1".into(),
                network_id: "local".into(),
                genesis_digest: Digest::of("genesis"),
                contract_address: [1; 20],
                proxy_address: None,
                implementation_address: None,
                code_digest: Digest::of("code"),
                implementation_code_digest: None,
                abi_digest: Digest::of("abi"),
                canonical_signature: "read(uint256)".into(),
                selector: [0x12, 0x34, 0x56, 0x78],
                input_types: vec![AbiType::Uint(256)],
                required_roles: vec!["reader".into()],
                approval: ApprovalRequirement::None,
                webauthn_required: false,
                argument_rules: Vec::new(),
                named_sets: Vec::new(),
                nested_policies: Vec::new(),
            })
            .unwrap(),
        ]
    }

    fn body() -> Vec<u8> {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{{"to":"0x{}","data":"0x12345678{}"}},"0x10"]}}"#,
            "01".repeat(20),
            "00".repeat(32)
        )
        .into_bytes()
    }

    fn decode(body: &[u8]) -> RuntimeResult<RuntimeRequest> {
        decode_protected_json_rpc(
            body,
            &policies(),
            RequestDecodeLimits {
                maximum_request_bytes: 1024,
                maximum_response_bytes: 4096,
                timeout_ms: 1000,
                block_selector: "0x10",
            },
            100,
        )
    }

    #[test]
    fn ids_obey_the_public_json_rpc_exact_integer_ceiling() {
        assert_eq!(request_id_from_body(&body(), 1024).unwrap(), "1");
        assert!(request_id_from_body(&body(), body().len() - 1).is_err());
        assert!(request_id(&serde_json::json!("λ".repeat(128))).is_ok());
        assert!(request_id(&serde_json::json!("λ".repeat(129))).is_err());
        assert_eq!(
            request_id(&serde_json::json!(9_007_199_254_740_991_u64)).unwrap(),
            "9007199254740991"
        );
        for value in [
            serde_json::json!(9_007_199_254_740_992_u64),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            Value::Null,
        ] {
            assert!(request_id(&value).is_err());
        }
        assert_ne!(
            request_id(&serde_json::json!(1)).unwrap(),
            request_id(&serde_json::json!("1")).unwrap()
        );
    }

    #[test]
    fn admitted_write_policy_cannot_turn_call_fields_into_a_signed_transaction() {
        let mut value: Value = serde_json::from_slice(&body()).unwrap();
        value["method"] = Value::String("eth_sendRawTransaction".into());
        let policies = policies_for("eth_sendRawTransaction", RequestClass::Write);
        assert_eq!(
            decode_protected_json_rpc(
                &serde_json::to_vec(&value).unwrap(),
                &policies,
                RequestDecodeLimits {
                    maximum_request_bytes: 1024,
                    maximum_response_bytes: 4096,
                    timeout_ms: 1000,
                    block_selector: "0x10"
                },
                100,
            ),
            Err(RuntimeError::Denied)
        );
        assert!(
            DecodedProtectedRequest::decode(
                &serde_json::to_vec(&value).unwrap(),
                &policies,
                RequestDecodeLimits {
                    maximum_request_bytes: 1024,
                    maximum_response_bytes: 4096,
                    timeout_ms: 1000,
                    block_selector: "0x10"
                },
                100
            )
            .is_err()
        );
    }

    #[test]
    fn signed_body_binds_signer_nonce_chain_and_compiled_call_without_caller_overrides() {
        use sha3::{Digest as _, Keccak256};
        fn list(payload: &[u8]) -> Vec<u8> {
            let mut out = if payload.len() < 56 {
                vec![0xc0 + payload.len() as u8]
            } else {
                vec![0xf8, payload.len() as u8]
            };
            out.extend(payload);
            out
        }
        let key = k256::ecdsa::SigningKey::from_bytes((&[0x46; 32]).into()).unwrap();
        // EIP-1559: chain, nonce, priority fee, maximum fee, gas, target, value, calldata, access list.
        let mut fields = vec![1, 9, 1, 2, 0x83, 1, 0x86, 0xa0, 0x94];
        fields.extend([1; 20]);
        fields.push(0x80);
        fields.push(0xa4);
        fields.extend([0x12, 0x34, 0x56, 0x78]);
        fields.extend([0; 32]);
        fields.push(0xc0);
        let mut unsigned = vec![2];
        unsigned.extend(list(&fields));
        let (signature, parity) = key.sign_prehash_recoverable(&Keccak256::digest(&unsigned));
        fields.push(if parity.to_byte() == 0 { 0x80 } else { 1 });
        for scalar in [signature.r().to_bytes(), signature.s().to_bytes()] {
            let start = scalar.iter().position(|b| *b != 0).unwrap();
            fields.push(0x80 + (32 - start) as u8);
            fields.extend(&scalar[start..]);
        }
        let mut raw = vec![2];
        raw.extend(list(&fields));
        let encoded = format!(
            "0x{}",
            raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let body=serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":"signed-1","method":"eth_sendRawTransaction","params":[encoded]})).unwrap();
        let limits = RequestDecodeLimits {
            maximum_request_bytes: 4096,
            maximum_response_bytes: 4096,
            timeout_ms: 1000,
            block_selector: "0x10",
        };
        let policies = policies_for("eth_sendRawTransaction", RequestClass::Write);
        let decoded = DecodedProtectedRequest::decode(&body, &policies, limits, 100).unwrap();
        let mut uppercase: Value = serde_json::from_slice(&body).unwrap();
        uppercase["params"][0] = serde_json::json!(format!("0x{}", encoded[2..].to_uppercase()));
        // The public wire form requires canonical lower-case hexadecimal.
        assert!(
            DecodedProtectedRequest::decode(
                &serde_json::to_vec(&uppercase).unwrap(),
                &policies,
                limits,
                100,
            )
            .is_err()
        );
        assert!(
            DecodedProtectedRequest::decode(
                &body,
                &policies,
                RequestDecodeLimits {
                    timeout_ms: 10_001,
                    ..limits
                },
                100
            )
            .is_err()
        );
        assert_eq!(decoded.signed_transaction().unwrap().nonce(), 9);
        assert_eq!(decoded.request().class, RequestClass::Write);
        decoded.request().validate_digest().unwrap();
        assert_eq!(
            decoded
                .request()
                .invocation
                .as_ref()
                .unwrap()
                .contract_address,
            [1; 20]
        );
        assert!(DecodedProtectedRequest::decode(&body, &self::policies(), limits, 100).is_err());
        let mut altered: Value = serde_json::from_slice(&body).unwrap();
        altered["params"][0] = serde_json::json!({"from":"override","raw":altered["params"][0]});
        assert!(
            DecodedProtectedRequest::decode(
                &serde_json::to_vec(&altered).unwrap(),
                &policies,
                limits,
                100
            )
            .is_err()
        );
    }

    #[test]
    fn request_data_resolves_only_admitted_contract_bindings() {
        let request = decode(&body()).unwrap();
        assert_eq!(request.request_id, "1");
        assert_eq!(request.class, RequestClass::Read);
        assert_eq!(request.deadline_at_ms, 1100);
        assert_eq!(
            request.invocation.as_ref().unwrap().contract_address,
            [1; 20]
        );
        request.validate_digest().unwrap();
    }

    #[test]
    fn standard_call_sender_is_captured_without_becoming_authority() {
        let mut input: Value = serde_json::from_slice(&body()).unwrap();
        input["params"][0]["from"] = Value::String(format!("0x{}", "aB".repeat(20)));
        input["params"][1] = Value::String("latest".into());
        let bytes = serde_json::to_vec(&input).unwrap();
        let decoded = DecodedProtectedRequest::decode(
            &bytes,
            &policies(),
            RequestDecodeLimits {
                maximum_request_bytes: 1024,
                maximum_response_bytes: 4096,
                timeout_ms: 1000,
                block_selector: "0x10",
            },
            100,
        )
        .unwrap();
        assert_eq!(decoded.call_sender(), Some(&[0xab; 20]));
        assert_eq!(decoded.call_block_selector.as_deref(), Some("0x10"));
        assert_eq!(decoded.body(), bytes);
        assert_ne!(
            decoded.request().params_digest,
            decode(&body()).unwrap().params_digest
        );
        // Decoding records a claim only. The authenticated snapshot owner must
        // still match the address and require a separate invocation grant.
        decoded.request().validate_digest().unwrap();
        for sender in [
            Value::Null,
            serde_json::json!(1),
            serde_json::json!("0x01"),
            serde_json::json!(format!("0x{}", "gg".repeat(20))),
        ] {
            input["params"][0]["from"] = sender;
            assert!(decode(&serde_json::to_vec(&input).unwrap()).is_err());
        }
        input["params"][0]["from"] = serde_json::json!(format!("0x{}", "ab".repeat(20)));
        input["params"][0]["stateOverride"] = serde_json::json!({});
        assert!(decode(&serde_json::to_vec(&input).unwrap()).is_err());
    }

    #[test]
    fn captured_provider_bytes_cannot_follow_later_caller_mutations() {
        let mut input = body();
        let captured = DecodedProtectedRequest::decode(
            &input,
            &policies(),
            RequestDecodeLimits {
                maximum_request_bytes: 1024,
                maximum_response_bytes: 4096,
                timeout_ms: 1000,
                block_selector: "0x10",
            },
            100,
        )
        .unwrap();
        let original = input.clone();
        input.fill(b' ');
        assert_eq!(captured.body(), original);
        assert_eq!(captured.request(), &decode(&original).unwrap());
        let mut copied_request = captured.request().clone();
        copied_request.method = "eth_sendRawTransaction".into();
        assert_ne!(&copied_request, captured.request());
        assert_eq!(captured.request().method, "eth_call");
    }

    #[test]
    fn provider_call_pins_verified_hash_and_rejects_chain_or_height_substitution() {
        use openpc_multi_rpc::route_witness::{ChainAnchor, ChainAnchorBindings};
        use pc_policy_core::runtime_wire::Signer;
        let original = body();
        let decoded = DecodedProtectedRequest::decode(
            &original,
            &policies(),
            RequestDecodeLimits {
                maximum_request_bytes: 1024,
                maximum_response_bytes: 4096,
                timeout_ms: 1000,
                block_selector: "0x10",
            },
            100,
        )
        .unwrap();
        let signer = Signer::from_secret_bytes([73; 32]).unwrap();
        let mut anchor = ChainAnchor {
            chain_environment_id: "test-chain".into(),
            chain_id: 1,
            block_number: 16,
            block_hash: Digest::of(b"selected block"),
            state_root: Digest::of(b"selected state"),
            canonical_generation: 1,
            observed_at_ns: 100,
        };
        let verify = |anchor: &ChainAnchor| {
            VerifiedChainAnchor::verify(
                &signer.verifier(),
                &anchor.sign(&signer).unwrap(),
                &ChainAnchorBindings {
                    chain_environment_id: "test-chain",
                    chain_id: anchor.chain_id,
                    canonical_generation: 1,
                    maximum_age_ns: 100,
                },
                101,
            )
            .unwrap()
        };
        let provider = decoded.hash_pinned_provider_body(&verify(&anchor)).unwrap();
        let provider: Value = serde_json::from_slice(&provider).unwrap();
        let caller: Value = serde_json::from_slice(&original).unwrap();
        let mut latest = caller.clone();
        latest["params"][1] = Value::String("latest".into());
        let latest = DecodedProtectedRequest::decode(
            &serde_json::to_vec(&latest).unwrap(),
            &policies(),
            RequestDecodeLimits {
                maximum_request_bytes: 1024,
                maximum_response_bytes: 4096,
                timeout_ms: 1000,
                block_selector: "0x10",
            },
            100,
        )
        .unwrap();
        assert_eq!(
            latest.hash_pinned_provider_body(&verify(&anchor)).unwrap(),
            decoded.hash_pinned_provider_body(&verify(&anchor)).unwrap()
        );
        assert_eq!(provider["id"], caller["id"]);
        assert_eq!(provider["method"], caller["method"]);
        assert_eq!(provider["params"][0], caller["params"][0]);
        assert_eq!(
            provider["params"][1],
            serde_json::json!({
                "blockHash": format!("0x{}", anchor.block_hash.as_str()), "requireCanonical": true,
            })
        );
        assert_eq!(decoded.body(), original);
        let mut by_hash: Value = serde_json::from_slice(&original).unwrap();
        by_hash["params"][1] = provider["params"][1].clone();
        let decode_hash = |value: &Value| {
            DecodedProtectedRequest::decode(
                &serde_json::to_vec(value).unwrap(),
                &policies(),
                RequestDecodeLimits {
                    maximum_request_bytes: 1024,
                    maximum_response_bytes: 4096,
                    timeout_ms: 1000,
                    block_selector: "0x10",
                },
                100,
            )
        };
        let exact_hash = decode_hash(&by_hash).unwrap();
        assert!(
            exact_hash
                .hash_pinned_provider_body(&verify(&anchor))
                .is_ok()
        );
        by_hash["params"][1]["requireCanonical"] = Value::Bool(false);
        assert!(decode_hash(&by_hash).is_err());
        by_hash["params"][1]["requireCanonical"] = Value::Bool(true);
        by_hash["params"][1]["blockHash"] =
            Value::String(format!("0x{}", Digest::of("different block").as_str()));
        assert!(
            decode_hash(&by_hash)
                .unwrap()
                .hash_pinned_provider_body(&verify(&anchor))
                .is_err()
        );
        anchor.chain_id = 31337;
        assert!(decoded.hash_pinned_provider_body(&verify(&anchor)).is_err());
        anchor.chain_id = 1;
        anchor.block_number = 17;
        assert!(decoded.hash_pinned_provider_body(&verify(&anchor)).is_err());
        assert!(latest.hash_pinned_provider_body(&verify(&anchor)).is_err());
    }

    #[test]
    fn duplicate_unknown_anchor_address_and_selector_substitution_fail_closed() {
        let original = String::from_utf8(body()).unwrap();
        for changed in [
            original.replacen("\"id\":1", "\"id\":1,\"id\":2", 1),
            original.replacen("\"method\":", "\"extra\":true,\"method\":", 1),
            original.replacen("\"0x10\"", "\"pending\"", 1),
            original.replacen("\"0x10\"", "\"0x11\"", 1),
            original.replacen(&"01".repeat(20), &"02".repeat(20), 1),
            original.replacen("12345678", "87654321", 1),
        ] {
            assert!(decode(changed.as_bytes()).is_err());
        }
    }
}
