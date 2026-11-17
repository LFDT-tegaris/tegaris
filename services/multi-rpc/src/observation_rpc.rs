//! Shared bounded pinned JSON-RPC observation transport. Authorization is
//! reacquired before every exchange; no synchronous owner lock crosses I/O.
use crate::provider_connection::ConnectionLease;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde_json::{Value, json};
use tokio::time::Instant;

pub(crate) struct ObservationRpc<'a> {
    pub connection: &'a ConnectionLease,
    pub request_digest: &'a Digest,
    pub deadline: Instant,
    pub revalidate: &'a (dyn Fn() -> RuntimeResult<()> + Sync),
    pub exchanges: Vec<(Digest, Digest)>,
    pub maximum_calls: usize,
    pub maximum_depth: u32,
    pub purpose: &'static str,
}
impl ObservationRpc<'_> {
    pub async fn rpc(&mut self, method: &str, params: Value) -> RuntimeResult<Value> {
        self.rpc_with_response_limit(method, params, usize::MAX)
            .await
    }

    pub async fn rpc_with_response_limit(
        &mut self,
        method: &str,
        params: Value,
        response_limit: usize,
    ) -> RuntimeResult<Value> {
        let mut remaining_response_bytes = usize::MAX;
        self.rpc_with_response_budget(
            method,
            params,
            response_limit,
            &mut remaining_response_bytes,
        )
        .await
    }

    pub async fn rpc_with_response_budget(
        &mut self,
        method: &str,
        params: Value,
        response_limit: usize,
        remaining_response_bytes: &mut usize,
    ) -> RuntimeResult<Value> {
        if self.exchanges.len() >= self.maximum_calls || Instant::now() >= self.deadline {
            return Err(RuntimeError::BudgetExhausted);
        }
        let response_limit = response_limit.min(*remaining_response_bytes);
        if response_limit == 0 {
            return Err(RuntimeError::BudgetExhausted);
        }
        (self.revalidate)()?;
        let id = format!(
            "{}:{}:{}",
            self.purpose,
            self.request_digest.as_str(),
            self.exchanges.len()
        );
        let body = crate::rfc8785_canonical_bytes(&json!({
            "jsonrpc":"2.0", "id":id, "method":method, "params":params
        }))
        .map_err(|_| RuntimeError::InvalidInput)?;
        let request_digest = Digest::of(&body);
        let response = self
            .connection
            .connection()
            .map_err(|_| RuntimeError::GenerationMismatch)?
            .post_json_with_response_limit(body, self.deadline, response_limit)
            .await
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        *remaining_response_bytes = remaining_response_bytes
            .checked_sub(response.len())
            .ok_or(RuntimeError::BudgetExhausted)?;
        let value = crate::parse_strict_json(&response, self.maximum_depth)
            .map_err(|_| RuntimeError::ResponseWithheld)?;
        let Value::Object(mut object) = value else {
            return Err(RuntimeError::ResponseWithheld);
        };
        if object.len() != 3
            || object.get("jsonrpc") != Some(&Value::String("2.0".into()))
            || object.get("id") != Some(&Value::String(id))
            || !object.contains_key("result")
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        self.exchanges.push((request_digest, Digest::of(response)));
        // Transfer the parsed result. Traces can be large; cloning the entire
        // result tree adds a second live copy without adding any evidence.
        object
            .remove("result")
            .ok_or(RuntimeError::ResponseWithheld)
    }
}
