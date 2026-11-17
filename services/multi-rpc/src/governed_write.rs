//! Production one-attempt transport over an installed, pinned connection.
//! The runtime authority owner must retain its admission fence and supply the
//! immutable command. This module never interprets a request field as authority.
use crate::{
    event::hex_digest,
    journal::{GovernedCommand, JournalState, PreparedCommand, WriteJournal},
    provider_connection::{ConnectionLease, ConnectionRecord},
    signed_transaction::SignedTransaction,
};
use pc_runtime_types::{Digest, RequestClass, RuntimeError, RuntimeRequest, RuntimeResult};
use serde_json::Value;
use std::sync::Mutex;
use tokio::time::Instant;

/// Implemented by the current target owner, not an HTTP input or a provider.
/// It checks live actor/signer, nonce reservation, generation, purpose, route,
/// approval/step-up and deadline at the final boundary before STARTED.
pub trait LiveWriteAuthority: Send + Sync {
    fn acquire<'a>(
        &'a self,
        transaction: &SignedTransaction,
        command: &GovernedCommand,
        connection: &ConnectionRecord,
    ) -> RuntimeResult<Box<dyn WriteAuthorityLease + 'a>>;
}

/// The live owner retains its short authority/fact fences through the durable
/// attempt-start commit. No authority or journal lock crosses provider I/O.
pub trait WriteAuthorityLease {
    fn revalidate(&self) -> RuntimeResult<()>;
}

/// One canonical byte identity across workload decoding, PDS and Broker,
/// independent of the caller's hexadecimal letter case.
pub fn submission_params_digest(transaction: &SignedTransaction) -> RuntimeResult<Digest> {
    crate::rfc8785_canonical_bytes(&serde_json::json!([format!(
        "0x{}",
        hex(transaction.bytes())
    )]))
    .map(Digest::of)
    .map_err(|_| RuntimeError::InvalidInput)
}

pub fn validate_runtime_submission(
    request: &RuntimeRequest,
    transaction: &SignedTransaction,
) -> RuntimeResult<()> {
    validate_runtime_signed_command(request, transaction)?;
    let invocation = request
        .invocation
        .as_ref()
        .ok_or(RuntimeError::InvalidAuthorization)?;
    if invocation.chain_id != transaction.chain_id().to_string()
        || transaction.destination() != Some(&invocation.contract_address)
        || invocation.calldata != transaction.data()
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}

pub(crate) fn validate_runtime_signed_command(
    request: &RuntimeRequest,
    transaction: &SignedTransaction,
) -> RuntimeResult<()> {
    request.validate_digest()?;
    if request.class != RequestClass::Write
        || request.method != "eth_sendRawTransaction"
        || request.batch_index != 0
        || request.params_digest != submission_params_digest(transaction)?
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}

/// Returned body is constructed here from verified bytes and an opaque command
/// ID. A caller cannot pair an admitted transaction with alternate JSON-RPC data.
pub fn submission_body(
    transaction: &SignedTransaction,
    command_id: &str,
) -> RuntimeResult<Vec<u8>> {
    if command_id.is_empty() || command_id.len() > 160 {
        return Err(RuntimeError::InvalidInput);
    }
    crate::rfc8785_canonical_bytes(&serde_json::json!({
        "jsonrpc":"2.0", "id":command_id, "method":"eth_sendRawTransaction",
        "params":[format!("0x{}",hex(transaction.bytes()))]
    }))
    .map_err(|_| RuntimeError::InvalidInput)
}

pub fn validate_submission(
    transaction: &SignedTransaction,
    command: &GovernedCommand,
) -> RuntimeResult<Vec<u8>> {
    let body = submission_body(transaction, &command.command_id)?;
    if command.method != "eth_sendRawTransaction"
        || command.request_or_transaction_hash != format!("0x{}", hex(transaction.hash()))
        || command.submitted_bytes_digest != hex_digest(&body)
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(body)
}

/// All errors after durable STARTED are ambiguous. Neither HTTP status nor a
/// provider error proves that the bytes did not reach the chain's transaction pool.
pub async fn submit(
    journal: &Mutex<WriteJournal>,
    prepared: PreparedCommand,
    transaction: &SignedTransaction,
    connection: &ConnectionLease,
    authority: &dyn LiveWriteAuthority,
    deadline: Instant,
) -> RuntimeResult<JournalState> {
    let (started, body, transport) = {
        let preflight = (|| {
            let body = validate_submission(transaction, prepared.command())?;
            let record = connection
                .record()
                .map_err(|_| RuntimeError::GenerationMismatch)?;
            let transport = connection
                .connection()
                .map_err(|_| RuntimeError::GenerationMismatch)?;
            let authority = authority.acquire(transaction, prepared.command(), record)?;
            Ok::<_, RuntimeError>((body, transport, authority))
        })();
        let (body, transport, authority) = match preflight {
            Ok(value) => value,
            Err(error) => {
                journal
                    .lock()
                    .map_err(|_| RuntimeError::RuntimeUnavailable)?
                    .fail_pre_start(prepared, hex_digest(error.pc_code().as_bytes()))
                    .map_err(|_| RuntimeError::RuntimeUnavailable)?;
                return Err(error);
            }
        };
        let mut journal = journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let readiness = journal
            .validate_signed_prepared(&prepared, transaction)
            .map_err(|_| RuntimeError::InvalidAuthorization)
            .and_then(|()| authority.revalidate())
            .and_then(|()| {
                if deadline <= Instant::now() {
                    Err(RuntimeError::BudgetExhausted)
                } else {
                    Ok(())
                }
            });
        if let Err(error) = readiness {
            journal
                .fail_pre_start(prepared, hex_digest(error.pc_code().as_bytes()))
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            return Err(error);
        }
        let started = journal
            .mark_started(prepared, hex_digest(&body))
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        (started, body, transport)
    };
    let response = transport.post_json(body, deadline).await;
    let acknowledgement = response.as_ref().ok().is_some_and(|bytes| {
        let Ok(Value::Object(value)) = crate::parse_strict_json(bytes, 4) else {
            return false;
        };
        value.len() == 3
            && value.get("jsonrpc") == Some(&Value::String("2.0".into()))
            && value.get("id") == Some(&Value::String(started.command().command_id.clone()))
            && value.get("result")
                == Some(&Value::String(
                    started.command().request_or_transaction_hash.clone(),
                ))
    });
    if !acknowledgement {
        let evidence = response.as_ref().map_or_else(
            |_| hex_digest(b"provider-outcome-unknown"),
            |bytes| hex_digest(bytes),
        );
        journal
            .lock()
            .map_err(|_| RuntimeError::WriteAmbiguity)?
            .mark_ambiguous(&started, evidence)
            .map_err(|_| RuntimeError::WriteAmbiguity)?;
        return Ok(JournalState::Ambiguous);
    }
    journal
        .lock()
        .map_err(|_| RuntimeError::WriteAmbiguity)?
        .mark_acknowledged(
            &started,
            hex_digest(response.as_ref().expect("validated response")),
        )
        .map_err(|_| RuntimeError::WriteAmbiguity)?;
    // The effect remains durable if authority changed during I/O; disclosure
    // requires a fresh authorization and cannot roll back an external send.
    authority
        .acquire(
            transaction,
            started.command(),
            connection
                .record()
                .map_err(|_| RuntimeError::WriteAmbiguity)?,
        )
        .and_then(|lease| lease.revalidate())
        .map_err(|_| RuntimeError::WriteAmbiguity)?;
    Ok(JournalState::Acknowledged)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            write!(s, "{b:02x}").expect("string");
            s
        })
}
