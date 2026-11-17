//! Public observation entry of the existing authenticated target. Path/ID select
//! a non-granting operation; all identity, root permission, installed settings,
//! facts and provider checks remain in the captured-request owner.
use super::*;
use openpc_multi_rpc::cigl::analysis::receipt::PURPOSE;
use pc_runtime_types::PurposeSigner;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AnalysisInput {
    signed_transaction: String,
}

fn analysis_rpc_body(body: &[u8], limit: usize, id: &str) -> RuntimeResult<Vec<u8>> {
    if body.is_empty() || body.len() > limit {
        return Err(RuntimeError::BudgetExhausted);
    }
    let input: AnalysisInput =
        serde_json::from_slice(body).map_err(|_| RuntimeError::InvalidInput)?;
    // Public analysis input is deliberately not a JSON-RPC submission. A typo
    // or encoded alias in its URL therefore cannot turn it into a send request.
    pc_runtime_types::canonical_bytes(
        &serde_json::json!({"jsonrpc":"2.0","id":format!("cigl:{id}"),
        "method":"eth_sendRawTransaction","params":[input.signed_transaction]}),
    )
}

pub(super) struct AnalysisExporter {
    target_runtime_id: String,
    signer: PurposeSigner,
}

impl ProtectedTargetOwner {
    pub fn with_cigl_analysis_target(
        mut self,
        target_runtime_id: &str,
        target_key: [u8; 32],
    ) -> RuntimeResult<Self> {
        if !valid_id(target_runtime_id) {
            return Err(RuntimeError::InvalidInput);
        }
        self.analysis_exporter = Some(Arc::new(AnalysisExporter {
            target_runtime_id: target_runtime_id.into(),
            signer: PurposeSigner::from_secret_bytes(PURPOSE, target_key)?,
        }));
        Ok(self)
    }
}

fn valid_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == value)
}

pub(super) fn request_analysis_id(headers: &[(String, Vec<u8>)]) -> RuntimeResult<Option<String>> {
    let paths = headers.iter().filter(|(name, _)| name == ":path");
    let mut selected = None;
    let mut count = 0;
    for (_, path) in paths {
        count += 1;
        if path.starts_with(b"/api/v1/cigl-analyses") {
            let path = std::str::from_utf8(path).map_err(|_| RuntimeError::InvalidInput)?;
            let id = path
                .strip_prefix("/api/v1/cigl-analyses/")
                .and_then(|path| path.strip_suffix("/observe"))
                .and_then(|path| path.strip_prefix("urn:openpc:resource:"))
                .filter(|id| valid_id(id))
                .ok_or(RuntimeError::InvalidInput)?;
            selected = Some(id.into());
        }
    }
    if selected.is_some() && count != 1 {
        return Err(RuntimeError::InvalidInput);
    }
    if selected.is_some() {
        let mut methods = headers.iter().filter(|(name, _)| name == ":method");
        if methods.next().map(|(_, value)| value.as_slice()) != Some(b"POST")
            || methods.next().is_some()
        {
            return Err(RuntimeError::InvalidInput);
        }
    }
    Ok(selected)
}

impl TargetRequest {
    pub(super) async fn observe_analysis(&mut self, body: &[u8]) -> RuntimeResult<Vec<u8>> {
        let id = self.analysis_id.clone().ok_or(RuntimeError::Denied)?;
        let exporter = self.analysis_exporter.clone().ok_or(RuntimeError::Denied)?;
        let rpc_body = analysis_rpc_body(body, self.decode.maximum_request_bytes, &id)?;
        let request = self.bind_body(&rpc_body)?;
        let capsule_digest = {
            let lease = request.acquire()?;
            let capsule = lease.state().active().capsule();
            if capsule.target_runtime_id != exporter.target_runtime_id {
                return Err(RuntimeError::GenerationMismatch);
            }
            capsule.digest()?
        };
        let connection = self.authority.submission_connection(&request)?;
        let observed = request
            .clone()
            .analyze_submission_method(connection, |head| {
                self.authority.submission_route_evidence(&request, head)
            })
            .await?;
        // The captured producer revalidated live authority after observation.
        // Move its sanitized result directly to the purpose-separated signer;
        // neither raw input nor frames are retained by this response adapter.
        observed.into_receipt(
            &id,
            &exporter.target_runtime_id,
            &capsule_digest,
            &exporter.signer,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_input_cannot_be_interpreted_as_a_public_submission() {
        let body = br#"{"signedTransaction":"0x02"}"#;
        assert!(crate::request_decode::request_id_from_body(body, 4096).is_err());
        let rpc = analysis_rpc_body(body, 4096, "job").unwrap();
        assert!(crate::request_decode::request_id_from_body(&rpc, 4096).is_ok());
        assert!(analysis_rpc_body(&rpc, 4096, "job").is_err());
        for malformed in [
            br#"{"signedTransaction":"0x02","signedTransaction":"0x03"}"#.as_slice(),
            br#"{"signedTransaction":"0x02","dispatch":true}"#.as_slice(),
        ] {
            assert!(analysis_rpc_body(malformed, 4096, "job").is_err());
        }
    }

    #[test]
    fn analysis_paths_cannot_fall_through_to_transaction_dispatch() {
        let id = "019963de-8824-7000-8000-000000000001";
        let path = format!("/api/v1/cigl-analyses/urn:openpc:resource:{id}/observe");
        let headers = vec![
            (":method".into(), b"POST".to_vec()),
            (":path".into(), path.as_bytes().to_vec()),
        ];
        assert_eq!(request_analysis_id(&headers).unwrap().as_deref(), Some(id));
        for wrong in [
            format!("{path}?dispatch=true"),
            format!("{path}/"),
            path.replace("/observe", "/submit"),
            path.replace("resource:", "workload:"),
            path.replace(id, "*"),
            "/api/v1/cigl-analyses".into(),
        ] {
            assert!(
                request_analysis_id(&[
                    (":method".into(), b"POST".to_vec()),
                    (":path".into(), wrong.into_bytes())
                ])
                .is_err()
            );
        }
        let mut duplicate = headers.clone();
        duplicate.push((":path".into(), b"/rpc".to_vec()));
        assert!(request_analysis_id(&duplicate).is_err());
        let mut wrong_method = headers;
        wrong_method[0].1 = b"GET".to_vec();
        assert!(request_analysis_id(&wrong_method).is_err());
        assert_eq!(
            request_analysis_id(&[(":path".into(), b"/rpc".to_vec())]).unwrap(),
            None
        );
    }
}
