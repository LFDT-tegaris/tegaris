//! Header release is explicit and independent of provider-controlled metadata.
use super::{ExtProcLimits, HeaderMutation, HeaderValue, HeaderValueOption};
use pc_runtime_types::{RuntimeError, RuntimeResult};
use std::collections::BTreeSet;

pub(super) fn mutation(
    upstream: &[(String, Vec<u8>)],
    admitted: Vec<(String, Vec<u8>)>,
    limits: ExtProcLimits,
) -> RuntimeResult<HeaderMutation> {
    let statuses: Vec<_> = upstream.iter().filter(|(k, _)| k == ":status").collect();
    if statuses.len() != 1
        || statuses[0].1.len() != 3
        || !matches!(statuses[0].1[0], b'2'..=b'5')
        || !statuses[0].1[1..].iter().all(u8::is_ascii_digit)
        || upstream
            .iter()
            .any(|(k, _)| k.starts_with(':') && k != ":status")
        || admitted.len() > limits.headers
    {
        return Err(RuntimeError::ResponseWithheld);
    }
    let mut bytes = 0usize;
    let mut names = BTreeSet::new();
    let mut set_headers = Vec::with_capacity(admitted.len());
    for (key, value) in admitted {
        bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
        if bytes > limits.header_bytes
            || key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || value.iter().any(|b| *b == 0 || *b == b'\r' || *b == b'\n')
            || !names.insert(key.clone())
            || matches!(
                key.as_str(),
                "content-length"
                    | "content-encoding"
                    | "transfer-encoding"
                    | "connection"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "upgrade"
                    | "x-openpc-runtime-capability"
            )
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        set_headers.push(HeaderValueOption {
            header: Some(HeaderValue {
                key,
                value: String::new(),
                raw_value: value,
            }),
            append_action: 2,
        });
    }
    // Removing all ordinary upstream headers also handles duplicate headers and
    // future provider metadata that is unknown to the installed response owner.
    let remove_headers = upstream
        .iter()
        .filter(|(k, _)| k != ":status")
        .map(|(k, _)| k.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(HeaderMutation {
        set_headers,
        remove_headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn limits() -> ExtProcLimits {
        ExtProcLimits {
            headers: 4,
            header_bytes: 256,
            body_bytes: 256,
        }
    }
    fn header(key: &str, value: &str) -> (String, Vec<u8>) {
        (key.into(), value.as_bytes().to_vec())
    }
    #[test]
    fn provider_metadata_is_removed_unless_explicitly_replaced() {
        let original = vec![
            header(":status", "200"),
            header("set-cookie", "secret"),
            header("x-provider-private", "secret"),
            header("content-length", "999"),
            header("content-type", "text/plain"),
        ];
        let result = mutation(
            &original,
            vec![header("content-type", "application/json")],
            limits(),
        )
        .unwrap();
        assert_eq!(
            result.remove_headers,
            [
                "content-length",
                "content-type",
                "set-cookie",
                "x-provider-private"
            ]
        );
        assert_eq!(result.set_headers.len(), 1);
        assert_eq!(
            result.set_headers[0].header.as_ref().unwrap().raw_value,
            b"application/json"
        );
    }
    #[test]
    fn status_framing_injection_duplicate_and_capacity_fail_closed() {
        let original = vec![header(":status", "200")];
        for admitted in [
            vec![header("content-length", "5")],
            vec![header(":status", "200")],
            vec![header("x-safe", "ok\r\nprivate: secret")],
            vec![header("x-safe", "1"), header("x-safe", "2")],
            vec![header("x-safe", &"x".repeat(257))],
            vec![header("x-openpc-runtime-capability", "token")],
        ] {
            assert_eq!(
                mutation(&original, admitted, limits()),
                Err(RuntimeError::ResponseWithheld)
            );
        }
        for original in [
            vec![],
            vec![header(":status", "200"), header(":status", "200")],
            vec![header(":status", "101")],
            vec![header(":status", "200"), header(":method", "POST")],
        ] {
            assert_eq!(
                mutation(&original, vec![], limits()),
                Err(RuntimeError::ResponseWithheld)
            );
        }
    }
}
