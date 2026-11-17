//! Lossless codec for the authenticated Control-store Native Value owner.
//! Encoding or decoding a document neither issues nor consumes its authority.
use pc_policy_core::native_value::NativeValueAuthorizationV1;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Encode {
    document: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Read {
    document_bytes: String,
    consumed: bool,
}

pub fn execute(command: &str, value: Value) -> Result<Value, ()> {
    let authorization = match command {
        "ENCODE_NATIVE_VALUE_AUTHORIZATION" => {
            let mut input: Encode = serde_json::from_value(value).map_err(|_| ())?;
            let document = input.document.as_object_mut().ok_or(())?;
            if document.contains_key("semanticDigest")
                || document.get("used") != Some(&json!(false))
            {
                return Err(());
            }
            // The existing JavaScript authority context transports uint64
            // epochs as decimal text. Convert once inside the Rust owner.
            let epoch = document
                .get("participantEpoch")
                .and_then(Value::as_str)
                .ok_or(())?;
            let parsed = epoch.parse::<u64>().map_err(|_| ())?;
            if parsed.to_string() != epoch {
                return Err(());
            }
            document.insert("participantEpoch".into(), json!(parsed));
            document.insert("semanticDigest".into(), json!("00".repeat(32)));
            let mut authorization: NativeValueAuthorizationV1 =
                serde_json::from_value(input.document).map_err(|_| ())?;
            authorization.semantic_digest = authorization.computed_digest().map_err(|_| ())?;
            authorization.validate().map_err(|_| ())?;
            authorization
        }
        "READ_NATIVE_VALUE_AUTHORIZATION" => {
            let input: Read = serde_json::from_value(value).map_err(|_| ())?;
            let source = input.document_bytes.strip_prefix("0x").ok_or(())?;
            if source.len() > 8192
                || !source.len().is_multiple_of(2)
                || !source
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(());
            }
            let bytes = (0..source.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&source[i..i + 2], 16).map_err(|_| ()))
                .collect::<Result<Vec<_>, _>>()?;
            let mut authorization = NativeValueAuthorizationV1::decode(&bytes).map_err(|_| ())?;
            if authorization.used && !input.consumed {
                return Err(());
            }
            authorization.used = input.consumed;
            authorization.semantic_digest = authorization.computed_digest().map_err(|_| ())?;
            authorization
        }
        _ => return Err(()),
    };
    Ok(json!({
        "identity":"PC-NATIVE-VALUE-AUTHORIZATION-1", "authority":"NONE",
        "documentBytes":format!("0x{}",super::hex(&authorization.document_bytes().map_err(|_| ())?)),
        "semanticDigest":authorization.semantic_digest,
        "authorizationId":authorization.authorization_id,
        "participantEpoch":authorization.participant_epoch.to_string(),
        "validUntil":authorization.valid_until,
        "used":authorization.used,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        json!({"document":{
            "authorizationId":"native:test-1", "participantId":"participant:1",
            "participantEpoch":u64::MAX.to_string(), "actorSubjectId":"actor:1",
            "chainEnvironmentId":"chain:devnet", "chainId":"92870",
            "genesisHash":"11".repeat(32), "purpose":"CONTRACT_CREATION_ENDOWMENT",
            "amountMode":"MAXIMUM", "maxAmountWei":"10", "oneUse":true, "used":false,
            "policyDecisionDigest":"22".repeat(32), "validUntil":"2030-01-01T00:00:00Z"
        }})
    }

    #[test]
    fn codec_preserves_c17_epoch_and_renders_consumption_without_issuing_authority() {
        let original = execute("ENCODE_NATIVE_VALUE_AUTHORIZATION", input()).unwrap();
        assert_eq!(original["authority"], "NONE");
        assert_eq!(original["participantEpoch"], u64::MAX.to_string());
        assert_eq!(
            original["semanticDigest"],
            "1f698cd70b8d061aa746d4aa4a570594fdeb858c3bd218c15397fedf561f85bc"
        );
        let read = |document: &Value, consumed| {
            execute(
                "READ_NATIVE_VALUE_AUTHORIZATION",
                json!({"documentBytes":document["documentBytes"],"consumed":consumed}),
            )
        };
        assert_eq!(read(&original, false).unwrap(), original);
        let consumed = read(&original, true).unwrap();
        assert_eq!(consumed["used"], true);
        assert_eq!(consumed["authorizationId"], original["authorizationId"]);
        assert_eq!(consumed["validUntil"], original["validUntil"]);
        assert_ne!(consumed["semanticDigest"], original["semanticDigest"]);
        assert_eq!(read(&consumed, true).unwrap(), consumed);
        assert!(read(&consumed, false).is_err());
    }

    #[test]
    fn codec_rejects_rounded_epochs_and_caller_injected_issue_state() {
        for (field, value) in [
            ("participantEpoch", json!(u64::MAX)),
            ("participantEpoch", json!("01")),
            ("participantEpoch", json!("18446744073709551616")),
            ("used", json!(true)),
            ("oneUse", json!(false)),
            ("semanticDigest", json!("00".repeat(32))),
            ("ready", json!(true)),
        ] {
            let mut input = input();
            input["document"][field] = value;
            assert!(
                execute("ENCODE_NATIVE_VALUE_AUTHORIZATION", input).is_err(),
                "{field}"
            );
        }
    }
}
