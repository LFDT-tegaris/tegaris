use super::deployment_intent_command::decode;
use openpc_multi_rpc::deployment::{
    intent::PreparedDeploymentIntent,
    projection::{DeploymentProjection, ProjectionExpectation},
};
use pc_policy_core::deployment_policy::AdmittedDeploymentPolicy;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Read {
    publication: AdmittedDeploymentPolicy,
    record_bytes: String,
    signed_bytes: String,
    verification_key: String,
    expected: ProjectionExpectation,
    association: Option<Association>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Association {
    document_bytes: String,
    activation_bytes: String,
    activation_sequence: String,
    current_sequence: String,
}
pub fn execute(value: Value) -> Result<Value, ()> {
    let input: Read = serde_json::from_value(value).map_err(|_| ())?;
    let key = decode(&input.verification_key)?;
    let prepared =
        PreparedDeploymentIntent::restore(&decode(&input.record_bytes)?, &input.publication)
            .map_err(|_| ())?;
    let result = DeploymentProjection::verify(&decode(&input.signed_bytes)?, &key, &input.expected)
        .map_err(|_| ())?;
    result
        .verify_preparation(&prepared, &input.publication)
        .map_err(|_| ())?;
    let association = if let Some(association) = input.association {
        let activation = DeploymentProjection::verify(
            &decode(&association.activation_bytes)?,
            &key,
            &input.expected,
        )
        .map_err(|_| ())?;
        activation
            .verify_preparation(&prepared, &input.publication)
            .map_err(|_| ())?;
        if activation.claims().sequence().map_err(|_| ())?.to_string()
            != association.activation_sequence
            || result.claims().sequence().map_err(|_| ())?.to_string()
                != association.current_sequence
        {
            return Err(());
        }
        Some(
            result
                .verify_association(
                    &decode(&association.document_bytes)?,
                    &activation,
                    &input.expected.attempt_id,
                    &prepared,
                )
                .map_err(|_| ())?,
        )
    } else {
        None
    };
    Ok(
        json!({"identity":"PC-DEPLOYMENT-JOURNAL-PROJECTION-1","authority":"OBSERVATION_ONLY",
        "resultDigest":result.digest(),"sequence":result.claims().sequence().map_err(|_|())?.to_string(),
        "observedAt":result.claims().observed_at(),"status":result.claims().status(),"outcome":result.claims().outcome(),"association":association}),
    )
}
