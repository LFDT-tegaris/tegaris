//! Resolve visibility references from their current Control owners. These
//! scoped configuration snapshots permit compilation, never response release.
use pc_policy_core::{
    contract_policy::event_fields,
    semantics::PolicySemanticDocument,
    visibility_policy::{AdmittedVisibilityResource, VisibilitySelector},
};
use serde_json::Value;
use sqlx::PgConnection;
use std::collections::BTreeSet;

pub async fn load_visibility_policy_inputs(
    connection: &mut PgConnection,
    document: &PolicySemanticDocument,
) -> Result<Vec<AdmittedVisibilityResource>, String> {
    document.validate()?;
    let mut resources = Vec::new();
    let mut seen = BTreeSet::new();
    for policy in &document.visibility_policies {
        let selector = &policy.selector;
        if matches!(selector, VisibilitySelector::StateRead { .. })
            || !seen.insert(pc_policy_core::pc_cbor_1(selector))
        {
            continue;
        }
        let mut contract_binding = None;
        let fields = match selector {
            VisibilitySelector::Disclosure {
                profile_id,
                profile_digest,
                data_class_id,
            } => {
                sqlx::query("select pg_advisory_xact_lock_shared(hashtextextended($1,0))")
                    .bind(format!("privacy-explorer-profile:{profile_id}"))
                    .execute(&mut *connection)
                    .await
                    .map_err(|_| "profile fence unavailable")?;
                let fields: Option<(Value,)> = sqlx::query_as(
                    r#"select profile->'allowedFieldIds' from control.privacy_explorer_profile
                    where registration_id=$1::text::uuid and participant_id=$2::text::uuid
                      and privacy_domain_id=$3::text::uuid and state='REGISTERED'
                      and profile_digest=$4 and profile->>'digest'=$4
                      and profile_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(profile-'digest'),'UTF8')),'hex')
                      and (profile->>'maximumDeadlineAt')::timestamptz>clock_timestamp()
                      and exists(select 1 from jsonb_array_elements(profile->'operationVersions') operation
                        where operation->'acceptedDataClassIds' ? $5)"#,
                ).bind(profile_id).bind(&document.participant_id).bind(&document.privacy_domain_id)
                    .bind(profile_digest).bind(data_class_id).fetch_optional(&mut *connection).await
                    .map_err(|_| "profile reference unavailable")?;
                serde_json::from_value(fields.ok_or("profile reference rejected")?.0)
                    .map_err(|_| "profile fields rejected")?
            }
            VisibilitySelector::Event {
                runtime_binding_id,
                binding_revision,
                ..
            }
            | VisibilitySelector::Transaction {
                runtime_binding_id,
                binding_revision,
            }
            | VisibilitySelector::Receipt {
                runtime_binding_id,
                binding_revision,
            } => {
                let row: Option<(String, Value, Value)> = sqlx::query_as(
                    r#"select artifact.abi_digest,artifact.canonical_abi,
                      jsonb_build_object('chainId',binding.chain_id,'networkId',binding.network_id,
                        'genesisDigest',binding.genesis_digest,'contractAddress',binding.contract_address,
                        'codeDigest',binding.code_digest,'abiDigest',artifact.abi_digest,
                        'canonicalAbi',artifact.canonical_abi)
                    from control.contract_runtime_binding binding
                    join control.abi_artifact artifact on artifact.participant_id=binding.participant_id
                      and artifact.privacy_domain_id=binding.privacy_domain_id and artifact.abi_artifact_id=binding.abi_artifact_id
                    where binding.runtime_binding_id=$1::text::uuid and binding.participant_id=$2::text::uuid
                      and binding.privacy_domain_id=$3::text::uuid and binding.state='BOUND' and binding.revision=$4::text::bigint
                      and artifact.abi_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(artifact.canonical_abi),'UTF8')),'hex')
                    for share of binding,artifact"#,
                ).bind(runtime_binding_id).bind(&document.participant_id).bind(&document.privacy_domain_id)
                    .bind(binding_revision).fetch_optional(&mut *connection).await
                    .map_err(|_| "visibility binding unavailable")?;
                let (digest, abi, binding) = row.ok_or("visibility binding rejected")?;
                contract_binding = Some(
                    serde_json::from_value(binding).map_err(|_| "visibility binding rejected")?,
                );
                match selector {
                    VisibilitySelector::Event {
                        abi_digest,
                        event_signature,
                        ..
                    } if abi_digest == &digest => event_fields(&abi, event_signature)?,
                    VisibilitySelector::Receipt { .. } => Vec::new(),
                    VisibilitySelector::Transaction { .. } => [
                        "blockHash",
                        "blockNumber",
                        "chainId",
                        "from",
                        "gas",
                        "gasPrice",
                        "hash",
                        "input",
                        "maxFeePerGas",
                        "maxPriorityFeePerGas",
                        "nonce",
                        "to",
                        "transactionIndex",
                        "type",
                        "value",
                        "r",
                        "s",
                        "v",
                        "yParity",
                        "accessList",
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                    _ => return Err("visibility event binding rejected".into()),
                }
            }
            VisibilitySelector::StateRead { .. } => {
                unreachable!("state reads use admitted method assets")
            }
        };
        resources.push(AdmittedVisibilityResource {
            state_output_types: None,
            contract_binding,
            participant_id: document.participant_id.clone(),
            privacy_domain_id: document.privacy_domain_id.clone(),
            selector: selector.clone(),
            available_fields: fields,
        });
    }
    Ok(resources)
}
