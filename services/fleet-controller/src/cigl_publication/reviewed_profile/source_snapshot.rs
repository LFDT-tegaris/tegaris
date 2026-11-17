//! Current method registrations and the complete shared grant snapshot. The
//! caller retains the scoped grant fence and source row locks through commit.
use super::*;
use pc_policy_core::cigl::profile::MethodProfileDefinition;
use std::collections::BTreeSet;

pub(in crate::cigl_publication) struct Snapshot {
    pub methods: Vec<MethodSourceVersion>,
    pub grants: Vec<InteractionGrant>,
    pub versions: Vec<GrantSourceVersion>,
}

pub(in crate::cigl_publication) enum MethodState {
    PreparedOrActive,
    Active,
}

pub(in crate::cigl_publication) async fn load(
    tx: &mut Transaction<'_, Postgres>,
    definition: &MethodProfileDefinition,
    policies: &[ValidatedInvocationPolicy],
    state: MethodState,
) -> RuntimeResult<Snapshot> {
    let required: BTreeSet<_> = definition
        .interactions
        .iter()
        .map(|rule| rule.contract_method_policy_id.as_str())
        .chain(std::iter::once(
            definition.root_contract_method_policy_id.as_str(),
        ))
        .collect();
    let mut methods = Vec::new();
    let mut keys = BTreeMap::new();
    for id in required {
        let mut matching = policies.iter().filter(|p| {
            p.configured_identity()
                .is_ok_and(|identity| identity.contract_method_policy_id() == id)
        });
        let policy = matching.next().ok_or(RuntimeError::GenerationMismatch)?;
        if matching.next().is_some() {
            return Err(RuntimeError::GenerationMismatch);
        }
        let binding = policy.configured_identity()?.runtime_binding_id();
        let row = sqlx::query(r#"select method.revision::text method_revision,binding.revision::text binding_revision,
          method.rpc_method_policy_digest,method.nested_call_set_digest,method.selector,
          binding.chain_id,binding.network_id,binding.genesis_digest,binding.contract_address,binding.code_digest,
          binding.proxy_address,binding.implementation_address,binding.implementation_code_digest,abi.abi_digest
          from control.contract_method_policy method join control.contract_runtime_binding binding
            on binding.runtime_binding_id=method.runtime_binding_id and binding.participant_id=method.participant_id
            and binding.privacy_domain_id=method.privacy_domain_id and binding.abi_artifact_id=method.abi_artifact_id
          join control.abi_artifact abi on abi.abi_artifact_id=binding.abi_artifact_id
            and abi.participant_id=binding.participant_id and abi.privacy_domain_id=binding.privacy_domain_id
          where method.contract_method_policy_id=$1::text::uuid and binding.runtime_binding_id=$2::text::uuid
            and method.participant_id=$3::text::uuid and method.privacy_domain_id=$4::text::uuid
            and method.state in ('PREPARED','ACTIVE') and (not $5 or method.state='ACTIVE') and binding.state='BOUND'
          for share of method,binding,abi"#)
            .bind(id).bind(binding).bind(&definition.participant_id).bind(&definition.privacy_domain_id)
            .bind(matches!(state, MethodState::Active))
            .fetch_optional(&mut **tx).await.map_err(|_| RuntimeError::RuntimeUnavailable)?
            .ok_or(RuntimeError::GenerationMismatch)?;
        check_method_source(&row, policy)?;
        methods.push(MethodSourceVersion {
            method_id: id.into(),
            runtime_binding_id: binding.into(),
            method_revision: number(&row, "method_revision")?,
            binding_revision: number(&row, "binding_revision")?,
        });
        if definition
            .interactions
            .iter()
            .any(|rule| rule.contract_method_policy_id == id)
        {
            keys.insert((binding.to_owned(), policy.selector()), methods.len() - 1);
        }
    }
    load_grants(tx, definition, methods, keys).await
}

/// Currentness checks for an already approved immutable source manifest do not
/// reopen the live target's exclusively owned journal. Registration revisions
/// and the complete grant set are still resolved at the same database owner.
pub(in crate::cigl_publication) async fn load_retained(
    tx: &mut Transaction<'_, Postgres>,
    definition: &MethodProfileDefinition,
    methods: Vec<MethodSourceVersion>,
) -> RuntimeResult<Snapshot> {
    let required: BTreeSet<_> = definition
        .interactions
        .iter()
        .map(|rule| rule.contract_method_policy_id.as_str())
        .chain(std::iter::once(
            definition.root_contract_method_policy_id.as_str(),
        ))
        .collect();
    if methods.len() != required.len()
        || methods
            .iter()
            .map(|method| method.method_id.as_str())
            .collect::<BTreeSet<_>>()
            != required
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    let rows = sqlx::query(r#"select method.contract_method_policy_id::text method_id,
            binding.runtime_binding_id::text binding_id,method.selector,
            method.revision::text method_revision,binding.revision::text binding_revision
          from control.contract_method_policy method join control.contract_runtime_binding binding
            on binding.runtime_binding_id=method.runtime_binding_id and binding.participant_id=method.participant_id
            and binding.privacy_domain_id=method.privacy_domain_id and binding.abi_artifact_id=method.abi_artifact_id
          where method.contract_method_policy_id::text=any($1::text[])
            and method.participant_id=$2::text::uuid and method.privacy_domain_id=$3::text::uuid
            and method.state='ACTIVE' and binding.state='BOUND'
          for share of method,binding"#)
            .bind(required.into_iter().collect::<Vec<_>>())
            .bind(&definition.participant_id).bind(&definition.privacy_domain_id)
            .fetch_all(&mut **tx).await.map_err(|_| RuntimeError::RuntimeUnavailable)?;
    if rows.len() != methods.len() {
        return Err(RuntimeError::GenerationMismatch);
    }
    let by_id: BTreeMap<_, _> = methods
        .iter()
        .enumerate()
        .map(|(index, method)| (method.method_id.as_str(), index))
        .collect();
    let mut keys = BTreeMap::new();
    for row in rows {
        let id = text(&row, "method_id")?;
        let index = *by_id
            .get(id.as_str())
            .ok_or(RuntimeError::GenerationMismatch)?;
        let method = &methods[index];
        if text(&row, "binding_id")? != method.runtime_binding_id
            || number(&row, "method_revision")? != method.method_revision
            || number(&row, "binding_revision")? != method.binding_revision
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        if definition
            .interactions
            .iter()
            .any(|rule| rule.contract_method_policy_id == method.method_id)
        {
            keys.insert(
                (
                    method.runtime_binding_id.clone(),
                    bytes(&text(&row, "selector")?)?,
                ),
                index,
            );
        }
    }
    load_grants(tx, definition, methods, keys).await
}

async fn load_grants(
    tx: &mut Transaction<'_, Postgres>,
    definition: &MethodProfileDefinition,
    methods: Vec<MethodSourceVersion>,
    keys: BTreeMap<(String, [u8; 4]), usize>,
) -> RuntimeResult<Snapshot> {
    let mut grants = Vec::new();
    let mut versions = Vec::new();
    for ((binding, selector), method_index) in keys {
        let source = &methods[method_index];
        let selector_hex = format!(
            "0x{}",
            selector
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let rows = sqlx::query(r#"select grant_id::text,definition,status,revision::text,grant_digest,
          binding_revision::text,method_revision::text,
          openpc.cigl_subject_current(participant_id,definition->'subject') subject_current
          from control.cigl_method_access_grants where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid
          and runtime_binding_id=$3::text::uuid and selector=$4 order by grant_id limit 4097"#)
            .bind(&definition.participant_id).bind(&definition.privacy_domain_id).bind(&binding).bind(selector_hex)
            .fetch_all(&mut **tx).await.map_err(|_| RuntimeError::RuntimeUnavailable)?;
        for row in rows {
            if grants.len() >= 4096 {
                return Err(RuntimeError::BudgetExhausted);
            }
            let mut value: Value = row
                .try_get("definition")
                .map_err(|_| RuntimeError::InvalidInput)?;
            value["grantId"] = Value::String(text(&row, "grant_id")?);
            value["runtimeBindingId"] = Value::String(binding.clone());
            value["selector"] = serde_json::json!(selector);
            value["status"] = Value::String(text(&row, "status")?);
            let grant: InteractionGrant =
                serde_json::from_value(value).map_err(|_| RuntimeError::InvalidInput)?;
            let grant_digest = digest(&text(&row, "grant_digest")?)?;
            if grant.digest()? != grant_digest {
                return Err(RuntimeError::InvalidDigest);
            }
            if grant.status == GrantStatus::Active
                && (!row
                    .try_get::<bool, _>("subject_current")
                    .map_err(|_| RuntimeError::InvalidInput)?
                    || source.method_revision != number(&row, "method_revision")?
                    || source.binding_revision != number(&row, "binding_revision")?)
            {
                return Err(RuntimeError::GenerationMismatch);
            }
            versions.push(GrantSourceVersion {
                grant_id: grant.grant_id.clone(),
                revision: number(&row, "revision")?,
                digest: grant_digest,
            });
            grants.push(grant);
        }
    }
    Ok(Snapshot {
        methods,
        grants,
        versions,
    })
}

fn check_method_source(row: &PgRow, policy: &ValidatedInvocationPolicy) -> RuntimeResult<()> {
    let p = policy.artifact();
    let optional = |key| {
        row.try_get::<Option<String>, _>(key)
            .map_err(|_| RuntimeError::InvalidInput)
    };
    let version = format!(
        "{}:{}:{}",
        text(row, "method_revision")?,
        digest(&text(row, "rpc_method_policy_digest")?)?.as_str(),
        digest(&text(row, "nested_call_set_digest")?)?.as_str()
    );
    if p.policy_version != version
        || p.selector != bytes(&text(row, "selector")?)?
        || p.chain_id != text(row, "chain_id")?
        || p.network_id != text(row, "network_id")?
        || p.genesis_digest != digest(&text(row, "genesis_digest")?)?
        || p.contract_address != bytes(&text(row, "contract_address")?)?
        || p.code_digest != digest(&text(row, "code_digest")?)?
        || p.abi_digest != digest(&text(row, "abi_digest")?)?
        || p.proxy_address
            != optional("proxy_address")?
                .as_deref()
                .map(bytes)
                .transpose()?
        || p.implementation_address
            != optional("implementation_address")?
                .as_deref()
                .map(bytes)
                .transpose()?
        || p.implementation_code_digest
            != optional("implementation_code_digest")?
                .as_deref()
                .map(digest)
                .transpose()?
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    Ok(())
}
