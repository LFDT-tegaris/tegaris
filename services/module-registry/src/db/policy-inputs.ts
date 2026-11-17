import {
  transactionPolicySchema,
  type TransactionPolicy,
} from '../../../control-api/src/configuration/transaction-policy.js';
import type { PoolClient } from 'pg';

import {
  assertAbiContainsFunction,
  assertArgumentRulesMatchAbi,
  canonicalAbiBytes,
  selectorFor,
} from '../../../control-api/src/configuration/contract-assets.js';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import { pcCbor1 } from '../domain/digest.js';
import { ContractError } from '../domain/errors.js';
import type { PolicySemanticDocument } from '../domain/policy-semantics.js';

export interface AdmittedContractInput {
  readonly assetId: string;
  readonly runtimeBindingId: string;
  readonly transactionPolicy: TransactionPolicy | null;
  readonly policyVersion: string;
  readonly tenantId: string;
  readonly privacyDomainId: string;
  readonly chainId: string;
  readonly networkId: string;
  readonly genesisDigest: string;
  readonly contractAddress: string;
  readonly proxyAddress: string | null;
  readonly implementationAddress: string | null;
  readonly codeDigest: string;
  readonly implementationCodeDigest: string | null;
  readonly abiDigest: string;
  readonly canonicalSignature: string;
  readonly selector: string;
  readonly canonicalAbi: readonly unknown[];
  readonly effect: 'READ' | 'WRITE';
  readonly requiredRoles: readonly string[];
  readonly approvalRequirement: string;
  readonly mfaRequirement: string;
  readonly rpcMethodPolicyDigest: string;
  readonly nestedCallSetDigest: string;
  readonly namedSetCount: number;
  readonly rules: readonly {
    readonly parameterPath: string;
    readonly operandType: string;
    readonly operator: string;
    readonly values: readonly string[];
  }[];
}

/** Resolve exact admitted module/configuration references inside the caller's scoped transaction. */
export async function assertPolicyModuleBindings(
  client: PoolClient,
  document: PolicySemanticDocument,
  dependencyDigest: Buffer,
  requireActive = false,
) {
  if (!pcCbor1(document.moduleBindings).digest.equals(dependencyDigest))
    throw new ContractError('PC-POLICY-2003', 'policy dependency identity rejected');
  // Share the admission owner's scope fence. Module versions are immutable;
  // readers must not acquire UPDATE privileges merely to take row locks.
  await client.query('select pg_advisory_xact_lock_shared(hashtextextended($1,0))', [
    `module-admission:${document.participantId}:${document.privacyDomainId}`,
  ]);
  const bindings = new Map(document.moduleBindings.map((binding) => [binding.moduleId, binding]));
  for (const binding of document.moduleBindings) {
    const result = await client.query<{ manifest: Buffer }>(
      `select version.release_manifest_json as manifest
       from control.module_installation installation
       join control.module_version version using(module_version_id)
       join control.module_configuration_generation configuration using(module_installation_id)
       where installation.participant_id=$1 and installation.privacy_domain_id=$2
        and configuration.participant_id=installation.participant_id
        and configuration.privacy_domain_id=installation.privacy_domain_id
        and version.module_id=$3 and version.semantic_version=$4
        and version.manifest_digest=$5 and configuration.configuration_digest=$6
        and installation.state in ('ADMITTED','INSTALLED_DISABLED','ENABLED')
        and installation.admission_dependency_digest is not null
        and version.release_payload_cbor is not null
        and ($7::boolean=false or (installation.state='ENABLED' and configuration.active=true
          and installation.active_manifest_digest=version.manifest_digest))`,
      [
        document.participantId,
        document.privacyDomainId,
        binding.moduleId,
        binding.semanticVersion,
        Buffer.from(binding.manifestDigest.slice(7), 'hex'),
        Buffer.from(binding.configurationDigest.slice(7), 'hex'),
        requireActive,
      ],
    );
    if (result.rowCount !== 1 || !Buffer.isBuffer(result.rows[0]?.manifest))
      throw new ContractError('PC-POLICY-2003', 'required policy module unavailable');
    const manifest = JSON.parse(result.rows[0]!.manifest.toString('utf8')) as {
      dependencies: { moduleId: string; version: string; manifestDigest: string }[];
    };
    for (const dependency of manifest.dependencies) {
      const bound = bindings.get(dependency.moduleId);
      if (
        bound?.semanticVersion !== dependency.version ||
        bound.manifestDigest !== dependency.manifestDigest
      )
        throw new ContractError('PC-POLICY-2003', 'policy dependency closure incomplete');
    }
  }
}

/** The configuration owner supplies ABI, method and argument meaning; a request supplies only references. */
export async function loadPolicyContractInputs(
  client: PoolClient,
  document: PolicySemanticDocument,
): Promise<readonly AdmittedContractInput[]> {
  const result = await client.query<AdmittedContractInput>(
    `select method.contract_method_policy_id::text as "assetId",binding.runtime_binding_id::text as "runtimeBindingId",
      binding.transaction_policy as "transactionPolicy",method.revision::text as "policyVersion",
      method.participant_id::text as "tenantId",method.privacy_domain_id::text as "privacyDomainId",
      binding.chain_id as "chainId",binding.network_id as "networkId",binding.genesis_digest as "genesisDigest",
      binding.contract_address as "contractAddress",binding.proxy_address as "proxyAddress",
      binding.implementation_address as "implementationAddress",binding.code_digest as "codeDigest",
      binding.implementation_code_digest as "implementationCodeDigest",artifact.abi_digest as "abiDigest",
      method.canonical_signature as "canonicalSignature",method.selector,artifact.canonical_abi as "canonicalAbi",
      method.effect,method.required_roles as "requiredRoles",method.approval_requirement as "approvalRequirement",
      method.mfa_requirement as "mfaRequirement",method.rpc_method_policy_digest as "rpcMethodPolicyDigest",
      method.nested_call_set_digest as "nestedCallSetDigest",
      (select count(*)::integer from control.argument_rule_named_set_binding named
        where named.argument_rule_version_id=method.argument_rule_version_id) as "namedSetCount",
      coalesce((select jsonb_agg(jsonb_build_object('parameterPath',rule.parameter_path,
        'operandType',rule.operand_type,'operator',rule.operator,'values',rule.scalar_values) order by rule.ordinal::integer)
        from control.typed_argument_rule rule where rule.argument_rule_version_id=method.argument_rule_version_id),'[]'::jsonb) rules
     from control.contract_method_policy method
     join control.contract_runtime_binding binding on binding.participant_id=method.participant_id
      and binding.privacy_domain_id=method.privacy_domain_id and binding.runtime_binding_id=method.runtime_binding_id
      and binding.abi_artifact_id=method.abi_artifact_id and binding.state='BOUND'
     join control.abi_artifact artifact on artifact.participant_id=binding.participant_id
      and artifact.privacy_domain_id=binding.privacy_domain_id and artifact.abi_artifact_id=binding.abi_artifact_id
     where method.participant_id=$1 and method.privacy_domain_id=$2
      and method.contract_method_policy_id=any($3::uuid[]) and method.state='ACTIVE'
      and (method.argument_rule_version_id is null or exists (
        select 1 from control.typed_argument_rule_version version where version.argument_rule_version_id=method.argument_rule_version_id
         and version.participant_id=method.participant_id and version.privacy_domain_id=method.privacy_domain_id
         and version.runtime_binding_id=method.runtime_binding_id and version.abi_artifact_id=method.abi_artifact_id
         and version.canonical_signature=method.canonical_signature and version.state='ACTIVE'))
     order by method.contract_method_policy_id for share of method,binding,artifact`,
    [
      document.participantId,
      document.privacyDomainId,
      document.contractPolicies.map((reference) => reference.contractMethodPolicyId),
    ],
  );
  if (result.rowCount !== document.contractPolicies.length)
    throw new ContractError('PC-POLICY-2003', 'policy contract references unavailable');
  for (const row of result.rows) {
    const reference = document.contractPolicies.find(
      (reference) => reference.contractMethodPolicyId === row.assetId,
    );
    if (
      reference?.revision !== row.policyVersion ||
      row.namedSetCount !== 0 ||
      sha256(canonicalAbiBytes(row.canonicalAbi)) !== row.abiDigest ||
      selectorFor(row.canonicalSignature) !== row.selector
    )
      throw new ContractError('PC-POLICY-2003', 'policy contract binding rejected');
    try {
      if (row.transactionPolicy !== null) transactionPolicySchema.parse(row.transactionPolicy);
      assertAbiContainsFunction(row.canonicalAbi, row.canonicalSignature);
      assertArgumentRulesMatchAbi(row.canonicalAbi, row.canonicalSignature, row.rules);
    } catch {
      throw new ContractError('PC-POLICY-2003', 'policy ABI semantics rejected');
    }
  }
  return result.rows;
}
