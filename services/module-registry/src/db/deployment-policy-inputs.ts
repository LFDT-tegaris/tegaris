import type { PoolClient } from 'pg';
import {
  deploymentDefinitionDigests,
  deploymentPolicyDefinitionSchema,
  type DeploymentPolicyDefinition,
} from '../../../control-api/src/configuration/deployment/policy-contract.js';
import { canonicalAbiBytes } from '../../../control-api/src/configuration/contract-assets.js';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import { ContractError } from '../domain/errors.js';
import type { PolicySemanticDocument } from '../domain/policy-semantics.js';

export interface AdmittedDeploymentInput {
  readonly deploymentPolicyId: string;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly definition: DeploymentPolicyDefinition;
  readonly definitionDigest: string;
  readonly artifactDigest: string;
  readonly initCodeHash: string;
  readonly abiDigest: string;
  readonly publicationOperationId: string;
  readonly publicationAuthorityDigest: string;
  readonly factoryBinding: {
    readonly runtimeBindingId: string;
    readonly chainId: string;
    readonly networkId: string;
    readonly genesisDigest: string;
    readonly contractAddress: string;
    readonly codeDigest: string;
    readonly abiDigest: string;
    readonly canonicalAbi: readonly unknown[];
  } | null;
}

/** Resolve published inputs and current factory identity inside the caller's
 * scoped transaction. Public authoring supplies immutable references only.
 */
export async function loadPolicyDeploymentInputs(
  client: PoolClient,
  document: PolicySemanticDocument,
): Promise<readonly AdmittedDeploymentInput[]> {
  const references = document.deploymentPolicies ?? [];
  if (references.length === 0) return [];
  const result = await client.query<AdmittedDeploymentInput & { canonicalAbi: readonly unknown[] }>(
    `select policy.deployment_policy_id::text as "deploymentPolicyId",
      policy.participant_id::text as "participantId",policy.privacy_domain_id::text as "privacyDomainId",
      policy.definition,policy.definition_digest as "definitionDigest",policy.artifact_digest as "artifactDigest",
      policy.init_code_hash as "initCodeHash",policy.abi_digest as "abiDigest",abi.canonical_abi as "canonicalAbi",
      policy.publication_operation_id::text as "publicationOperationId",policy.publication_authority_digest as "publicationAuthorityDigest",
      (select jsonb_build_object('runtimeBindingId',factory.runtime_binding_id::text,'chainId',factory.chain_id,
        'networkId',factory.network_id,'genesisDigest',factory.genesis_digest,'contractAddress',factory.contract_address,
        'codeDigest',factory.code_digest,'abiDigest',factory_abi.abi_digest,'canonicalAbi',factory_abi.canonical_abi)
       from control.contract_runtime_binding factory join control.abi_artifact factory_abi
        on factory_abi.participant_id=factory.participant_id and factory_abi.privacy_domain_id=factory.privacy_domain_id
        and factory_abi.abi_artifact_id=factory.abi_artifact_id
       where factory.participant_id=policy.participant_id and factory.privacy_domain_id=policy.privacy_domain_id
        and factory.runtime_binding_id=policy.factory_runtime_binding_id and factory.state='BOUND'
        and factory.chain_id=policy.definition->>'chainId' and factory.network_id=policy.definition->>'networkId'
        and factory.genesis_digest=policy.definition->>'genesisDigest'
        and factory.proxy_address is null and factory.implementation_address is null
        and factory.implementation_code_digest is null for share of factory,factory_abi) as "factoryBinding"
     from control.deployment_policy policy join control.abi_artifact abi
      on abi.participant_id=policy.participant_id and abi.privacy_domain_id=policy.privacy_domain_id
      and abi.abi_artifact_id=policy.abi_artifact_id and abi.abi_digest=policy.abi_digest
     where policy.participant_id=$1 and policy.privacy_domain_id=$2
      and policy.deployment_policy_id=any($3::uuid[]) and (policy.definition->>'expiresAt')::timestamptz>clock_timestamp()
     order by policy.deployment_policy_id for share of policy,abi`,
    [
      document.participantId,
      document.privacyDomainId,
      references.map((reference) => reference.deploymentPolicyId),
    ],
  );
  if (result.rowCount !== references.length)
    throw new ContractError('PC-POLICY-2003', 'deployment publication unavailable');
  return result.rows.map(({ canonicalAbi, ...row }) => {
    try {
      const definition = deploymentPolicyDefinitionSchema.parse(row.definition);
      const digests = deploymentDefinitionDigests(definition);
      if (
        references.find((reference) => reference.deploymentPolicyId === row.deploymentPolicyId)
          ?.definitionDigest !== row.definitionDigest ||
        digests.definitionDigest !== row.definitionDigest ||
        digests.artifactDigest !== row.artifactDigest ||
        digests.initCodeHash !== row.initCodeHash ||
        sha256(canonicalAbiBytes(canonicalAbi)) !== row.abiDigest ||
        (definition.route.mechanism === 'TRANSACTION_CREATE') !== (row.factoryBinding === null)
      )
        throw new Error('deployment identity changed');
      return { ...row, definition };
    } catch {
      throw new ContractError('PC-POLICY-2003', 'deployment publication binding rejected');
    }
  });
}
