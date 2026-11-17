import type { PoolClient } from 'pg';
import {
  canonicalAbiBytes,
  eventSignature,
} from '../../../control-api/src/configuration/contract-assets.js';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import { ContractError } from '../domain/errors.js';
import type { PolicySemanticDocument } from '../domain/policy-semantics.js';
import type { AdmittedVisibilityResource } from '../domain/visibility-policy.js';
import { pcCbor1 } from '../domain/digest.js';
import { loadRegisteredExplorerProfile } from '../../../control-api/src/configuration/privacy-explorer/profile-repository.js';

/** Resolve exact configured resource versions under the caller's scoped transaction.
 * State outputs are derived from admitted method ABI by the Rust compiler. */
export async function loadPolicyVisibilityInputs(
  client: PoolClient,
  document: PolicySemanticDocument,
): Promise<readonly AdmittedVisibilityResource[]> {
  const result: AdmittedVisibilityResource[] = [];
  const seen = new Set<string>();
  for (const policy of document.visibilityPolicies ?? []) {
    const selector = policy.selector;
    if (selector.kind === 'STATE_READ') continue;
    const identity = pcCbor1(selector).digest.toString('hex');
    if (seen.has(identity)) continue;
    seen.add(identity);
    if (selector.kind === 'DISCLOSURE') {
      const profile = await loadRegisteredExplorerProfile(
        client,
        document.participantId,
        document.privacyDomainId,
        selector.profileId,
      );
      if (
        profile.digest !== selector.profileDigest ||
        !profile.operationVersions.some((operation) =>
          operation.acceptedDataClassIds.includes(selector.dataClassId),
        )
      )
        throw new ContractError('PC-POLICY-2003', 'disclosure profile reference unavailable');
      result.push({
        participantId: document.participantId,
        privacyDomainId: document.privacyDomainId,
        selector,
        availableFields: profile.allowedFieldIds,
      });
      continue;
    }
    const selected = await client.query<{
      revision: string;
      abiDigest: string;
      canonicalAbi: readonly unknown[];
      contractBinding: NonNullable<AdmittedVisibilityResource['contractBinding']>;
    }>(
      `select binding.revision::text,artifact.abi_digest as "abiDigest",artifact.canonical_abi as "canonicalAbi",
          jsonb_build_object('chainId',binding.chain_id,'networkId',binding.network_id,
            'genesisDigest',binding.genesis_digest,'contractAddress',binding.contract_address,
            'codeDigest',binding.code_digest,'abiDigest',artifact.abi_digest,
            'canonicalAbi',artifact.canonical_abi) as "contractBinding"
         from control.contract_runtime_binding binding
         join control.abi_artifact artifact on artifact.participant_id=binding.participant_id
          and artifact.privacy_domain_id=binding.privacy_domain_id and artifact.abi_artifact_id=binding.abi_artifact_id
        where binding.participant_id=$1 and binding.privacy_domain_id=$2 and binding.runtime_binding_id=$3
          and binding.state='BOUND' for share of binding,artifact`,
      [document.participantId, document.privacyDomainId, selector.runtimeBindingId],
    );
    const row = selected.rows[0];
    if (
      selected.rowCount !== 1 ||
      row?.revision !== selector.bindingRevision ||
      sha256(canonicalAbiBytes(row.canonicalAbi)) !== row.abiDigest
    )
      throw new ContractError('PC-POLICY-2003', 'visibility binding unavailable');
    let availableFields: string[] = [];
    if (selector.kind === 'EVENT') {
      const events = row.canonicalAbi.filter(
        (item) => eventSignature(item) === selector.eventSignature,
      );
      if (selector.abiDigest !== row.abiDigest || events.length !== 1)
        throw new ContractError('PC-POLICY-2003', 'visibility event ABI unavailable');
      const event = events[0] as { readonly inputs: readonly unknown[] };
      availableFields = event.inputs.map((_, index) => `inputs[${index}]`);
    } else if (selector.kind === 'TRANSACTION') {
      availableFields = [
        'blockHash',
        'blockNumber',
        'chainId',
        'from',
        'gas',
        'gasPrice',
        'hash',
        'input',
        'maxFeePerGas',
        'maxPriorityFeePerGas',
        'nonce',
        'to',
        'transactionIndex',
        'type',
        'value',
        'r',
        's',
        'v',
        'yParity',
        'accessList',
      ];
    }
    result.push({
      participantId: document.participantId,
      privacyDomainId: document.privacyDomainId,
      selector,
      availableFields,
      contractBinding: row.contractBinding,
    });
  }
  return result;
}
