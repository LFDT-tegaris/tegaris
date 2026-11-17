import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';
import { assertAbiContainsFunction, canonicalAbiBytes } from '../contract-assets.js';
import { sha256 } from '../digest.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import { ConfigurationRepositoryError, type MutationContext } from '../persistence/types.js';
import {
  deploymentDefinitionDigests,
  deploymentPolicyDefinitionSchema,
  deploymentPolicyResponseSchema,
  type DeploymentPolicyDefinition,
} from './policy-contract.js';

const id = (urn: string) => urn.slice(urn.lastIndexOf(':') + 1);

export class DeploymentPolicyRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(pool: Pool, verifier?: IdentityRuntimeVerifier) {
    this.mutations = new AtomicConfigurationMutation(pool, verifier);
    this.reads = new ScopedConfigurationRead(pool);
  }

  create(context: MutationContext, input: DeploymentPolicyDefinition) {
    const definition = deploymentPolicyDefinitionSchema.parse(input);
    const digests = deploymentDefinitionDigests(definition);
    return this.mutations.execute(context, async (client, deploymentPolicyId, operationId) => {
      const abi = await client.query<{ abiDigest: string; canonicalAbi: unknown[] }>(
        `select abi_digest as "abiDigest",canonical_abi as "canonicalAbi" from control.abi_artifact
         where abi_artifact_id=$1 and participant_id=$2 and privacy_domain_id=$3 for share`,
        [
          id(definition.abiArtifactId),
          context.authorization.participantId,
          context.authorization.privacyDomainId,
        ],
      );
      const artifact = abi.rows[0];
      if (
        abi.rowCount !== 1 ||
        !artifact ||
        sha256(canonicalAbiBytes(artifact.canonicalAbi)) !== artifact.abiDigest
      )
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      let factoryRuntimeBindingId: string | null = null;
      if (definition.route.mechanism !== 'TRANSACTION_CREATE') {
        factoryRuntimeBindingId = id(definition.route.runtimeBindingId);
        const factory = await client.query<{ canonicalAbi: unknown[] }>(
          `select artifact.canonical_abi as "canonicalAbi" from control.contract_runtime_binding binding
           join control.abi_artifact artifact on artifact.participant_id=binding.participant_id
            and artifact.privacy_domain_id=binding.privacy_domain_id and artifact.abi_artifact_id=binding.abi_artifact_id
           where binding.runtime_binding_id=$1 and binding.participant_id=$2 and binding.privacy_domain_id=$3
            and binding.state='BOUND' and binding.network_id=$4 and binding.genesis_digest=$5
            and binding.chain_id=$6
            and binding.proxy_address is null and binding.implementation_address is null
            and binding.implementation_code_digest is null for share of binding,artifact`,
          [
            factoryRuntimeBindingId,
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            definition.networkId,
            definition.genesisDigest,
            definition.chainId,
          ],
        );
        if (factory.rowCount !== 1 || !factory.rows[0])
          throw new ConfigurationRepositoryError('PC-FACT-4001');
        try {
          assertAbiContainsFunction(
            factory.rows[0].canonicalAbi,
            definition.route.canonicalSignature,
          );
        } catch {
          throw new ConfigurationRepositoryError('PC-FACT-4001');
        }
      }
      const inserted = await client.query(
        `insert into control.deployment_policy(deployment_policy_id,participant_id,privacy_domain_id,
         definition,definition_digest,artifact_digest,init_code_hash,abi_artifact_id,abi_digest,
         factory_runtime_binding_id,publication_operation_id,publication_authority_digest)
         select $1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12 where $13::timestamptz>clock_timestamp()
         on conflict do nothing`,
        [
          deploymentPolicyId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          JSON.stringify(definition),
          digests.definitionDigest,
          digests.artifactDigest,
          digests.initCodeHash,
          id(definition.abiArtifactId),
          artifact.abiDigest,
          factoryRuntimeBindingId,
          operationId,
          `sha256:${context.authorization.evidenceDigest.toString('hex')}`,
          definition.expiresAt,
        ],
      );
      if (inserted.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      return {
        result: undefined,
        revision: '1',
        outboxEventType: 'openpc.deployment.policy.staged.v1',
      };
    });
  }

  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const result = await client.query(
        `select deployment_policy_id as "deploymentPolicyId",definition,
        definition_digest as "definitionDigest",artifact_digest as "artifactDigest",init_code_hash as "initCodeHash",
        abi_digest as "abiDigest",publication_operation_id as "publicationOperationId",
        publication_authority_digest as "publicationAuthorityDigest",created_at as "createdAt"
        from control.deployment_policy where deployment_policy_id=$1 and participant_id=$2 and privacy_domain_id=$3`,
        [
          context.resourceId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
        ],
      );
      const row = result.rows[0];
      if (result.rowCount !== 1 || !row) throw new ConfigurationRepositoryError('PC-AUTH-0005');
      const definition = deploymentPolicyDefinitionSchema.parse(row.definition);
      const digests = deploymentDefinitionDigests(definition);
      if (
        digests.definitionDigest !== row.definitionDigest ||
        digests.artifactDigest !== row.artifactDigest ||
        digests.initCodeHash !== row.initCodeHash
      )
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      return deploymentPolicyResponseSchema.parse({
        ...row,
        deploymentPolicyId: `urn:openpc:resource:${row.deploymentPolicyId}`,
        createdAt: new Date(row.createdAt as string).toISOString(),
        revision: '1',
        state: 'STAGED',
        runtimePermission: 'REQUIRES_EFFECTIVE_POLICY_AND_LIVE_AUTHORITY',
      });
    });
  }
}
