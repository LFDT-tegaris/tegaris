import type { PoolClient } from 'pg';
import { materializePolicySimulation } from '../../../module-registry/src/db/policy-simulation-input.js';
import {
  PolicyFactReader,
  type HeldPolicyFacts,
} from '../../../module-registry/src/domain/policy-facts.js';
import {
  validatePolicySemantics,
  type PolicySemanticDocument,
} from '../../../module-registry/src/domain/policy-semantics.js';
import type { AuthorizedPolicyActor } from '../../../module-registry/src/policy-http.js';
import type { ExplorerProjectionRequestV1 } from '../contracts/privacy-explorer-adapter.js';
import { sha256CanonicalJson } from './canonical.js';

type Generation = {
  generation_digest: Buffer;
  policy_version_id: string;
  semantic_digest: Buffer;
  dependency_closure_digest: Buffer;
  fact_generation_digest: Buffer;
  semantic_cbor: Buffer;
};
type DisclosureGeneration = Readonly<{
  row: Generation;
  document: PolicySemanticDocument;
  policyIds: readonly string[];
}>;
const unavailable = () => new Error('Privacy Explorer disclosure authority unavailable');

/** Consume active public policy artifacts, including every matching mode and deny contribution. */
export async function loadDisclosureGenerations(
  client: PoolClient,
  actor: AuthorizedPolicyActor,
  intent: ExplorerProjectionRequestV1,
): Promise<readonly DisclosureGeneration[]> {
  await client.query(`select pg_advisory_xact_lock_shared(hashtextextended($1,0))`, [
    `openpc-policy-generations:${actor.participantId}:${intent.scope.privacyDomainId}`,
  ]);
  const selected = await client.query<Generation>(
    `select generation.generation_digest,version.policy_version_id,version.semantic_digest,
      generation.dependency_closure_digest,generation.fact_generation_digest,artifact.semantic_cbor
     from control.policy_generation generation
     join control.policy_version version on
      (version.participant_id,version.privacy_domain_id,version.policy_version_id)=
      (generation.participant_id,generation.privacy_domain_id,generation.policy_version_id)
     join control.policy_artifact artifact on
      (artifact.participant_id,artifact.privacy_domain_id,artifact.policy_id,artifact.semantic_version,artifact.semantic_digest)=
      (version.participant_id,version.privacy_domain_id,version.policy_id,version.version,version.semantic_digest)
     where generation.participant_id=$1 and generation.privacy_domain_id=$2
      and generation.active=true and generation.state='ACTIVE'
     order by generation.policy_generation_id limit 65 for share of generation`,
    [actor.participantId, intent.scope.privacyDomainId],
  );
  if (selected.rows.length > 64) throw unavailable();
  const generations: DisclosureGeneration[] = [];
  for (const row of selected.rows) {
    const decoded = validatePolicySemantics(Array.from(row.semantic_cbor), 'DECODE_SEMANTICS');
    const document = decoded.document;
    if (
      !decoded.digest.equals(row.semantic_digest) ||
      document.participantId !== actor.participantId ||
      document.privacyDomainId !== intent.scope.privacyDomainId
    )
      throw unavailable();
    const matching = (document.visibilityPolicies ?? []).filter(
      (policy) =>
        policy.selector.kind === 'DISCLOSURE' &&
        `urn:openpc:resource:${policy.selector.profileId}` === intent.resource &&
        policy.selector.profileDigest === intent.exportProfile.digest &&
        policy.selector.dataClassId === intent.dataClassId &&
        policy.subject.kind === 'PRINCIPAL' &&
        policy.subject.principalId === actor.principalId &&
        policy.purpose === intent.purpose,
    );
    const policyIds = [
      ...new Map(matching.map((policy) => [policy.mode, policy.policyId])).values(),
    ];
    if (policyIds.length) generations.push({ row, document, policyIds });
  }
  if (!generations.length) throw unavailable();
  return generations;
}

export const disclosureGenerationIdentity = (generations: readonly DisclosureGeneration[]) => ({
  authorityGeneration: sha256CanonicalJson(
    generations.map(({ row }) => ({
      version: row.policy_version_id,
      generation: row.generation_digest.toString('hex'),
      semantics: row.semantic_digest.toString('hex'),
      dependencies: row.dependency_closure_digest.toString('hex'),
    })),
  ),
  factGeneration: sha256CanonicalJson(
    generations.map(({ row }) => row.fact_generation_digest.toString('hex')),
  ),
});

export async function evaluateDisclosure(
  client: PoolClient,
  actor: AuthorizedPolicyActor,
  intent: ExplorerProjectionRequestV1,
  generations: readonly DisclosureGeneration[],
  facts: Pick<PolicyFactReader, 'read'> = new PolicyFactReader(),
) {
  for (const generation of generations) {
    for (const policyId of generation.policyIds) {
      const result = await materializePolicySimulation(
        client,
        generation.row,
        actor,
        intent.scope.privacyDomainId,
        {
          visibilityPolicyId: policyId,
          purpose: intent.purpose,
          dimensions: ['EXISTENCE', 'PAYLOAD', 'EXPORT'],
          fields: intent.projectionFields,
        },
        facts,
        true,
      );
      if (
        result.evaluation.truthState !== 'SUCCESS' ||
        !result.factDigest.equals(generation.row.fact_generation_digest)
      )
        throw unavailable();
    }
  }
}

/** Hold the existing Fact mutation fences until the caller has enqueued or suppressed delivery. */
export async function withDisclosureFacts<T>(
  generations: readonly DisclosureGeneration[],
  principalId: string,
  work: (
    facts: Pick<PolicyFactReader, 'read'>,
    revalidate: () => Promise<void>,
    assertHeld: () => void,
  ) => Promise<T>,
) {
  const reader = new PolicyFactReader();
  const held = new Map<string, HeldPolicyFacts>();
  const next = async (index: number): Promise<T> => {
    const generation = generations[index];
    if (generation)
      return reader.withLease(generation.document, principalId, async (lease) => {
        held.set(sha256CanonicalJson(generation.document), lease);
        return next(index + 1);
      });
    return work(
      {
        read: async (document, subject) => {
          if (subject !== principalId) throw unavailable();
          const key = sha256CanonicalJson(document);
          const lease = held.get(key);
          if (!lease) throw unavailable();
          await lease.revalidate();
          return lease.snapshots;
        },
      },
      async () => {
        for (const lease of held.values()) await lease.revalidate();
      },
      () => {
        for (const lease of held.values()) lease.assertHeld();
      },
    );
  };
  return next(0);
}
