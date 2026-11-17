import type { PoolClient } from 'pg';
import { ConfigurationRepositoryError } from '../../configuration/persistence/types.js';
import type { ReadContext } from '../../configuration/persistence/scoped-read.js';
import { candidateArchiveManifest, CANDIDATE_MANIFEST_FORMAT } from './contract.js';
import { retirementSelection } from '../store-retirement-wire.js';

/** Selection comes from immutable, natively verified custody identity. It is
 * historical evidence, never a claim about current native source eligibility. */
export function candidateRetirementSelection(value: unknown) {
  const { identity } = candidateArchiveManifest.parse(value);
  return retirementSelection.parse({
    class: 'CANDIDATE_PROJECTION',
    source: {
      profile_id: identity.sourceProfileId,
      generation_id: identity.generationId,
      partition_id: identity.partitionId,
      identity_digest: identity.publicationDigest.slice(7),
    },
    rows: [
      {
        candidate_id: identity.candidateId,
        candidate_feed_sequence: BigInt(identity.candidateFeedSequence),
        payload_digest: identity.payloadDigest.slice(7),
        payload_bytes: BigInt(identity.payloadBytes),
        checkpoint_digest: identity.checkpointDigest.slice(7),
      },
    ],
  });
}

export async function readCandidateRetirementSelection(client: PoolClient, context: ReadContext) {
  const selected = await client.query<{ manifest: unknown }>(
    `select a.manifest from control.evidence_catalogue c
     join control.evidence_candidate_archive a using(participant_id,privacy_domain_id,stream_id,record_id)
     where c.participant_id=$1 and c.privacy_domain_id=$2 and c.evidence_id=$3
      and c.source_format=$4 and c.evidence_class='EFFECT' and c.receipt_digest=a.manifest_digest`,
    [
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      context.resourceId,
      CANDIDATE_MANIFEST_FORMAT,
    ],
  );
  if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
  const manifest = candidateArchiveManifest.parse(selected.rows[0]!.manifest);
  if (
    manifest.identity.participantId !== context.authorization.participantId ||
    manifest.identity.privacyDomainId !== context.authorization.privacyDomainId
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  return candidateRetirementSelection(manifest);
}
