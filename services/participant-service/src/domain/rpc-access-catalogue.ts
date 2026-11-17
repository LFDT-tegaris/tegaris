import type { PoolClient } from 'pg';

import { inEnvelopeParticipantScope } from '../../../identity-service/src/db/identity-envelope-proposal.js';
import type { AuthenticatedActor, ParticipantRecord } from './participant-kernel.js';
import { ParticipantKernelError } from './participant-errors.js';

export interface ParticipantCatalogueQuery {
  readonly search: string;
  readonly state:
    'ALL' | 'PROVISIONING' | 'ACTIVE' | 'SUSPENDED' | 'TRANSFER_PENDING' | 'REVOKED' | 'OFFBOARDED';
  readonly after?: string;
}

export interface ParticipantCatalogueCandidates {
  readonly items: readonly ParticipantRecord[];
  readonly observedAt: string;
}

export interface EnvelopeCatalogueQuery {
  readonly state: 'ALL' | 'DRAFT' | 'SUBMITTED' | 'APPROVED' | 'ACTIVE' | 'SUPERSEDED' | 'REVOKED';
  readonly capabilityId?: 'CALL_RESULT_DISCLOSURE' | 'SIGNED_TRANSACTION_SUBMISSION';
  readonly after?: string;
}

export interface EnvelopeCatalogueCandidates {
  readonly ids: readonly string[];
  readonly observedAt: string;
}

const maximumCatalogueCandidates = 16_384;

/**
 * Platform discovery is deliberately rooted in the caller's durable governance
 * history. It cannot scan arbitrary tenants through a caller supplied selector.
 */
export async function participantCatalogueCandidates(
  client: PoolClient,
  actor: AuthenticatedActor,
  privacyDomainId: string,
  operationId: string,
  query: ParticipantCatalogueQuery,
): Promise<ParticipantCatalogueCandidates> {
  if (!actor.platform) throw new ParticipantKernelError('PC-IDENTITY-1008');
  const discovered = await client.query<{ participant_id: string }>(
    `select participant_id::text from (
       select $1::uuid participant_id
       union
       select resource_id from control.mutation_candidate
        where participant_id=$1 and privacy_domain_id=$2
          and catalog_operation_id='ID-OP-PARTICIPANT-CREATE' and state='CONSUMED'
       union
       select target_participant_id from control.identity_envelope_proposal
        where participant_id=$1 and privacy_domain_id=$2
     ) candidates order by participant_id limit 16385`,
    [actor.participantId, privacyDomainId],
  );
  if (discovered.rows.length > maximumCatalogueCandidates)
    throw new ParticipantKernelError('PC-IDENTITY-1004');
  const owner = {
    participantId: actor.participantId,
    privacyDomainId,
    operationId,
    actionIntentId: 'ACT-PARTICIPANTS_READ_COLLECTION-V1',
  };
  const items: ParticipantRecord[] = [];
  for (const candidate of discovered.rows) {
    if (query.after && candidate.participant_id <= query.after) continue;
    const selected = await inEnvelopeParticipantScope(client, owner, candidate.participant_id, () =>
      client.query<{
        participant_id: string;
        display_name: string;
        state: ParticipantRecord['state'];
        authority_epoch: string;
        row_version: string;
      }>(
        `select participant_id::text,display_name,state,
                authority_epoch::text,row_version::text
           from control.participant where participant_id=$1`,
        [candidate.participant_id],
      ),
    );
    const row = selected.rows[0];
    if (
      !row ||
      (query.state !== 'ALL' && row.state !== query.state) ||
      !row.display_name.toLocaleLowerCase('en-US').includes(query.search.toLocaleLowerCase('en-US'))
    )
      continue;
    items.push({
      participantId: row.participant_id,
      displayName: row.display_name,
      state: row.state,
      authorityEpoch: row.authority_epoch,
      rowVersion: row.row_version,
    });
  }
  return { items, observedAt: new Date().toISOString() };
}

export async function envelopeCatalogueCandidates(
  client: PoolClient,
  actor: AuthenticatedActor,
  targetParticipantId: string,
  privacyDomainId: string,
  query: EnvelopeCatalogueQuery,
): Promise<EnvelopeCatalogueCandidates> {
  const rows = actor.platform
    ? await client.query<{ id: string; observed_at: Date }>(
        `select envelope_id::text id,statement_timestamp() observed_at
           from control.identity_envelope_proposal
          where participant_id=$1 and privacy_domain_id=$2 and target_participant_id=$3
            and ($4::uuid is null or envelope_id>$4::uuid)
          order by envelope_id limit 16385`,
        [actor.participantId, privacyDomainId, targetParticipantId, query.after ?? null],
      )
    : await client.query<{ id: string; observed_at: Date }>(
        `select authority_envelope_id::text id,statement_timestamp() observed_at
           from control.authority_envelope
          where participant_id=$1 and ($2='ALL' or state::text=$2)
            and ($3::text is null or $3=any(runtime_capability_ids))
            and ($4::uuid is null or authority_envelope_id>$4::uuid)
          order by authority_envelope_id limit 16385`,
        [targetParticipantId, query.state, query.capabilityId ?? null, query.after ?? null],
      );
  if (rows.rows.length > maximumCatalogueCandidates)
    throw new ParticipantKernelError('PC-IDENTITY-1004');
  return {
    ids: rows.rows.map((row) => row.id),
    observedAt: rows.rows[0]?.observed_at.toISOString() ?? new Date().toISOString(),
  };
}
