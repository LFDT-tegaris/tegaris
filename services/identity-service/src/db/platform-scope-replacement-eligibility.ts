import type { PoolClient } from 'pg';
import {
  platformScopeReplacementPreparation,
  platformScopeReplacementCommit,
} from '../../../participant-service/src/contracts/platform-scope-replacement.js';
import { fenceEnvelopePlatformScope } from './platform-envelope-scope.js';

/** Only a context-mode exception for the two explicit root operations. The
 * caller must first hold its actual current actor/role/grant fences; the shared
 * authorization query still checks the action, resource and selected grant. */
export async function platformScopeReplacementContextEligible(
  client: PoolClient,
  context: {
    catalogOperationId: string;
    actionIntentId: string;
    operationClass: string;
    resourceType: string;
    expectedRevision: string;
    participantId: string;
    privacyDomainId: string;
    resourceId: string;
    candidate: unknown;
    authorityEnvelopeId: string;
  },
): Promise<boolean> {
  const preparation = context.catalogOperationId === 'ID-OP-PLATFORM-SCOPE-PREPARE';
  const commit = context.catalogOperationId === 'ID-OP-PLATFORM-SCOPE-COMMIT';
  if (
    (!preparation && !commit) ||
    context.actionIntentId !== 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' ||
    context.operationClass !== 'UPDATE' ||
    context.resourceType !== 'participant' ||
    context.expectedRevision !== (preparation ? '0' : '1')
  )
    return false;
  const parsed = (
    preparation ? platformScopeReplacementPreparation : platformScopeReplacementCommit
  ).safeParse(context.candidate);
  if (!parsed.success || parsed.data.replacementId !== context.resourceId) return false;
  const root = await fenceEnvelopePlatformScope(
    client,
    context.participantId,
    context.authorityEnvelopeId,
  );
  if (
    root.ownerParticipantId !== context.participantId ||
    root.installationPrivacyDomainId !== context.privacyDomainId ||
    root.platformContextId !== parsed.data.platformContextId ||
    root.platformAuthorityEpoch !== parsed.data.predecessorEpoch ||
    root.platformAuthorityDigest !== parsed.data.predecessorDigest
  )
    return false;
  const current = await client.query<{ eligible: boolean }>(
    `select p.state='ACTIVE' and p.row_version=$2 and p.authority_epoch=$3
      and case when $4 then not exists(select 1 from control.platform_scope_replacement r
        where r.platform_context_id=p.platform_context_id and r.state='WITHDRAWING'
          and ($7::jsonb is null or $7::jsonb<>jsonb_build_object('replacementId',r.replacement_id::text,
            'expectedRevision',r.row_version::text,'successorDigest','sha256:'||encode(r.successor_digest,'hex'))))
        and ($7::jsonb is null or exists(select 1 from control.platform_scope_replacement r
          where r.platform_context_id=p.platform_context_id and r.state='WITHDRAWING'
            and r.replacement_id::text=$7::jsonb->>'replacementId'))
      else exists(select 1 from control.platform_scope_replacement r
        where r.platform_context_id=p.platform_context_id and r.replacement_id=$5 and r.state='WITHDRAWING'
          and r.row_version=1 and r.predecessor_epoch=p.authority_epoch and r.expected_root_revision=p.row_version)
      end as eligible from control.platform_context p where p.platform_context_id=$1 and p.owner_participant_id=$6`,
    [
      root.platformContextId,
      parsed.data.expectedRootRevision,
      parsed.data.predecessorEpoch,
      preparation,
      parsed.data.replacementId,
      context.participantId,
      'supersedes' in parsed.data ? (parsed.data.supersedes ?? null) : null,
    ],
  );
  return current.rowCount === 1 && current.rows[0]!.eligible === true;
}
