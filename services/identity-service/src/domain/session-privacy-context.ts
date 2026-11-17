import type { Pool } from 'pg';
import { runScopedTransaction } from '../db/scoped-transaction.js';
import { IdentityKernel, IdentityKernelError } from './identity-kernel.js';
import { localOperationId } from './local-operation-id.js';
import { currentPlatformEnvelopeSql } from '../db/current-platform-envelope.js';

/** Resolve context from the authenticated session and its own Participant, never a deployment's seed tenant. */
export async function sessionPrivacyContext(
  pool: Pool,
  kernel: IdentityKernel,
  sessionToken: string,
): Promise<string> {
  const session = await kernel.sessionSnapshot(sessionToken);
  if (session.contextMode === 'PARTICIPANT' && session.privacyDomainId)
    return session.privacyDomainId;
  return runScopedTransaction(
    pool,
    { participantId: session.participantId, actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1' },
    localOperationId,
    async (client) => {
      const row = (
        await client.query<{ privacy_domain_id: string }>(
          `select privacy.privacy_domain_id from control.participant participant
      join control.privacy_domain privacy on privacy.participant_id=participant.participant_id and privacy.privacy_domain_id=participant.root_privacy_domain_id
      where participant.participant_id=$1 and participant.state='ACTIVE' and privacy.state='ACTIVE'`,
          [session.participantId],
        )
      ).rows[0];
      if (!row) throw new IdentityKernelError('PC-AUTH-0002');
      return row.privacy_domain_id;
    },
  );
}

/** Discovery hints from current direct authority, matching the supported context
 * entry owner. Selection still revalidates the session, grants and authenticator.
 * Domain existence alone does not make a context visible. */
export async function availableSessionPrivacyContexts(
  pool: Pool,
  kernel: IdentityKernel,
  sessionToken: string,
): Promise<readonly { participantId: string; privacyDomainId: string }[]> {
  const session = await kernel.sessionSnapshot(sessionToken);
  return runScopedTransaction(
    pool,
    { participantId: session.participantId, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
    localOperationId,
    async (client) => {
      const result = await client.query<{ participantId: string; privacyDomainId: string }>(
        `select distinct privacy.participant_id::text "participantId",privacy.privacy_domain_id::text "privacyDomainId"
         from control.privacy_domain privacy
         join control.assignment a on a.participant_id=privacy.participant_id and a.principal_id=$2::text::uuid
          and a.state='ACTIVE' and a.valid_during @> clock_timestamp()
          and privacy.privacy_domain_id::text=any(a.privacy_domain_ids)
          and 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'=any(a.action_intent_ids)
          and ($2::text=any(a.resource_ids) or '*'=any(a.resource_ids))
          and openpc.assignment_role_permits(a.participant_id,a.role_id,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
          and openpc.assignment_group_permits(a.participant_id,a.authority_group_id,a.principal_id,a.valid_during)
         join control.authority_envelope e on e.participant_id=a.participant_id
          and e.authority_envelope_id=a.authority_envelope_id and e.state='ACTIVE'
          and ${currentPlatformEnvelopeSql('e')}
          and e.valid_from<=clock_timestamp() and (e.valid_until is null or e.valid_until>clock_timestamp())
          and privacy.privacy_domain_id::text=any(e.privacy_domain_ids)
          and 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'=any(e.action_intent_ids)
          and ($2::text=any(e.resource_ids) or '*'=any(e.resource_ids))
         where privacy.participant_id=$1 and privacy.state='ACTIVE'
         order by "privacyDomainId"`,
        [session.participantId, session.principalId],
      );
      return result.rows;
    },
  );
}
