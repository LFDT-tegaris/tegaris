import type { PoolClient } from 'pg';
import { fenceBoundAuthorities, type BoundAuthority } from '../db/authority-fence.js';

import {
  readRuntimeAuthorityGraph,
  sourceDigest,
  type SourceValue,
} from './runtime-authority-graph.js';

/** Recheck the author in the same locked transaction. Calling the HTTP session
 * refresh here would block on this transaction's participant authority fence. */
export async function fenceWorkloadPredictionAuthor(
  client: PoolClient,
  participantId: string,
  author: BoundAuthority,
) {
  await fenceBoundAuthorities(client, participantId, [author]);
  const context = await client.query(
    `select session_id from control.session where participant_id=$1 and session_id=$2
       and context_mode='PARTICIPANT' and privacy_domain_id=$3`,
    [participantId, author.sessionId, author.privacyDomainId],
  );
  if (context.rowCount !== 1) throw new Error('Simulation author context changed');
}

/** Advisory source only. The caller holds the participant authority fence and
 * separately authorizes the human simulation request. No peer or assertion is
 * created here; runtime still authenticates a certificate at the transport. */
export async function readWorkloadPolicyPrediction(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  workloadId: string,
  evaluatedAtMs: number,
) {
  const graph = await readRuntimeAuthorityGraph(client, participantId, privacyDomainId);
  const actors = graph.actors.filter((actor) => actor.workloadId === workloadId);
  if (actors.length !== 1) throw new Error('Workload prediction subject unavailable');
  const actor = actors[0]!;
  const record = (value: SourceValue) => {
    if (value === null || Array.isArray(value) || typeof value !== 'object')
      throw new Error('Workload credential source rejected');
    return value as Readonly<Record<string, SourceValue>>;
  };
  const credentialDeadlines = actor.credentials.map(record).flatMap((credential) => {
    if (
      credential.principal_id !== actor.principalId ||
      credential.audience !== workloadId ||
      typeof credential.valid_from !== 'string' ||
      typeof credential.valid_until !== 'string'
    )
      throw new Error('Workload credential binding rejected');
    const start = Date.parse(credential.valid_from),
      end = Date.parse(credential.valid_until);
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start >= end)
      throw new Error('Workload credential validity rejected');
    return credential.state === 'ACTIVE' && start <= evaluatedAtMs && evaluatedAtMs < end
      ? [end]
      : [];
  });
  const source = {
    participant: graph.participant,
    privacy: graph.privacy,
    principalId: actor.principalId,
    workloadId: actor.workloadId,
    principal: actor.principal,
    credentials: actor.credentials,
    paths: actor.paths,
    envelopes: actor.envelopes,
    revocations: actor.revocations,
  };
  return {
    principalId: actor.principalId,
    input: {
      workloadId,
      principal: actor.principal,
      paths: actor.paths,
      envelopes: actor.envelopes,
      revocations: actor.revocations,
      sourceDigest: sourceDigest(source).toString('hex'),
      evaluatedAtNs: (BigInt(evaluatedAtMs) * 1_000_000n).toString(),
      credentialValidUntilNs: (BigInt(Math.max(0, ...credentialDeadlines)) * 1_000_000n).toString(),
    },
    nextTransitionNs: graph.nextTransitionNs,
  };
}
