import type { PoolClient } from 'pg';
import { SigningRotationError } from '../domain/signing-rotation.js';
import type { RotationCommand } from './signing-rotation-command.js';
import type { SigningRotationPartition } from './signing-rotation-store.js';

/** Called in the signed transition transaction. Deferred owners require the exact receipt and original approval consumption. */
export async function consumeSigningGeneration(
  client: PoolClient,
  scope: SigningRotationPartition,
  command: RotationCommand,
  resultRevision: string,
) {
  if (command.authorizationGenerationId === null) return;
  const changed = await client.query<{ candidateId: string; holdId: string | null }>(
    `update control.signing_authorization_generation set state='CONSUMED',consumed_operation_id=$4,result_revision=$5
     where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3 and state='STAGED'
     returning candidate_id::text as "candidateId",hold_id::text as "holdId"`,
    [
      scope.participantId,
      scope.privacyDomainId,
      command.authorizationGenerationId,
      command.operationId,
      resultRevision,
    ],
  );
  if (changed.rowCount === 0) return;
  if (changed.rowCount !== 1) throw new SigningRotationError('CONFLICT');
  const candidate = await client.query(
    `update control.mutation_candidate set state='CONSUMED',consumed_operation_id=$4,updated_at=clock_timestamp()
     where participant_id=$1 and privacy_domain_id=$2 and mutation_candidate_id=$3 and state='APPROVED'`,
    [scope.participantId, scope.privacyDomainId, changed.rows[0]!.candidateId, command.operationId],
  );
  if (candidate.rowCount !== 1) throw new SigningRotationError('CONFLICT');
  if (changed.rows[0]!.holdId !== null) {
    const hold = await client.query(
      `update control.signing_rotation_authority_hold set state='CLEARED',cleared_by_operation_id=$4
       where participant_id=$1 and privacy_domain_id=$2 and hold_id=$3 and state='ACTIVE'`,
      [scope.participantId, scope.privacyDomainId, changed.rows[0]!.holdId, command.operationId],
    );
    if (hold.rowCount !== 1) throw new SigningRotationError('CONFLICT');
  }
}
