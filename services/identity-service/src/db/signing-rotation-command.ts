import type { PoolClient } from 'pg';
import { SigningRotationError, type SigningRotationState } from '../domain/signing-rotation.js';
import type { SigningRotationPartition } from './signing-rotation-store.js';

export interface RotationCommand {
  operationId: string;
  rotationId: string;
  principalId: string;
  idempotencyKey: string;
  actionIntentId: string;
  actionIntentDigest: Buffer;
  inputDigest: Buffer;
  authorizationSnapshot: Buffer;
  authorizationSnapshotDigest: Buffer;
  authorizationGenerationId: string | null;
  approvalRequestId: string;
  approvalCandidateDigest: Buffer;
  fromRevision: string;
  toState: SigningRotationState;
  state: 'ACCEPTED' | 'SUCCEEDED' | 'FAILED' | 'WRITE_AMBIGUITY';
  resultRevision: string | null;
  originalOperationId: string | null;
  recoveryAttemptId: string | null;
  priorObservationDigest: Buffer | null;
  recoveryObservationDigest: Buffer | null;
  resultKind:
    | 'NO_NEW_OBSERVATION'
    | 'NEW_OBSERVATION'
    | 'LOOKUP_UNAVAILABLE'
    | 'SIGNATURE_UNAVAILABLE'
    | 'NO_EFFECT_RETRYABLE'
    | 'AUTHORITY_CHANGED_BEFORE_DISPATCH'
    | 'PROVIDER_REJECTED'
    | 'AUTHORITY_RENEWED'
    | 'FORWARD_RECOVERY'
    | null;
  createdAt: Date;
  updatedAt: Date;
}
export const rotationCommandColumns = `operation_id::text as "operationId",rotation_id::text as "rotationId",principal_id::text as "principalId",
  idempotency_key as "idempotencyKey",action_intent_id as "actionIntentId",action_intent_digest as "actionIntentDigest",input_digest as "inputDigest",
  authorization_snapshot as "authorizationSnapshot",authorization_snapshot_digest as "authorizationSnapshotDigest",
  authorization_generation_id::text as "authorizationGenerationId",approval_request_id::text as "approvalRequestId",approval_candidate_digest as "approvalCandidateDigest",
  from_revision::text as "fromRevision",to_state as "toState",state,result_revision::text as "resultRevision",original_operation_id::text as "originalOperationId",recovery_attempt_id::text as "recoveryAttemptId",prior_observation_digest as "priorObservationDigest",recovery_observation_digest as "recoveryObservationDigest",result_kind as "resultKind",created_at as "createdAt",updated_at as "updatedAt"`;
export function rotationOperationView(row: RotationCommand) {
  const timestamp = (value: Date) => value.toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z');
  return {
    operationId: row.operationId,
    resourceRef: `urn:openpc:resource:${row.rotationId}`,
    actionIntentId: row.actionIntentId,
    intentDigest: `sha256:${row.actionIntentDigest.toString('hex')}`,
    idempotencyKey: row.idempotencyKey,
    state: row.state,
    truthState:
      row.state === 'SUCCEEDED'
        ? 'SUCCESS'
        : row.state === 'FAILED'
          ? 'FAILED'
          : row.state === 'WRITE_AMBIGUITY'
            ? 'WRITE_AMBIGUITY'
            : 'UNKNOWN',
    revision: row.resultRevision ?? row.fromRevision,
    ...(row.resultKind === null
      ? {}
      : {
          signingResult: {
            kind: row.resultKind,
            retryable: [
              'LOOKUP_UNAVAILABLE',
              'SIGNATURE_UNAVAILABLE',
              'NO_EFFECT_RETRYABLE',
            ].includes(row.resultKind),
            ...(row.resultKind === 'LOOKUP_UNAVAILABLE' ||
            row.resultKind === 'SIGNATURE_UNAVAILABLE'
              ? { code: 'PC-INTEGRATION-5001' }
              : {}),
            ...(row.originalOperationId === null
              ? {}
              : { originalOperationId: row.originalOperationId, attemptId: row.recoveryAttemptId }),
            ...(row.recoveryObservationDigest === null
              ? {}
              : { observationDigest: 'sha256:' + row.recoveryObservationDigest.toString('hex') }),
          },
        }),
    createdAt: timestamp(row.createdAt),
    updatedAt: timestamp(row.updatedAt),
  };
}
export async function getRotationCommand(
  client: PoolClient,
  scope: SigningRotationPartition,
  operationId: string,
): Promise<RotationCommand> {
  const selected = await client.query<RotationCommand>(
    `select ${rotationCommandColumns} from control.signing_rotation_command
    where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
    [scope.participantId, scope.privacyDomainId, operationId],
  );
  if (selected.rowCount !== 1) throw new SigningRotationError('NOT_FOUND');
  return selected.rows[0]!;
}
