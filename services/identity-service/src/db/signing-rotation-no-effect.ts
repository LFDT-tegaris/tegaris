import type { PoolClient } from 'pg';
import {
  SigningContinuationDenied,
  type VerifiedSigningContinuation,
} from '../domain/signing-continuation.js';
import { consumeSigningContinuation } from './signing-continuation-consumption.js';
import { getRotationCommand, rotationOperationView } from './signing-rotation-command.js';
import { rotationDigest } from './signing-rotation-store.js';

/** The exact authenticated provider result guarantees no effect now or later; ABSENT/timeout never enters this owner. */
export async function finishSigningRotationNoEffect(
  client: PoolClient,
  verified: VerifiedSigningContinuation,
) {
  const c = verified.context;
  if (c.resultDisposition !== 'NO_EFFECT_RETRYABLE') throw new SigningContinuationDenied();
  await client.query(
    `update control.signing_provider_attempt set state='SUPERSEDED' where participant_id=$1 and privacy_domain_id=$2
  and operation_id=$3 and request->>'method'='SIGN_RECEIPT' and state in ('READY','DISPATCHING','OBSERVED')`,
    [c.participantId, c.privacyDomainId, c.operationId],
  );
  await client.query(
    `insert into control.signing_rotation_operation_evidence(operation_id,participant_id,privacy_domain_id,rotation_id,
  provider_attempt_id,continuation_assertion_id,kind,preimage,digest,recorded_at_ns)
  select $1,$2,$3,$4,$5,$6,'NO_EFFECT_RETRYABLE',bytes,sha256(bytes),1
  from (select openpc.signing_operation_failure_preimage($5,'NO_EFFECT_RETRYABLE',$6) bytes) retained`,
    [
      c.operationId,
      c.participantId,
      c.privacyDomainId,
      c.rotationId,
      c.providerAttemptId,
      verified.assertionId,
    ],
  );
  await consumeSigningContinuation(client, verified, null);
  const rejected = await client.query(
    `update control.signing_provider_attempt set state='REJECTED' where participant_id=$1 and privacy_domain_id=$2
  and operation_id=$3 and attempt_id=$4 and state='OBSERVED'`,
    [c.participantId, c.privacyDomainId, c.operationId, c.providerAttemptId],
  );
  if (rejected.rowCount !== 1) throw new SigningContinuationDenied();
  await client.query(
    `update control.signing_rotation_command set state='FAILED',result_kind='NO_EFFECT_RETRYABLE',result_revision=$4,
  updated_at=clock_timestamp() where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and state in ('ACCEPTED','WRITE_AMBIGUITY')`,
    [c.participantId, c.privacyDomainId, c.operationId, c.rotationRevision],
  );
  const result = rotationOperationView(await getRotationCommand(client, c, c.operationId));
  await client.query(
    `update control.idempotency_record set terminal_state='COMMITTED',result_aggregate_version=$4,result_payload=$5,result_digest=$6
  where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and terminal_state is null`,
    [
      c.participantId,
      c.privacyDomainId,
      c.operationId,
      result.revision,
      result,
      rotationDigest(result),
    ],
  );
}
