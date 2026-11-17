import type { PoolClient } from 'pg';
import type { VerifiedSigningContinuation } from '../domain/signing-continuation.js';
import { SigningContinuationDenied } from '../domain/signing-continuation.js';
import { localOperationId } from '../domain/local-operation-id.js';

/** Called inside the locked original operation's business commit, never as an independent acknowledgement. */
export async function consumeSigningContinuation(
  client: PoolClient,
  verified: VerifiedSigningContinuation,
  receiptId: string | null,
) {
  const c = verified.context;
  const used = await client.query(
    `update control.signing_continuation set state='CONSUMED',consumed_receipt_id=$4
  where participant_id=$1 and privacy_domain_id=$2 and assertion_id=$3 and state='ISSUED'`,
    [c.participantId, c.privacyDomainId, verified.assertionId, receiptId],
  );
  if (used.rowCount !== 1) throw new SigningContinuationDenied();
  if (c.currentAuthorityStatus === 'CHANGED')
    await client.query(
      `insert into control.signing_rotation_authority_hold
  (hold_id,participant_id,privacy_domain_id,rotation_id,operation_id,continuation_assertion_id,reason,state,created_at_ns)
  values($1,$2,$3,$4,$5,$6,'AUTHORITY_CHANGED_AFTER_DISPATCH','ACTIVE',1)`,
      [
        localOperationId(),
        c.participantId,
        c.privacyDomainId,
        c.rotationId,
        c.operationId,
        verified.assertionId,
      ],
    );
}
