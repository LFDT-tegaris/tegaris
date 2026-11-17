import type { PoolClient } from 'pg';
import { canonicalAuthorizationJson } from '../contracts/authorization.js';
import {
  SigningContinuationDenied,
  type VerifiedSigningContinuation,
  type createSigningContinuationVerifier,
} from '../domain/signing-continuation.js';
import {
  loadSigningContinuationContext,
  type SigningContinuationPeer,
} from './signing-continuation-context.js';
import { rotationDigest } from './signing-rotation-store.js';

/** Every use checks fresh workload/authority, original pending truth, the pinned signature and the durable unspent JTI. */
export async function verifyStoredSigningContinuation(
  client: PoolClient,
  peer: SigningContinuationPeer,
  input: { rotationId: string; operationId: string; attemptId: string; assertion: string },
  verify: ReturnType<typeof createSigningContinuationVerifier>,
) {
  const context = await loadSigningContinuationContext(
    client,
    peer,
    input.rotationId,
    input.operationId,
    input.attemptId,
  );
  const now = (await client.query<{ now: Date }>('select clock_timestamp() as now')).rows[0]!.now;
  const verified = await verify(input.assertion, context, now);
  const stored = await client.query(
    `select 1 from control.signing_continuation where participant_id=$1 and privacy_domain_id=$2
  and assertion_id=$3 and operation_id=$4 and provider_attempt_id=$5 and state='ISSUED' and context_digest=$6
  and assertion_digest=$7 and issuer_key_digest=$8 and issued_at_ns=$9 and expires_at_ns=$10
  and expires_at_ns>floor(extract(epoch from clock_timestamp())*1000000)*1000 for update`,
    [
      peer.participantId,
      peer.privacyDomainId,
      verified.assertionId,
      input.operationId,
      input.attemptId,
      rotationDigest(context),
      verified.assertionDigest,
      verified.signerKeyDigest,
      verified.issuedAtNs.toString(),
      verified.expiresAtNs.toString(),
    ],
  );
  if (stored.rowCount !== 1) throw new SigningContinuationDenied();
  return verified;
}
export async function signingContinuationSnapshot(
  client: PoolClient,
  verified: VerifiedSigningContinuation,
) {
  const now = (
    await client.query<{ ns: string }>(
      'select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text as ns',
    )
  ).rows[0]!.ns;
  const value = {
    schema: 'pc.control.signing-rotation-continuation-snapshot.v1',
    participantId: verified.context.participantId,
    privacyDomainId: verified.context.privacyDomainId,
    operationId: verified.context.operationId,
    recordedAtNs: now,
    decision: 'RECORD_DISPATCHED_TRUTH',
    continuationAssertionId: verified.assertionId,
    continuationAssertionDigest: 'sha256:' + verified.assertionDigest.toString('hex'),
    context: verified.context,
  };
  return { bytes: Buffer.from(canonicalAuthorizationJson(value)), digest: rotationDigest(value) };
}
