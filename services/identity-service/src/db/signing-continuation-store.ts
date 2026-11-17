import type { Pool } from 'pg';
import { canonicalAuthorizationJson } from '../contracts/authorization.js';
import { localOperationId } from '../domain/local-operation-id.js';
import {
  SigningContinuationDenied,
  type createSigningContinuationSigner,
  type createSigningContinuationVerifier,
} from '../domain/signing-continuation.js';
import { runScopedTransaction } from './scoped-transaction.js';
import {
  loadSigningContinuationContext,
  type SigningContinuationPeer,
} from './signing-continuation-context.js';
import { rotationDigest } from './signing-rotation-store.js';

export class SigningContinuationIssuer {
  constructor(
    private readonly pool: Pool,
    private readonly sign: ReturnType<typeof createSigningContinuationSigner>,
    private readonly verify: ReturnType<typeof createSigningContinuationVerifier>,
  ) {}

  async issue(
    peer: SigningContinuationPeer,
    rotationId: string,
    operationId: string,
    attemptId: string,
  ) {
    return runScopedTransaction(
      this.pool,
      {
        ...peer,
        actionIntentId: 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',
      },
      () => operationId,
      async (client) => {
        const context = await loadSigningContinuationContext(
          client,
          peer,
          rotationId,
          operationId,
          attemptId,
        );
        const retained = await client.query<{ state: string }>(
          `select state from control.signing_continuation
        where participant_id=$1 and privacy_domain_id=$2 and provider_attempt_id=$3 and state in ('ISSUED','CONSUMED') for update`,
          [peer.participantId, peer.privacyDomainId, attemptId],
        );
        if (retained.rows.some((row) => row.state === 'CONSUMED'))
          throw new SigningContinuationDenied();
        // An interrupted issuer never stores or recovers a bearer. Wait for its short TTL, then issue a fresh JTI.
        await client.query(
          `update control.signing_continuation set state='EXPIRED' where participant_id=$1 and privacy_domain_id=$2
        and provider_attempt_id=$3 and state='ISSUED' and expires_at_ns<=floor(extract(epoch from clock_timestamp())*1000000)*1000`,
          [peer.participantId, peer.privacyDomainId, attemptId],
        );
        const pending = await client.query(
          `select 1 from control.signing_continuation where participant_id=$1 and privacy_domain_id=$2
        and provider_attempt_id=$3 and state='ISSUED'`,
          [peer.participantId, peer.privacyDomainId, attemptId],
        );
        if (pending.rowCount !== 0) throw new SigningContinuationDenied();
        const now = (await client.query<{ now: Date }>('select clock_timestamp() as now')).rows[0]!
          .now;
        const assertionId = localOperationId();
        const assertion = await this.sign(context, assertionId, now);
        const verified = await this.verify(assertion, context, now);
        await client.query(
          `insert into control.signing_continuation(assertion_id,participant_id,privacy_domain_id,operation_id,
        provider_attempt_id,context_preimage,context_digest,assertion_digest,issuer_key_digest,issued_at_ns,expires_at_ns,state)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'ISSUED')`,
          [
            assertionId,
            peer.participantId,
            peer.privacyDomainId,
            operationId,
            attemptId,
            Buffer.from(canonicalAuthorizationJson(context)),
            rotationDigest(context),
            verified.assertionDigest,
            verified.signerKeyDigest,
            verified.issuedAtNs.toString(),
            verified.expiresAtNs.toString(),
          ],
        );
        return { assertion, expiresAtNs: verified.expiresAtNs.toString() };
      },
    );
  }
}
