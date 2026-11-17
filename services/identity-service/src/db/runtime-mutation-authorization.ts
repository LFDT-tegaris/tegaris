import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { verifyIdentityRuntimeAuthorizationAssertion } from '../domain/identity-runtime-authorization.js';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import type { MutationAuthorization } from '../domain/control-mutation-authorization.js';

export interface RuntimeMutationAuthorizationBinding {
  readonly authorization: Exclude<MutationAuthorization, { readonly evidenceKind: 'READ_CONTEXT' }>;
  readonly sessionToken?: string;
  readonly actionIntentId: string;
  readonly catalogOperationId: string;
  readonly resourceId: string;
  readonly actionIntentDigest: string;
  readonly expectedRevision: string;
}
export class RuntimeMutationAuthorizationError extends Error {
  constructor() {
    super('PC-AUTH-0005');
  }
}

/** Called only after the exact authority path is fenced for this transaction. */
export async function verifyRuntimeMutationAuthorization(
  client: PoolClient,
  context: RuntimeMutationAuthorizationBinding,
  candidateDigest: Buffer,
  verifier: IdentityRuntimeVerifier | undefined,
): Promise<void> {
  const proof = context.authorization;
  if (
    proof.evidenceKind !== 'IDENTITY_RUNTIME' ||
    verifier === undefined ||
    proof.sessionEpoch === undefined ||
    context.sessionToken === undefined ||
    proof.signerCredentialId !== undefined ||
    proof.checkerPrincipalId !== undefined ||
    proof.approvalRequestId !== undefined ||
    proof.mfaChallengeId !== undefined ||
    proof.webauthnSessionId !== undefined ||
    proof.webauthnAssertionBindingDigest !== undefined ||
    proof.webauthnEvidenceCbor !== undefined ||
    proof.webauthnEvidenceDigest !== undefined ||
    proof.webauthnCoseSign1 !== undefined ||
    !createHash('sha256').update(proof.evidenceCbor).digest().equals(proof.evidenceDigest)
  )
    throw new RuntimeMutationAuthorizationError();
  const selected = await client.query<{
    readonly sessionIssuedAt: Date;
    readonly sessionIdleExpiresAt: Date;
    readonly sessionAbsoluteExpiresAt: Date;
    readonly now: Date;
  }>(
    `select issued_at as "sessionIssuedAt",idle_expires_at as "sessionIdleExpiresAt",
            absolute_expires_at as "sessionAbsoluteExpiresAt",clock_timestamp() as now
       from control.session where participant_id=$1 and session_id=$2 and principal_id=$3
        and session_epoch=$4 and opaque_token_digest=$5 and state='ACTIVE'
        and idle_expires_at>clock_timestamp() and absolute_expires_at>clock_timestamp()`,
    [
      proof.participantId,
      proof.sessionId,
      proof.principalId,
      proof.sessionEpoch,
      createHash('sha256').update(context.sessionToken).digest(),
    ],
  );
  const session = selected.rows[0];
  const verified = await verifier.verifyCanonicalAssertion(proof.evidenceCbor, proof.coseSign1);
  if (
    selected.rowCount !== 1 ||
    session === undefined ||
    verified === undefined ||
    !verified.signerKeyDigest.equals(proof.signerKeyDigest) ||
    verifyIdentityRuntimeAuthorizationAssertion(
      proof.evidenceCbor,
      {
        ...proof,
        ...session,
        sessionEpoch: proof.sessionEpoch,
        assignmentRowVersion: proof.assignmentEpoch,
        actionIntentId: context.actionIntentId,
        catalogOperationId: context.catalogOperationId,
        resourceId: context.resourceId,
        candidateDigest: `sha256:${candidateDigest.toString('hex')}`,
        sessionToken: context.sessionToken,
        configurationBinding: {
          privacyDomainId: proof.privacyDomainId,
          actionIntentDigest: context.actionIntentDigest,
          expectedRevision: context.expectedRevision,
        },
      },
      session.now,
    ) === undefined
  )
    throw new RuntimeMutationAuthorizationError();
}
