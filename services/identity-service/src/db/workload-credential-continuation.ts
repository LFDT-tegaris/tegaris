import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { identityCredentialCoseContext, verifyCoseSign1Es256 } from '@openpc/security-kernel';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import { authenticateHistoricalRuntimeStepUpEvidence } from './verified-step-up-evidence.js';
import { IdentityEnvelopeRotationIssuerUnavailable } from './identity-envelope-rotation-issuer.js';

/** Authenticate the original normal rotation's exact checker evidence. Current
 * issuer availability, custody and lease are independently fenced by callers.
 * This read never renews an old credential or grants current authority. */
export async function assertWorkloadCredentialContinuation(
  client: PoolClient,
  input: {
    participantId: string;
    privacyDomainId: string;
    predecessorId: string;
    predecessorEpoch: string;
    successorId: string;
    successorEpoch: string;
    principalId: string;
  },
  verifier: IdentityRuntimeVerifier | undefined,
) {
  const deny = () => {
    throw new IdentityEnvelopeRotationIssuerUnavailable();
  };
  if (!verifier || input.predecessorId === input.successorId) deny();
  const result = await client.query<{
    principalId: string;
    checkerPrincipalId: string;
    credentialPublicKey: Buffer;
    credentialPublicKeyDigest: Buffer;
    evidenceCbor: Buffer;
    evidenceDigest: Buffer;
    coseSign1: Buffer;
    verificationCandidateDigest: Buffer | null;
    verificationSessionId: string | null;
    verificationOccurredAt: Date | null;
  }>(
    `select history.* from openpc.read_identity_envelope_credential_continuation($3,$5,$4,$6,$7) history
      where openpc.matches_participant($1::uuid) and openpc.matches_privacy($2::uuid)`,
    [
      input.participantId,
      input.privacyDomainId,
      input.predecessorId,
      input.successorId,
      input.predecessorEpoch,
      input.successorEpoch,
      input.principalId,
    ],
  );
  const row = result.rows[0];
  try {
    if (
      result.rowCount !== 1 ||
      !row ||
      row.principalId !== input.principalId ||
      !createHash('sha256').update(row.evidenceCbor).digest().equals(row.evidenceDigest) ||
      !createHash('sha256')
        .update(row.credentialPublicKey)
        .digest()
        .equals(row.credentialPublicKeyDigest)
    )
      deny();
    if (
      verifyCoseSign1Es256(
        row!.credentialPublicKey,
        row!.evidenceCbor,
        row!.coseSign1,
        identityCredentialCoseContext,
      )
    )
      return;
    if (
      !row!.verificationCandidateDigest ||
      !row!.verificationSessionId ||
      !row!.verificationOccurredAt ||
      !(await verifier!.verifyCanonicalAssertion(row!.evidenceCbor, row!.coseSign1)) ||
      !authenticateHistoricalRuntimeStepUpEvidence(
        {
          participantId: input.participantId,
          principalId: row!.checkerPrincipalId,
          evidenceCbor: row!.evidenceCbor,
        },
        {
          candidate_digest: row!.verificationCandidateDigest!,
          session_id: row!.verificationSessionId!,
          occurred_at: row!.verificationOccurredAt!,
        },
      )
    )
      deny();
  } catch {
    deny();
  }
}
