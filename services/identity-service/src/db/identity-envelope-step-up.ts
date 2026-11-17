import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { EnvelopeActorEvidence, EnvelopeAuthorityBinding } from '@openpc/security-kernel';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import { AuthorityFenceError } from './authority-fence.js';
import { lockLiveStepUpRecord, type LiveStepUpBinding } from './live-step-up.js';
import { verifyStoredStepUpEvidence } from './verified-step-up-evidence.js';

/** Call after the ordinary live actor/session/grant/credential fences and before
 * the Platform fence. The business authority and step-up action may differ:
 * SUBMIT requires both the issuance grant and permission to request approval.
 * This verifies committed proof provenance; it never supplies either grant.
 * The caller consumes the returned record in the same effect transaction. */
export async function captureEnvelopeActorEvidence(
  client: PoolClient,
  binding: LiveStepUpBinding,
  authority: EnvelopeAuthorityBinding,
  verifier: IdentityRuntimeVerifier | undefined,
) {
  if (
    !binding.resourceId ||
    authority.participantId !== binding.participantId ||
    authority.participantEpoch !== binding.participantEpoch ||
    authority.principalId !== binding.principalId ||
    authority.principalEpoch !== binding.principalEpoch ||
    authority.sessionId !== binding.sessionId
  )
    throw new AuthorityFenceError();
  const record = await lockLiveStepUpRecord(client, binding);
  if (
    !createHash('sha256').update(record.evidenceCbor).digest().equals(record.evidenceDigest) ||
    !(await verifyStoredStepUpEvidence(
      client,
      {
        participantId: binding.participantId,
        privacyDomainId: binding.privacyDomainId,
        principalId: binding.principalId,
        credentialId: record.signerCredentialId,
        credentialEpoch: record.signerCredentialEpoch,
        mfaChallengeId: record.mfaChallengeId,
        actionIntentId: binding.actionIntentId,
        candidateDigest: binding.resourceDigest,
        resourceId: binding.resourceId,
        credentialPublicKey: record.credentialPublicKey,
        evidenceCbor: record.evidenceCbor,
        coseSign1: record.coseSign1,
      },
      verifier,
    ))
  )
    throw new AuthorityFenceError();
  const evidence: EnvelopeActorEvidence = {
    authority,
    stepUpChallengeId: record.mfaChallengeId,
    stepUpEvidenceDigest: `sha256:${record.evidenceDigest.toString('hex')}`,
    signerCredentialId: record.signerCredentialId,
    signerCredentialEpoch: record.signerCredentialEpoch,
  };
  return { evidence, record };
}
