import { z } from 'zod';
import { recoveryActor, recoveryStepUp } from './recovery-workflow';

const uuid = z.uuid();
const revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const credentialInventory = z.strictObject({
  participantId: uuid,
  principalId: uuid,
  items: z
    .array(
      z.strictObject({
        credentialId: uuid,
        state: z.string(),
        credentialEpoch: revision,
        revision,
        issuer: z.string().nullable(),
        active: z.boolean(),
        replacedCredentialId: uuid.nullable(),
      }),
    )
    .max(50),
  nextCursor: uuid.nullable(),
});
export const replacementCandidate = z.strictObject({
  enrollmentId: uuid,
  replacedCredentialId: uuid,
  externalCredentialId: z.string().min(1).max(2048),
  publicKeyDigest: digest,
  publicKeySpkiDer: z.string().min(1).max(16384),
  signCount: revision,
  attestationDigest: digest,
  hardwareAttestation: z
    .strictObject({
      profileId: z.string().min(1).max(160),
      profileDigest: digest,
      aaguid: uuid,
      attestationDigest: digest,
    })
    .optional(),
});
export const credentialProposal = z.strictObject({
  candidateDigest: digest,
  resourceId: uuid,
  makerPrincipalId: uuid,
  catalogOperationId: z.literal('ID-OP-WEBAUTHN-REGISTER'),
  expectedRevision: revision,
  state: z.string(),
  expiresAt: z.string().datetime(),
  candidate: replacementCandidate,
  approval: z.strictObject({ approvalRequestId: uuid, reason: z.string().nullable() }).optional(),
});
export const credentialReview = z.strictObject({
  enrollmentId: uuid,
  replacedCredentialId: uuid,
  expectedRevision: revision,
  candidateDigest: digest,
  checkerPrincipalId: uuid,
  reason: z.string().min(10).max(1024),
  expiresAt: z.string().datetime(),
  stepUp: recoveryStepUp,
});
export const savedCredentialReview = z.strictObject({
  reviewToken: z.string().min(80).max(131072),
  review: credentialReview,
  approvalRequestId: uuid.optional(),
});
export const credentialState = z.strictObject({
  actor: recoveryActor,
  inventory: credentialInventory,
  approvals: z.array(
    z.object({
      approvalRequestId: z.string(),
      candidateDigest: digest,
      makerSubjectRef: z.string(),
      checkerSubjectRef: z.string().nullable(),
      revision,
      state: z.string(),
      proposal: credentialProposal,
      stepUp: recoveryStepUp,
    }),
  ),
  nextCursor: z.string().nullable(),
});
export type CredentialReview = z.infer<typeof savedCredentialReview>;
