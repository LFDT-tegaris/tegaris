import { z } from 'zod';
import { recoveryActor, recoveryStepUp } from './recovery-workflow';

const uuid = z.uuid();
const revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const key = z.string().min(1).max(4096);
export const workloadId = z
  .string()
  .regex(
    /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
export const workloadCandidates = {
  ISSUE: z.strictObject({
    credentialId: uuid,
    participantId: uuid,
    principalId: uuid,
    workloadId,
    publicKeySpkiDer: key,
  }),
  ROTATE: z.strictObject({ replacedCredentialId: uuid, credentialId: uuid, publicKeySpkiDer: key }),
  REVOKE: z.strictObject({ credentialId: uuid, state: z.literal('REVOKED') }),
};
export const workloadCandidate = z.union(Object.values(workloadCandidates));
export const workloadCertificate = z.strictObject({
  credentialId: uuid,
  participantId: uuid,
  principalId: uuid,
  workloadId,
  state: z.enum(['PENDING', 'ISSUED', 'ACTIVE', 'ROTATING', 'REVOKED', 'EXPIRED']),
  workloadEpoch: revision,
  revision,
  certificateDer: z.string().min(1).max(32768).nullable(),
  keyId: digest,
  certificateFingerprint: digest,
  uriSan: z.string(),
  issuer: z.string(),
  notBefore: z.string().datetime(),
  notAfter: z.string().datetime(),
  rotateAt: z.string().datetime(),
  replacedCredentialId: uuid.nullable(),
});
export const workloadReview = z.strictObject({
  mutation: z.enum(['ISSUE', 'ROTATE', 'REVOKE']),
  candidate: workloadCandidate,
  resourceId: uuid,
  expectedRevision: revision,
  candidateDigest: digest,
  checkerPrincipalId: uuid,
  reason: z.string().min(10).max(1024),
  expiresAt: z.string().datetime(),
  stepUp: recoveryStepUp,
  resumeDraft: z.strictObject({ approvalRequestId: uuid, expectedAttempt: revision }).optional(),
});
export const savedWorkloadReview = z.strictObject({
  reviewToken: z.string().min(80).max(65536),
  review: workloadReview,
  approvalRequestId: uuid.optional(),
  resumeSent: z.boolean().optional(),
});
export const workloadProposal = z.strictObject({
  candidateDigest: digest,
  resourceId: uuid,
  makerPrincipalId: uuid,
  catalogOperationId: z.enum([
    'ID-OP-WORKLOAD-ISSUE',
    'ID-OP-WORKLOAD-ROTATE',
    'ID-OP-WORKLOAD-REVOKE',
  ]),
  expectedRevision: revision,
  state: z.string(),
  operationId: uuid.nullable(),
  expiresAt: z.string().datetime(),
  candidate: workloadCandidate,
  approval: z.strictObject({ approvalRequestId: uuid, reason: z.string().nullable() }).optional(),
});
export const workloadState = z.strictObject({
  restoredReview: savedWorkloadReview.optional(),
  preapprovalState: z.enum(['ABSENT', 'PRESENT']).optional(),
  actor: recoveryActor,
  approvals: z.array(
    z.object({
      approvalRequestId: z.string(),
      candidateDigest: digest,
      makerSubjectRef: z.string(),
      checkerSubjectRef: z.string().nullable(),
      revision,
      state: z.string(),
      proposal: workloadProposal,
      stepUp: recoveryStepUp,
    }),
  ),
  nextCursor: z.string().nullable(),
});
export type WorkloadReview = z.infer<typeof savedWorkloadReview>;
