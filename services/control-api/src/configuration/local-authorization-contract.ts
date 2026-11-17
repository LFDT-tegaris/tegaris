import { z } from 'zod';

import type { MutationAuthorization } from './persistence/types.js';

const epochSchema = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const base64Schema = z
  .string()
  .min(4)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u);
const digestBytesSchema = base64Schema.refine(
  (value) => Buffer.from(value, 'base64').length === 32,
);

const policyProofSchema = z.strictObject({
  sessionId: z.uuid(),
  sessionEpoch: epochSchema,
  participantId: z.uuid(),
  principalId: z.uuid(),
  participantEpoch: epochSchema,
  principalEpoch: epochSchema,
  assignmentId: z.uuid(),
  roleIds: z
    .array(
      z
        .string()
        .regex(
          /^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
        ),
    )
    .max(1)
    .optional(),
  assignmentRowVersion: epochSchema,
  authorityEnvelopeId: z.uuid(),
  authorityEpoch: epochSchema,
  delegationEpoch: epochSchema,
});

export function decodeLocalConfigurationProposal(value: unknown) {
  return policyProofSchema.parse(value);
}

const userMutationProofSchema = z.strictObject({
  evidenceKind: z.literal('USER_WEBAUTHN'),
  sessionId: z.uuid(),
  sessionEpoch: epochSchema,
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  principalId: z.uuid(),
  principalEpoch: epochSchema,
  checkerPrincipalId: z.uuid().optional(),
  signerCredentialId: z.uuid(),
  approvalRequestId: z.uuid().optional(),
  mfaChallengeId: z.uuid().optional(),
  webauthnSessionId: z.uuid().optional(),
  webauthnSignerCredentialId: z.uuid().optional(),
  participantEpoch: epochSchema,
  authorityEnvelopeId: z.uuid(),
  authorityEpoch: epochSchema,
  delegationEpoch: epochSchema,
  assignmentId: z.uuid(),
  assignmentEpoch: epochSchema,
  webauthnAssertionBindingDigest: digestBytesSchema.optional(),
  webauthnEvidenceCbor: base64Schema.optional(),
  webauthnEvidenceDigest: digestBytesSchema.optional(),
  webauthnCoseSign1: base64Schema.optional(),
  evidenceCbor: base64Schema,
  evidenceDigest: digestBytesSchema,
  coseSign1: base64Schema,
});

const runtimeMutationProofSchema = userMutationProofSchema
  .omit({
    evidenceKind: true,
    signerCredentialId: true,
    checkerPrincipalId: true,
    approvalRequestId: true,
    mfaChallengeId: true,
    webauthnSessionId: true,
    webauthnSignerCredentialId: true,
    webauthnAssertionBindingDigest: true,
    webauthnEvidenceCbor: true,
    webauthnEvidenceDigest: true,
    webauthnCoseSign1: true,
  })
  .extend({ evidenceKind: z.literal('IDENTITY_RUNTIME'), signerKeyDigest: digestBytesSchema });
const stepUpMutationProofSchema = runtimeMutationProofSchema.extend({
  evidenceKind: z.literal('IDENTITY_RUNTIME_STEP_UP'),
  mfaChallengeId: z.uuid(),
  webauthnSessionId: z.uuid(),
  webauthnSignerCredentialId: z.uuid(),
  webauthnAssertionBindingDigest: digestBytesSchema,
  webauthnEvidenceCbor: base64Schema,
  webauthnEvidenceDigest: digestBytesSchema,
  webauthnCoseSign1: base64Schema,
});
const mutationProofSchema = z.discriminatedUnion('evidenceKind', [
  userMutationProofSchema,
  runtimeMutationProofSchema,
  stepUpMutationProofSchema,
]);

export function decodeLocalMutationAuthorization(value: unknown): MutationAuthorization {
  const proof = mutationProofSchema.parse(value);
  if (proof.evidenceKind === 'IDENTITY_RUNTIME_STEP_UP')
    return {
      ...proof,
      signerKeyDigest: Buffer.from(proof.signerKeyDigest, 'base64'),
      evidenceCbor: Buffer.from(proof.evidenceCbor, 'base64'),
      evidenceDigest: Buffer.from(proof.evidenceDigest, 'base64'),
      coseSign1: Buffer.from(proof.coseSign1, 'base64'),
      webauthnAssertionBindingDigest: Buffer.from(proof.webauthnAssertionBindingDigest, 'base64'),
      webauthnEvidenceCbor: Buffer.from(proof.webauthnEvidenceCbor, 'base64'),
      webauthnEvidenceDigest: Buffer.from(proof.webauthnEvidenceDigest, 'base64'),
      webauthnCoseSign1: Buffer.from(proof.webauthnCoseSign1, 'base64'),
    };
  if (proof.evidenceKind === 'IDENTITY_RUNTIME')
    return {
      ...proof,
      signerKeyDigest: Buffer.from(proof.signerKeyDigest, 'base64'),
      evidenceCbor: Buffer.from(proof.evidenceCbor, 'base64'),
      evidenceDigest: Buffer.from(proof.evidenceDigest, 'base64'),
      coseSign1: Buffer.from(proof.coseSign1, 'base64'),
    };
  return {
    evidenceKind: proof.evidenceKind,
    sessionId: proof.sessionId,
    sessionEpoch: proof.sessionEpoch,
    participantId: proof.participantId,
    privacyDomainId: proof.privacyDomainId,
    principalId: proof.principalId,
    principalEpoch: proof.principalEpoch,
    ...(proof.checkerPrincipalId === undefined
      ? {}
      : { checkerPrincipalId: proof.checkerPrincipalId }),
    signerCredentialId: proof.signerCredentialId,
    ...(proof.approvalRequestId === undefined
      ? {}
      : { approvalRequestId: proof.approvalRequestId }),
    ...(proof.mfaChallengeId === undefined ? {} : { mfaChallengeId: proof.mfaChallengeId }),
    ...(proof.webauthnSessionId === undefined
      ? {}
      : { webauthnSessionId: proof.webauthnSessionId }),
    ...(proof.webauthnSignerCredentialId === undefined
      ? {}
      : { webauthnSignerCredentialId: proof.webauthnSignerCredentialId }),
    participantEpoch: proof.participantEpoch,
    authorityEnvelopeId: proof.authorityEnvelopeId,
    authorityEpoch: proof.authorityEpoch,
    delegationEpoch: proof.delegationEpoch,
    assignmentId: proof.assignmentId,
    assignmentEpoch: proof.assignmentEpoch,
    ...(proof.webauthnAssertionBindingDigest === undefined
      ? {}
      : {
          webauthnAssertionBindingDigest: Buffer.from(
            proof.webauthnAssertionBindingDigest,
            'base64',
          ),
        }),
    ...(proof.webauthnEvidenceCbor === undefined
      ? {}
      : { webauthnEvidenceCbor: Buffer.from(proof.webauthnEvidenceCbor, 'base64') }),
    ...(proof.webauthnEvidenceDigest === undefined
      ? {}
      : { webauthnEvidenceDigest: Buffer.from(proof.webauthnEvidenceDigest, 'base64') }),
    ...(proof.webauthnCoseSign1 === undefined
      ? {}
      : { webauthnCoseSign1: Buffer.from(proof.webauthnCoseSign1, 'base64') }),
    evidenceCbor: Buffer.from(proof.evidenceCbor, 'base64'),
    evidenceDigest: Buffer.from(proof.evidenceDigest, 'base64'),
    coseSign1: Buffer.from(proof.coseSign1, 'base64'),
  };
}

export function decodeLocalPolicyAuthorization(
  value: unknown,
  privacyDomainId: string,
): MutationAuthorization {
  const proof = policyProofSchema.parse(value);
  return {
    sessionId: proof.sessionId,
    participantId: proof.participantId,
    privacyDomainId,
    principalId: proof.principalId,
    principalEpoch: proof.principalEpoch,
    evidenceKind: 'READ_CONTEXT',
    sessionEpoch: proof.sessionEpoch,
    participantEpoch: proof.participantEpoch,
    authorityEnvelopeId: proof.authorityEnvelopeId,
    authorityEpoch: proof.authorityEpoch,
    delegationEpoch: proof.delegationEpoch,
    assignmentId: proof.assignmentId,
    assignmentEpoch: proof.assignmentRowVersion,
    evidenceCbor: Buffer.alloc(0),
    evidenceDigest: Buffer.alloc(0),
    coseSign1: Buffer.alloc(0),
  };
}
