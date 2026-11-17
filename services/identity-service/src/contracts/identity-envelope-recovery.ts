import { recoveryLifetimeSettings } from '../domain/platform-recovery-lifetimes.js';
import { createHash, createPublicKey } from 'node:crypto';
import { z } from 'zod';
import {
  independentRecoveryEnrollmentCustody,
  platformRecoverySigner,
} from './platform-recovery.js';
import { envelopeSigningRotationRequestSchema } from '../domain/signing-rotation.js';
import { signingRotationStates } from '../domain/signing-rotation.js';
import { identityEnvelopeRotationIssuerSchema } from '../db/identity-envelope-rotation-issuer.js';

const id = z.uuidv7();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const positive = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const instant = z.iso.datetime({ offset: true });
const nanos = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n && BigInt(value) % 1000n === 0n);
export const identityEnvelopeRecoveryCustodyPurpose =
  'pc.installation.identity-envelope-repair-custody.v1' as const;
export const identityEnvelopeRecoveryLeasePurpose = 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY' as const;

/** Explicit receiving trust, installed independently of the signed enrollment.
 * Neither an OperationsSiteDocument key nor a runtime signer is inferred here.
 * Host installation receiving trust does not define another COSE purpose code. */
export const identityEnvelopeRecoveryReceivingTrust = z
  .strictObject({
    schema: z.literal('pc.installation.identity-envelope-recovery-receiving-trust'),
    schemaVersion: z.literal(1),
    custodyTrustId: id,
    participantId: id,
    privacyDomainId: id,
    platformContextId: id,
    installationDigest: digest,
    installationEnvironmentId: z.string().min(1).max(160),
    profile: z.enum(['PRODUCTION', 'LOCAL_QA']),
    purpose: z.literal(identityEnvelopeRecoveryCustodyPurpose),
    algorithm: z.literal('ES256'),
    issuerKeyId: digest,
    issuerPublicKeySpkiDer: z.string().min(24).max(8192),
    issuerEpoch: positive,
    validFrom: instant,
    validUntil: instant,
  })
  .superRefine((value, ctx) => {
    let validKey = false;
    try {
      const bytes = Buffer.from(value.issuerPublicKeySpkiDer, 'base64');
      const key = createPublicKey({ key: bytes, format: 'der', type: 'spki' });
      validKey =
        bytes.toString('base64') === value.issuerPublicKeySpkiDer &&
        key.asymmetricKeyType === 'ec' &&
        key.asymmetricKeyDetails?.namedCurve === 'prime256v1' &&
        Buffer.from(key.export({ format: 'der', type: 'spki' })).equals(bytes) &&
        `sha256:${createHash('sha256').update(bytes).digest('hex')}` === value.issuerKeyId;
    } catch {
      // Invalid public material never becomes receiving trust.
    }
    if (!validKey || Date.parse(value.validUntil) <= Date.parse(value.validFrom))
      ctx.addIssue({ code: 'custom', message: 'Invalid recovery receiving trust' });
  });
export type IdentityEnvelopeRecoveryReceivingTrust = z.infer<
  typeof identityEnvelopeRecoveryReceivingTrust
>;

/** Immutable, independently signed installation custody. No fabricated expired
 * handoff, ordinary administrator grant or caller-supplied verification key. */
export const identityEnvelopeRecoveryEnrollment = z
  .strictObject({
    schema: z.literal('pc.identity.identity-envelope-recovery-enrollment'),
    schemaVersion: z.literal(1),
    purpose: z.literal(identityEnvelopeRecoveryCustodyPurpose),
    enrollmentId: id,
    participantId: id,
    privacyDomainId: id,
    platformContextId: id,
    rootEpoch: positive,
    rootRevision: positive,
    rootDigest: digest,
    custodyTrustId: id,
    custodyTrustDigest: digest,
    custodyIssuerKeyId: digest,
    custodyIssuerEpoch: positive,
    installationDigest: digest,
    installationEnvironmentId: z.string().min(1).max(160),
    profile: z.enum(['PRODUCTION', 'LOCAL_QA']),
    administratorPrincipalIds: z.tuple([id, id]),
    recoveryPrincipal: platformRecoverySigner,
    custodians: z.tuple([platformRecoverySigner, platformRecoverySigner]),
    issuerPrincipalId: id,
    issuerPrincipalEpoch: positive,
    issuerParticipantEpoch: positive,
    issuerCredentialEpoch: positive,
    issuerCredentialPublicKeyDigest: digest,
    oldTrustDigest: digest,
    selectionAdmissionVersion: positive,
    request: envelopeSigningRotationRequestSchema,
    validFrom: instant,
    validUntil: instant,
    assurance: z.enum(['HARDWARE_ATTESTED', 'LOCAL_QA_VIRTUAL_AUTHENTICATOR']),
  })
  .superRefine((value, ctx) => {
    const humans = [
      ...value.administratorPrincipalIds,
      value.recoveryPrincipal.principalId,
      ...value.custodians.map((v) => v.principalId),
    ];
    const humanCredentials = [value.recoveryPrincipal, ...value.custodians].map(
      (v) => v.credentialId,
    );
    if (
      !independentRecoveryEnrollmentCustody(value) ||
      humans.includes(value.issuerPrincipalId) ||
      humanCredentials.includes(value.request.workloadCredentialId) ||
      (value.profile === 'PRODUCTION' && value.assurance !== 'HARDWARE_ATTESTED')
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid independent signer recovery custody' });
  });
export type IdentityEnvelopeRecoveryEnrollment = z.infer<typeof identityEnvelopeRecoveryEnrollment>;

export const signedIdentityEnvelopeRecoveryEnrollment = z.strictObject({
  document: identityEnvelopeRecoveryEnrollment,
  // Raw fixed-size P-256 r||s; not COSE and not a site-document signature.
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/u),
});

/** A separate proposal reserves one exact rotation. It supplies no ordinary
 * actions, Root successor, CALL capability or runtime identity. */
export const identityEnvelopeRecoveryIntent = z
  .strictObject({
    schema: z.literal('pc.identity.identity-envelope-recovery-intent'),
    schemaVersion: z.literal(1),
    purpose: z.literal(identityEnvelopeRecoveryLeasePurpose),
    recoveryId: id,
    enrollmentId: id,
    enrollmentRevision: positive,
    enrollmentDigest: digest,
    rotationId: id,
    creationOperationId: id,
    sourceParticipantEpoch: positive,
    sourceIssuerPrincipalEpoch: positive,
    sourceIssuerCredentialEpoch: positive,
    oldTrustDigest: digest,
    selectionAdmissionVersion: positive,
    validFrom: instant,
    validUntil: instant,
    lifetimes: recoveryLifetimeSettings
      .refine((value) => value.profile === 'LOCAL_QA_10X')
      .optional(),
    postReviewRequired: z.literal(true),
  })
  .superRefine((value, ctx) => {
    const duration = Date.parse(value.validUntil) - Date.parse(value.validFrom);
    if (
      duration <= 0 ||
      duration > (value.lifetimes?.leaseMs ?? 900000) ||
      new Set([value.recoveryId, value.rotationId, value.creationOperationId]).size !== 3
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid bounded signer recovery proposal' });
  });
export type IdentityEnvelopeRecoveryIntent = z.infer<typeof identityEnvelopeRecoveryIntent>;

/** An exact recovery effect reservation, not an ordinary role or envelope. The
 * current issuer is captured after the original issuer/session fence. */
export const identityEnvelopeRecoveryLease = z
  .strictObject({
    schema: z.literal('pc.identity.identity-envelope-recovery-lease'),
    schemaVersion: z.literal(1),
    purpose: z.literal(identityEnvelopeRecoveryLeasePurpose),
    recoveryId: id,
    enrollmentId: id,
    enrollmentDigest: digest,
    intentDigest: digest,
    rotationId: id,
    creationOperationId: id,
    activationOperationId: id,
    executorPrincipalId: id,
    issuer: identityEnvelopeRotationIssuerSchema,
    oldTrustDigest: digest,
    selectionAdmissionVersion: positive,
    proofIds: z.tuple([id, id, id, id]),
    proofEvidenceDigest: digest,
    validFrom: instant,
    validUntil: instant,
    lifetimes: recoveryLifetimeSettings
      .refine((value) => value.profile === 'LOCAL_QA_10X')
      .optional(),
    postReviewRequired: z.literal(true),
  })
  .superRefine((value, ctx) => {
    const duration = Date.parse(value.validUntil) - Date.parse(value.validFrom);
    if (
      duration <= 0 ||
      duration > (value.lifetimes?.leaseMs ?? 900000) ||
      new Set(value.proofIds).size !== 4
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid exact signer recovery lease' });
  });
export type IdentityEnvelopeRecoveryLease = z.infer<typeof identityEnvelopeRecoveryLease>;

const caseState = z.enum(['DRAFT', 'REQUESTED', 'ACTIVE', 'COMPLETED', 'REVOKED', 'EXPIRED']);
const authority = z.enum(['NONE', identityEnvelopeRecoveryLeasePurpose]);
export const identityEnvelopeRecoverySourceView = z.strictObject({
  enrollmentId: id,
  purpose: z.literal(identityEnvelopeRecoveryLeasePurpose),
  authority: z.literal('NONE'),
  request: envelopeSigningRotationRequestSchema,
  source: z.strictObject({
    rootEpoch: positive,
    rootDigest: digest,
    oldTrustDigest: digest,
    issuerPrincipalId: id,
    executorPrincipalId: id,
    custodianPrincipalIds: z.tuple([id, id]),
  }),
  liveCase: z.strictObject({ recoveryId: id, state: caseState }).nullable(),
});
export const identityEnvelopeRecoveryDraftView = z.strictObject({
  intent: identityEnvelopeRecoveryIntent,
  intentDigest: digest,
  state: z.literal('DRAFT'),
  authority: z.literal('NONE'),
  assurance: z.enum(['HARDWARE_ATTESTED', 'LOCAL_QA_VIRTUAL_AUTHENTICATOR']),
});
export const identityEnvelopeRecoveryReceiptView = z
  .strictObject({
    actors: z.strictObject({
      executorPrincipalId: id,
      custodianPrincipalIds: z.tuple([id, id]),
    }),
    assurance: z.enum(['HARDWARE_ATTESTED', 'LOCAL_QA_VIRTUAL_AUTHENTICATOR']),
    proofs: z
      .array(
        z.strictObject({
          principalId: id,
          phase: z.enum(['REQUEST', 'APPROVE', 'ACTIVATE']),
          proofId: id,
          verifiedAt: instant,
        }),
      )
      .max(4),
    recoveryId: id,
    enrollmentId: id,
    revision: positive,
    state: caseState,
    intent: identityEnvelopeRecoveryIntent,
    intentDigest: digest,
    authority,
    lease: identityEnvelopeRecoveryLease.optional(),
    activationEvidenceDigest: digest.optional(),
    postReviewRequired: z.literal(true),
    postReviewStatus: z.enum(['REQUIRED', 'REVIEWED']),
    expired: z.boolean(),
    enrollmentState: z.enum(['ACTIVE', 'REVOKED']),
    receivingTrustState: z.enum(['ACTIVE', 'REVOKED']),
  })
  .superRefine((value, ctx) => {
    if (
      new Set([value.actors.executorPrincipalId, ...value.actors.custodianPrincipalIds]).size !==
        3 ||
      new Set(value.proofs.map((proof) => `${proof.phase}:${proof.principalId}`)).size !==
        value.proofs.length ||
      value.proofs.some((proof) =>
        proof.phase === 'APPROVE'
          ? !value.actors.custodianPrincipalIds.includes(proof.principalId)
          : proof.principalId !== value.actors.executorPrincipalId,
      ) ||
      value.recoveryId !== value.intent.recoveryId ||
      value.enrollmentId !== value.intent.enrollmentId ||
      (value.lease === undefined) !== (value.activationEvidenceDigest === undefined) ||
      (value.lease &&
        (value.lease.recoveryId !== value.recoveryId ||
          value.lease.enrollmentId !== value.enrollmentId)) ||
      (value.authority !== 'NONE' &&
        (value.state !== 'ACTIVE' || value.lease === undefined || value.expired))
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid signer recovery receipt' });
  });
export const identityEnvelopeRecoveryRotationCreationView = z.strictObject({
  schema: z.literal('pc.identity.identity-envelope-recovery-rotation-creation'),
  schemaVersion: z.literal(1),
  operationId: id,
  recoveryId: id,
  enrollmentId: id,
  rotationId: id,
  candidateDigest: digest,
  revision: z.literal('2'),
  state: z.literal('APPROVED'),
  createdAt: instant,
  replay: z.boolean(),
  currentState: z.enum(signingRotationStates),
  currentRevision: positive,
  authority,
  evidenceDigest: digest,
});
export const identityEnvelopeRecoveryRotationPrepareResult = z.strictObject({
  schema: z.literal('pc.identity.identity-envelope-recovery-rotation-phase'),
  schemaVersion: z.literal(1),
  operationId: id,
  rotationId: id,
  recoveryId: id,
  fromRevision: z.literal('2'),
  revision: z.literal('3'),
  state: z.literal('PREPARED'),
  signerId: digest,
  trustDigest: digest,
  observationsDigest: digest,
  completedAt: instant,
});
export const identityEnvelopeRecoveryRotationDistributionResult =
  identityEnvelopeRecoveryRotationPrepareResult.extend({
    fromRevision: z.literal('3'),
    revision: z.literal('4'),
    state: z.literal('DISTRIBUTED'),
  });
export type IdentityEnvelopeRecoveryRotationPrepareResult = z.infer<
  typeof identityEnvelopeRecoveryRotationPrepareResult
>;
export type IdentityEnvelopeRecoveryRotationDistributionResult = z.infer<
  typeof identityEnvelopeRecoveryRotationDistributionResult
>;
export const identityEnvelopeRecoveryRotationVerificationResult =
  identityEnvelopeRecoveryRotationPrepareResult.extend({
    fromRevision: z.literal('4'),
    revision: z.literal('5'),
    state: z.literal('VERIFIED'),
    admissionState: z.literal('ADMITTED'),
  });
export type IdentityEnvelopeRecoveryRotationVerificationResult = z.infer<
  typeof identityEnvelopeRecoveryRotationVerificationResult
>;
export const identityEnvelopeRecoveryRotationCutoverResult =
  identityEnvelopeRecoveryRotationPrepareResult.extend({
    fromRevision: z.literal('5'),
    revision: z.literal('6'),
    state: z.literal('CUTOVER_FENCED'),
    selectionAdmissionVersion: positive,
    permissionEffect: z.literal('NONE'),
  });
export type IdentityEnvelopeRecoveryRotationCutoverResult = z.infer<
  typeof identityEnvelopeRecoveryRotationCutoverResult
>;
export const identityEnvelopeRecoveryRotationObservationResult =
  identityEnvelopeRecoveryRotationCutoverResult.extend({
    fromRevision: z.literal('6'),
    revision: z.literal('7'),
    state: z.literal('OBSERVING'),
    consumerActivationOperationId: id,
    consumerEnvelopeId: id,
    consumerPayloadDigest: digest,
    consumerReceiptDigest: digest,
  });
export type IdentityEnvelopeRecoveryRotationObservationResult = z.infer<
  typeof identityEnvelopeRecoveryRotationObservationResult
>;
export const identityEnvelopeRecoveryRotationRevocationResult =
  identityEnvelopeRecoveryRotationObservationResult.extend({
    fromRevision: z.literal('7'),
    revision: z.literal('8'),
    state: z.literal('OLD_REVOKED'),
    consumerObservationOperationId: id,
    predecessorSignerId: digest,
    oldPrivateKeyState: z.literal('REVOKED'),
    oldPrivateKeyRevokedAtNs: nanos,
    oldPrivateKeyRetiredAtNs: z.null(),
  });
export type IdentityEnvelopeRecoveryRotationRevocationResult = z.infer<
  typeof identityEnvelopeRecoveryRotationRevocationResult
>;
const identityEnvelopeRecoveryRotationRetirementShape =
  identityEnvelopeRecoveryRotationRevocationResult.extend({
    fromRevision: z.literal('8'),
    revision: z.literal('9'),
    state: z.literal('OLD_RETIRED'),
    oldPrivateKeyState: z.literal('RETIRED'),
    oldPrivateKeyRetiredAtNs: nanos,
  });
export const identityEnvelopeRecoveryRotationRetirementResult =
  identityEnvelopeRecoveryRotationRetirementShape.refine(
    (value) => BigInt(value.oldPrivateKeyRetiredAtNs) >= BigInt(value.oldPrivateKeyRevokedAtNs),
  );
export type IdentityEnvelopeRecoveryRotationRetirementResult = z.infer<
  typeof identityEnvelopeRecoveryRotationRetirementResult
>;
export const identityEnvelopeRecoveryRotationCompletionResult =
  identityEnvelopeRecoveryRotationRetirementShape
    .extend({
      fromRevision: z.literal('9'),
      revision: z.literal('10'),
      state: z.literal('COMPLETE'),
      postReviewRequired: z.literal(true),
    })
    .refine(
      (value) => BigInt(value.oldPrivateKeyRetiredAtNs) >= BigInt(value.oldPrivateKeyRevokedAtNs),
    );
export type IdentityEnvelopeRecoveryRotationCompletionResult = z.infer<
  typeof identityEnvelopeRecoveryRotationCompletionResult
>;
export const identityEnvelopeRecoveryRotationQueueView = z
  .strictObject({
    operationId: id,
    rotationId: id,
    recoveryId: id,
    fromRevision: positive,
    fromState: z.enum([
      'APPROVED',
      'PREPARED',
      'DISTRIBUTED',
      'VERIFIED',
      'CUTOVER_FENCED',
      'OBSERVING',
      'OLD_REVOKED',
      'OLD_RETIRED',
    ]),
    toState: z.enum([
      'PREPARED',
      'DISTRIBUTED',
      'VERIFIED',
      'CUTOVER_FENCED',
      'OBSERVING',
      'OLD_REVOKED',
      'OLD_RETIRED',
      'COMPLETE',
    ]),
    state: z.enum(['READY', 'STARTED', 'WRITE_AMBIGUITY', 'COMMITTED', 'FAILED']),
    replay: z.boolean(),
    authority,
    permissionEffect: z.literal('NONE'),
    result: z
      .union([
        identityEnvelopeRecoveryRotationPrepareResult,
        identityEnvelopeRecoveryRotationDistributionResult,
        identityEnvelopeRecoveryRotationVerificationResult,
        identityEnvelopeRecoveryRotationCutoverResult,
        identityEnvelopeRecoveryRotationObservationResult,
        identityEnvelopeRecoveryRotationRevocationResult,
        identityEnvelopeRecoveryRotationRetirementResult,
        identityEnvelopeRecoveryRotationCompletionResult,
      ])
      .optional(),
    attempts: z
      .array(
        z.strictObject({
          attemptId: id,
          method: z.enum(['PREPARE', 'DISTRIBUTE', 'PROVE', 'REVOKE', 'RETIRE']),
          state: z.enum(['READY', 'STARTED', 'WRITE_AMBIGUITY', 'OBSERVED']),
          ambiguityKind: z.enum(['LOOKUP_UNAVAILABLE', 'NOT_FOUND', 'UNKNOWN']).nullable(),
        }),
      )
      .min(0)
      .max(2),
  })
  .superRefine((value, ctx) => {
    if (
      !(
        (value.fromRevision === '2' &&
          value.fromState === 'APPROVED' &&
          value.toState === 'PREPARED' &&
          value.attempts.length === 1 &&
          value.attempts.every((a) => a.method === 'PREPARE')) ||
        (value.fromRevision === '3' &&
          value.fromState === 'PREPARED' &&
          value.toState === 'DISTRIBUTED' &&
          value.attempts.length === 1 &&
          value.attempts.every((a) => a.method === 'DISTRIBUTE')) ||
        (value.fromRevision === '4' &&
          value.fromState === 'DISTRIBUTED' &&
          value.toState === 'VERIFIED' &&
          value.attempts.length === 2 &&
          value.attempts.every((a) => a.method === 'PROVE') &&
          new Set(value.attempts.map((a) => a.attemptId)).size === 2) ||
        (value.fromRevision === '5' &&
          value.fromState === 'VERIFIED' &&
          value.toState === 'CUTOVER_FENCED' &&
          value.attempts.length === 0 &&
          value.state === 'COMMITTED') ||
        (value.fromRevision === '6' &&
          value.fromState === 'CUTOVER_FENCED' &&
          value.toState === 'OBSERVING' &&
          value.attempts.length === 1 &&
          value.attempts[0]?.method === 'PROVE') ||
        (value.fromRevision === '7' &&
          value.fromState === 'OBSERVING' &&
          value.toState === 'OLD_REVOKED' &&
          value.attempts.length === 1 &&
          value.attempts[0]?.method === 'REVOKE') ||
        (value.fromRevision === '8' &&
          value.fromState === 'OLD_REVOKED' &&
          value.toState === 'OLD_RETIRED' &&
          value.attempts.length === 1 &&
          value.attempts[0]?.method === 'RETIRE') ||
        (value.fromRevision === '9' &&
          value.fromState === 'OLD_RETIRED' &&
          value.toState === 'COMPLETE' &&
          value.attempts.length === 0 &&
          value.state === 'COMMITTED')
      ) ||
      (value.state === 'COMMITTED') !== (value.result !== undefined) ||
      (value.state === 'COMMITTED' &&
        value.attempts.some((attempt) => attempt.state !== 'OBSERVED')) ||
      (value.result &&
        (value.result.operationId !== value.operationId ||
          value.result.rotationId !== value.rotationId ||
          value.result.recoveryId !== value.recoveryId ||
          value.result.fromRevision !== value.fromRevision ||
          value.result.state !== value.toState))
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid signed rotation preparation result' });
  });
