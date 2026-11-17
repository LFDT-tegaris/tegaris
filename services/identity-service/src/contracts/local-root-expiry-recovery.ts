import { z } from 'zod';
import { identityEnvelopeRecoveryReceivingTrust } from './identity-envelope-recovery.js';
import {
  platformRecoverySigner,
  independentRecoveryEnrollmentCustody,
} from './platform-recovery.js';
import { envelopeScopeSchema } from '../../../participant-service/src/contracts/envelope.js';

const id = z.uuidv7();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n);
const instant = z.iso.datetime({ offset: true });
export const localRootExpiryRecoveryPurpose =
  'pc.installation.local-root-expiry-recovery-custody.v1' as const;
export const localRootExpiryRecoveryAuthority = 'LOCAL_ROOT_EXPIRY_RECOVERY_ONLY' as const;
export const localRootExpiryPendingRecoveryPurpose =
  'pc.installation.local-root-expiry-pending-recovery-custody.v2' as const;
export const localRootExpiryPendingRecoveryAuthority =
  'LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY' as const;
export const localRootExpiryPendingAncestryPurpose =
  'pc.installation.local-root-expiry-pending-ancestry-custody.v3' as const;
export const localRootExpiryPendingAncestryAuthority =
  'LOCAL_ROOT_EXPIRY_PENDING_ANCESTRY_RECOVERY_ONLY' as const;

/** Exact owning witness, never an acknowledgment or a replacement approval. */
export const localRootExpiryPendingWitness = z.strictObject({
  schema: z.literal('pc.identity.local-root-expiry-pending-witness'),
  schemaVersion: z.literal(1),
  replacementId: id,
  replacementRevision: revision,
  predecessorEpoch: revision,
  expectedRootRevision: revision,
  predecessorDigest: digest,
  preparationCandidateId: id,
  preparationOperationId: id,
  preparationApprovalId: id,
  preparationDigest: digest,
  preparationReceiptDigest: digest,
  successorDigest: digest,
  pendingRecordDigest: digest,
  administrationEffectsDigest: digest,
  affectedTargetCount: z.number().int().min(0).max(128),
  readinessDigest: digest,
});
export type LocalRootExpiryPendingWitness = z.infer<typeof localRootExpiryPendingWitness>;

/** Immutable completed receipt references are history, never fresh authority. */
export const localRootExpiryAncestryReceipt = z.strictObject({
  enrollmentId: id,
  recoveryId: id,
  activationOperationId: id,
  enrollmentDigest: digest,
  intentDigest: digest,
  receiptDigest: digest,
  predecessorEpoch: revision,
  predecessorRevision: revision,
  predecessorDigest: digest,
  rootEpoch: revision,
  rootRevision: revision,
  rootDigest: digest,
});
export const localRootExpiryPendingAncestry = z
  .strictObject({
    schema: z.literal('pc.identity.local-root-expiry-pending-ancestry'),
    schemaVersion: z.literal(1),
    rootEpoch: revision,
    rootRevision: revision,
    rootDigest: digest,
    receipts: z.array(localRootExpiryAncestryReceipt).min(1).max(32),
  })
  .superRefine((value, ctx) => {
    const ids = new Set<string>();
    for (const [index, receipt] of value.receipts.entries()) {
      const prior = value.receipts[index - 1];
      if (
        new Set([receipt.recoveryId, receipt.activationOperationId, receipt.enrollmentId]).size !==
          3 ||
        ids.has(receipt.recoveryId) ||
        ids.has(receipt.activationOperationId) ||
        ids.has(receipt.enrollmentId) ||
        BigInt(receipt.rootEpoch) !== BigInt(receipt.predecessorEpoch) + 1n ||
        BigInt(receipt.rootRevision) !== BigInt(receipt.predecessorRevision) + 1n ||
        (prior &&
          (prior.rootEpoch !== receipt.predecessorEpoch ||
            prior.rootRevision !== receipt.predecessorRevision ||
            prior.rootDigest !== receipt.predecessorDigest))
      )
        ctx.addIssue({ code: 'custom', message: 'Invalid ordered Root expiry receipt ancestry' });
      ids.add(receipt.recoveryId);
      ids.add(receipt.activationOperationId);
      ids.add(receipt.enrollmentId);
    }
    const last = value.receipts.at(-1);
    if (
      !last ||
      last.rootEpoch !== value.rootEpoch ||
      last.rootRevision !== value.rootRevision ||
      last.rootDigest !== value.rootDigest
    )
      ctx.addIssue({ code: 'custom', message: 'Root expiry ancestry does not end at its head' });
  });
export type LocalRootExpiryPendingAncestry = z.infer<typeof localRootExpiryPendingAncestry>;
function ancestryStartsAtPending(
  pending: LocalRootExpiryPendingWitness,
  ancestry: LocalRootExpiryPendingAncestry,
) {
  const first = ancestry.receipts[0];
  return (
    !!first &&
    first.predecessorEpoch === pending.predecessorEpoch &&
    first.predecessorRevision === pending.expectedRootRevision &&
    first.predecessorDigest === pending.predecessorDigest
  );
}
export const localRootExpiryPendingAncestryWitness = z
  .strictObject({
    pending: localRootExpiryPendingWitness,
    rootAncestry: localRootExpiryPendingAncestry,
  })
  .superRefine((value, ctx) => {
    if (!ancestryStartsAtPending(value.pending, value.rootAncestry))
      ctx.addIssue({
        code: 'custom',
        message: 'Root expiry ancestry does not start at the original pending preparation',
      });
  });

/** Deliberately local only. Existing production and normal replacement
 * authority is unchanged. Independent receiving trust is installed first. */
const localRootExpiryRecoveryReceivingTrustV1 = z
  .strictObject({
    ...identityEnvelopeRecoveryReceivingTrust.shape,
    schema: z.literal('pc.installation.local-root-expiry-recovery-receiving-trust'),
    purpose: z.literal(localRootExpiryRecoveryPurpose),
    profile: z.literal('LOCAL_QA'),
    qaDurationProfile: z.literal('LOCAL_QA_10X').optional(),
  })
  .superRefine((value, ctx) => {
    const { qaDurationProfile, ...legacyTrust } = value;
    if (
      !identityEnvelopeRecoveryReceivingTrust.safeParse({
        ...legacyTrust,
        schema: 'pc.installation.identity-envelope-recovery-receiving-trust',
        purpose: 'pc.installation.identity-envelope-repair-custody.v1',
      }).success
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid independent receiving trust' });
    if (
      Date.parse(value.validUntil) - Date.parse(value.validFrom) >
      (qaDurationProfile ? 864000000 : 86400000)
    )
      ctx.addIssue({ code: 'custom', message: 'Local receiving trust exceeds one day' });
  });

const localRootExpiryRecoveryEnrollmentV1 = z
  .strictObject({
    schema: z.literal('pc.identity.local-root-expiry-recovery-enrollment'),
    schemaVersion: z.literal(1),
    purpose: z.literal(localRootExpiryRecoveryPurpose),
    enrollmentId: id,
    participantId: id,
    privacyDomainId: id,
    platformContextId: id,
    rootEpoch: revision.refine((v) => BigInt(v) < 18446744073709551615n),
    rootRevision: revision,
    rootDigest: digest,
    custodyTrustId: id,
    custodyTrustDigest: digest,
    custodyIssuerKeyId: digest,
    custodyIssuerEpoch: revision,
    installationDigest: digest,
    installationEnvironmentId: z.string().min(1).max(160),
    profile: z.literal('LOCAL_QA'),
    qaDurationProfile: z.literal('LOCAL_QA_10X').optional(),
    administratorPrincipalIds: z.tuple([id, id]),
    recoveryPrincipal: platformRecoverySigner,
    custodians: z.tuple([platformRecoverySigner, platformRecoverySigner]),
    // Signed custody approves exact new validity; the source owner supplies all dimensions.
    successorValidFrom: instant,
    successorValidUntil: instant,
    validFrom: instant,
    validUntil: instant,
    assurance: z.enum(['HARDWARE_ATTESTED', 'LOCAL_QA_VIRTUAL_AUTHENTICATOR']),
  })
  .superRefine((value, ctx) => {
    const duration = Date.parse(value.successorValidUntil) - Date.parse(value.successorValidFrom);
    if (
      !independentRecoveryEnrollmentCustody(value) ||
      duration <= 0 ||
      duration > (value.qaDurationProfile ? 864000000 : 86400000) ||
      Date.parse(value.successorValidFrom) < Date.parse(value.validFrom) ||
      Date.parse(value.successorValidUntil) > Date.parse(value.validUntil) ||
      Date.parse(value.validUntil) - Date.parse(value.validFrom) >
        (value.qaDurationProfile ? 864000000 : 86400000)
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid bounded local Root expiry custody' });
  });
const localRootExpiryRecoveryReceivingTrustV2 = z
  .strictObject({
    ...localRootExpiryRecoveryReceivingTrustV1.shape,
    schemaVersion: z.literal(2),
    purpose: z.literal(localRootExpiryPendingRecoveryPurpose),
    pending: localRootExpiryPendingWitness,
  })
  .superRefine((value, ctx) => {
    const { pending: _pending, ...base } = value;
    void _pending;
    if (
      !localRootExpiryRecoveryReceivingTrustV1.safeParse({
        ...base,
        schemaVersion: 1,
        purpose: localRootExpiryRecoveryPurpose,
      }).success
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid pending recovery trust' });
  });
const localRootExpiryRecoveryEnrollmentV2 = z
  .strictObject({
    ...localRootExpiryRecoveryEnrollmentV1.shape,
    schemaVersion: z.literal(2),
    purpose: z.literal(localRootExpiryPendingRecoveryPurpose),
    pending: localRootExpiryPendingWitness,
  })
  .superRefine((value, ctx) => {
    const { pending: _pending, ...base } = value;
    void _pending;
    if (
      !localRootExpiryRecoveryEnrollmentV1.safeParse({
        ...base,
        schemaVersion: 1,
        purpose: localRootExpiryRecoveryPurpose,
      }).success ||
      value.pending.predecessorEpoch !== value.rootEpoch ||
      value.pending.expectedRootRevision !== value.rootRevision ||
      value.pending.predecessorDigest !== value.rootDigest
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid pending recovery custody' });
  });
const localRootExpiryRecoveryReceivingTrustV3 = z
  .strictObject({
    ...localRootExpiryRecoveryReceivingTrustV1.shape,
    schemaVersion: z.literal(3),
    purpose: z.literal(localRootExpiryPendingAncestryPurpose),
    ...localRootExpiryPendingAncestryWitness.shape,
  })
  .superRefine((value, ctx) => {
    const { pending, rootAncestry, ...base } = value;
    if (
      !localRootExpiryRecoveryReceivingTrustV1.safeParse({
        ...base,
        schemaVersion: 1,
        purpose: localRootExpiryRecoveryPurpose,
      }).success ||
      !localRootExpiryPendingAncestryWitness.safeParse({ pending, rootAncestry }).success
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Invalid independently governed pending ancestry trust',
      });
  });
const localRootExpiryRecoveryEnrollmentV3 = z
  .strictObject({
    ...localRootExpiryRecoveryEnrollmentV1.shape,
    schemaVersion: z.literal(3),
    purpose: z.literal(localRootExpiryPendingAncestryPurpose),
    ...localRootExpiryPendingAncestryWitness.shape,
  })
  .superRefine((value, ctx) => {
    const { pending, rootAncestry, ...base } = value;
    if (
      !localRootExpiryRecoveryEnrollmentV1.safeParse({
        ...base,
        schemaVersion: 1,
        purpose: localRootExpiryRecoveryPurpose,
      }).success ||
      !localRootExpiryPendingAncestryWitness.safeParse({ pending, rootAncestry }).success ||
      rootAncestry.rootEpoch !== value.rootEpoch ||
      rootAncestry.rootRevision !== value.rootRevision ||
      rootAncestry.rootDigest !== value.rootDigest
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid current Root pending ancestry custody' });
  });
export const localRootExpiryRecoveryReceivingTrust = z.union([
  localRootExpiryRecoveryReceivingTrustV1,
  localRootExpiryRecoveryReceivingTrustV2,
  localRootExpiryRecoveryReceivingTrustV3,
]);
export const localRootExpiryRecoveryEnrollment = z.union([
  localRootExpiryRecoveryEnrollmentV1,
  localRootExpiryRecoveryEnrollmentV2,
  localRootExpiryRecoveryEnrollmentV3,
]);
export type LocalRootExpiryRecoveryEnrollment = z.infer<typeof localRootExpiryRecoveryEnrollment>;
export const signedLocalRootExpiryRecoveryEnrollment = z.strictObject({
  document: localRootExpiryRecoveryEnrollment,
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/u),
});
const localRootExpiryRecoveryIntentV1 = z
  .strictObject({
    schema: z.literal('pc.identity.local-root-expiry-recovery-intent'),
    schemaVersion: z.literal(1),
    purpose: z.literal(localRootExpiryRecoveryAuthority),
    recoveryId: id,
    enrollmentId: id,
    enrollmentRevision: revision,
    enrollmentDigest: digest,
    sourceParticipantEpoch: revision,
    predecessorEpoch: revision,
    predecessorRevision: revision,
    predecessorDigest: digest,
    qaDurationProfile: z.literal('LOCAL_QA_10X').optional(),
    successorScope: envelopeScopeSchema,
    validFrom: instant,
    validUntil: instant,
  })
  .superRefine((value, ctx) => {
    const duration = Date.parse(value.validUntil) - Date.parse(value.validFrom);
    if (duration <= 0 || duration > (value.qaDurationProfile ? 172800000 : 900000))
      ctx.addIssue({ code: 'custom', message: 'Recovery proposal exceeds fifteen minutes' });
  });
const localRootExpiryRecoveryIntentV2 = z
  .strictObject({
    ...localRootExpiryRecoveryIntentV1.shape,
    schemaVersion: z.literal(2),
    purpose: z.literal(localRootExpiryPendingRecoveryAuthority),
    pending: localRootExpiryPendingWitness,
  })
  .superRefine((value, ctx) => {
    const { pending: _pending, ...base } = value;
    void _pending;
    if (
      !localRootExpiryRecoveryIntentV1.safeParse({
        ...base,
        schemaVersion: 1,
        purpose: localRootExpiryRecoveryAuthority,
      }).success ||
      value.pending.predecessorEpoch !== value.predecessorEpoch ||
      value.pending.expectedRootRevision !== value.predecessorRevision ||
      value.pending.predecessorDigest !== value.predecessorDigest
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid pending recovery intent' });
  });
const localRootExpiryRecoveryIntentV3 = z
  .strictObject({
    ...localRootExpiryRecoveryIntentV1.shape,
    schemaVersion: z.literal(3),
    purpose: z.literal(localRootExpiryPendingAncestryAuthority),
    ...localRootExpiryPendingAncestryWitness.shape,
  })
  .superRefine((value, ctx) => {
    const { pending, rootAncestry, ...base } = value;
    if (
      !localRootExpiryRecoveryIntentV1.safeParse({
        ...base,
        schemaVersion: 1,
        purpose: localRootExpiryRecoveryAuthority,
      }).success ||
      !localRootExpiryPendingAncestryWitness.safeParse({ pending, rootAncestry }).success ||
      rootAncestry.rootEpoch !== value.predecessorEpoch ||
      rootAncestry.rootRevision !== value.predecessorRevision ||
      rootAncestry.rootDigest !== value.predecessorDigest
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Invalid exact current Root pending ancestry intent',
      });
  });
export const localRootExpiryRecoveryIntent = z.union([
  localRootExpiryRecoveryIntentV1,
  localRootExpiryRecoveryIntentV2,
  localRootExpiryRecoveryIntentV3,
]);
export type LocalRootExpiryRecoveryIntent = z.infer<typeof localRootExpiryRecoveryIntent>;
const actors = z.strictObject({
  executorPrincipalId: id,
  custodianPrincipalIds: z.tuple([id, id]),
});
export const localRootExpiryRecoverySourceView = z.strictObject({
  enrollmentId: id,
  purpose: z.enum([
    localRootExpiryRecoveryAuthority,
    localRootExpiryPendingRecoveryAuthority,
    localRootExpiryPendingAncestryAuthority,
  ]),
  authority: z.literal('NONE'),
  actors,
  assurance: localRootExpiryRecoveryEnrollmentV1.shape.assurance,
  source: z.strictObject({
    rootEpoch: revision,
    rootRevision: revision,
    rootDigest: digest,
    expiredAt: instant,
    pending: localRootExpiryPendingWitness.optional(),
    rootAncestry: localRootExpiryPendingAncestry.optional(),
  }),
  successorScope: envelopeScopeSchema,
  liveCase: z.strictObject({ recoveryId: id, state: z.enum(['DRAFT', 'REQUESTED']) }).nullable(),
});
export const localRootExpiryRecoveryDraftView = z.strictObject({
  intent: localRootExpiryRecoveryIntent,
  intentDigest: digest,
  state: z.literal('DRAFT'),
  authority: z.literal('NONE'),
  assurance: localRootExpiryRecoveryEnrollmentV1.shape.assurance,
});
export const localRootExpiryRecoveryReceiptView = z.strictObject({
  actors,
  recoveryId: id,
  enrollmentId: id,
  purpose: z.enum([
    localRootExpiryRecoveryAuthority,
    localRootExpiryPendingRecoveryAuthority,
    localRootExpiryPendingAncestryAuthority,
  ]),
  intent: localRootExpiryRecoveryIntent,
  intentDigest: digest,
  revision,
  state: z.enum(['DRAFT', 'REQUESTED', 'COMPLETED', 'REVOKED', 'EXPIRED']),
  authority: z.literal('NONE'),
  assurance: localRootExpiryRecoveryEnrollmentV1.shape.assurance,
  proofs: z
    .array(
      z.strictObject({
        principalId: id,
        phase: z.enum(['REQUEST', 'APPROVE', 'ACTIVATE']),
        proofId: id,
      }),
    )
    .max(4),
  result: z
    .strictObject({
      rootEpoch: revision,
      rootRevision: revision,
      rootDigest: digest,
      operationId: id,
    })
    .nullable(),
});
