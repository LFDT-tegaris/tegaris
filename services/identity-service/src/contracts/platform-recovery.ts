import { z } from 'zod';
import {
  recoveryLifetimeLimits,
  recoveryLifetimeSettings,
} from '../domain/platform-recovery-lifetimes.js';
import {
  platformScopeReplacementPreparation,
  platformSuccessorAdministrator,
} from '../../../participant-service/src/contracts/platform-scope-replacement.js';

const id = z.uuidv7();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n);
const epoch = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n);
const instant = z.iso.datetime({ offset: true });

export const platformRecoverySigner = z.strictObject({
  principalId: id,
  credentialId: id,
  principalEpoch: epoch,
  credentialEpoch: epoch,
});

/** Shared structural custody rule; purpose schemas remain distinct. */
export function independentRecoveryEnrollmentCustody(value: {
  readonly administratorPrincipalIds: readonly string[];
  readonly recoveryPrincipal: { readonly principalId: string; readonly credentialId: string };
  readonly custodians: readonly { readonly principalId: string; readonly credentialId: string }[];
  readonly validFrom: string;
  readonly validUntil: string;
}) {
  const actors = [value.recoveryPrincipal, ...value.custodians];
  const principals = [...value.administratorPrincipalIds, ...actors.map((v) => v.principalId)];
  return (
    new Set(principals).size === 5 &&
    new Set(actors.map((v) => v.credentialId)).size === 3 &&
    Date.parse(value.validUntil) > Date.parse(value.validFrom)
  );
}

/** Installation-owner enrollment, not a custom role or a live administration grant. */
export const expiredPlatformRecoveryEnrollment = z
  .strictObject({
    schema: z.literal('pc.identity.platform-recovery-enrollment'),
    schemaVersion: z.literal(1),
    enrollmentId: id,
    platformContextId: id,
    participantId: id,
    privacyDomainId: id,
    rootEpoch: revision,
    rootRevision: revision,
    rootDigest: digest,
    expiredReplacementId: id,
    administratorPrincipalIds: z.tuple([id, id]),
    recoveryPrincipal: platformRecoverySigner,
    custodians: z.tuple([platformRecoverySigner, platformRecoverySigner]),
    validFrom: instant,
    validUntil: instant,
    assurance: z.enum(['HARDWARE_ATTESTED', 'LOCAL_QA_VIRTUAL_AUTHENTICATOR']),
  })
  .superRefine((value, ctx) => {
    if (!independentRecoveryEnrollmentCustody(value))
      ctx.addIssue({ code: 'custom', message: 'Recovery enrollment requires independent custody' });
  });

/** Exact immutable receipt reference; ordered ancestors never substitute for the current Root. */
const rootExpiryReceiptReference = z.strictObject({
  recoveryId: id,
  enrollmentId: id,
  activationOperationId: id,
  receiptDigest: digest,
});
/** This source names a real signed Root-expiry receipt, never a normal replacement. */
export const platformRecoveryRootExpirySource = z.strictObject({
  kind: z.literal('ROOT_EXPIRY_RECOVERY'),
  ...rootExpiryReceiptReference.shape,
  ancestorReceipts: z.array(rootExpiryReceiptReference).min(1).max(31).optional(),
  originalAdministrators: z.tuple([
    platformSuccessorAdministrator.safeExtend({
      envelopeId: z.uuid(),
      assignmentId: z.uuid(),
      envelopeRevision: revision,
      assignmentRevision: revision,
    }),
    platformSuccessorAdministrator.safeExtend({
      envelopeId: z.uuid(),
      assignmentId: z.uuid(),
      envelopeRevision: revision,
      assignmentRevision: revision,
    }),
  ]),
});
const platformRecoveryCustodyShape = z
  .strictObject(expiredPlatformRecoveryEnrollment.shape)
  .omit({ expiredReplacementId: true }).shape;
type RootReceiptEnrollmentCustody = Omit<
  z.infer<typeof expiredPlatformRecoveryEnrollment>,
  'expiredReplacementId' | 'schemaVersion'
> & { schemaVersion: 2 | 3 | 4; source: z.infer<typeof platformRecoveryRootExpirySource> };
function assertRootReceiptEnrollmentCustody(
  value: RootReceiptEnrollmentCustody,
  ctx: z.RefinementCtx,
) {
  if (
    !independentRecoveryEnrollmentCustody(value) ||
    value.source.originalAdministrators.some(
      (v, i) => v.principalId !== value.administratorPrincipalIds[i],
    ) ||
    new Set(value.source.originalAdministrators.flatMap((v) => [v.envelopeId, v.assignmentId]))
      .size !== 4 ||
    ['recoveryId', 'enrollmentId', 'activationOperationId'].some((field) => {
      const references = [value.source, ...(value.source.ancestorReceipts ?? [])];
      return (
        new Set(references.map((v) => v[field as keyof typeof rootExpiryReceiptReference.shape]))
          .size !== references.length
      );
    }) ||
    Date.parse(value.validUntil) - Date.parse(value.validFrom) >
      (value.assurance === 'LOCAL_QA_VIRTUAL_AUTHENTICATOR'
        ? recoveryLifetimeLimits.qa10RootEnrollmentMs
        : recoveryLifetimeLimits.rootEnrollmentMs)
  )
    ctx.addIssue({ code: 'custom', message: 'Invalid bounded Root receipt recovery custody' });
}
/** Fresh authorization for exactly one already-effected pending handoff.
 * These references preserve historical authority; they never renew its signed lease. */
export const platformRecoveryContinuation = z.strictObject({
  schema: z.literal('pc.identity.platform-pending-recovery-continuation'),
  schemaVersion: z.literal(1),
  enrollmentId: id,
  recoveryId: id,
  intentDigest: digest,
  activationOperationId: id,
  activationReceiptDigest: digest,
  replacementId: id,
  preparationCandidateId: id,
  preparationDigest: digest,
  preparationOperationId: id,
  preparationApprovalId: id,
  expectedRevision: z.literal('1'),
  successorDigest: digest,
});
/** Historical evidence for a handoff that created no administrator grant.
 * Its expired enrollment and approval never supply current authority. */
export const platformRecoveryUneffectedPredecessor = platformRecoveryContinuation.extend({
  schema: z.literal('pc.identity.platform-expired-uneffected-recovery'),
});
export const rootExpiryPlatformRecoveryEnrollment = z
  .strictObject({
    ...platformRecoveryCustodyShape,
    schemaVersion: z.literal(2),
    source: platformRecoveryRootExpirySource,
    uneffectedPredecessor: platformRecoveryUneffectedPredecessor.optional(),
  })
  .superRefine(assertRootReceiptEnrollmentCustody)
  .superRefine((value, ctx) => {
    const previous = value.uneffectedPredecessor;
    if (
      previous &&
      (previous.enrollmentId === value.enrollmentId ||
        previous.recoveryId === value.source.recoveryId ||
        previous.activationOperationId === value.source.activationOperationId)
    )
      ctx.addIssue({ code: 'custom', message: 'Uneffected recovery requires distinct custody' });
  });
/** Exact historical effects of a terminally expired partial handoff. These
 * declarations are witnesses, never permission or proof of provider absence. */
const partialAdministratorEffect = z.discriminatedUnion('state', [
  z.strictObject({ state: z.literal('ABSENT') }),
  z.strictObject({
    state: z.literal('APPROVED_PROPOSAL'),
    proposalEnvelopeId: id,
    proposalRevision: z.literal('3'),
    proposalDigest: digest,
    createCandidateId: id,
    createApprovalId: id,
    createOperationId: id,
    activationCandidateId: id,
    activationApprovalId: id,
    activationCandidateDigest: digest,
    activationAttempt: revision,
  }),
]);
const legacyPendingAdministrationExpiry = z.strictObject({
  schema: z.literal('pc.identity.platform-pending-administration-expiry'),
  schemaVersion: z.literal(1),
  preparation: platformRecoveryContinuation,
  administrators: z.tuple([
    z.strictObject({
      principalId: id,
      envelopeId: id,
      assignmentId: id,
      effect: partialAdministratorEffect,
    }),
    z.strictObject({
      principalId: id,
      envelopeId: id,
      assignmentId: id,
      effect: partialAdministratorEffect,
    }),
  ]),
});
/** A separately signed witness for one consumed activation with no assignment.
 * Historical dates and signatures are evidence only; successor authority is fresh. */
export const activatedPendingAdministrationExpiry = z.strictObject({
  schema: z.literal('pc.identity.platform-pending-administration-expiry'),
  schemaVersion: z.literal(2),
  predecessorEnrollmentDigest: digest,
  predecessorClosedApprovalDigest: digest,
  preparation: platformRecoveryContinuation,
  administrators: z.tuple([
    z.strictObject({
      principalId: id,
      envelopeId: id,
      assignmentId: id,
      effect: z.strictObject({
        state: z.literal('ACTIVE_UNASSIGNED'),
        proposalEnvelopeId: id,
        proposalRevision: z.literal('3'),
        envelopeRevision: z.literal('4'),
        proposalDigest: digest,
        createCandidateId: id,
        createApprovalId: id,
        createOperationId: id,
        activationCandidateId: id,
        activationApprovalId: id,
        activationCandidateDigest: digest,
        activationAttempt: revision,
        activationOperationId: id,
        activationAttemptId: id,
        activationEvidenceDigest: digest,
        activationPayloadDigest: digest,
      }),
    }),
    z.strictObject({
      principalId: id,
      envelopeId: id,
      assignmentId: id,
      effect: z.strictObject({ state: z.literal('ABSENT') }),
    }),
  ]),
});
/** Distinct from schema2 enrollment and uneffected supersession. */
export const pendingPlatformRecoveryEnrollment = z
  .strictObject({
    ...platformRecoveryCustodyShape,
    schemaVersion: z.literal(3),
    source: platformRecoveryRootExpirySource.extend({
      continuation: platformRecoveryContinuation,
      activatedHandoff: z
        .strictObject({
          schemaVersion: z.literal(1),
          predecessorEnrollmentDigest: digest,
          administrators: activatedPendingAdministrationExpiry.shape.administrators,
        })
        .optional(),
    }),
  })
  .superRefine(assertRootReceiptEnrollmentCustody)
  .superRefine((value, ctx) => {
    if (
      value.source.continuation.enrollmentId === value.enrollmentId ||
      value.source.continuation.recoveryId === value.source.recoveryId ||
      value.source.continuation.activationOperationId === value.source.activationOperationId
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Pending continuation must preserve distinct original custody',
      });
  });

export const platformPendingAdministrationExpiry = z.discriminatedUnion('schemaVersion', [
  legacyPendingAdministrationExpiry,
  activatedPendingAdministrationExpiry,
]);

/** A single closed initial approval may cross an enrollment boundary only with
 * the exact signed closure and original enrollment. This is historical evidence,
 * never a lease extension or an authorization to repeat the original command. */
export const platformRecoveryApprovalContinuation = z.strictObject({
  schema: z.literal('pc.identity.platform-prepare-approval-continuation'),
  schemaVersion: z.literal(1),
  recoveryId: id,
  intentDigest: digest,
  activationOperationId: id,
  activationReceiptDigest: digest,
  candidateId: id,
  approvalId: id,
  candidateDigest: digest,
  businessKey: z.string().min(16).max(128),
  attempt: revision,
});
export const platformRecoveryClosedApprovalSource = z.strictObject({
  schema: z.literal('pc.identity.closed-platform-approval-source'),
  schemaVersion: z.literal(1),
  enrollmentId: id,
  enrollmentDigest: digest,
  approval: platformRecoveryApprovalContinuation,
  closure: z.strictObject({
    eventId: id,
    evidenceDigest: digest,
    operationId: id,
    state: z.enum(['REVOKED', 'EXPIRED']),
    revision,
    actorPrincipalId: id,
    closedAt: instant,
    session: z.union([
      z.strictObject({ sessionId: id, sessionEpoch: epoch }),
      z.strictObject({
        sessionId: id,
        sessionEpoch: epoch,
        durationProfile: z.enum(['C17', 'LOCAL_QA', 'LOCAL_QA_10X']),
        expiresAt: instant,
      }),
    ]),
  }),
});
export const pendingExpiryPlatformRecoveryEnrollment = z
  .strictObject({
    ...platformRecoveryCustodyShape,
    schemaVersion: z.literal(4),
    source: platformRecoveryRootExpirySource.extend({
      pendingExpiry: platformPendingAdministrationExpiry,
      closedApproval: platformRecoveryClosedApprovalSource.optional(),
    }),
  })
  .superRefine(assertRootReceiptEnrollmentCustody)
  .superRefine((value, ctx) => {
    const witness = value.source.pendingExpiry;
    const closed = value.source.closedApproval;
    if (witness.schemaVersion === 2 && closed)
      ctx.addIssue({ code: 'custom', message: 'Activated handoff cannot resume a prior approval' });
    if (
      closed &&
      (closed.enrollmentId === value.enrollmentId ||
        closed.approval.recoveryId === value.source.recoveryId ||
        closed.approval.attempt !== '1' ||
        BigInt(closed.closure.revision) < 2n ||
        Date.parse(closed.closure.closedAt) > Date.parse(value.validFrom) ||
        ![
          value.recoveryPrincipal.principalId,
          ...value.custodians.map((v) => v.principalId),
        ].includes(closed.closure.actorPrincipalId))
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid exact closed approval source' });
    if (
      witness.preparation.enrollmentId === value.enrollmentId ||
      witness.preparation.recoveryId === value.source.recoveryId ||
      witness.preparation.activationOperationId === value.source.activationOperationId ||
      witness.administrators.some(
        (admin, index) => admin.principalId !== value.administratorPrincipalIds[index],
      ) ||
      new Set(witness.administrators.flatMap((admin) => [admin.envelopeId, admin.assignmentId]))
        .size !== 4 ||
      (witness.schemaVersion === 1 &&
        witness.administrators.filter((admin) => admin.effect.state === 'APPROVED_PROPOSAL')
          .length !== 1)
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Expiry recovery requires the exact partial predecessor',
      });
  });
/** Preserve the original expired-replacement contract for purpose extensions. */
export const platformRecoveryEnrollment = expiredPlatformRecoveryEnrollment;
export const platformAdministrationRecoveryEnrollment = z.discriminatedUnion('schemaVersion', [
  expiredPlatformRecoveryEnrollment,
  rootExpiryPlatformRecoveryEnrollment,
  pendingPlatformRecoveryEnrollment,
  pendingExpiryPlatformRecoveryEnrollment,
]);

export const platformRecoveryApprovalResumeReason =
  'Resume the original unconsumed Platform administrator handoff under fresh independent recovery custody.';
export const platformRecoveryApprovalResumePurpose = z.strictObject({
  command: z.literal('RESUME'),
  actionIntentId: z.literal('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'),
  actionIntentDigest: digest,
  expectedRevision: revision,
  predecessorCandidateId: id,
  expectedAttempt: revision,
  candidateDigest: digest,
  reason: z.literal(platformRecoveryApprovalResumeReason),
  approvalRequestId: z
    .string()
    .regex(
      /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    ),
});

export const platformRecoverySupersession = z.strictObject({
  recoveryId: id,
  intentDigest: digest,
  replacementId: id,
  preparationDigest: digest,
  preparationOperationId: id,
  preparationApprovalId: id,
  expectedRevision: z.literal('1'),
  successorDigest: digest,
});

/** A proposed lease authorizes no effect until its three independent proofs are verified. */
export const platformRecoveryIntent = z
  .strictObject({
    schema: z.literal('pc.identity.platform-recovery-intent'),
    schemaVersion: z.literal(1),
    recoveryId: id,
    enrollmentId: id,
    enrollmentRevision: revision,
    enrollmentDigest: digest,
    validFrom: instant,
    validUntil: instant,
    administratorEpochs: z.tuple([
      z.strictObject({ principalId: id, principalEpoch: epoch }),
      z.strictObject({ principalId: id, principalEpoch: epoch }),
    ]),
    preparation: platformScopeReplacementPreparation,
    lifetimes: recoveryLifetimeSettings.optional(),
    supersession: platformRecoverySupersession.optional(),
    continuation: platformRecoveryContinuation.optional(),
    pendingExpiry: platformPendingAdministrationExpiry.optional(),
    approvalContinuation: platformRecoveryApprovalContinuation.optional(),
    closedApprovalSourceDigest: digest.optional(),
    completionSourceDigest: digest.optional(),
  })
  .superRefine((value, ctx) => {
    if (
      value.pendingExpiry?.schemaVersion === 2 &&
      (value.approvalContinuation || value.closedApprovalSourceDigest)
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Activated handoff requires new ordinary approvals',
      });
    if (
      value.completionSourceDigest &&
      (!value.continuation ||
        value.pendingExpiry ||
        value.approvalContinuation ||
        value.closedApprovalSourceDigest ||
        value.supersession)
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Completion requires the unchanged pending handoff',
      });
    if (value.closedApprovalSourceDigest && !value.approvalContinuation)
      ctx.addIssue({
        code: 'custom',
        message: 'Closed source requires exact approval continuation',
      });
    if (
      value.approvalContinuation &&
      (!value.pendingExpiry ||
        value.continuation ||
        value.supersession ||
        value.approvalContinuation.recoveryId === value.recoveryId)
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Approval continuation requires distinct exact pending-expiry custody',
      });
    if (
      value.continuation &&
      (value.supersession ||
        value.pendingExpiry ||
        (!value.completionSourceDigest && value.preparation.supersedes) ||
        value.continuation.replacementId !== value.preparation.replacementId ||
        value.continuation.recoveryId === value.recoveryId ||
        value.continuation.enrollmentId === value.enrollmentId)
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Continuation preserves the same pending business lineage',
      });
    if (
      value.pendingExpiry &&
      (value.continuation ||
        value.supersession ||
        value.preparation.supersedes?.replacementId !==
          value.pendingExpiry.preparation.replacementId ||
        value.preparation.supersedes.expectedRevision !==
          value.pendingExpiry.preparation.expectedRevision ||
        value.preparation.supersedes.successorDigest !==
          value.pendingExpiry.preparation.successorDigest ||
        value.preparation.replacementId === value.pendingExpiry.preparation.replacementId)
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Expiry renewal requires a distinct linked preparation',
      });
  });

export type PlatformRecoveryApprovalContinuation = z.infer<
  typeof platformRecoveryApprovalContinuation
>;
export type PlatformRecoveryContinuation = z.infer<typeof platformRecoveryContinuation>;
export type PendingPlatformRecoveryEnrollment = z.infer<typeof pendingPlatformRecoveryEnrollment>;
export type PendingExpiryPlatformRecoveryEnrollment = z.infer<
  typeof pendingExpiryPlatformRecoveryEnrollment
>;
export type PlatformPendingAdministrationExpiry = z.infer<
  typeof platformPendingAdministrationExpiry
>;
export type PlatformRecoveryEnrollment = z.infer<typeof platformRecoveryEnrollment>;
export type RootExpiryPlatformRecoveryEnrollment = z.infer<
  typeof rootExpiryPlatformRecoveryEnrollment
>;
export type PlatformAdministrationRecoveryEnrollment = z.infer<
  typeof platformAdministrationRecoveryEnrollment
>;
export type PlatformRecoveryIntent = z.infer<typeof platformRecoveryIntent>;
export type PlatformRecoverySigner = z.infer<typeof platformRecoverySigner>;

const caseScope = { recoveryId: id };
const phase = z.enum(['REQUEST', 'APPROVE', 'ACTIVATE']);
export const platformRecoveryAdministrationCommand = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('SOURCE') }),
  z.strictObject({ kind: z.literal('CREATE'), preparation: platformScopeReplacementPreparation }),
  z.strictObject({ kind: z.literal('READ'), ...caseScope }),
  z.strictObject({ kind: z.literal('CLOSE'), ...caseScope }),
  z.strictObject({ kind: z.literal('CHALLENGE'), ...caseScope, phase }),
  z.strictObject({
    kind: z.literal('PROVE'),
    ...caseScope,
    phase,
    proof: z.strictObject({
      challengeId: id,
      challenge: z.string().min(32).max(256),
      intentDigest: digest,
      assertion: z.string().min(16).max(16384),
    }),
  }),
]);

// Empty CREATE is admitted only by the authenticated stored signer-repair owner.
export const platformRecoveryCommand = z.union([
  platformRecoveryAdministrationCommand,
  z.strictObject({ kind: z.literal('READ'), ...caseScope, preparationDigest: digest }),
  z.strictObject({ kind: z.literal('CREATE') }),
  z.strictObject({ kind: z.literal('ROTATION_CREATE'), ...caseScope }),
  z.strictObject({
    kind: z.literal('ROTATION_ADVANCE'),
    ...caseScope,
    expectedRevision: z.string().regex(/^[1-9][0-9]{0,18}$/u),
    idempotencyKey: z.string().min(16).max(128),
  }),
]);

/** Separate Platform extension: no Participant recovery inference or ordinary role substitution. */
export const platformRecoveryOperations = [
  {
    id: 'ID-OP-PLATFORM-RECOVERY-SOURCE',
    command: 'SOURCE',
    authority: 'ENROLLED_ACTOR_OR_SUBJECT_ONLY',
  },
  { id: 'ID-OP-PLATFORM-RECOVERY-CREATE', command: 'CREATE', authority: 'ENROLLED_EXECUTOR_ONLY' },
  {
    id: 'ID-OP-PLATFORM-RECOVERY-ROTATION-CREATE',
    command: 'ROTATION_CREATE',
    authority: 'EXACT_SIGNED_SIGNER_LEASE_EXECUTOR_ONLY',
  },
  {
    id: 'ID-OP-PLATFORM-RECOVERY-ROTATION-ADVANCE',
    command: 'ROTATION_ADVANCE',
    authority: 'EXACT_SIGNED_SIGNER_LEASE_EXECUTOR_ONLY',
  },
  {
    id: 'ID-OP-PLATFORM-RECOVERY-READ',
    command: 'READ',
    authority: 'ENROLLED_ACTOR_OR_SUBJECT_ONLY',
  },
  {
    id: 'ID-OP-PLATFORM-RECOVERY-CHALLENGE',
    command: 'CHALLENGE',
    authority: 'ENROLLED_PHASE_ACTOR_ONLY',
  },
  {
    id: 'ID-OP-PLATFORM-RECOVERY-PROVE',
    command: 'PROVE',
    authority: 'FRESH_WEBAUTHN_UV_AND_ENROLLED_PHASE_ACTOR',
  },
  {
    id: 'ID-OP-PLATFORM-RECOVERY-CLOSE',
    command: 'CLOSE',
    authority: 'ENROLLED_EXECUTOR_OR_CUSTODIAN_ONLY',
  },
] as const;

const assurance = expiredPlatformRecoveryEnrollment.shape.assurance;
const binding = z.strictObject({
  principalId: id,
  principalEpoch: epoch,
  envelopeId: id,
  assignmentId: id,
});
export const platformRecoverySourceView = z
  .strictObject({
    enrollmentId: id,
    assurance,
    authority: z.literal('NONE'),
    proposalBefore: instant,
    lifetimes: recoveryLifetimeSettings.optional(),
    supersession: platformRecoverySupersession.optional(),
    continuation: platformRecoveryContinuation.optional(),
    pendingExpiry: platformPendingAdministrationExpiry.optional(),
    approvalContinuation: platformRecoveryApprovalContinuation.optional(),
    source: z.union([
      z.strictObject({
        platformContextId: id,
        rootEpoch: revision,
        rootRevision: revision,
        rootDigest: digest,
        expiredReplacementId: id,
        executorPrincipalId: id,
        custodianPrincipalIds: z.tuple([id, id]),
        administratorPrincipalIds: z.tuple([id, id]),
      }),
      z.strictObject({
        platformContextId: id,
        rootEpoch: revision,
        rootRevision: revision,
        rootDigest: digest,
        recoverySource: z.union([
          platformRecoveryRootExpirySource,
          pendingPlatformRecoveryEnrollment.shape.source,
          pendingExpiryPlatformRecoveryEnrollment.shape.source,
        ]),
        executorPrincipalId: id,
        custodianPrincipalIds: z.tuple([id, id]),
        administratorPrincipalIds: z.tuple([id, id]),
      }),
    ]),
    preparation: platformScopeReplacementPreparation,
  })
  .superRefine((value, ctx) => {
    if (
      value.approvalContinuation &&
      (!value.pendingExpiry || value.continuation || value.supersession)
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Approval continuation requires the exact pending-expiry source',
      });
    const sourceWitness =
      'recoverySource' in value.source && 'pendingExpiry' in value.source.recoverySource
        ? value.source.recoverySource.pendingExpiry
        : undefined;
    if (
      Boolean(value.pendingExpiry) !== Boolean(sourceWitness) ||
      (value.pendingExpiry &&
        (value.continuation ||
          value.supersession ||
          JSON.stringify(value.pendingExpiry) !== JSON.stringify(sourceWitness) ||
          value.preparation.supersedes?.replacementId !==
            value.pendingExpiry.preparation.replacementId ||
          value.preparation.supersedes?.expectedRevision !==
            value.pendingExpiry.preparation.expectedRevision ||
          value.preparation.supersedes?.successorDigest !==
            value.pendingExpiry.preparation.successorDigest ||
          value.preparation.replacementId === value.pendingExpiry.preparation.replacementId))
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Expiry renewal source must preserve its exact separate purpose',
      });
  });
export const platformRecoveryDraftView = z.strictObject({
  intent: platformRecoveryIntent,
  intentDigest: digest,
  state: z.literal('DRAFT'),
  authority: z.literal('NONE'),
  assurance,
});
export const platformRecoveryChallengeView = z.strictObject({
  challengeId: id,
  challenge: z.string().min(32).max(256),
  intentDigest: digest,
  phase,
  rpId: z.string().min(1).max(255),
  credentialIds: z.array(z.string().min(1).max(1024)).length(1),
  userVerification: z.literal('required'),
  expiresAt: instant,
});
export const platformRecoveryReceiptView = z.strictObject({
  actors: z.strictObject({
    executorPrincipalId: id,
    custodianPrincipalIds: z.tuple([id, id]),
    administratorPrincipalIds: z.tuple([id, id]),
  }),
  recoveryId: id,
  enrollmentId: id,
  intent: platformRecoveryIntent,
  intentDigest: digest,
  state: z.enum(['DRAFT', 'REQUESTED', 'ACTIVE', 'COMPLETED', 'REVOKED', 'EXPIRED']),
  revision,
  assurance,
  authority: z.enum(['NONE', 'FIXED_PLATFORM_HANDOFF_ONLY']),
  proofs: z.array(z.strictObject({ principalId: id, phase, proofId: id })).max(4),
  activation: z
    .strictObject({
      recoveryId: id,
      enrollmentId: id,
      operationId: id,
      state: z.literal('ACTIVE'),
      authority: z.literal('FIXED_PLATFORM_HANDOFF_ONLY'),
      assurance,
      activatedAt: instant,
      expiresAt: instant,
      intentDigest: digest,
      bindings: z.tuple([binding, binding]),
    })
    .optional(),
  closedPreparationCorrespondence: z
    .strictObject({
      schema: z.literal('pc.identity.closed-platform-preparation-correspondence'),
      schemaVersion: z.literal(1),
      preparationDigest: digest,
      enrollmentId: id,
      recoveryId: id,
      intentDigest: digest,
      activationOperationId: id,
    })
    .optional(),
});
