/** Unit inputs only; never enrolls trust or seeds any runtime state. */
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
  envelopeFixtureScope,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import type { PlatformRecoveryIntent } from '../contracts/platform-recovery.js';
import {
  pendingPlatformRecoveryEnrollment,
  platformRecoveryContinuation,
  pendingExpiryPlatformRecoveryEnrollment,
} from '../contracts/platform-recovery.js';
import type { PlatformRecoverySource } from './platform-recovery-policy.js';
import { pendingAdministrationExpiryReason } from './platform-recovery-policy.js';

type Mutable<T> = { -readonly [K in keyof T]: T[K] };

export function platformRecoveryFixture() {
  const now = new Date(1800000060000);
  const scope = envelopeFixtureScope(0);
  const names = [id(10), id(11), id(12), id(13), id(14)];
  const source: Mutable<Omit<PlatformRecoverySource, 'root'>> & {
    root: Mutable<PlatformRecoverySource['root']>;
    enrollment: import('../contracts/platform-recovery.js').PlatformRecoveryEnrollment;
  } = {
    root: {
      platformContextId: id(4),
      ownerParticipantId: id(1),
      installationPrivacyDomainId: id(2),
      platformAuthorityEpoch: '2',
      environmentId: 'local-qa',
      installationDigest: digest(1),
      grantable: scope,
    },
    rootRevision: '2',
    rootDigest: digest(2),
    rootState: 'ACTIVE',
    enrollmentRevision: '1',
    enrollmentState: 'ACTIVE',
    enrollment: {
      schema: 'pc.identity.platform-recovery-enrollment',
      schemaVersion: 1,
      enrollmentId: id(5),
      platformContextId: id(4),
      participantId: id(1),
      privacyDomainId: id(2),
      rootEpoch: '2',
      rootRevision: '2',
      rootDigest: digest(2),
      expiredReplacementId: id(6),
      administratorPrincipalIds: [id(100), id(101)],
      recoveryPrincipal: {
        principalId: id(102),
        credentialId: id(202),
        principalEpoch: '1',
        credentialEpoch: '0',
      },
      custodians: [
        { principalId: id(103), credentialId: id(203), principalEpoch: '1', credentialEpoch: '0' },
        { principalId: id(104), credentialId: id(204), principalEpoch: '1', credentialEpoch: '0' },
      ],
      validFrom: new Date(now.getTime() - 60000).toISOString(),
      validUntil: new Date(now.getTime() + 1800000).toISOString(),
      assurance: 'LOCAL_QA_VIRTUAL_AUTHENTICATOR',
    },
    expiredReplacementId: id(6),
    administratorPrincipalIds: [id(100), id(101)],
    administratorEpochs: [100, 101].map((n) => ({ principalId: id(n), principalEpoch: '1' })),
    originalAdministrators: [],
    administrationExpired: true,
    plannedRecordIds: names,
    pendingReplacementId: null,
    now,
    localQaEnabled: true,
  };
  const successor = structuredClone(scope);
  successor.administration.resourceIds.push(...names);
  const usable = structuredClone(successor);
  for (const key of Object.keys(usable.runtime) as (keyof typeof usable.runtime)[])
    usable.runtime[key] = [];
  usable.validFromNs = (BigInt(now.getTime()) * 1000000n).toString();
  usable.validUntilNs = scope.validUntilNs;
  const intent: PlatformRecoveryIntent = {
    schema: 'pc.identity.platform-recovery-intent',
    schemaVersion: 1,
    recoveryId: id(7),
    enrollmentId: id(5),
    enrollmentRevision: '1',
    enrollmentDigest: canonicalAuthorizationDigest(source.enrollment),
    validFrom: now.toISOString(),
    validUntil: new Date(now.getTime() + 900000).toISOString(),
    administratorEpochs: [
      { principalId: id(100), principalEpoch: '1' },
      { principalId: id(101), principalEpoch: '1' },
    ],
    preparation: {
      schema: 'pc.identity.platform-scope-replacement',
      schemaVersion: 1,
      replacementId: names[0]!,
      platformContextId: id(4),
      expectedRootRevision: '2',
      predecessorEpoch: '2',
      predecessorDigest: digest(2),
      successorScope: successor,
      affectedTargets: [],
      reason: 'Recover only the current expired administration handoff.',
      administrators: [100, 101].map((n, index) => ({
        principalId: id(n),
        envelopeId: names[1 + index * 2]!,
        assignmentId: names[2 + index * 2]!,
        roleId: id(n + 300),
        expectedRoleRevision: '1',
        roleDigest: digest(n),
        usable: structuredClone(usable),
        grantable: structuredClone(usable),
      })),
    },
  };
  source.originalAdministrators = structuredClone(intent.preparation.administrators);
  return { source, intent };
}

/** Pure declarations only; no enrollment, receipt or authority is installed. */
export function rootExpiryPlatformRecoveryFixture() {
  const original = platformRecoveryFixture();
  const { expiredReplacementId: unused, ...custody } = original.source.enrollment;
  void unused;
  const enrollment: import('../contracts/platform-recovery.js').RootExpiryPlatformRecoveryEnrollment =
    {
      ...custody,
      schemaVersion: 2,
      source: {
        kind: 'ROOT_EXPIRY_RECOVERY',
        recoveryId: id(500),
        enrollmentId: id(501),
        activationOperationId: id(502),
        receiptDigest: digest(503),
        originalAdministrators: original.source.originalAdministrators.map((v) => ({
          ...structuredClone(v),
          envelopeRevision: '1',
          assignmentRevision: '1',
        })) as import('../contracts/platform-recovery.js').RootExpiryPlatformRecoveryEnrollment['source']['originalAdministrators'],
      },
    };
  const root = structuredClone(original.source.root);
  for (const key of Object.keys(
    root.grantable.administration,
  ) as (keyof typeof root.grantable.administration)[])
    root.grantable.administration[key] = [];
  const source = {
    ...original.source,
    root,
    enrollment,
    expiredReplacementId: null,
    administrationExpired: false,
    originalAdministrationDisplaced: true,
  };
  const intent = { ...original.intent, enrollmentDigest: canonicalAuthorizationDigest(enrollment) };
  return { source, intent };
}

/** An authenticated-history declaration for pure continuation regressions only. */
export function pendingPlatformRecoveryFixture() {
  const original = rootExpiryPlatformRecoveryFixture();
  const continuation = platformRecoveryContinuation.parse({
    schema: 'pc.identity.platform-pending-recovery-continuation',
    schemaVersion: 1,
    enrollmentId: original.intent.enrollmentId,
    recoveryId: original.intent.recoveryId,
    intentDigest: canonicalAuthorizationDigest(original.intent),
    activationOperationId: id(520),
    activationReceiptDigest: digest(521),
    replacementId: original.intent.preparation.replacementId,
    preparationCandidateId: id(522),
    preparationDigest: canonicalAuthorizationDigest(original.intent.preparation),
    preparationOperationId: id(523),
    preparationApprovalId: id(524),
    expectedRevision: '1',
    successorDigest: digest(525),
  });
  const now = new Date(Date.parse(original.intent.validUntil) + 1000);
  const enrollment = pendingPlatformRecoveryEnrollment.parse({
    ...original.source.enrollment,
    schemaVersion: 3,
    enrollmentId: id(526),
    validFrom: now.toISOString(),
    validUntil: new Date(now.getTime() + 1800000).toISOString(),
    source: { ...original.source.enrollment.source, continuation },
  });
  const source: PlatformRecoverySource = {
    ...original.source,
    enrollment,
    now,
    pendingReplacementId: continuation.replacementId,
    recoveryContinuation: continuation,
    continuationPreparation: structuredClone(original.intent.preparation),
  };
  const intent: PlatformRecoveryIntent = {
    ...original.intent,
    recoveryId: id(527),
    enrollmentId: enrollment.enrollmentId,
    enrollmentDigest: canonicalAuthorizationDigest(enrollment),
    continuation,
    validFrom: now.toISOString(),
    validUntil: new Date(now.getTime() + 900000).toISOString(),
    preparation: structuredClone(original.intent.preparation),
  };
  return { source, intent, original };
}

/** Pure expired-partial witnesses only; no business state or custody is seeded. */
export function pendingExpiryPlatformRecoveryFixture() {
  const prior = pendingPlatformRecoveryFixture();
  const now = prior.source.now;
  const original = structuredClone(prior.original.intent.preparation);
  for (const admin of original.administrators)
    for (const dimension of ['usable', 'grantable'] as const)
      admin[dimension].validUntilNs = (BigInt(now.getTime()) * 1000000n).toString();
  const preparation = {
    ...prior.intent.continuation!,
    preparationDigest: canonicalAuthorizationDigest(original),
  };
  const witness = {
    schema: 'pc.identity.platform-pending-administration-expiry' as const,
    schemaVersion: 1 as const,
    preparation,
    administrators: original.administrators.map((admin, index) => ({
      principalId: admin.principalId,
      envelopeId: admin.envelopeId,
      assignmentId: admin.assignmentId,
      effect:
        index === 0
          ? {
              state: 'APPROVED_PROPOSAL' as const,
              proposalEnvelopeId: id(540),
              proposalRevision: '3' as const,
              proposalDigest: digest(541),
              createCandidateId: id(542),
              createApprovalId: id(543),
              createOperationId: id(544),
              activationCandidateId: id(545),
              activationApprovalId: id(546),
              activationCandidateDigest: digest(547),
              activationAttempt: '3',
            }
          : { state: 'ABSENT' as const },
    })) as Extract<
      import('../contracts/platform-recovery.js').PlatformPendingAdministrationExpiry,
      { schemaVersion: 1 }
    >['administrators'],
  };
  const { continuation: _old, ...rootSource } =
    prior.source.enrollment.schemaVersion === 3
      ? prior.source.enrollment.source
      : (() => {
          throw Error('fixture source');
        })();
  void _old;
  const enrollment = pendingExpiryPlatformRecoveryEnrollment.parse({
    ...prior.source.enrollment,
    schemaVersion: 4,
    enrollmentId: id(548),
    source: { ...rootSource, pendingExpiry: witness },
  });
  const next = structuredClone(original);
  const names = [id(550), id(551), id(552), id(553), id(554)];
  const oldNames = [
    original.replacementId,
    ...original.administrators.flatMap((admin) => [admin.envelopeId, admin.assignmentId]),
  ];
  const substitute = (scope: typeof next.successorScope) => {
    scope.administration.resourceIds = scope.administration.resourceIds
      .map((name) => {
        const index = oldNames.indexOf(name);
        return index < 0 ? name : names[index]!;
      })
      .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  };
  next.replacementId = names[0]!;
  next.reason = pendingAdministrationExpiryReason;
  next.supersedes = {
    replacementId: original.replacementId,
    expectedRevision: '1',
    successorDigest: preparation.successorDigest,
  };
  substitute(next.successorScope);
  for (const [index, admin] of next.administrators.entries()) {
    admin.envelopeId = names[index * 2 + 1]!;
    admin.assignmentId = names[index * 2 + 2]!;
    for (const dimension of ['usable', 'grantable'] as const) {
      substitute(admin[dimension]);
      admin[dimension].validFromNs = (BigInt(now.getTime()) * 1000000n).toString();
      admin[dimension].validUntilNs = (BigInt(now.getTime() + 1200000) * 1000000n).toString();
    }
  }
  const source: Mutable<PlatformRecoverySource> = {
    ...prior.source,
    enrollment,
    originalAdministrators: structuredClone(original.administrators),
    recoveryContinuation: undefined,
    continuationPreparation: undefined,
    pendingExpiry: witness,
    expiryPreparation: structuredClone(original),
    plannedRecordIds: names,
  };
  const { continuation: _continuation, ...priorIntent } = prior.intent;
  void _continuation;
  const intent: PlatformRecoveryIntent = {
    ...priorIntent,
    recoveryId: id(549),
    enrollmentId: enrollment.enrollmentId,
    enrollmentDigest: canonicalAuthorizationDigest(enrollment),
    pendingExpiry: witness,
    preparation: next,
  };
  return { source, intent, original };
}
