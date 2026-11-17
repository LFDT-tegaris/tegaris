import { describe, expect, it } from 'vitest';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  assertPlatformRecoveryIntent,
  assertPlatformRecoverySource,
  platformRecoverySourceCeiling,
} from './platform-recovery-policy.js';
import {
  platformRecoveryFixture as fixture,
  rootExpiryPlatformRecoveryFixture,
  pendingPlatformRecoveryFixture,
  pendingExpiryPlatformRecoveryFixture,
} from './platform-recovery.test-fixture.js';
import {
  platformAdministrationRecoveryEnrollment,
  rootExpiryPlatformRecoveryEnrollment,
  platformRecoverySourceView,
} from '../contracts/platform-recovery.js';
import { assertPlatformRecoveryOperation } from './platform-recovery-operation.js';

function rootExpiryPendingBridgeFixture() {
  const v = pendingExpiryPlatformRecoveryFixture();
  const old = v.source.expiryPreparation!;
  old.successorScope.validUntilNs = (BigInt(v.source.now.getTime() - 1) * 1000000n).toString();
  const pendingExpiry = v.source.pendingExpiry!;
  pendingExpiry.preparation.preparationDigest = canonicalAuthorizationDigest(old);
  v.intent.pendingExpiry = structuredClone(pendingExpiry);
  if (v.source.enrollment.schemaVersion !== 4) throw Error('fixture source');
  v.source.enrollment.source.pendingExpiry = structuredClone(pendingExpiry);
  const epoch = (BigInt(old.predecessorEpoch) + 1n).toString();
  const revision = (BigInt(old.expectedRootRevision) + 1n).toString();
  const rootDigest = digest(998);
  Object.assign(v.source.root, { platformAuthorityEpoch: epoch });
  Object.assign(v.source, { rootRevision: revision, rootDigest });
  Object.assign(v.source.enrollment, { rootEpoch: epoch, rootRevision: revision, rootDigest });
  v.source.root.grantable.validFromNs = (
    BigInt(v.source.now.getTime() - 1000) * 1000000n
  ).toString();
  v.source.root.grantable.validUntilNs = (
    BigInt(v.source.now.getTime() + 7200000) * 1000000n
  ).toString();
  v.source.rootExpiryPendingBridge = {
    rootEpoch: epoch,
    rootRevision: revision,
    rootDigest,
    pending: {
      schema: 'pc.identity.local-root-expiry-pending-witness',
      schemaVersion: 1,
      replacementId: old.replacementId,
      replacementRevision: '1',
      predecessorEpoch: old.predecessorEpoch,
      expectedRootRevision: old.expectedRootRevision,
      predecessorDigest: old.predecessorDigest,
      preparationCandidateId: pendingExpiry.preparation.preparationCandidateId,
      preparationOperationId: pendingExpiry.preparation.preparationOperationId,
      preparationApprovalId: pendingExpiry.preparation.preparationApprovalId,
      preparationDigest: canonicalAuthorizationDigest(old),
      preparationReceiptDigest: digest(997),
      successorDigest: pendingExpiry.preparation.successorDigest,
      pendingRecordDigest: digest(996),
      administrationEffectsDigest: digest(995),
      affectedTargetCount: old.affectedTargets.length,
      readinessDigest: digest(994),
    },
  };
  Object.assign(v.intent.preparation, {
    predecessorEpoch: epoch,
    expectedRootRevision: revision,
    predecessorDigest: rootDigest,
  });
  v.intent.preparation.successorScope.validFromNs = v.source.root.grantable.validFromNs;
  v.intent.preparation.successorScope.validUntilNs = v.source.root.grantable.validUntilNs;
  v.intent.enrollmentDigest = canonicalAuthorizationDigest(v.source.enrollment);
  return v;
}

it('uses only the exact authenticated next Root for fresh pending preparation without changing its expired original', () => {
  const v = rootExpiryPendingBridgeFixture();
  const original = structuredClone(v.source.expiryPreparation);
  expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).not.toThrow();
  expect(v.source.expiryPreparation).toEqual(original);
  delete v.source.rootExpiryPendingBridge;
  expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).toThrow();
});

it.each([
  'rootEpoch',
  'rootRevision',
  'rootDigest',
  'replacementId',
  'predecessorEpoch',
  'expectedRootRevision',
  'predecessorDigest',
  'preparationDigest',
])('rejects a changed Root continuity %s without granting the fresh preparation', (field) => {
  const v = rootExpiryPendingBridgeFixture();
  const bridge = v.source.rootExpiryPendingBridge!;
  if (['rootEpoch', 'rootRevision', 'rootDigest'].includes(field))
    Object.assign(bridge, { [field]: field === 'rootDigest' ? digest(993) : '99' });
  else
    Object.assign(bridge.pending, {
      [field]: ['predecessorEpoch', 'expectedRootRevision'].includes(field) ? '99' : digest(993),
    });
  expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).toThrow();
});

describe('independently enrolled Root receipt administration bounds', () => {
  it('permits only declared finite administration while preserving the current runtime and expiry', () => {
    const v = rootExpiryPlatformRecoveryFixture();
    const before = structuredClone(v);
    expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).not.toThrow();
    const ceiling = platformRecoverySourceCeiling(v.source);
    expect(ceiling.runtime).toEqual(v.source.root.grantable.runtime);
    expect(ceiling.validUntilNs).toEqual(v.source.root.grantable.validUntilNs);
    expect(v.source.root.grantable.administration.actionIntentIds).toEqual([]);
    expect(v).toEqual(before);
  });
  it.each([
    'unverified displacement',
    'existing administration',
    'production context',
    'expiry widening',
    'runtime widening',
    'undeclared action',
    'expired source',
  ])('denies %s', (failure) => {
    const v = rootExpiryPlatformRecoveryFixture();
    if (failure === 'unverified displacement') v.source.originalAdministrationDisplaced = false;
    if (failure === 'existing administration')
      v.source.root.grantable.administration.actionIntentIds = [
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      ];
    if (failure === 'production context') v.source.localQaEnabled = false;
    if (failure === 'expiry widening')
      v.intent.preparation.successorScope.validUntilNs = (
        BigInt(v.source.root.grantable.validUntilNs) + 1n
      ).toString();
    if (failure === 'runtime widening')
      v.intent.preparation.successorScope.runtime.capabilityIds.push(
        'SIGNED_TRANSACTION_SUBMISSION',
      );
    if (failure === 'undeclared action')
      v.intent.preparation.successorScope.administration.actionIntentIds.push(
        'ACT-UNDECLARED_CREATE_RESOURCE-V1',
      );
    if (failure === 'expired source') v.source.enrollment.validUntil = v.source.now.toISOString();
    expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).toThrow();
  });
  it('rejects a different source purpose even if the receipt remains authentic', () => {
    const v = rootExpiryPlatformRecoveryFixture();
    const invalid = { ...v.source, enrollment: { ...v.source.enrollment, schemaVersion: 1 } };
    expect(() => assertPlatformRecoverySource(invalid as never)).toThrow();
  });
});

describe('distinct governed expiry renewal for the exact partial predecessor', () => {
  function sourceViewFixture() {
    const v = pendingExpiryPlatformRecoveryFixture(),
      enrollment = v.source.enrollment;
    if (enrollment.schemaVersion !== 4) throw new Error('fixture purpose');
    return {
      enrollmentId: enrollment.enrollmentId,
      assurance: enrollment.assurance,
      authority: 'NONE' as const,
      proposalBefore: new Date(v.source.now.getTime() + 60000).toISOString(),
      pendingExpiry: structuredClone(v.intent.pendingExpiry!),
      source: {
        platformContextId: enrollment.platformContextId,
        rootEpoch: enrollment.rootEpoch,
        rootRevision: enrollment.rootRevision,
        rootDigest: enrollment.rootDigest,
        recoverySource: structuredClone(enrollment.source),
        executorPrincipalId: enrollment.recoveryPrincipal.principalId,
        custodianPrincipalIds: enrollment.custodians.map((a) => a.principalId),
        administratorPrincipalIds: enrollment.administratorPrincipalIds,
      },
      preparation: structuredClone(v.intent.preparation),
    };
  }
  it('exposes the same finite new-purpose source through the strict browser contract without granting authority', () => {
    const v = sourceViewFixture();
    expect(platformRecoverySourceView.parse(v)).toEqual(v);
  });
  it.each([
    'missing source witness',
    'missing view witness',
    'different witness',
    'old replacement',
    'different predecessor',
    'mixed purpose',
  ])('rejects expiry renewal preview %s', (defect) => {
    const v = sourceViewFixture();
    if (defect === 'missing source witness')
      delete (v.source.recoverySource as { pendingExpiry?: unknown }).pendingExpiry;
    if (defect === 'missing view witness') delete (v as { pendingExpiry?: unknown }).pendingExpiry;
    if (defect === 'different witness')
      v.pendingExpiry.administrators[0].effect = { state: 'ABSENT' };
    if (defect === 'old replacement')
      v.preparation.replacementId = v.pendingExpiry.preparation.replacementId;
    if (defect === 'different predecessor') v.preparation.supersedes!.replacementId = id(999);
    if (defect === 'mixed purpose') Object.assign(v, { continuation: v.pendingExpiry.preparation });
    expect(platformRecoverySourceView.safeParse(v).success).toBe(false);
  });
  it('preserves the historical preparation and admits only new owner-generated names and bounded time', () => {
    const v = pendingExpiryPlatformRecoveryFixture(),
      before = structuredClone(v);
    expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).not.toThrow();
    expect(v).toEqual(before);
    expect(v.intent.continuation).toBeUndefined();
    expect(v.intent.supersession).toBeUndefined();
    expect(v.intent.preparation.replacementId).not.toBe(v.original.replacementId);
    expect(v.intent.preparation.successorScope.runtime).toEqual(v.original.successorScope.runtime);
  });
  function preparedFixture() {
    const v = pendingExpiryPlatformRecoveryFixture();
    v.source.pendingReplacementId = v.intent.preparation.replacementId;
    v.source.expiryPendingSuccessor = {
      replacementId: v.intent.preparation.replacementId,
      recoveryId: v.intent.recoveryId,
      intentDigest: canonicalAuthorizationDigest(v.intent),
      preparationDigest: canonicalAuthorizationDigest(v.intent.preparation),
      plannedRecordIds: [...v.source.plannedRecordIds],
    };
    return v;
  }
  it('keeps the same new intent readable after its authenticated linked PREPARE', () => {
    const v = preparedFixture(),
      before = structuredClone(v);
    expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).not.toThrow();
    expect(v).toEqual(before);
  });
  it.each([
    'unproven successor',
    'null pending',
    'foreign pending',
    'foreign successor',
    'different case',
    'changed intent',
    'changed preparation',
    'changed planned names',
    'original pending after successor',
  ])('denies post-PREPARE %s while retaining original signed scope', (defect) => {
    const v = preparedFixture(),
      original = structuredClone(v.original);
    if (defect === 'unproven successor') delete v.source.expiryPendingSuccessor;
    if (defect === 'null pending') v.source.pendingReplacementId = null;
    if (defect === 'foreign pending') v.source.pendingReplacementId = id(999);
    if (defect === 'foreign successor')
      v.source.expiryPendingSuccessor = {
        ...v.source.expiryPendingSuccessor!,
        replacementId: id(999),
      };
    if (defect === 'different case')
      v.source.expiryPendingSuccessor = {
        ...v.source.expiryPendingSuccessor!,
        recoveryId: id(999),
      };
    if (defect === 'changed intent')
      v.intent.validUntil = new Date(v.source.now.getTime() + 1000).toISOString();
    if (defect === 'changed preparation') v.intent.preparation.reason = 'Changed body';
    if (defect === 'changed planned names')
      v.source.expiryPendingSuccessor = {
        ...v.source.expiryPendingSuccessor!,
        plannedRecordIds: [id(999), ...v.source.expiryPendingSuccessor!.plannedRecordIds.slice(1)],
      };
    if (defect === 'original pending after successor')
      v.source.pendingReplacementId = v.original.replacementId;
    expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).toThrow();
    expect(v.original).toEqual(original);
  });
  it.each([
    'live predecessor',
    'wrong current root',
    'wrong witness',
    'old names',
    'foreign resource',
    'removed action',
    'extra action',
    'foreign role',
    'runtime',
    'parent expiry',
    'original expiry',
    'wrong supersession',
    'wrong purpose',
    'third administrator',
  ])('denies %s without changing originals', (defect) => {
    const v = pendingExpiryPlatformRecoveryFixture();
    const original = JSON.stringify(v.original);
    if (defect === 'live predecessor') {
      v.source.expiryPreparation!.administrators[0]!.usable.validUntilNs = (
        BigInt(v.source.now.getTime()) * 1000000n +
        1n
      ).toString();
    }
    if (defect === 'wrong current root') v.source.rootRevision = '99';
    if (defect === 'wrong witness')
      v.intent.pendingExpiry!.administrators[0].effect = { state: 'ABSENT' };
    if (defect === 'old names')
      v.intent.preparation.administrators[0]!.envelopeId = v.original.administrators[0]!.envelopeId;
    if (defect === 'foreign resource')
      v.intent.preparation.administrators[0]!.usable.administration.resourceIds.push(id(998));
    if (defect === 'removed action')
      v.intent.preparation.administrators[0]!.usable.administration.actionIntentIds.pop();
    if (defect === 'extra action')
      v.intent.preparation.administrators[0]!.usable.administration.actionIntentIds.push(
        'ACT-UNDECLARED_CREATE_RESOURCE-V1',
      );
    if (defect === 'foreign role') v.intent.preparation.administrators[0]!.roleId = id(999);
    if (defect === 'runtime')
      v.intent.preparation.administrators[0]!.usable.runtime.capabilityIds.push(
        'SIGNED_TRANSACTION_SUBMISSION',
      );
    if (defect === 'parent expiry')
      v.source.root.grantable.validUntilNs = (BigInt(v.source.now.getTime()) * 1000000n).toString();
    if (defect === 'original expiry')
      v.intent.preparation.successorScope.validUntilNs = (
        BigInt(v.original.successorScope.validUntilNs) + 1n
      ).toString();
    if (defect === 'wrong supersession') v.intent.preparation.supersedes!.replacementId = id(999);
    if (defect === 'wrong purpose')
      v.source.enrollment = { ...v.source.enrollment, schemaVersion: 3 } as never;
    if (defect === 'third administrator')
      v.intent.preparation.administrators.push(
        structuredClone(v.intent.preparation.administrators[0]!),
      );
    expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).toThrow();
    expect(JSON.stringify(v.original)).toBe(original);
  });
});

describe('independently governed pending Platform continuation', () => {
  it('preserves every original preparation byte and requires distinct schema3 enrollment', () => {
    const v = pendingPlatformRecoveryFixture(),
      before = structuredClone(v);
    expect(() => assertPlatformRecoveryIntent(v.intent, v.source)).not.toThrow();
    expect(v.intent.preparation).toEqual(v.original.intent.preparation);
    expect(canonicalAuthorizationDigest(v.intent.preparation)).toBe(
      v.intent.continuation!.preparationDigest,
    );
    expect(platformAdministrationRecoveryEnrollment.parse(v.source.enrollment)).toEqual(
      v.source.enrollment,
    );
    expect(rootExpiryPlatformRecoveryEnrollment.safeParse(v.source.enrollment).success).toBe(false);
    expect(
      rootExpiryPlatformRecoveryEnrollment.safeParse({ ...v.source.enrollment, schemaVersion: 2 })
        .success,
    ).toBe(false);
    expect(v).toEqual(before);
    expect(() =>
      assertPlatformRecoveryOperation(
        v.intent,
        v.source.enrollment.participantId,
        'ID-OP-PLATFORM-SCOPE-PREPARE',
        v.intent.preparation.replacementId,
        v.intent.preparation,
      ),
    ).toThrow();
  });
  it.each([
    'missing history',
    'changed history',
    'foreign pending',
    'changed preparation',
    'extended case',
    'supersession',
    'foreign enrollment',
    'production',
  ])('denies %s without changing the original intent', (failure) => {
    const v = pendingPlatformRecoveryFixture(),
      source = { ...v.source },
      original = structuredClone(v.original);
    if (failure === 'missing history') delete source.recoveryContinuation;
    if (failure === 'changed history')
      source.recoveryContinuation = {
        ...source.recoveryContinuation!,
        preparationDigest: digest(900),
      };
    if (failure === 'foreign pending') source.pendingReplacementId = id(999);
    if (failure === 'changed preparation')
      v.intent.preparation.reason = 'Caller supplied a new business intent.';
    if (failure === 'extended case')
      v.intent.validUntil = new Date(
        Number(BigInt(v.intent.preparation.administrators[0]!.usable.validUntilNs) / 1000000n) + 1,
      ).toISOString();
    if (failure === 'supersession')
      v.intent.preparation.supersedes = {
        replacementId: id(900),
        expectedRevision: '1',
        successorDigest: digest(900),
      };
    if (failure === 'foreign enrollment') v.intent.enrollmentId = id(999);
    if (failure === 'production') source.localQaEnabled = false;
    expect(() => assertPlatformRecoveryIntent(v.intent, source)).toThrow();
    expect(v.original).toEqual(original);
  });
});

describe('fixed Platform recovery bounds', () => {
  it('accepts only the bounded proposal; does not create authority or mutate its input', () => {
    const value = fixture(),
      before = structuredClone(value);
    expect(() => assertPlatformRecoveryIntent(value.intent, value.source)).not.toThrow();
    expect(value).toEqual(before);
  });

  it.each([
    [
      'changed administrator role',
      ({ intent }) => {
        intent.preparation.administrators[0]!.roleId = id(999);
      },
    ],
    [
      'extended administration lifetime',
      ({ source, intent }) => {
        intent.preparation.administrators[0]!.usable.validUntilNs = (
          BigInt(source.now.getTime() + 3600001) * 1000000n
        ).toString();
      },
    ],
    [
      'changed administrator epoch',
      ({ intent }) => {
        intent.administratorEpochs[0].principalEpoch = '2';
      },
    ],
    [
      'duplicate administrator epoch binding',
      ({ intent }) => {
        intent.administratorEpochs[1] = intent.administratorEpochs[0];
      },
    ],
    [
      'root suspended',
      ({ source }) => {
        source.rootState = 'SUSPENDED';
      },
    ],
    [
      'source revoked',
      ({ source }) => {
        source.enrollmentState = 'REVOKED';
      },
    ],
    [
      'new root epoch',
      ({ source }) => {
        source.root.platformAuthorityEpoch = '3';
      },
    ],
    [
      'foreign participant',
      ({ source }) => {
        source.root.ownerParticipantId = id(999);
      },
    ],
    [
      'foreign privacy',
      ({ source }) => {
        source.root.installationPrivacyDomainId = id(999);
      },
    ],
    [
      'live prior administration',
      ({ source }) => {
        source.administrationExpired = false;
      },
    ],
    [
      'unrelated replacement',
      ({ source }) => {
        source.expiredReplacementId = id(999);
      },
    ],
    [
      'source expiry',
      ({ source }) => {
        source.enrollment.validUntil = source.now.toISOString();
      },
    ],
    [
      'lease expiry',
      ({ source, intent }) => {
        intent.validUntil = source.now.toISOString();
      },
    ],
    [
      'overlong lease',
      ({ source, intent }) => {
        intent.validUntil = new Date(source.now.getTime() + 900001).toISOString();
      },
    ],
    [
      'future lease',
      ({ source, intent }) => {
        intent.validFrom = new Date(source.now.getTime() + 1).toISOString();
      },
    ],
    [
      'stale source version',
      ({ intent }) => {
        intent.enrollmentRevision = '2';
      },
    ],
    [
      'changed source digest',
      ({ intent }) => {
        intent.enrollmentDigest = digest(999);
      },
    ],
    [
      'QA claim in production',
      ({ source }) => {
        source.localQaEnabled = false;
      },
    ],
    [
      'subject is custodian',
      ({ source }) => {
        source.enrollment.custodians[0].principalId = id(100);
      },
    ],
    [
      'one custodian twice',
      ({ source }) => {
        source.enrollment.custodians[1] = source.enrollment.custodians[0];
      },
    ],
    [
      'shared authenticator',
      ({ source }) => {
        source.enrollment.custodians[1].credentialId = source.enrollment.custodians[0].credentialId;
      },
    ],
    [
      'caller-chosen record names',
      ({ source }) => {
        source.plannedRecordIds = [id(999), ...source.plannedRecordIds.slice(1)];
      },
    ],
    [
      'foreign business resource',
      ({ intent }) => {
        intent.preparation.successorScope.administration.resourceIds.push(id(999));
      },
    ],
    [
      'new business action',
      ({ intent }) => {
        intent.preparation.successorScope.administration.actionIntentIds.push(
          'ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1',
        );
      },
    ],
    [
      'runtime widening',
      ({ intent }) => {
        intent.preparation.successorScope.runtime.capabilityIds.push(
          'SIGNED_TRANSACTION_SUBMISSION',
        );
      },
    ],
    [
      'different pending intent',
      ({ source }) => {
        source.pendingReplacementId = id(999);
      },
    ],
  ] satisfies [string, (value: ReturnType<typeof fixture>) => void][])(
    'denies %s before any owner effect',
    (_label, mutate) => {
      const value = fixture();
      mutate(value);
      expect(() => assertPlatformRecoveryIntent(value.intent, value.source)).toThrow();
    },
  );
});

it('permits an owner-verified expired supersession only with exact immutable history linkage', () => {
  const { source, intent } = fixture();
  const link = {
    recoveryId: id(700),
    intentDigest: digest(701),
    replacementId: id(702),
    preparationDigest: digest(703),
    preparationOperationId: id(704),
    preparationApprovalId: id(705),
    expectedRevision: '1' as const,
    successorDigest: digest(706),
  };
  source.pendingReplacementId = link.replacementId;
  source.recoverySupersession = link;
  intent.supersession = link;
  intent.preparation.supersedes = {
    replacementId: link.replacementId,
    expectedRevision: link.expectedRevision,
    successorDigest: link.successorDigest,
  };
  expect(() => assertPlatformRecoveryIntent(intent, source)).not.toThrow();
  intent.supersession = { ...link, preparationOperationId: id(999) };
  expect(() => assertPlatformRecoveryIntent(intent, source)).toThrow();
  intent.supersession = link;
  source.recoverySupersession = undefined;
  expect(() => assertPlatformRecoveryIntent(intent, source)).toThrow();
});
