import { describe, expect, it } from 'vitest';
import { generateKeyPairSync, sign } from 'node:crypto';
import { encodeEnvelopeScope } from '../../../../packages/security-kernel/src/index.js';
import {
  localRootExpiryRecoveryReceivingTrust,
  localRootExpiryRecoveryEnrollment,
  localRootExpiryPendingRecoveryPurpose,
  localRootExpiryRecoveryIntent,
  localRootExpiryPendingAncestryPurpose,
  localRootExpiryPendingAncestryWitness,
} from '../contracts/local-root-expiry-recovery.js';
import {
  authenticateLocalRootExpiryRecoveryCustody,
  localRootExpirySuccessorScope,
  assertLocalRootExpiryRecoveryInstallationTime,
  localRootExpiryRecoveryCustodyPreimage,
} from './local-root-expiry-recovery.js';

it('binds successor validity to immutable installation time while allowing a later ceremony', () => {
  const f = localRootExpiryRecoveryFixture();
  expect(() =>
    assertLocalRootExpiryRecoveryInstallationTime(f.enrollment, f.now, f.now),
  ).not.toThrow();
  expect(() =>
    localRootExpirySuccessorScope(
      f.root,
      f.enrollment,
      f.enrollment.rootRevision,
      new Date(f.now.getTime() + 600000),
      true,
    ),
  ).not.toThrow();
  const past = {
    ...f.enrollment,
    successorValidFrom: new Date(f.now.getTime() - 30001).toISOString(),
  };
  expect(() => assertLocalRootExpiryRecoveryInstallationTime(past, f.now, f.now)).toThrow();
  expect(() =>
    assertLocalRootExpiryRecoveryInstallationTime(
      f.enrollment,
      new Date(f.now.getTime() - 60000),
      f.now,
    ),
  ).not.toThrow();
  expect(() =>
    assertLocalRootExpiryRecoveryInstallationTime(
      f.enrollment,
      f.now,
      new Date(f.now.getTime() + 60000),
    ),
  ).toThrow();
  expect(() =>
    assertLocalRootExpiryRecoveryInstallationTime(f.enrollment, new Date(NaN), f.now),
  ).toThrow();
});
import { localRootExpiryRecoveryFixture } from './local-root-expiry-recovery.test-fixture.js';
import { assertPlatformRecoveryCeremony } from './platform-recovery-ceremony.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';

it('separates signed pending recovery custody from V1 and binds every original witness field', () => {
  const f = localRootExpiryRecoveryFixture();
  const pending = {
    schema: 'pc.identity.local-root-expiry-pending-witness' as const,
    schemaVersion: 1 as const,
    replacementId: f.enrollment.enrollmentId,
    replacementRevision: '1',
    predecessorEpoch: f.enrollment.rootEpoch,
    expectedRootRevision: f.enrollment.rootRevision,
    predecessorDigest: f.enrollment.rootDigest,
    preparationCandidateId: f.trust.custodyTrustId,
    preparationOperationId: f.enrollment.recoveryPrincipal.principalId,
    preparationApprovalId: f.enrollment.custodians[0].principalId,
    preparationDigest: f.enrollment.rootDigest,
    preparationReceiptDigest: f.enrollment.rootDigest,
    successorDigest: f.enrollment.rootDigest,
    pendingRecordDigest: f.enrollment.rootDigest,
    administrationEffectsDigest: f.enrollment.rootDigest,
    affectedTargetCount: 1,
    readinessDigest: f.enrollment.rootDigest,
  };
  const trust = localRootExpiryRecoveryReceivingTrust.parse({
    ...f.trust,
    schemaVersion: 2,
    purpose: localRootExpiryPendingRecoveryPurpose,
    pending,
  });
  const document = localRootExpiryRecoveryEnrollment.parse({
    ...f.enrollment,
    schemaVersion: 2,
    purpose: localRootExpiryPendingRecoveryPurpose,
    pending,
    custodyTrustDigest: canonicalAuthorizationDigest(trust),
  });
  const signature = sign('sha256', localRootExpiryRecoveryCustodyPreimage(document), {
    key: f.privateKey,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  expect(
    authenticateLocalRootExpiryRecoveryCustody(trust, { document, signature }).enrollment,
  ).toEqual(document);
  expect(() =>
    authenticateLocalRootExpiryRecoveryCustody(trust, { document, signature: f.signed.signature }),
  ).toThrow();
  expect(() =>
    authenticateLocalRootExpiryRecoveryCustody(f.trust, { document, signature }),
  ).toThrow();
  expect(localRootExpiryRecoveryEnrollment.safeParse({ ...f.enrollment, pending }).success).toBe(
    false,
  );
  expect(
    localRootExpiryRecoveryEnrollment.safeParse({ ...document, pending: undefined }).success,
  ).toBe(false);
  for (const field of Object.keys(pending)) {
    const changed = {
      ...document,
      pending: { ...pending, [field]: field === 'affectedTargetCount' ? 0 : 'changed' },
    };
    expect(() =>
      authenticateLocalRootExpiryRecoveryCustody(trust, { document: changed, signature }),
    ).toThrow();
  }
  expect(() =>
    localRootExpirySuccessorScope(f.root, document, f.rootRevision, f.now, true),
  ).not.toThrow();
  const intent = {
    schema: 'pc.identity.local-root-expiry-recovery-intent',
    schemaVersion: 2,
    purpose: 'LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY',
    pending,
    recoveryId: f.enrollment.custodians[1].principalId,
    enrollmentId: document.enrollmentId,
    enrollmentRevision: '1',
    enrollmentDigest: canonicalAuthorizationDigest(document),
    sourceParticipantEpoch: '1',
    predecessorEpoch: document.rootEpoch,
    predecessorRevision: document.rootRevision,
    predecessorDigest: document.rootDigest,
    successorScope: localRootExpirySuccessorScope(f.root, document, f.rootRevision, f.now, true),
    validFrom: f.now.toISOString(),
    validUntil: new Date(f.now.getTime() + 900000).toISOString(),
  };
  expect(localRootExpiryRecoveryIntent.safeParse(intent).success).toBe(true);
  expect(
    localRootExpiryRecoveryIntent.safeParse({
      ...intent,
      purpose: 'LOCAL_ROOT_EXPIRY_RECOVERY_ONLY',
    }).success,
  ).toBe(false);
  expect(
    localRootExpiryRecoveryIntent.safeParse({
      ...intent,
      pending: { ...pending, predecessorEpoch: '999' },
    }).success,
  ).toBe(false);
});

describe('independently governed local Root expiry recovery', () => {
  it('authenticates the original independent signature and preserves every non-time permission byte', () => {
    const f = localRootExpiryRecoveryFixture();
    expect(authenticateLocalRootExpiryRecoveryCustody(f.trust, f.signed).enrollment).toEqual(
      f.enrollment,
    );
    const original = encodeEnvelopeScope(f.root.grantable);
    const scope = localRootExpirySuccessorScope(f.root, f.enrollment, f.rootRevision, f.now, true);
    expect({
      ...scope,
      validFromNs: f.root.grantable.validFromNs,
      validUntilNs: f.root.grantable.validUntilNs,
    }).toEqual(f.root.grantable);
    expect(encodeEnvelopeScope(f.root.grantable)).toEqual(original);
    expect(scope.validUntilNs).toBe(
      (BigInt(Date.parse(f.enrollment.successorValidUntil)) * 1000000n).toString(),
    );
  });
  it('rejects production, unsigned, cross-purpose, foreign installation, changed key and changed signed times', () => {
    const f = localRootExpiryRecoveryFixture();
    const foreign = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      .publicKey.export({ format: 'der', type: 'spki' })
      .toString('base64');
    for (const trust of [
      { ...f.trust, profile: 'PRODUCTION' },
      { ...f.trust, purpose: 'pc.installation.identity-envelope-repair-custody.v1' },
      { ...f.trust, installationEnvironmentId: 'foreign' },
      { ...f.trust, issuerPublicKeySpkiDer: foreign },
    ])
      expect(() => authenticateLocalRootExpiryRecoveryCustody(trust, f.signed)).toThrow();
    for (const document of [
      { ...f.enrollment, rootDigest: 'sha256:' + 'a'.repeat(64) },
      { ...f.enrollment, successorValidUntil: new Date(f.now.getTime() + 1800000).toISOString() },
    ])
      expect(() =>
        authenticateLocalRootExpiryRecoveryCustody(f.trust, { ...f.signed, document }),
      ).toThrow();
    expect(() =>
      authenticateLocalRootExpiryRecoveryCustody(f.trust, { document: f.enrollment }),
    ).toThrow();
  });
  it('fails closed for a live Root, stale revision/epoch/digest, expired receiving window or disabled local mode', () => {
    const f = localRootExpiryRecoveryFixture();
    const use = (
      root = f.root,
      e = f.enrollment,
      revision = f.rootRevision,
      now = f.now,
      local = true,
    ) => localRootExpirySuccessorScope(root, e, revision, now, local);
    expect(() => use(f.root, f.enrollment, f.rootRevision, f.now, false)).toThrow();
    expect(() =>
      use({
        ...f.root,
        grantable: {
          ...f.root.grantable,
          validUntilNs: (BigInt(f.now.getTime() + 1000) * 1000000n).toString(),
        },
      }),
    ).toThrow();
    expect(() => use(f.root, f.enrollment, '3')).toThrow();
    expect(() => use({ ...f.root, platformAuthorityEpoch: '1' })).toThrow();
    expect(() => use({ ...f.root, platformAuthorityDigest: 'sha256:' + 'b'.repeat(64) })).toThrow();
    expect(() =>
      use(f.root, f.enrollment, f.rootRevision, new Date(Date.parse(f.enrollment.validUntil))),
    ).toThrow();
    expect(() =>
      use({ ...f.root, installationPrivacyDomainId: f.enrollment.custodians[0].principalId }),
    ).toThrow();
    expect(() =>
      use({
        ...f.root,
        grantable: {
          ...f.root.grantable,
          validFromNs: (BigInt(f.now.getTime() - 2000) * 1000000n).toString(),
        },
      }),
    ).toThrow();
  });
  it('rejects substituted custodians, shared principals, malformed public pins and excessive renewal windows', () => {
    const f = localRootExpiryRecoveryFixture();
    expect(
      localRootExpiryRecoveryEnrollment.safeParse({
        ...f.enrollment,
        custodians: [f.enrollment.recoveryPrincipal, f.enrollment.custodians[1]],
      }).success,
    ).toBe(false);
    expect(
      localRootExpiryRecoveryEnrollment.safeParse({
        ...f.enrollment,
        successorValidUntil: new Date(f.now.getTime() + 86401000).toISOString(),
      }).success,
    ).toBe(false);
    expect(
      localRootExpiryRecoveryReceivingTrust.safeParse({
        ...f.trust,
        issuerKeyId: 'sha256:' + 'c'.repeat(64),
      }).success,
    ).toBe(false);
    expect(
      localRootExpiryRecoveryReceivingTrust.safeParse({
        ...f.trust,
        validUntil: new Date(f.now.getTime() + 86401000).toISOString(),
      }).success,
    ).toBe(false);
  });
  it('cannot use local Root custody to approve a signer-repair intent', () => {
    const f = localRootExpiryRecoveryFixture();
    const intent = {
      schema: 'pc.identity.identity-envelope-recovery-intent',
      enrollmentId: f.enrollment.enrollmentId,
      enrollmentDigest: canonicalAuthorizationDigest(f.enrollment),
    };
    expect(() =>
      assertPlatformRecoveryCeremony(
        f.enrollment,
        intent as never,
        'DRAFT',
        [],
        'REQUEST',
        f.enrollment.recoveryPrincipal.principalId,
        f.now,
      ),
    ).toThrow();
  });
});

it('requires a separate temporary signed Root profile for a longer new successor and keeps the original immutable', () => {
  const f = localRootExpiryRecoveryFixture();
  const original = structuredClone(f.enrollment);
  const next = {
    ...f.enrollment,
    qaDurationProfile: 'LOCAL_QA_10X' as const,
    validUntil: new Date(f.now.getTime() + 3 * 86400000).toISOString(),
    successorValidUntil: new Date(f.now.getTime() + 2 * 86400000).toISOString(),
  };
  expect(localRootExpiryRecoveryEnrollment.safeParse(next).success).toBe(true);
  expect(() =>
    localRootExpirySuccessorScope(f.root, next, next.rootRevision, f.now, true),
  ).toThrow();
  expect(() =>
    localRootExpirySuccessorScope(f.root, next, next.rootRevision, f.now, true, true),
  ).not.toThrow();
  const { qaDurationProfile, ...legacy } = next;
  expect(qaDurationProfile).toBe('LOCAL_QA_10X');
  expect(localRootExpiryRecoveryEnrollment.safeParse(legacy).success).toBe(false);
  expect(f.enrollment).toEqual(original);
});

function ancestryFixture(depth = 1) {
  const f = localRootExpiryRecoveryFixture();
  const pending = {
    schema: 'pc.identity.local-root-expiry-pending-witness' as const,
    schemaVersion: 1 as const,
    replacementId: '018f1000-0000-7000-8000-000000000001',
    replacementRevision: '1',
    predecessorEpoch: f.enrollment.rootEpoch,
    expectedRootRevision: f.enrollment.rootRevision,
    predecessorDigest: f.enrollment.rootDigest,
    preparationCandidateId: '018f1000-0000-7000-8000-000000000002',
    preparationOperationId: '018f1000-0000-7000-8000-000000000003',
    preparationApprovalId: '018f1000-0000-7000-8000-000000000004',
    preparationDigest: f.enrollment.rootDigest,
    preparationReceiptDigest: f.enrollment.rootDigest,
    successorDigest: f.enrollment.rootDigest,
    pendingRecordDigest: f.enrollment.rootDigest,
    administrationEffectsDigest: f.enrollment.rootDigest,
    affectedTargetCount: 0,
    readinessDigest: f.enrollment.rootDigest,
  };
  const receipts = Array.from({ length: depth }, (_, index) => ({
    enrollmentId: `018f1000-0000-7000-8000-${(100 + index * 3).toString().padStart(12, '0')}`,
    recoveryId: `018f1000-0000-7000-8000-${(101 + index * 3).toString().padStart(12, '0')}`,
    activationOperationId: `018f1000-0000-7000-8000-${(102 + index * 3).toString().padStart(12, '0')}`,
    enrollmentDigest: f.enrollment.rootDigest,
    intentDigest: f.enrollment.rootDigest,
    receiptDigest: f.enrollment.rootDigest,
    predecessorEpoch: (BigInt(pending.predecessorEpoch) + BigInt(index)).toString(),
    predecessorRevision: (BigInt(pending.expectedRootRevision) + BigInt(index)).toString(),
    predecessorDigest: f.enrollment.rootDigest,
    rootEpoch: (BigInt(pending.predecessorEpoch) + BigInt(index) + 1n).toString(),
    rootRevision: (BigInt(pending.expectedRootRevision) + BigInt(index) + 1n).toString(),
    rootDigest: f.enrollment.rootDigest,
  }));
  const last = receipts.at(-1)!;
  const rootAncestry = {
    schema: 'pc.identity.local-root-expiry-pending-ancestry' as const,
    schemaVersion: 1 as const,
    rootEpoch: last.rootEpoch,
    rootRevision: last.rootRevision,
    rootDigest: last.rootDigest,
    receipts,
  };
  return { f, pending, rootAncestry };
}
it('authenticates independently signed V3 custody while keeping V1/V2 purposes distinct', () => {
  const { f, pending, rootAncestry } = ancestryFixture(2);
  const trust = localRootExpiryRecoveryReceivingTrust.parse({
    ...f.trust,
    schemaVersion: 3,
    purpose: localRootExpiryPendingAncestryPurpose,
    pending,
    rootAncestry,
  });
  const document = localRootExpiryRecoveryEnrollment.parse({
    ...f.enrollment,
    schemaVersion: 3,
    purpose: localRootExpiryPendingAncestryPurpose,
    pending,
    rootAncestry,
    rootEpoch: rootAncestry.rootEpoch,
    rootRevision: rootAncestry.rootRevision,
    rootDigest: rootAncestry.rootDigest,
    custodyTrustDigest: canonicalAuthorizationDigest(trust),
  });
  const signature = sign('sha256', localRootExpiryRecoveryCustodyPreimage(document), {
    key: f.privateKey,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  expect(
    authenticateLocalRootExpiryRecoveryCustody(trust, { document, signature }).enrollment,
  ).toEqual(document);
  expect(() =>
    authenticateLocalRootExpiryRecoveryCustody(trust, { document, signature: f.signed.signature }),
  ).toThrow();
  expect(() =>
    authenticateLocalRootExpiryRecoveryCustody(f.trust, { document, signature }),
  ).toThrow();
  for (const field of Object.keys(rootAncestry.receipts[0]!)) {
    const altered = structuredClone(document);
    if (altered.schemaVersion !== 3) throw new Error('fixture');
    Object.assign(altered.rootAncestry.receipts[0]!, {
      [field]: field.endsWith('Digest') ? 'sha256:' + '0'.repeat(64) : 'changed',
    });
    expect(() =>
      authenticateLocalRootExpiryRecoveryCustody(trust, { document: altered, signature }),
    ).toThrow();
  }
  for (const version of [1, 2])
    expect(
      localRootExpiryRecoveryEnrollment.safeParse({ ...document, schemaVersion: version }).success,
    ).toBe(false);
  expect(
    localRootExpiryRecoveryEnrollment.safeParse({ ...document, rootEpoch: '99' }).success,
  ).toBe(false);
});
it('accepts a complete depth32 chain and denies depth33, gaps, cycles, duplicates and changed endpoints', () => {
  const { pending, rootAncestry } = ancestryFixture(32);
  expect(localRootExpiryPendingAncestryWitness.safeParse({ pending, rootAncestry }).success).toBe(
    true,
  );
  const tooDeep = ancestryFixture(33);
  expect(
    localRootExpiryPendingAncestryWitness.safeParse({
      pending: tooDeep.pending,
      rootAncestry: tooDeep.rootAncestry,
    }).success,
  ).toBe(false);
  const changes = [
    (a: typeof rootAncestry) => {
      a.receipts.splice(1, 1);
    },
    (a: typeof rootAncestry) => {
      a.receipts.reverse();
    },
    (a: typeof rootAncestry) => {
      a.receipts[1]!.recoveryId = a.receipts[0]!.recoveryId;
    },
    (a: typeof rootAncestry) => {
      a.receipts[0]!.enrollmentId = a.receipts[0]!.recoveryId;
    },
    (a: typeof rootAncestry) => {
      a.receipts[0]!.predecessorRevision = '99';
    },
    (a: typeof rootAncestry) => {
      a.receipts[1]!.predecessorDigest = 'sha256:' + '0'.repeat(64);
    },
    (a: typeof rootAncestry) => {
      a.receipts[1]!.rootEpoch = a.receipts[1]!.predecessorEpoch;
    },
    (a: typeof rootAncestry) => {
      a.rootDigest = 'sha256:' + '0'.repeat(64);
    },
  ];
  for (const change of changes) {
    const altered = structuredClone(rootAncestry);
    change(altered);
    expect(
      localRootExpiryPendingAncestryWitness.safeParse({ pending, rootAncestry: altered }).success,
    ).toBe(false);
  }
  expect(
    localRootExpiryPendingAncestryWitness.safeParse({
      pending: { ...pending, predecessorDigest: 'sha256:' + '0'.repeat(64) },
      rootAncestry,
    }).success,
  ).toBe(false);
});
