import { beforeEach, expect, it, vi } from 'vitest';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { rootExpiryPlatformRecoveryFixture } from '../domain/platform-recovery.test-fixture.js';
import { rootExpiryPlatformRecoveryEnrollment } from '../contracts/platform-recovery.js';
import { readRootExpiryPlatformAdministration } from './platform-recovery-enrollment.js';
import { readCompletedRootExpiryRecoverySource } from './root-expiry-recovery-command.js';
import { readCurrentPlatformScope } from './platform-envelope-scope.js';
import { readDiscoveryCertificateRecoverySource } from './discovery-certificate-recovery-source.js';
import { discoveryCertificateRecoveryEnrollment } from '../contracts/discovery-certificate-recovery.js';
import {
  fixture as certificateFixture,
  publicKey,
} from '../domain/discovery-certificate-recovery.test-fixture.js';
import { createHash } from 'node:crypto';
import { discoveryCertificateRecoveryPermissions } from '../domain/discovery-certificate-recovery.js';
vi.mock('./root-expiry-recovery-command.js', () => ({
  readCompletedRootExpiryRecoverySource: vi.fn(),
}));
vi.mock('./platform-envelope-scope.js', () => ({ readCurrentPlatformScope: vi.fn() }));
beforeEach(() => vi.clearAllMocks());

function setup(failure?: string, discovery = false) {
  const { source } = rootExpiryPlatformRecoveryFixture();
  const e = source.enrollment;
  if (discovery)
    for (const declared of e.source.originalAdministrators)
      for (const scope of [declared.usable, declared.grantable])
        scope.administration.actionIntentIds = discoveryCertificateRecoveryPermissions(
          certificateFixture().binding,
          e.privacyDomainId,
          declared.principalId,
        ).actionIntentIds;
  const receipt = {
    enrollment: { ...e, rootEpoch: '1', rootRevision: '1' },
    intent: { successorScope: structuredClone(source.root.grantable) },
    row: {
      operation_id: e.source.activationOperationId,
      evidence_digest: Buffer.from(e.source.receiptDigest.slice(7), 'hex'),
      result: {
        rootEpoch: e.rootEpoch,
        rootRevision: e.rootRevision,
        rootDigest: e.rootDigest,
        operationId: e.source.activationOperationId,
      },
    },
  };
  if (failure === 'receipt operation') receipt.row.operation_id = e.source.recoveryId;
  if (failure === 'receipt digest') receipt.row.evidence_digest = Buffer.alloc(32);
  if (failure === 'receipt root epoch') receipt.enrollment.rootEpoch = '2';
  if (failure === 'receipt foreign admin')
    receipt.enrollment.administratorPrincipalIds = [
      ...e.administratorPrincipalIds,
    ].reverse() as typeof e.administratorPrincipalIds;
  vi.mocked(readCompletedRootExpiryRecoverySource).mockResolvedValue(receipt as never);
  if (failure === 'receipt signature')
    vi.mocked(readCompletedRootExpiryRecoverySource).mockRejectedValue(
      new Error('Receipt verification denied'),
    );
  vi.mocked(readCurrentPlatformScope).mockResolvedValue({
    ...source.root,
    platformAuthorityDigest: source.rootDigest,
  });
  const rows = e.source.originalAdministrators.map((a) => {
    const role = {
      roleId: `urn:openpc:role:${a.roleId}`,
      version: '1',
      actions: a.usable.administration.actionIntentIds,
    };
    a.roleDigest = canonicalAuthorizationDigest({
      domain: 'pc.identity.envelope-role-binding.v1',
      participantId: e.participantId,
      role,
    });
    return {
      principalId: a.principalId,
      principalEpoch: '1',
      assignmentId: a.assignmentId,
      envelopeId: a.envelopeId,
      assignmentRevision: a.assignmentRevision,
      envelopeRevision: a.envelopeRevision,
      roleId: a.roleId,
      role,
      envelopeActions: [...role.actions],
      assignmentActions: [...role.actions],
    };
  });
  if (failure === 'changed assignment') rows[0]!.assignmentRevision = '2';
  if (failure === 'changed envelope') rows[0]!.envelopeRevision = '2';
  if (failure === 'changed role') rows[0]!.role.version = '2';
  if (failure === 'crossed envelope') rows[0]!.envelopeId = rows[1]!.envelopeId;
  if (failure === 'role action') rows[0]!.role.actions = [];
  if (failure === 'envelope action') rows[0]!.envelopeActions = [];
  if (failure === 'assignment action') rows[0]!.assignmentActions = [];
  if (failure === 'foreign scope')
    e.source.originalAdministrators[0].usable.administration.privacyDomainIds = [];
  if (failure === 'root expiry extension')
    e.source.originalAdministrators[0].usable.validUntilNs = (
      BigInt(source.root.grantable.validUntilNs) + 1n
    ).toString();
  if (failure === 'revoked original') rows.pop();
  const queries: string[] = [];
  const query = vi.fn(async (sql: string, _parameters?: unknown[]) => {
    queries.push(sql);
    if (sql.startsWith('select row_version'))
      return {
        rowCount: 1,
        rows: [
          {
            rootRevision: source.rootRevision,
            rootState: source.rootState,
            now: source.now,
            pending: null,
          },
        ],
      };
    if (sql.startsWith('select p.principal_id')) return { rowCount: rows.length, rows };
    throw new Error('Unexpected owner boundary');
  });
  const verifier = { verifyCanonicalAssertion: vi.fn() };
  return { e, source, client: { query } as never, verifier, queries, query, receipt, rows };
}

it.each([
  'complete',
  'verifier absent',
  'receipt signature',
  'changed assignment',
  'role action',
  'foreign scope',
  'root expiry extension',
  'revoked original',
  'competing successor',
])('routes receipt discovery through the genuine shared source owner: %s', async (failure) => {
  const v = setup(failure, true);
  const transport = certificateFixture();
  const selected = discoveryCertificateRecoveryEnrollment.safeParse({
    ...v.e,
    schema: 'pc.identity.discovery-certificate-recovery-enrollment',
    certificateRecovery: transport.binding,
  });
  if (failure === 'root expiry extension') {
    expect(selected.success).toBe(false);
    expect(v.queries).toEqual([]);
    return;
  }
  expect(selected.success).toBe(true);
  if (!selected.success) throw new Error('Invalid mocked receipt source');
  const enrollment = selected.data;
  const queries: string[] = [];
  const query = vi.fn(async (sql: string, parameters?: unknown[]) => {
    queries.push(sql);
    if (sql.includes('from openpc.lock_platform_recovery_enrollment'))
      return {
        rowCount: 1,
        rows: [
          {
            document: enrollment,
            document_digest: Buffer.from(canonicalAuthorizationDigest(enrollment).slice(7), 'hex'),
            row_version: '1',
            state: 'ACTIVE',
          },
        ],
      };
    if (sql.includes('current_user=')) return { rowCount: 1, rows: [{ allowed: true }] };
    if (sql.startsWith('select c.public_key_spki_der'))
      return {
        rowCount: 1,
        rows: [
          {
            publicKey,
            publicKeyDigest: createHash('sha256').update(publicKey).digest(),
            hardware: false,
          },
        ],
      };
    if (sql.startsWith("select jsonb_build_object('roleId'"))
      return {
        rowCount: 1,
        rows: [{ role: v.rows.find((r) => r.roleId === parameters?.[1])!.role }],
      };
    if (sql.includes('openpc.lock_discovery_certificate_recovery_source'))
      return {
        rowCount: 1,
        rows: [
          {
            source: { ...transport.source, competingSuccessor: failure === 'competing successor' },
          },
        ],
      };
    return v.query(sql, parameters);
  });
  const client = { query } as never;
  const result = readDiscoveryCertificateRecoverySource(
    client,
    enrollment.enrollmentId,
    true,
    undefined,
    null,
    failure === 'verifier absent' ? undefined : v.verifier,
  );
  if (failure === 'complete') {
    await expect(result).resolves.toMatchObject({
      enrollment,
      originalAdministrationDisplaced: true,
      administrationExpired: false,
      rootAdministrationEmpty: true,
    });
    expect(readCompletedRootExpiryRecoverySource).toHaveBeenCalledWith(
      client,
      expect.objectContaining({ recoveryId: v.e.source.recoveryId }),
      v.verifier,
    );
  } else await expect(result).rejects.toThrow();
  expect(queries.every((sql) => !/^(insert|update|delete)/iu.test(sql))).toBe(true);
  if (failure === 'verifier absent')
    expect(readCompletedRootExpiryRecoverySource).not.toHaveBeenCalled();
});

it('authenticates the original receipt before exact row locks and returns facts without effects', async () => {
  const v = setup();
  const before = structuredClone(v.e);
  const result = await readRootExpiryPlatformAdministration(v.client, v.e, v.verifier);
  expect(readCompletedRootExpiryRecoverySource).toHaveBeenCalledWith(
    v.client,
    {
      participantId: v.e.participantId,
      privacyDomainId: v.e.privacyDomainId,
      enrollmentId: v.e.source.enrollmentId,
      recoveryId: v.e.source.recoveryId,
    },
    v.verifier,
  );
  expect(result).toMatchObject({
    originalAdministrationDisplaced: true,
    administrationExpired: false,
    expiredReplacementId: null,
  });
  expect(result.root.grantable.administration.actionIntentIds).toEqual([]);
  expect(result.preparation.successorScope.runtime).toEqual(v.source.root.grantable.runtime);
  expect(v.queries.every((sql) => !/\b(insert|delete|update)\b/iu.test(sql))).toBe(true);
  expect(v.e).toEqual(before);
});
it.each([
  'receipt operation',
  'receipt digest',
  'receipt root epoch',
  'receipt foreign admin',
  'receipt signature',
  'changed assignment',
  'changed envelope',
  'changed role',
  'crossed envelope',
  'role action',
  'envelope action',
  'assignment action',
  'foreign scope',
  'root expiry extension',
  'revoked original',
])('denies %s', async (failure) => {
  const v = setup(failure);
  await expect(readRootExpiryPlatformAdministration(v.client, v.e, v.verifier)).rejects.toThrow();
});
it('fails before any read without an installed independent receipt verifier', async () => {
  const v = setup();
  await expect(readRootExpiryPlatformAdministration(v.client, v.e, undefined)).rejects.toThrow();
  expect(readCompletedRootExpiryRecoverySource).not.toHaveBeenCalled();
  expect(v.queries).toEqual([]);
});

function lineageSetup(failure?: string) {
  const v = setup();
  const oldest = {
    ...v.receipt,
    enrollment: structuredClone(v.receipt.enrollment),
    row: { ...v.receipt.row, evidence_digest: Buffer.from(v.receipt.row.evidence_digest) },
  };
  const reference = {
    recoveryId: v.e.source.recoveryId,
    enrollmentId: v.e.source.enrollmentId,
    activationOperationId: v.e.source.activationOperationId,
    receiptDigest: v.e.source.receiptDigest,
  };
  const oldRootDigest = v.e.rootDigest;
  const newerReference = {
    recoveryId: '018f0000-0000-7000-8000-000000000910',
    enrollmentId: '018f0000-0000-7000-8000-000000000911',
    activationOperationId: '018f0000-0000-7000-8000-000000000912',
    receiptDigest: `sha256:${'b'.repeat(64)}`,
  };
  v.e.rootEpoch = '3';
  v.e.rootRevision = '3';
  v.e.rootDigest = `sha256:${'c'.repeat(64)}`;
  v.e.source = { ...v.e.source, ...newerReference, ancestorReceipts: [reference] };
  const older = {
    ...oldest,
    row: {
      ...oldest.row,
      result: {
        rootEpoch: '2',
        rootRevision: '2',
        rootDigest: oldRootDigest,
        operationId: oldest.row.operation_id,
      },
    },
  };
  const newer = {
    intent: structuredClone(oldest.intent),
    enrollment: {
      ...structuredClone(oldest.enrollment),
      rootEpoch: '2',
      rootRevision: '2',
      rootDigest: oldRootDigest,
    },
    row: {
      operation_id: newerReference.activationOperationId,
      evidence_digest: Buffer.from(newerReference.receiptDigest.slice(7), 'hex'),
      result: {
        rootEpoch: '3',
        rootRevision: '3',
        rootDigest: v.e.rootDigest,
        operationId: newerReference.activationOperationId,
      },
    },
  };
  if (failure === 'gap') older.row.result.rootEpoch = '1';
  if (failure === 'revision link') older.row.result.rootRevision = '1';
  if (failure === 'digest link') older.row.result.rootDigest = `sha256:${'d'.repeat(64)}`;
  if (failure === 'foreign ancestor')
    older.enrollment.participantId = '018f0000-0000-7000-8000-000000000999';
  if (failure === 'foreign privacy')
    older.enrollment.privacyDomainId = '018f0000-0000-7000-8000-000000000999';
  if (failure === 'foreign context')
    older.enrollment.platformContextId = '018f0000-0000-7000-8000-000000000999';
  if (failure === 'foreign administrators') older.enrollment.administratorPrincipalIds.reverse();
  if (failure === 'ancestor operation')
    older.row.operation_id = newerReference.activationOperationId;
  if (failure === 'ancestor digest') older.row.evidence_digest = Buffer.alloc(32);
  if (failure === 'ancestor runtime') older.intent.successorScope.runtime.capabilityIds = [];
  if (failure === 'reordered')
    v.e.source = { ...v.e.source, ...reference, ancestorReceipts: [newerReference] };
  if (failure === 'duplicate') v.e.source.ancestorReceipts = [newerReference];
  if (failure === 'oversized')
    v.e.source.ancestorReceipts = Array.from({ length: 32 }, () => reference);
  vi.mocked(readCompletedRootExpiryRecoverySource)
    .mockReset()
    .mockResolvedValueOnce(newer as never);
  if (failure === 'ancestor cryptographic failure')
    vi.mocked(readCompletedRootExpiryRecoverySource).mockRejectedValueOnce(
      new Error('Original custody signature denied'),
    );
  else vi.mocked(readCompletedRootExpiryRecoverySource).mockResolvedValueOnce(older as never);
  vi.mocked(readCurrentPlatformScope).mockResolvedValue({
    ...v.source.root,
    platformAuthorityEpoch: '3',
    platformAuthorityDigest: v.e.rootDigest,
  });
  return v;
}
it('authenticates every ordered receipt and derives the untouched original administration epoch', async () => {
  const v = lineageSetup();
  await expect(
    readRootExpiryPlatformAdministration(v.client, v.e, v.verifier),
  ).resolves.toMatchObject({ originalAdministrationDisplaced: true });
  expect(readCompletedRootExpiryRecoverySource).toHaveBeenCalledTimes(2);
  const originalRead = v.query.mock.calls.find((call) =>
    call[0].startsWith('select p.principal_id'),
  );
  expect(originalRead?.[1]?.[5]).toBe('1');
  expect(v.e.rootEpoch).toBe('3');
});
it.each([
  'gap',
  'revision link',
  'digest link',
  'foreign ancestor',
  'foreign privacy',
  'foreign context',
  'foreign administrators',
  'ancestor operation',
  'ancestor digest',
  'reordered',
  'duplicate',
  'oversized',
  'ancestor cryptographic failure',
  'ancestor runtime',
])('rejects broken historical lineage: %s', async (failure) => {
  const v = lineageSetup(failure);
  await expect(readRootExpiryPlatformAdministration(v.client, v.e, v.verifier)).rejects.toThrow();
  expect(v.query).not.toHaveBeenCalled();
});
it('keeps old V2 serialization unchanged and rejects duplicate or oversized ancestor declarations', () => {
  const v = setup(),
    before = canonicalAuthorizationDigest(v.e);
  expect(rootExpiryPlatformRecoveryEnrollment.parse(v.e)).toEqual(v.e);
  expect(canonicalAuthorizationDigest(rootExpiryPlatformRecoveryEnrollment.parse(v.e))).toBe(
    before,
  );
  expect(
    Object.hasOwn(rootExpiryPlatformRecoveryEnrollment.parse(v.e).source, 'ancestorReceipts'),
  ).toBe(false);
  const repeated = {
    recoveryId: v.e.source.recoveryId,
    enrollmentId: v.e.source.enrollmentId,
    activationOperationId: v.e.source.activationOperationId,
    receiptDigest: v.e.source.receiptDigest,
  };
  expect(
    rootExpiryPlatformRecoveryEnrollment.safeParse({
      ...v.e,
      source: { ...v.e.source, ancestorReceipts: [repeated] },
    }).success,
  ).toBe(false);
  expect(
    rootExpiryPlatformRecoveryEnrollment.safeParse({
      ...v.e,
      source: { ...v.e.source, ancestorReceipts: Array.from({ length: 32 }, () => repeated) },
    }).success,
  ).toBe(false);
});
