import { createHash, generateKeyPairSync } from 'node:crypto';
import { beforeEach, expect, it, vi } from 'vitest';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { platformRecoveryFixture } from '../domain/platform-recovery.test-fixture.js';
import { readCurrentPlatformScope } from './platform-envelope-scope.js';
import { enrollPlatformRecovery } from './platform-recovery-enrollment.js';

vi.mock('./platform-envelope-scope.js', () => ({ readCurrentPlatformScope: vi.fn() }));
beforeEach(() => vi.clearAllMocks());

function setup(failure?: string) {
  const { source, intent } = platformRecoveryFixture();
  const original = structuredClone(intent.preparation);
  original.replacementId = source.enrollment.expiredReplacementId;
  original.predecessorEpoch = '1';
  original.expectedRootRevision = '1';
  for (const administrator of original.administrators)
    for (const scope of [administrator.usable, administrator.grantable]) {
      scope.validFromNs = (BigInt(source.now.getTime() - 60000) * 1000000n).toString();
      scope.validUntilNs = (BigInt(source.now.getTime() - 1) * 1000000n).toString();
    }
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
    format: 'der',
    type: 'spki',
  });
  vi.mocked(readCurrentPlatformScope).mockResolvedValue({
    ...source.root,
    platformAuthorityDigest: source.rootDigest,
  });
  const statements: string[] = [];
  const query = vi.fn(async (sql: string) => {
    statements.push(sql);
    if (sql.includes('current_user='))
      return { rowCount: 1, rows: [{ permitted: failure !== 'runtime enrollment' }] };
    if (sql.includes('select r.candidate'))
      return {
        rowCount: 1,
        rows: [
          {
            candidate: original,
            candidateDigest:
              failure === 'changed original'
                ? Buffer.alloc(32)
                : Buffer.from(canonicalAuthorizationDigest(original).slice(7), 'hex'),
            rootRevision: source.rootRevision,
            rootState: source.rootState,
            now: source.now,
            pending: failure === 'pending handoff' ? original.replacementId : null,
          },
        ],
      };
    if (sql.includes('select a.principal_id')) {
      const rows = original.administrators.map((v) => ({
        principalId: v.principalId,
        principalEpoch: '1',
        assignmentId: v.assignmentId,
        envelopeId: v.envelopeId,
      }));
      if (failure === 'crossed grant bindings')
        [rows[0]!.envelopeId, rows[1]!.envelopeId] = [rows[1]!.envelopeId, rows[0]!.envelopeId];
      if (failure === 'partial expiry') rows.pop();
      return { rowCount: rows.length, rows };
    }
    if (sql.includes('select c.public_key_spki_der'))
      return failure === 'revoked credential'
        ? { rowCount: 0, rows: [] }
        : {
            rowCount: 1,
            rows: [
              {
                publicKey: key,
                publicKeyDigest:
                  failure === 'key mismatch'
                    ? Buffer.alloc(32)
                    : createHash('sha256').update(key).digest(),
                hardware: false,
              },
            ],
          };
    if (sql.startsWith('insert into control.platform_recovery_enrollment'))
      return { rowCount: 1, rows: [] };
    if (sql.startsWith('select document,document_digest'))
      return {
        rowCount: 1,
        rows: [
          {
            document: source.enrollment,
            digest: Buffer.from(canonicalAuthorizationDigest(source.enrollment).slice(7), 'hex'),
            revision: '1',
            state: failure === 'revoked source replay' ? 'REVOKED' : 'ACTIVE',
          },
        ],
      };
    throw new Error('Unexpected enrollment boundary');
  });
  return { source, statements, client: { query } as never };
}

it('enrolls only fixed initial trust, with an exact idempotent readback', async () => {
  const { source, client, statements } = setup();
  const result = await enrollPlatformRecovery(client, source.enrollment, { localQaEnabled: true });
  expect(result).toMatchObject({
    state: 'ENROLLED',
    authority: 'NONE',
    assurance: 'LOCAL_QA_VIRTUAL_AUTHENTICATOR',
    revision: '1',
  });
  expect(result.digest).toBe(canonicalAuthorizationDigest(source.enrollment));
  expect(statements.findIndex((sql) => sql.startsWith('insert'))).toBeLessThan(
    statements.findIndex((sql) => sql.includes('select a.principal_id')),
  );
  expect(
    statements.findIndex((sql) => sql.startsWith('select document,document_digest')),
  ).toBeLessThan(statements.findIndex((sql) => sql.includes('select c.public_key_spki_der')));
  expect(statements.filter((sql) => /\b(insert|update|delete)\b/iu.test(sql))).toHaveLength(1);
  expect(
    statements.some((sql) =>
      /insert into control\.(assignment|authority_envelope|mutation_candidate|approval_request|platform_recovery_case)\b/u.test(
        sql,
      ),
    ),
  ).toBe(false);
});

it.each([
  'runtime enrollment',
  'changed original',
  'pending handoff',
  'partial expiry',
  'crossed grant bindings',
  'revoked credential',
  'key mismatch',
])('rejects %s before the installation transaction can commit', async (failure) => {
  const { source, client, statements } = setup(failure);
  await expect(
    enrollPlatformRecovery(client, source.enrollment, { localQaEnabled: true }),
  ).rejects.toThrow();
  expect(statements.filter((sql) => sql.startsWith('insert'))).toHaveLength(
    failure === 'runtime enrollment' ? 0 : 1,
  );
  expect(statements.some((sql) => /^(commit|update|delete)/u.test(sql))).toBe(false);
});

it('never reactivates revoked trust through enrollment replay', async () => {
  const { source, client, statements } = setup('revoked source replay');
  await expect(
    enrollPlatformRecovery(client, source.enrollment, { localQaEnabled: true }),
  ).rejects.toThrow();
  expect(statements.some((sql) => sql.startsWith('update'))).toBe(false);
});

it('does not claim hardware attestation for a virtual authenticator', async () => {
  const { source, client, statements } = setup();
  source.enrollment.assurance = 'HARDWARE_ATTESTED';
  await expect(
    enrollPlatformRecovery(client, source.enrollment, { localQaEnabled: false }),
  ).rejects.toThrow();
  expect(statements.filter((sql) => sql.startsWith('insert'))).toHaveLength(1);
  expect(statements.some((sql) => /^(commit|update|delete)/u.test(sql))).toBe(false);
});
