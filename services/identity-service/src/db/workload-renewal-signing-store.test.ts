import { generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import {
  workloadRenewalSigningTrustDigest,
  workloadRenewalSigningTrustPreimage,
} from '@openpc/security-kernel';
import { renewalSigningTrustFixture } from '../../../../packages/security-kernel/src/workload-renewal/fixture.js';
import {
  authenticatedWorkloadRenewalSigningTrust,
  discoverWorkloadRenewalSigningDependencies,
  fenceWorkloadRenewalSigningTrust,
} from './workload-renewal-signing-store.js';
const spki = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
  type: 'spki',
  format: 'der',
});
function fixture() {
  const t = renewalSigningTrustFixture(spki);
  const row = {
    participant_id: t.participantId,
    privacy_domain_id: t.privacyDomainId,
    environment_id: t.environmentId,
    signer_id: t.signerId,
    public_key_spki_der: t.publicKeySpkiDer,
    principal_id: t.principalId,
    workload_id: t.workloadId,
    family_id: t.familyId,
    family_security_epoch: '2',
    participant_security_invalidation_epoch: '0',
    key_security_generation: '2',
    provider_qualification_digest: Buffer.from(t.providerQualificationDigest.slice(7), 'hex'),
    key_epoch: '2',
    valid_from_ns: t.validFromNs.toString(),
    valid_until_ns: t.validUntilNs.toString(),
    admission_kind: t.admissionKind,
    admission_reference: t.admissionReference,
    admission_digest: Buffer.from(t.admissionDigest.slice(7), 'hex'),
    secret_class: t.secretClass,
    secret_reference: t.secretReference,
    secret_version: t.secretVersion,
    trust_preimage: workloadRenewalSigningTrustPreimage(t),
    trust_digest: Buffer.from(workloadRenewalSigningTrustDigest(t).slice(7), 'hex'),
    credentialId: '018f0000-0000-7000-8000-000000000027',
    credentialEpoch: '4',
    familyGeneration: '13',
    familyVersion: '14',
    fingerprint: 'ab'.repeat(32),
    nowNs: '1800000001000000000',
  };
  return {
    t,
    row,
    scope: {
      participantId: t.participantId,
      privacyDomainId: t.privacyDomainId,
      environmentId: t.environmentId,
    },
    discovered: {
      signerId: t.signerId,
      familyId: t.familyId,
      principalId: t.principalId,
      credentialId: row.credentialId,
    },
  };
}
function database(f = fixture()) {
  let row = f.row,
    epoch = '0';
  const query = vi.fn(async (sql: string) => {
    if (sql.includes('workload_renewal_participant_security_epoch'))
      return { rowCount: 1, rows: [{ epoch }] };
    if (sql.startsWith('select k.*')) return { rowCount: 1, rows: [row] };
    return { rowCount: 1, rows: [] };
  });
  return {
    query,
    client: { query } as unknown as PoolClient,
    setRow: (value: typeof row) => {
      row = value;
    },
    setEpoch: (value: string) => {
      epoch = value;
    },
  };
}
it('authenticates exact immutable trust without confusing current leaf metadata with key provenance', () => {
  const f = fixture();
  expect(authenticatedWorkloadRenewalSigningTrust(f.row)).toEqual(f.t);
  const renewed = {
    ...f.row,
    credentialId: '018f0000-0000-7000-8000-000000000099',
    credentialEpoch: '5',
  };
  expect(authenticatedWorkloadRenewalSigningTrust(renewed)).toEqual(f.t);
});
it.each([
  'family_security_epoch',
  'participant_security_invalidation_epoch',
  'key_security_generation',
  'key_epoch',
] as const)('rejects descriptor substitution %s', (field) => {
  const f = fixture();
  expect(() => authenticatedWorkloadRenewalSigningTrust({ ...f.row, [field]: '9' })).toThrow();
});
it('discovers exact current C04 dependencies without claiming signer eligibility or accepting missing selection', async () => {
  const f = fixture(),
    query = vi
      .fn()
      .mockResolvedValueOnce({ rows: [], rowCount: 1 })
      .mockResolvedValueOnce({ rowCount: 1, rows: [f.discovered] });
  expect(
    await discoverWorkloadRenewalSigningDependencies({ query } as unknown as PoolClient, f.scope),
  ).toEqual(f.discovered);
  expect(query.mock.calls.every(([sql]) => !String(sql).includes('for share'))).toBe(true);
  query.mockResolvedValue({ rowCount: 0, rows: [] });
  await expect(
    discoverWorkloadRenewalSigningDependencies({ query } as unknown as PoolClient, f.scope),
  ).rejects.toThrow();
});
it('locks selection, lifecycle and signer family once, then rechecks under the same transaction', async () => {
  const f = fixture(),
    db = database(f),
    bound = await fenceWorkloadRenewalSigningTrust(db.client, f.scope, f.discovered);
  expect(bound.trust).toEqual(f.t);
  expect(bound.current).toEqual({ credentialId: f.row.credentialId, credentialEpoch: 4n });
  expect(bound.familyGeneration).toBe(13n);
  const lockCalls = db.query.mock.calls
    .map(([sql]) => sql)
    .filter((sql) => sql.includes('for share'));
  expect(lockCalls).toHaveLength(3);
  expect(lockCalls[0]).toContain('workload_renewal_signing_selection');
  expect(lockCalls[1]).toContain('business_signing_key_state');
  expect(lockCalls[2]).toContain('workload_credential_family');
  db.query.mockClear();
  await bound.revalidate();
  expect(db.query.mock.calls.every(([sql]) => !sql.includes('for share'))).toBe(true);
});
it.each([
  ['credentialId', '018f0000-0000-7000-8000-000000000099'],
  ['credentialEpoch', '5'],
  ['familyGeneration', '14'],
  ['familyVersion', '15'],
  ['fingerprint', 'cd'.repeat(32)],
] as const)('rejects final current-family drift %s', async (field, value) => {
  const f = fixture(),
    db = database(f),
    bound = await fenceWorkloadRenewalSigningTrust(db.client, f.scope, f.discovered);
  db.setRow({ ...f.row, [field]: value });
  await expect(bound.revalidate()).rejects.toThrow();
});
it('rejects later archive after restore and never turns hidden or unknown history into zero', async () => {
  const f = fixture(),
    db = database(f),
    bound = await fenceWorkloadRenewalSigningTrust(db.client, f.scope, f.discovered);
  db.setEpoch('4');
  await expect(bound.revalidate()).rejects.toThrow();
  db.setEpoch('');
  await expect(
    fenceWorkloadRenewalSigningTrust(db.client, f.scope, f.discovered),
  ).rejects.toThrow();
  db.query.mockRejectedValue(new Error('RLS completeness unavailable'));
  await expect(fenceWorkloadRenewalSigningTrust(db.client, f.scope, f.discovered)).rejects.toThrow(
    'RLS completeness unavailable',
  );
});
it.each([1, 2, 3])(
  'rejects unavailable selection/lifecycle/family fence %s before provenance or effect',
  async (position) => {
    const f = fixture(),
      query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [] });
    for (let n = 0; n < position; n++) query.mockResolvedValueOnce({ rowCount: 1, rows: [] });
    query.mockResolvedValueOnce({ rowCount: 0, rows: [] });
    await expect(
      fenceWorkloadRenewalSigningTrust({ query } as unknown as PoolClient, f.scope, f.discovered),
    ).rejects.toThrow();
    expect(query.mock.calls.some(([sql]) => String(sql).startsWith('select k.*'))).toBe(false);
  },
);
