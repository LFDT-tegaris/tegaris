import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import {
  assertIdentityEnvelopeRotationIssuerUnchanged,
  captureIdentityEnvelopeRotationIssuer,
  type IdentityEnvelopeRotationIssuer,
} from './identity-envelope-rotation-issuer.js';
const locks = vi.hoisted(() => ({ lock: vi.fn() }));
vi.mock('./authority-fence.js', () => ({ lockAuthorityFence: locks.lock }));

const issuer: IdentityEnvelopeRotationIssuer = {
  participantId: '01990000-0000-7000-8000-000000000001',
  privacyDomainId: '01990000-0000-7000-8000-000000000002',
  workloadCredentialId: '01990000-0000-7000-8000-000000000003',
  workloadPrincipalId: '01990000-0000-7000-8000-000000000004',
  workloadParticipantEpoch: '7',
  workloadPrincipalEpoch: '1',
  workloadCredentialEpoch: '1',
  workloadPublicKeyDigest: 'sha256:' + '71'.repeat(32),
  credentialValidFromNs: '1000',
  credentialValidUntilNs: '900000',
};
const scope = {
  participantId: issuer.participantId,
  privacyDomainId: issuer.privacyDomainId,
  workloadCredentialId: issuer.workloadCredentialId,
};
function database(rows: unknown[]) {
  const query = vi
    .fn()
    .mockResolvedValueOnce({ rows: [] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [{ principalId: issuer.workloadPrincipalId }] })
    .mockResolvedValueOnce({ rowCount: rows.length, rows });
  return { client: { query } as unknown as PoolClient, query };
}
describe('authoritative envelope issuer epochs for governed rotation', () => {
  it('captures the current issuer rather than copying stale key-admission epochs', async () => {
    const { client } = database([{ ...issuer, nowNs: '2000' }]);
    const result = await captureIdentityEnvelopeRotationIssuer(client, scope);
    expect(result.issuer.workloadParticipantEpoch).toBe('7');
    expect(Object.isFrozen(result.issuer)).toBe(true);
    expect(result.recordedAtNs).toBe(2000n);
  });
  it('does not read or return readiness after the ordered identity lock fails', async () => {
    const { client, query } = database([{ ...issuer, nowNs: '2000' }]);
    locks.lock.mockRejectedValueOnce(new Error('mocked missing identity lock'));
    await expect(captureIdentityEnvelopeRotationIssuer(client, scope)).rejects.toThrow(
      'missing identity lock',
    );
    expect(query).toHaveBeenCalledTimes(2);
  });
  it('rejects unavailable or ambiguous current identity without creating authority', async () => {
    for (const rows of [
      [],
      [
        { ...issuer, nowNs: '2000' },
        { ...issuer, nowNs: '2000' },
      ],
    ]) {
      const { client } = database(rows);
      await expect(captureIdentityEnvelopeRotationIssuer(client, scope)).rejects.toThrow(
        'issuer is unavailable',
      );
    }
  });
  it.each([
    { participantId: issuer.workloadPrincipalId },
    { privacyDomainId: issuer.workloadPrincipalId },
    { workloadCredentialId: issuer.workloadPrincipalId },
    { credentialValidFromNs: '3000' },
    { credentialValidUntilNs: '2000' },
    { workloadPublicKeyDigest: null },
    { workloadParticipantEpoch: '-1' },
  ])('rejects foreign, expired or malformed issuer sources: %j', async (change) => {
    const { client } = database([{ ...issuer, ...change, nowNs: '2000' }]);
    await expect(captureIdentityEnvelopeRotationIssuer(client, scope)).rejects.toThrow(
      'issuer is unavailable',
    );
  });
  it('accepts only an unchanged captured issuer across prepare and cutover', () => {
    expect(() =>
      assertIdentityEnvelopeRotationIssuerUnchanged(issuer, { ...issuer }),
    ).not.toThrow();
  });
  it.each([
    { workloadParticipantEpoch: '8' },
    { workloadPrincipalEpoch: '2' },
    { workloadCredentialEpoch: '2' },
    { workloadCredentialId: issuer.workloadPrincipalId },
    { workloadPrincipalId: issuer.workloadCredentialId },
    { workloadPublicKeyDigest: 'sha256:' + '72'.repeat(32) },
    { credentialValidUntilNs: '901000' },
  ])('requires a newly governed intent for issuer drift: %j', (change) => {
    expect(() =>
      assertIdentityEnvelopeRotationIssuerUnchanged(issuer, { ...issuer, ...change }),
    ).toThrow('issuer is unavailable');
  });
});
