import type { Pool } from 'pg';
import { PostgresIdentityRepository, type AuthenticatedIdentityActor } from './identity-kernel.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import {
  applyObservedWorkloadCredentialEffect,
  rotateWorkloadCredentialEffect,
} from './workload-rotation-effect.js';
import type { IssuedWorkloadCertificate } from './workload-credential-issuer.js';

/** External issuer and database are mocked. These checks never allocate a runtime. */
function fixture() {
  const now = new Date('2026-10-02T06:00:00.000Z');
  const input = {
    participantId: '018f0000-0000-7000-8000-000000000101',
    principalId: '018f0000-0000-7000-8000-000000000193',
    replacedCredentialId: '018f0000-0000-7000-8000-000000000401',
    credentialId: '018f0000-0000-7000-8000-000000000402',
    workloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000000194',
    predecessorEpoch: '3',
    publicKeySpkiDer: Buffer.from('unit-public-key'),
  };
  const certificateDer = Buffer.from('unit-external-certificate');
  const issued: IssuedWorkloadCertificate = {
    ...input,
    certificateDer,
    issuer: 'unit-external-issuer',
    uriSan: `urn:openpc:participant:${input.participantId}:workload:${input.workloadId.split(':').at(-1)}`,
    keyId: `sha256:${createHash('sha256').update(input.publicKeySpkiDer).digest('hex')}`,
    certificateFingerprint: createHash('sha256').update(certificateDer).digest(),
    notBefore: new Date(now.getTime() - 1000),
    notAfter: new Date(now.getTime() + 3600000),
  };
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [] });
  const client = { query } as unknown as PoolClient;
  const issuer = { issue: vi.fn().mockResolvedValue(issued) };
  return { now, input, issued, query, client, issuer };
}

it('retains the exact predecessor, successor, epoch, public key and issuer result', async () => {
  const f = fixture();
  const result = await rotateWorkloadCredentialEffect(f.client, f.input, f.issuer, () => f.now);
  expect(f.issuer.issue).toHaveBeenCalledOnce();
  expect(f.issuer.issue).toHaveBeenCalledWith({
    credentialId: f.input.credentialId,
    participantId: f.input.participantId,
    principalId: f.input.principalId,
    workloadId: f.input.workloadId,
    publicKeySpkiDer: f.input.publicKeySpkiDer,
  });
  expect(result).toMatchObject({
    credentialId: f.input.credentialId,
    replacedCredentialId: f.input.replacedCredentialId,
    workloadEpoch: '4',
    state: 'ACTIVE',
  });
  expect(f.query.mock.calls[1]![1]).toContain(f.issued.certificateDer);
  expect(f.query.mock.calls[1]![1]).toContain(f.input.replacedCredentialId);
});

it.each([
  ['foreign participant', { participantId: 'foreign' }],
  ['foreign workload', { workloadId: 'foreign' }],
  ['foreign principal', { principalId: 'foreign' }],
  ['different successor', { credentialId: 'foreign' }],
  ['different key', { publicKeySpkiDer: Buffer.from('other') }],
  ['wrong SAN', { uriSan: 'foreign' }],
  ['wrong key digest', { keyId: `sha256:${'00'.repeat(32)}` }],
  ['wrong certificate digest', { certificateFingerprint: Buffer.alloc(32) }],
  ['expired certificate', { notAfter: new Date('2026-10-02T06:00:00.000Z') }],
  ['future certificate', { notBefore: new Date('2026-10-02T06:00:01.000Z') }],
  ['invalid validity', { notAfter: new Date(NaN) }],
  ['above the security ceiling', { notAfter: new Date('2026-10-03T06:00:00.000Z') }],
])('rejects %s before credential mutation', async (_label, change) => {
  const f = fixture();
  f.issuer.issue.mockResolvedValue({ ...f.issued, ...change });
  await expect(
    rotateWorkloadCredentialEffect(f.client, f.input, f.issuer, () => f.now),
  ).rejects.toThrow('PC-IDENTITY-1006');
  expect(f.query).not.toHaveBeenCalled();
});

it('does not insert a successor after a failed predecessor fence', async () => {
  const f = fixture();
  f.query.mockResolvedValueOnce({ rowCount: 0, rows: [] });
  await expect(
    rotateWorkloadCredentialEffect(f.client, f.input, f.issuer, () => f.now),
  ).rejects.toThrow('PC-IDENTITY-1006');
  expect(f.query).toHaveBeenCalledOnce();
});

it('rejects exhausted epochs before calling the external issuer', async () => {
  const f = fixture();
  f.input.predecessorEpoch = '18446744073709551615';
  await expect(
    rotateWorkloadCredentialEffect(f.client, f.input, f.issuer, () => f.now),
  ).rejects.toThrow('PC-IDENTITY-1006');
  expect(f.issuer.issue).not.toHaveBeenCalled();
  expect(f.query).not.toHaveBeenCalled();
});

it('preserves an issuer failure without any credential writes', async () => {
  const f = fixture();
  f.issuer.issue.mockRejectedValue(new Error('external response unavailable'));
  await expect(
    rotateWorkloadCredentialEffect(f.client, f.input, f.issuer, () => f.now),
  ).rejects.toThrow('PC-IDENTITY-1006');
  expect(f.query).not.toHaveBeenCalled();
});

it('commits a pinned retained observation without dispatching the issuer again', async () => {
  const f = fixture();
  const result = await applyObservedWorkloadCredentialEffect(
    f.client,
    f.input,
    f.issued,
    () => f.now,
  );
  expect(result.credentialId).toBe(f.input.credentialId);
  expect(f.issuer.issue).not.toHaveBeenCalled();
  expect(f.query).toHaveBeenCalledTimes(2);
});
it('rejects an observation which expired after issuer response before any credential effect', async () => {
  const f = fixture();
  await expect(
    applyObservedWorkloadCredentialEffect(f.client, f.input, f.issued, () => f.issued.notAfter),
  ).rejects.toThrow('PC-IDENTITY-1006');
  expect(f.query).not.toHaveBeenCalled();
  expect(f.issuer.issue).not.toHaveBeenCalled();
});

/** Composition only: admission is mocked, not claimed as authority evidence. */
function repositoryCompositionFixture(observationOnly = false) {
  const f = fixture();
  const events: string[] = [];
  const repository = new PostgresIdentityRepository({} as Pool, { now: () => f.now });
  const internals = repository as unknown as {
    admittedMutation: (...args: unknown[]) => Promise<unknown>;
    scopedPrivacyTx: (...args: unknown[]) => Promise<unknown>;
    mutationTx: (...args: unknown[]) => Promise<unknown>;
  };
  const request = {
    participantId: f.input.participantId,
    principalId: f.input.principalId,
    credentialId: f.input.credentialId,
    workloadId: f.input.workloadId,
    publicKeySpkiDer: f.input.publicKeySpkiDer,
  };
  const prepared = observationOnly
    ? { kind: 'OBSERVED', issuanceId: f.input.credentialId, request }
    : {
        kind: 'CLAIM',
        issuanceId: f.input.credentialId,
        attemptId: f.input.replacedCredentialId,
        deadline: new Date(f.now.getTime() + 60000),
        request,
      };
  const admission = vi.spyOn(internals, 'admittedMutation').mockImplementation(async () => {
    events.push('claim_committed');
    return { preparation: prepared };
  });
  const observation = vi.spyOn(internals, 'scopedPrivacyTx').mockImplementation(async (...args) => {
    events.push('observation_transaction');
    const callback = args[3] as (client: PoolClient, operationId: string) => Promise<unknown>;
    const result = await callback(f.client, 'original-observation-operation');
    events.push('observation_committed');
    return result;
  });
  const final = vi.spyOn(internals, 'mutationTx').mockImplementation(async () => {
    events.push('final_admission');
    return { credentialId: f.input.credentialId };
  });
  const issuer = {
    recovery: {
      profileDigest: Buffer.alloc(32, 1),
      replayProfile: 'READBACK_REQUIRED' as const,
      verifyObservation: vi.fn().mockReturnValue(f.issued),
    },
    issue: vi.fn().mockImplementation(async (_request, signal: AbortSignal) => {
      events.push('issuer');
      expect(signal).toBeInstanceOf(AbortSignal);
      return f.issued;
    }),
  };
  const actor: AuthenticatedIdentityActor = {
    participantId: f.input.participantId,
    principalId: '018f0000-0000-7000-8000-000000000111',
    sessionToken: `${f.input.participantId}.018f0000-0000-7000-8000-000000000117`,
    platform: true,
    mutationAuthorization: {
      authorized: true,
      idempotencyKey: 'fixed-original-native-intent',
      candidateDigest: `sha256:${'a'.repeat(64)}`,
      privacyDomainId: '018f0000-0000-7000-8000-000000000201',
      aggregateVersion: '1',
      evidenceCbor: Buffer.from('decision'),
      evidenceDigest: Buffer.alloc(32, 1),
      coseSign1: Buffer.from('signed-decision'),
      evidenceKind: 'USER_WEBAUTHN',
      signerCredentialId: '018f0000-0000-7000-8000-000000000116',
    },
  };
  const run = () =>
    repository.rotateWorkloadFromIssuer(
      actor,
      f.input.replacedCredentialId,
      f.input.credentialId,
      f.input.publicKeySpkiDer,
      issuer,
    );
  return { ...f, events, repository, admission, observation, final, issuer, actor, run };
}
it('commits preparation before issuer dispatch, then observation before repeating final admission', async () => {
  const f = repositoryCompositionFixture();
  await f.run();
  expect(f.events).toEqual([
    'claim_committed',
    'issuer',
    'observation_transaction',
    'observation_committed',
    'final_admission',
  ]);
  expect(f.issuer.issue).toHaveBeenCalledOnce();
  expect(f.query).toHaveBeenCalledTimes(2);
});
it('retains observed certificate custody when the final current authority check fails', async () => {
  const f = repositoryCompositionFixture();
  f.final.mockRejectedValue(new Error('current authority expired'));
  await expect(f.run()).rejects.toThrow('current authority expired');
  expect(f.events).toEqual([
    'claim_committed',
    'issuer',
    'observation_transaction',
    'observation_committed',
  ]);
  expect(f.query.mock.calls[1]![1]).toContain(f.issued.certificateDer);
  expect(f.query.mock.calls.some((call) => String(call[0]).includes('control.credential'))).toBe(
    false,
  );
});
it('resumes retained observation through fresh final admission without dispatching the issuer', async () => {
  const f = repositoryCompositionFixture(true);
  await f.run();
  expect(f.events).toEqual(['claim_committed', 'final_admission']);
  expect(f.issuer.issue).not.toHaveBeenCalled();
  expect(f.observation).not.toHaveBeenCalled();
});
it('records external uncertainty and stops before any final business admission', async () => {
  const f = repositoryCompositionFixture();
  f.issuer.issue.mockRejectedValue(new Error('connection lost after dispatch'));
  await expect(f.run()).rejects.toThrow('PC-IDENTITY-1006');
  expect(f.final).not.toHaveBeenCalled();
  expect(f.query).toHaveBeenCalledTimes(2);
  expect(f.query.mock.calls[0]![1]).toContain('AMBIGUOUS');
});
