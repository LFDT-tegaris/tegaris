import { X509Certificate } from 'node:crypto';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { workloadRotationAuthority } from './workload-rotation-pki.js';
import { closeFixtureResources } from './close-fixture-resources.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

it('signs a finite initial native-test credential without extending an existing signed leaf', async () => {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent?.startsWith('/')) throw new Error('Absolute isolated test scratch is required');
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, 'handover-initial-credential-'));
  let failure: { error: unknown } | undefined;
  try {
    const participantId = id(),
      targetId = id(),
      workloadId = `urn:openpc:workload:${targetId}`;
    const authority = await workloadRotationAuthority(root, participantId);
    for (const value of [0, 999, 180001, 1.5, Number.NaN, Number.POSITIVE_INFINITY])
      await expect(
        authority.bindWorkload(workloadId, {
          runtimeTargetId: targetId,
          initiallyCurrent: true,
          initialCredentialLifetimeMs: value,
        }),
      ).rejects.toThrow('finite current test issuance');
    await expect(
      authority.bindWorkload(workloadId, {
        runtimeTargetId: targetId,
        initialCredentialLifetimeMs: 180000,
      }),
    ).rejects.toThrow('finite current test issuance');
    const before = Date.now();
    const pki = await authority.bindWorkload(workloadId, {
      runtimeTargetId: targetId,
      initiallyCurrent: true,
      initialCredentialLifetimeMs: 180000,
    });
    const ca = new X509Certificate(pki.ca),
      original = Buffer.from(pki.predecessor.certificate.raw);
    expect(pki.predecessor.certificate.verify(ca.publicKey)).toBe(true);
    expect(new Date(pki.predecessor.certificate.validTo).getTime()).toBeGreaterThanOrEqual(
      before + 178000,
    );
    expect(new Date(pki.predecessor.certificate.validTo).getTime()).toBeLessThanOrEqual(
      Date.now() + 180000,
    );
    const issuedBefore = Date.now(),
      enrolled = await pki.issueInitialPredecessor(),
      issuedAfter = Date.now();
    expect(enrolled.certificate.verify(ca.publicKey)).toBe(true);
    expect(enrolled.certificate.subjectAltName).toBe(
      `URI:urn:openpc:participant:${participantId}:workload:${targetId}`,
    );
    expect(new Date(enrolled.certificate.validFrom).getTime()).toBeGreaterThanOrEqual(
      issuedBefore - 2000,
    );
    expect(new Date(enrolled.certificate.validTo).getTime()).toBeGreaterThanOrEqual(
      issuedBefore + 178000,
    );
    expect(new Date(enrolled.certificate.validTo).getTime()).toBeLessThanOrEqual(
      issuedAfter + 180000,
    );
    expect(enrolled.certificate.raw).not.toEqual(original);
    expect(pki.predecessor.certificate.raw).toEqual(original);
    await expect(pki.issueInitialPredecessor()).rejects.toThrow('already issued');
    await expect(authority.bindWorkload(workloadId, { runtimeTargetId: targetId })).rejects.toThrow(
      'already bound',
    );
    expect(pki.predecessor.certificate.raw).toEqual(original);
  } catch (error) {
    failure = { error };
  }
  await closeFixtureResources(
    [() => (failure ? undefined : rm(root, { recursive: true, force: true }))],
    failure,
  );
  if (failure) throw failure.error;
}, 20000);
