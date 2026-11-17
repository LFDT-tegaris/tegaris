import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { closeFixtureResources } from './close-fixture-resources.js';
import {
  workloadRotationAuthority,
  workloadRotationCertificates,
} from './workload-rotation-pki.js';
import {
  checkCurrentWorkloadTransport,
  ordinaryCredentialContinuity,
} from './workload-credential-continuity-fixture.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

it('authenticates independent expired and current continuity certificates before database allocation', async () => {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent?.startsWith('/')) throw new Error('Absolute isolated test scratch is required');
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, 'continuity-transport-'));
  let failure: { error: unknown } | undefined;
  try {
    const pki = await workloadRotationCertificates(root, id(), `urn:openpc:workload:${id()}`);
    expect(new Date(pki.predecessor.certificate.validTo).getTime()).toBeLessThan(Date.now());
    expect(new Date(pki.successor.certificate.validTo).getTime()).toBeGreaterThan(Date.now());
    await checkCurrentWorkloadTransport(pki);
  } catch (error) {
    failure = { error };
  }
  await closeFixtureResources(
    [() => (failure ? undefined : rm(root, { recursive: true, force: true }))],
    failure,
  );
  if (failure) throw failure.error;
}, 20000);

const admin = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
  runtime = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = admin && runtime ? it : it.skip;
integration(
  'creates a public runtime target before certificate binding and renews its expired workload through genuine approval across restart',
  () => ordinaryCredentialContinuity(admin!, runtime!),
  60000,
);

it('binds a prepared authority once to the exact runtime target without changing its signed identity', async () => {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent?.startsWith('/')) throw new Error('Absolute isolated test scratch is required');
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, 'continuity-target-binding-'));
  let failure: { error: unknown } | undefined;
  try {
    const participantId = id(),
      targetId = id();
    const authority = await workloadRotationAuthority(root, participantId);
    const workloadId = `urn:openpc:workload:${targetId}`;
    await expect(authority.bindWorkload(workloadId, { runtimeTargetId: id() })).rejects.toThrow(
      'exact public runtime target',
    );
    const pki = await authority.bindWorkload(workloadId, { runtimeTargetId: targetId });
    expect(pki.ca).toEqual(authority.ca);
    for (const leaf of [pki.predecessor, pki.successor])
      expect(leaf.certificate.subjectAltName).toBe(
        `URI:urn:openpc:participant:${participantId}:workload:${targetId}`,
      );
    const original = Buffer.from(pki.predecessor.certificate.raw);
    await expect(authority.bindWorkload(`urn:openpc:workload:${id()}`)).rejects.toThrow(
      'already bound',
    );
    expect(pki.predecessor.certificate.raw).toEqual(original);
    await checkCurrentWorkloadTransport(pki);
  } catch (error) {
    failure = { error };
  }
  await closeFixtureResources(
    [() => (failure ? undefined : rm(root, { recursive: true, force: true }))],
    failure,
  );
  if (failure) throw failure.error;
}, 20000);
