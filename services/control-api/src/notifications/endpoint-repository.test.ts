import { expect, it, vi } from 'vitest';
import type { Pool } from 'pg';
import type { MutationContext } from '../configuration/persistence/types.js';
import type { ReadContext } from '../configuration/persistence/scoped-read.js';
import type { ListRequest } from '../configuration/pagination.js';
import {
  NotificationEndpointRepository,
  requireCanonicalEndpointPersistence,
} from './endpoint-repository.js';
import type { NotificationEndpointOwners } from './endpoint-owner-contract.js';

// Negative dependency/request tests only. No SQL, signed transition, identity,
// challenge, profile installation, fresh WebAuthn or runtime acceptance is mocked.
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = (n: number) => `urn:openpc:resource:${id(n)}`;
const digest = `sha256:${'a'.repeat(64)}`;
const create = {
  actionIntentId: 'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1',
  actionIntentDigest: digest,
  participantId: `urn:openpc:participant:${id(1)}`,
  channel: 'WEBHOOK' as const,
  destinationRef: ref(4),
  arbitraryEgress: false as const,
  reason: 'Create a disabled endpoint.',
};
const update = {
  actionIntentId: 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
  actionIntentDigest: digest,
  expectedRevision: '2',
  replacementDigest: digest,
  reason: 'Replace the admitted binding.',
};
const verify = {
  actionIntentId: 'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
  actionIntentDigest: digest,
  expectedRevision: '2',
  targetRef: ref(3),
  inputDigest: digest,
  reason: 'Verify this exact binding.',
};
function context(
  command: 'CREATE' | 'UPDATE' | 'VERIFY',
  candidate: typeof create | typeof update | typeof verify,
): MutationContext {
  return {
    authorization: { participantId: id(1), privacyDomainId: id(2) },
    resourceId: id(3),
    expectedRevision: command === 'CREATE' ? '0' : '2',
    candidate,
    aggregateType: 'notification-endpoint',
    catalogOperationId: `CFG-OP-${command}-NOTIFICATION-ENDPOINT`,
    actionIntentId: candidate.actionIntentId,
    actionIntentDigest: candidate.actionIntentDigest,
    resourceType: command === 'VERIFY' ? 'notification-endpoint' : 'notification-endpoints',
    operationClass: command === 'CREATE' ? 'CREATE' : 'UPDATE',
  } as MutationContext;
}
function fixture() {
  const connect = vi.fn(() => {
    throw new Error('Must not allocate SQL for missing dependencies');
  });
  const pool = { connect } as unknown as Pool;
  const unreachable = vi.fn(async () => {
    throw new Error('No authoritative owner installed');
  });
  const owners: NotificationEndpointOwners = {
    resolveCreate: unreachable,
    resolveReplacement: unreachable,
    verify: unreachable,
  };
  const runtime = { verifyCanonicalAssertion: vi.fn(async () => undefined) };
  const evidence = {
    environmentId: 'local',
    signer: {
      sign: vi.fn(async () => {
        throw new Error('Must not sign');
      }),
    },
  };
  return { connect, pool, unreachable, owners, runtime, evidence };
}

it('fails closed before transactions or owner calls when construction dependencies are missing', async () => {
  const f = fixture();
  for (const repository of [
    new NotificationEndpointRepository(f.pool),
    new NotificationEndpointRepository(f.pool, f.runtime, f.evidence),
    new NotificationEndpointRepository(f.pool, undefined, f.evidence, f.owners),
    new NotificationEndpointRepository(f.pool, f.runtime, undefined, f.owners),
  ]) {
    // Even constructor-shaped doubles cannot admit absent canonical endpoint
    // profiles or SQL bindings. There is deliberately no readiness boolean.
    await expect(repository.create(context('CREATE', create), create)).rejects.toThrow(
      'PC-INTEGRATION-5001',
    );
    await expect(repository.update(context('UPDATE', update), update)).rejects.toThrow(
      'PC-INTEGRATION-5001',
    );
    await expect(repository.verify(context('VERIFY', verify), verify)).rejects.toThrow(
      'PC-INTEGRATION-5001',
    );
  }
  expect(f.connect).not.toHaveBeenCalled();
  expect(f.unreachable).not.toHaveBeenCalled();
  expect(f.evidence.signer.sign).not.toHaveBeenCalled();
  expect(f.runtime.verifyCanonicalAssertion).not.toHaveBeenCalled();
});

it('rejects changed requests, cross-scope targets and public owner injection without effects', async () => {
  const f = fixture(),
    repository = new NotificationEndpointRepository(f.pool, f.runtime, f.evidence, f.owners);
  await expect(
    repository.create(context('CREATE', create), { ...create, destinationRef: ref(9) }),
  ).rejects.toThrow('PC-DATA-6007');
  await expect(
    repository.update(context('UPDATE', update), { ...update, expectedRevision: '1' }),
  ).rejects.toThrow('PC-DATA-6007');
  await expect(
    repository.verify(context('VERIFY', verify), { ...verify, targetRef: ref(9) }),
  ).rejects.toThrow('PC-DATA-6007');
  const injected = { ...create, owners: f.owners };
  await expect(repository.create(context('CREATE', injected), injected)).rejects.toThrow(
    'PC-DATA-6007',
  );
  const foreign = { ...create, participantId: `urn:openpc:participant:${id(9)}` };
  await expect(repository.create(context('CREATE', foreign), foreign)).rejects.toThrow(
    'PC-DATA-6007',
  );
  expect(f.connect).not.toHaveBeenCalled();
  expect(f.unreachable).not.toHaveBeenCalled();
});

it('does not reuse verification or notification authority for endpoint reads and collection counts', async () => {
  const f = fixture(),
    repository = new NotificationEndpointRepository(f.pool);
  const wrong = {
    actionIntentId: 'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
    resourceType: 'notification-endpoint',
    resourceId: id(3),
  } as ReadContext;
  await expect(repository.get(wrong)).rejects.toThrow('PC-AUTH-0005');
  await expect(repository.list({ ...wrong, resourceId: '*' }, {} as ListRequest)).rejects.toThrow(
    'PC-AUTH-0005',
  );
  await expect(
    repository.get({ ...wrong, actionIntentId: 'ACT-NOTIFICATIONS_READ_RESOURCE-V1' }),
  ).rejects.toThrow('PC-AUTH-0005');
  expect(f.connect).not.toHaveBeenCalled();
});

it('does not convert an unregistered operation into persistence readiness', async () => {
  const query = vi.fn();
  await expect(
    requireCanonicalEndpointPersistence({ query } as never, {
      ...context('CREATE', create),
      catalogOperationId: 'CFG-OP-NOT-REGISTERED',
    }),
  ).rejects.toThrow('PC-INTEGRATION-5001');
  expect(query).not.toHaveBeenCalled();
});
