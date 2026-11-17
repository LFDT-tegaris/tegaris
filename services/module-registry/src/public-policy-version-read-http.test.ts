import Fastify from 'fastify';
import type { Pool } from 'pg';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { registerPublicPolicyVersionReadRoutes } from './public-policy-version-read-http.js';
import type { PublicApprovalActor } from './public-approval-http.js';
const repository = vi.hoisted(() => ({ list: vi.fn(), get: vi.fn() }));
vi.mock('./db/policy-version-read-store.js', () => ({
  PolicyVersionReadRepository: class {
    list = repository.list;
    get = repository.get;
  },
}));
const id = (n: number) => `018f0000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const actor: PublicApprovalActor = {
  participantId: id(101),
  principalId: id(111),
  sessionId: id(117),
  sessionEpoch: '2',
  participantEpoch: '3',
  principalEpoch: '4',
  assignmentId: id(901),
  assignmentRowVersion: '5',
  authorityEnvelopeId: id(902),
  authorityEpoch: '6',
  delegationEpoch: '7',
};
const nativeHeaders = {
  'openpc-api-version': '1',
  'openpc-participant-id': `urn:openpc:participant:${actor.participantId}`,
  'x-request-id': id(801),
  'x-correlation-id': id(802),
};
const auth = { actor, privacyDomainId: id(201), sessionToken: 'native-private-token' };
afterEach(() => vi.resetAllMocks());
describe('canonical public policy-version read routes', () => {
  it('passes native identity scope, binds pagination to the session and reauthorizes before response', async () => {
    repository.list.mockResolvedValue({ items: [], total: '0', snapshotRevision: '1' });
    const authorize = vi.fn().mockResolvedValue(auth),
      app = Fastify();
    registerPublicPolicyVersionReadRoutes(app, { pool: {} as Pool, authorize });
    try {
      const response = await app.inject({
        url: `/api/v1/policy-versions?filter=policySetId:eq:urn:openpc:policy-set:${id(920)}`,
        headers: nativeHeaders,
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({
        items: [],
        authorizedEmpty: true,
        completeness: 'COMPLETE',
      });
      expect(response.headers['cache-control']).toBe('no-store');
      expect(authorize).toHaveBeenCalledTimes(2);
      expect(authorize.mock.calls[0]![1]).toEqual({
        actionIntentId: 'ACT-POLICY_VERSIONS_READ_COLLECTION-V1',
        resourceId: actor.participantId,
        stepUpRequired: false,
      });
      expect(repository.list.mock.calls[0]![0]).toMatchObject({
        resourceType: 'policy-version',
        authorization: {
          ...actor,
          privacyDomainId: auth.privacyDomainId,
          assignmentEpoch: actor.assignmentRowVersion,
        },
      });
      expect(repository.list.mock.calls[0]![0].authorization).not.toHaveProperty('evidenceCbor');
    } finally {
      await app.close();
    }
  });
  it('reads an exact version using the registered policy-version resource namespace', async () => {
    const versionId = id(921);
    repository.get.mockImplementation(async (context) => {
      if (context.resourceType !== 'policy-version' || context.resourceId !== versionId)
        throw new Error('The read must remain bound to the registered resource namespace');
      return { policyVersionId: `urn:openpc:policy-version:${versionId}`, state: 'DRAFT' };
    });
    const authorize = vi.fn().mockResolvedValue(auth);
    const app = Fastify();
    registerPublicPolicyVersionReadRoutes(app, { pool: {} as Pool, authorize });
    try {
      const response = await app.inject({
        url: `/api/v1/policy-versions/${encodeURIComponent(`urn:openpc:policy-version:${versionId}`)}`,
        headers: nativeHeaders,
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({
        policyVersionId: `urn:openpc:policy-version:${versionId}`,
        state: 'DRAFT',
      });
      expect(authorize).toHaveBeenCalledTimes(2);
      expect(authorize.mock.calls[0]![1]).toEqual({
        actionIntentId: 'ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
        resourceId: versionId,
        stepUpRequired: false,
      });
      expect(repository.get.mock.calls[0]![0].authorization).toMatchObject({
        ...actor,
        privacyDomainId: auth.privacyDomainId,
        assignmentEpoch: actor.assignmentRowVersion,
      });
    } finally {
      await app.close();
    }
  });
  it.each([
    'sessionEpoch',
    'participantEpoch',
    'principalEpoch',
    'assignmentRowVersion',
    'authorityEpoch',
    'delegationEpoch',
  ] as const)('withholds an earlier collection after %s changes', async (field) => {
    repository.list.mockResolvedValue({ items: [], total: '0', snapshotRevision: '1' });
    const authorize = vi
        .fn()
        .mockResolvedValueOnce(auth)
        .mockResolvedValueOnce({ ...auth, actor: { ...actor, [field]: '99' } }),
      app = Fastify();
    registerPublicPolicyVersionReadRoutes(app, { pool: {} as Pool, authorize });
    try {
      const response = await app.inject({ url: '/api/v1/policy-versions', headers: nativeHeaders });
      expect(response.statusCode).not.toBe(200);
      expect(response.json()).not.toHaveProperty('items');
    } finally {
      await app.close();
    }
  });
  it.each(['limit=201', 'sort=name', 'filter=unknown:eq:x', 'cursor=not-a-cursor', 'unknown=x'])(
    'rejects invalid collection input %s before repository access',
    async (query) => {
      const app = Fastify();
      registerPublicPolicyVersionReadRoutes(app, {
        pool: {} as Pool,
        authorize: vi.fn().mockResolvedValue(auth),
      });
      try {
        const response = await app.inject({
          url: `/api/v1/policy-versions?${query}`,
          headers: nativeHeaders,
        });
        expect(response.statusCode).not.toBe(200);
        expect(repository.list).not.toHaveBeenCalled();
      } finally {
        await app.close();
      }
    },
  );
});
