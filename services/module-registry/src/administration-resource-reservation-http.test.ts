import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { registerAdministrationResourceReservationRoutes } from './administration-resource-reservation-http.js';
import { reserveAdministrationResourceName } from './db/administration-resource-reservation-store.js';
import type { PublicApprovalRouteOptions } from './public-approval-http.js';

vi.mock('./db/administration-resource-reservation-store.js', () => ({
  reserveAdministrationResourceName: vi.fn(),
  getAdministrationResourceName: vi.fn(),
}));
const id = (n: number) => `018f0000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const actionDigest = `sha256:${'a'.repeat(64)}`;
const body = {
  command: 'RESERVE_RESOURCE_NAME',
  purpose: 'APPROVAL_REQUEST',
  makerSubjectRef: `urn:openpc:resource:${id(111)}`,
  businessActionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  businessResourceId: id(401),
  expectedBusinessRevision: '1',
  checkerPrincipalId: id(112),
  actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
  actionIntentDigest: actionDigest,
};
const requestHeaders = {
  'openpc-api-version': '1',
  'openpc-participant-id': `urn:openpc:participant:${id(101)}`,
  'x-request-id': id(501),
  'x-correlation-id': id(502),
  'x-openpc-action-intent-digest': actionDigest,
  'idempotency-key': 'reserve-01-administration',
  'x-csrf-token': 's'.repeat(32),
  'origin': 'https://qa.local',
  'host': 'qa.local',
};
const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
  vi.restoreAllMocks();
  vi.clearAllMocks();
});
function fixture() {
  const app = Fastify();
  apps.push(app);
  const authorize = vi.fn(async () => ({
    actor: { participantId: id(101), principalId: id(111) },
    privacyDomainId: id(201),
    sessionToken: 'session-secret-never-log',
  }));
  registerAdministrationResourceReservationRoutes(app, {
    pool: {},
    authorize,
  } as unknown as PublicApprovalRouteOptions);
  const logs: string[] = [];
  vi.spyOn(process.stderr, 'write').mockImplementation((value) => {
    logs.push(String(value));
    return true;
  });
  return { app, authorize, logs };
}
describe('public finite-name reservation boundary', () => {
  it('requires actual maker authorization and returns name-only readback with redacted diagnostics', async () => {
    const f = fixture();
    vi.mocked(reserveAdministrationResourceName).mockResolvedValue({
      ...body,
      kind: 'ADMINISTRATION_RESOURCE_NAME',
      version: 1,
      operationId: id(601),
      reservedResourceId: id(701),
      participantId: id(101),
      privacyDomainId: id(201),
      makerPrincipalId: id(111),
      createdAt: '2026-10-01T15:00:00.000Z',
      validUntil: '2026-10-01T16:00:00.000Z',
      authorityEffect: 'NONE',
      requiresFreshAuthority: true,
    } as unknown as Awaited<ReturnType<typeof reserveAdministrationResourceName>>);
    const response = await f.app.inject({
      method: 'POST',
      url: '/api/v1/administration-resource-reservations',
      headers: requestHeaders,
      payload: body,
    });
    expect(response.statusCode).toBe(201);
    expect(f.authorize).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ resourceId: id(111), actionIntentId: body.actionIntentId }),
    );
    expect(response.json().authorityEffect).toBe('NONE');
    expect(f.logs.join('')).toContain('NAME_ONLY_REQUIRES_FRESH_AUTHORITY');
    expect(f.logs.join('')).not.toContain('session-secret-never-log');
    expect(f.logs.join('')).not.toContain('s'.repeat(32));
  });
  it('denies another maker before creating a name', async () => {
    const f = fixture();
    const response = await f.app.inject({
      method: 'POST',
      url: '/api/v1/administration-resource-reservations',
      headers: requestHeaders,
      payload: { ...body, makerSubjectRef: `urn:openpc:resource:${id(113)}` },
    });
    expect(response.statusCode).toBe(403);
    expect(reserveAdministrationResourceName).not.toHaveBeenCalled();
  });
  it('rejects purpose substitution before authorization', async () => {
    const f = fixture();
    const response = await f.app.inject({
      method: 'POST',
      url: '/api/v1/administration-resource-reservations',
      headers: requestHeaders,
      payload: { ...body, purpose: 'POLICY_ACTIVATION_OCCURRENCE' },
    });
    expect(response.statusCode).toBe(403);
    expect(f.authorize).not.toHaveBeenCalled();
    expect(reserveAdministrationResourceName).not.toHaveBeenCalled();
  });
  it('preserves only stage and SQLSTATE after an owner failure', async () => {
    const f = fixture();
    vi.mocked(reserveAdministrationResourceName).mockRejectedValue(
      Object.assign(new Error('database statement contained secret signed bytes'), {
        code: '40001',
      }),
    );
    const response = await f.app.inject({
      method: 'POST',
      url: '/api/v1/administration-resource-reservations',
      headers: requestHeaders,
      payload: body,
    });
    expect(response.statusCode).toBe(403);
    expect(f.logs.join('')).toContain('commit_name_and_verify_readback');
    expect(f.logs.join('')).toContain('40001');
    expect(f.logs.join('')).not.toContain('secret signed bytes');
    expect(response.body).not.toContain('secret signed bytes');
  });
});
