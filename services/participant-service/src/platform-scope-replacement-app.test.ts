import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
  envelopeFixtureScope,
} from '../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { registerPlatformScopeReplacementRoutes } from './platform-scope-replacement-app.js';
import type { ParticipantKernel } from './domain/participant-kernel.js';
import { PlatformScopeOwnerFailure } from '../../identity-service/src/db/platform-scope-owner-failure.js';

function fixture() {
  const logs: string[] = [];
  const app = Fastify({
    logger: {
      level: 'info',
      stream: {
        write: (value: string) => {
          logs.push(value);
        },
      },
    },
  });
  const actor = { platform: true, principalId: id(100), participantId: id(1) };
  const helpers = {
    authenticate: vi.fn(async () => actor),
    read: vi.fn(async () => actor),
    prepare: vi.fn(async () => ({
      candidateHash: digest(3),
      aggregateVersion: '0',
      actionIntentDigest: digest(4),
    })),
    authorize: vi.fn(async () => actor),
    problem: (code: string) => ({ code, status: 409 }),
  };
  const prepare = vi.fn(async () => ({
    replacementId: id(8),
    successorDigest: digest(2),
    state: 'WITHDRAWING',
    revision: '1',
    operationId: id(50),
  }));
  const readiness = vi.fn(async () => ({ platformContextId: id(4), state: 'WITHDRAWING' }));
  registerPlatformScopeReplacementRoutes(
    app,
    {
      preparePlatformScope: prepare,
      platformScopeReadiness: readiness,
    } as unknown as ParticipantKernel,
    helpers as unknown as Parameters<typeof registerPlatformScopeReplacementRoutes>[2],
    (level, fields) => {
      logs.push(JSON.stringify({ level, ...fields }));
    },
  );
  const before = envelopeFixtureScope(0);
  const administration = {
    ...structuredClone(before),
    runtime: {
      participantIds: [],
      privacyDomainIds: [],
      resourceIds: [],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: [],
      capabilityIds: [],
    },
  };
  const body = {
    schema: 'pc.identity.platform-scope-replacement',
    schemaVersion: 1,
    replacementId: id(8),
    platformContextId: id(4),
    expectedRootRevision: '1',
    predecessorEpoch: '1',
    predecessorDigest: digest(1),
    successorScope: { ...before, makerCheckerRequired: false, stepUpRequired: false },
    administrators: [100, 101].map((n) => ({
      principalId: id(n),
      envelopeId: id(n + 10),
      assignmentId: id(n + 20),
      roleId: id(n + 30),
      expectedRoleRevision: '1',
      roleDigest: digest(6),
      usable: administration,
      grantable: administration,
    })),
    affectedTargets: [],
    reason: 'Exact governed successor scope request',
  };
  const headers = {
    'authorization': 'Bearer secret-session-token',
    'x-openpc-aggregate-version': '0',
  };
  return {
    app,
    logs,
    prepare,
    readiness,
    helpers,
    body,
    headers,
    url: `/v1/platform-contexts/${id(4)}/scope-replacements`,
  };
}
describe('Platform replacement route diagnostics with mocked owners', () => {
  it('logs approved diagnostic inputs and the pending effect without secrets or authority documents', async () => {
    const f = fixture();
    try {
      const response = await f.app.inject({
        method: 'POST',
        url: f.url,
        headers: f.headers,
        payload: f.body,
      });
      expect(response.statusCode).toBe(200);
      expect(response.json().state).toBe('WITHDRAWING');
      const logs = f.logs.join('\n');
      expect(logs).toContain('AWAIT_SIGNED_WITHDRAWAL_AND_HANDOFF');
      expect(logs).toContain('"predecessorEpoch":"1"');
      expect(logs).toContain('"runtimeStepUpRequired":false');
      expect(logs).not.toContain('secret-session-token');
      expect(logs).not.toContain(f.body.reason);
      expect(logs).not.toContain('"administrators":');
    } finally {
      await f.app.close();
    }
  });
  it('preserves the failing stage and SQLSTATE without printing driver messages, details or signed inputs', async () => {
    const f = fixture();
    f.prepare.mockRejectedValueOnce(
      Object.assign(new Error('secret-driver-message'), {
        code: '42501',
        detail: 'secret-signed-bytes',
      }),
    );
    try {
      const response = await f.app.inject({
        method: 'POST',
        url: f.url,
        headers: f.headers,
        payload: f.body,
      });
      expect(response.statusCode).toBe(409);
      const logs = f.logs.join('\n');
      expect(logs).toContain('"stage":"commit_preparation"');
      expect(logs).toContain('"sqlstate":"42501"');
      for (const secret of [
        'secret-session-token',
        'secret-driver-message',
        'secret-signed-bytes',
      ]) {
        expect(logs).not.toContain(secret);
        expect(response.body).not.toContain(secret);
      }
    } finally {
      await f.app.close();
    }
  });
  it('rejects a path binding mismatch before authorization or an effect', async () => {
    const f = fixture();
    f.body.platformContextId = id(9);
    try {
      const response = await f.app.inject({
        method: 'POST',
        url: f.url,
        headers: f.headers,
        payload: f.body,
      });
      expect(response.statusCode).toBe(409);
      expect(f.helpers.authorize).not.toHaveBeenCalled();
      expect(f.prepare).not.toHaveBeenCalled();
    } finally {
      await f.app.close();
    }
  });
  it('logs the owning transaction stage after sanitized failure propagation', async () => {
    const f = fixture();
    f.prepare.mockRejectedValueOnce(
      new PlatformScopeOwnerFailure(
        'atomic_prepare',
        Object.assign(new Error('secret driver message'), {
          code: '40001',
          detail: 'secret signed bytes',
        }),
      ),
    );
    try {
      const response = await f.app.inject({
        method: 'POST',
        url: f.url,
        headers: f.headers,
        payload: f.body,
      });
      expect(response.statusCode).toBe(409);
      const logs = f.logs.join('\n');
      expect(logs).toContain('"ownerStage":"atomic_prepare"');
      expect(logs).toContain('"sqlstate":"40001"');
      expect(logs).not.toContain('secret driver');
      expect(logs).not.toContain('secret signed');
      expect(response.body).not.toContain('secret');
    } finally {
      await f.app.close();
    }
  });
});

it('emits a redacted source failure when ordinary request logging is disabled', async () => {
  const f = fixture();
  const app = Fastify({ logger: false });
  const output = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  registerPlatformScopeReplacementRoutes(
    app,
    {
      platformScopeSource: vi
        .fn()
        .mockRejectedValue(Object.assign(new Error('private database input'), { code: '42501' })),
    } as unknown as ParticipantKernel,
    f.helpers as unknown as Parameters<typeof registerPlatformScopeReplacementRoutes>[2],
  );
  try {
    const response = await app.inject({
      method: 'GET',
      url: `/v1/platform-contexts/${id(4)}/scope-replacement-source`,
      headers: { ...f.headers, 'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${id(2)}` },
    });
    expect(response.statusCode).toBe(409);
    const log = output.mock.calls.map(([value]) => String(value)).join('');
    expect(log).toContain('platform_scope_source_failed');
    expect(log).toContain('"sqlstate":"42501"');
    expect(log).not.toContain('secret-session-token');
    expect(log).not.toContain('private database input');
  } finally {
    output.mockRestore();
    await app.close();
    await f.app.close();
  }
});

it.each([true, false])(
  'forwards authorized readiness with the actual session mode (Platform=%s)',
  async (platform) => {
    const f = fixture();
    f.helpers.authenticate.mockResolvedValue({
      platform,
      principalId: id(100),
      participantId: id(1),
    });
    f.helpers.read.mockResolvedValue({ platform, principalId: id(100), participantId: id(1) });
    try {
      const r = await f.app.inject({
        method: 'GET',
        url: `${f.url}/${id(8)}/readiness`,
        headers: {
          'authorization': 'Bearer secret-session-token',
          'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${id(2)}`,
        },
      });
      expect(r.statusCode).toBe(200);
      expect(f.readiness).toHaveBeenCalledWith(expect.objectContaining({ platform }), id(2), id(8));
      expect(f.prepare).not.toHaveBeenCalled();
      expect(f.helpers.authorize).not.toHaveBeenCalled();
    } finally {
      await f.app.close();
    }
  },
);
