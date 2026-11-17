import { writeRecoveryDiagnostic } from './platform-recovery-diagnostics.js';
import { expect, it, vi } from 'vitest';
import { buildIdentityService } from './app.js';
import type { IdentityKernel } from './domain/identity-kernel.js';
import { IdentityKernelError } from './domain/identity-errors.js';
import { localWebAuthnAllowedOrigin } from './local-runtime.js';
vi.mock('./platform-recovery-diagnostics.js', () => ({ writeRecoveryDiagnostic: vi.fn() }));
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
it.each(['platform-recovery', 'discovery-certificate-recovery'] as const)(
  'requires actual Platform login, unique cookie, CSRF and authenticated browser origin for %s',
  async (purpose) => {
    const sessionSnapshot = vi
      .fn()
      .mockResolvedValue({ participantId: id(101), principalId: id(111), contextMode: 'PLATFORM' });
    const verifyCsrf = vi.fn();
    const platformRecoveryCommand = vi
      .fn()
      .mockResolvedValue({ authority: 'NONE', state: 'DRAFT' });
    const discoveryCertificateRecoveryCommand = vi
      .fn()
      .mockResolvedValue({ authority: 'NONE', state: 'DRAFT' });
    const commandHandler =
      purpose === 'platform-recovery'
        ? platformRecoveryCommand
        : discoveryCertificateRecoveryCommand;
    const otherHandler =
      purpose === 'platform-recovery'
        ? discoveryCertificateRecoveryCommand
        : platformRecoveryCommand;
    vi.mocked(writeRecoveryDiagnostic).mockClear();
    const app = buildIdentityService(
      {
        sessionSnapshot,
        verifyCsrf,
        platformRecoveryCommand,
        discoveryCertificateRecoveryCommand,
      } as unknown as IdentityKernel,
      undefined,
      undefined,
      undefined,
      localWebAuthnAllowedOrigin(
        'test-internal-secret',
        'http://localhost:8080/api/v1/ui/oidc-session/callback',
      ),
    );
    const base = {
      'host': 'identity:3001',
      'origin': 'http://identity:3001',
      'authorization': 'Bearer test-internal-secret',
      'x-openpc-browser-origin': 'http://localhost:8080',
      'x-csrf-token': 'test-csrf',
      'cookie': `__Host-openpc_session=${id(101)}.${id(900)}`,
    };
    const payload = { privacyDomainId: id(201), command: { kind: 'READ', recoveryId: id(701) } };
    const send = (headers = base, body = payload) =>
      app.inject({
        method: 'POST',
        url: `/v1/identity/${purpose}/enrollments/${id(700)}/commands`,
        headers,
        payload: body,
      });
    try {
      const response = await send();
      expect(response.statusCode).toBe(200);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(commandHandler).toHaveBeenLastCalledWith(
        expect.objectContaining({ principalId: id(111), participantId: id(101), platform: true }),
        id(201),
        id(700),
        payload.command,
        'http://localhost:8080',
      );
      expect(verifyCsrf).toHaveBeenCalledWith(
        `${id(101)}.${id(900)}`,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'http://identity:3001',
        'identity:3001',
        'test-csrf',
      );
      for (const headers of [
        { ...base, authorization: 'Bearer untrusted' },
        { ...base, 'x-openpc-browser-origin': 'http://foreign.local' },
        { ...base, cookie: base.cookie + '; ' + base.cookie },
        { ...base, cookie: '' },
        { ...base, origin: 'http://foreign.local' },
        { ...base, 'x-csrf-token': '' },
      ]) {
        if (headers['x-csrf-token'] === '')
          verifyCsrf.mockRejectedValueOnce(new Error('denied csrf'));
        expect((await send(headers)).statusCode).toBeGreaterThanOrEqual(400);
      }
      sessionSnapshot.mockResolvedValueOnce({
        participantId: id(101),
        principalId: id(111),
        contextMode: 'PARTICIPANT',
      });
      expect((await send()).statusCode).toBeGreaterThanOrEqual(400);
      expect(
        (
          await send(base, {
            ...payload,
            command: { ...payload.command, roleId: id(999) },
          } as never)
        ).statusCode,
      ).toBeGreaterThanOrEqual(400);
      expect(commandHandler).toHaveBeenCalledOnce();
      expect(otherHandler).not.toHaveBeenCalled();
      if (purpose === 'discovery-certificate-recovery') {
        const create = { ...payload, command: { kind: 'CREATE' } } as never;
        expect((await send(base, create)).statusCode).toBe(201);
        expect(
          (
            await send(base, {
              ...payload,
              command: { kind: 'CREATE', preparation: {}, certificateRecovery: {} },
            } as never)
          ).statusCode,
        ).toBe(403);
        // Empty CREATE now has a signer-repair owner on the shared URL. The
        // actual stored discovery enrollment must still be denied by that owner.
        otherHandler.mockRejectedValueOnce(new IdentityKernelError('PC-AUTH-0005'));
        expect(
          (
            await app.inject({
              method: 'POST',
              url: `/v1/identity/platform-recovery/enrollments/${id(700)}/commands`,
              headers: base,
              payload: create,
            })
          ).statusCode,
        ).toBe(403);
        expect(commandHandler).toHaveBeenCalledTimes(2);
        expect(otherHandler).toHaveBeenCalledOnce();
      }
      const accepted = vi
        .mocked(writeRecoveryDiagnostic)
        .mock.calls.find(([v]) => v.outcome === 'ACCEPTED')![0];
      expect(accepted).toMatchObject({
        boundary: purpose.replaceAll('-', '_'),
        stage: 'COMMAND',
        command: 'READ',
        enrollmentId: id(700),
        outcome: 'ACCEPTED',
      });
      const diagnostics = JSON.stringify(vi.mocked(writeRecoveryDiagnostic).mock.calls);
      for (const secret of ['test-internal-secret', 'test-csrf', base.cookie, 'denied csrf'])
        expect(diagnostics).not.toContain(secret);
      expect(
        vi.mocked(writeRecoveryDiagnostic).mock.calls.some(([v]) => v.outcome === 'REJECTED'),
      ).toBe(true);
    } finally {
      await app.close();
    }
  },
);
