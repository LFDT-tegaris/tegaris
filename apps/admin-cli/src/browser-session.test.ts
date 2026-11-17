import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Page } from '@playwright/test';
import { browserRequest, login } from './browser-session.js';

afterEach(() => vi.unstubAllGlobals());

const config = {
  apiUrl: 'http://localhost:8080',
  localDevelopment: true,
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  browserProfile: '/private/profile',
};

function delayedContext(available = true) {
  let selected = false,
    readsAfterCeremony = 0;
  const selectOption = vi.fn(async () => undefined);
  const click = vi.fn(async () => {
    selected = true;
  });
  const page = {
    goto: vi.fn(async () => undefined),
    url: () => config.apiUrl,
    getByRole: vi.fn(() => ({ selectOption, click })),
    waitForResponse: vi.fn(async () => ({ ok: () => true, finished: async () => null })),
    evaluate: vi.fn(async (_: unknown, request: { path: string }) => {
      if (request.path === '/api/v1/ui/oidc-session')
        return { status: 200, value: { authorizationUri: 'https://idp.example/authorize' } };
      if (selected) readsAfterCeremony++;
      const entered = selected && readsAfterCeremony >= 2;
      return {
        status: 200,
        value: {
          authenticated: true,
          sessionId: '018f0000-0000-7000-8000-000000000301',
          principalId: '018f0000-0000-7000-8000-000000000141',
          participantId: config.participantId,
          contextMode: entered ? 'PARTICIPANT' : 'PLATFORM',
          contextEpoch: entered ? '2' : '1',
          ...(entered ? { privacyDomainId: config.privacyDomainId } : {}),
          availableContexts: available
            ? [{ participantId: config.participantId, privacyDomainId: config.privacyDomainId }]
            : [],
        },
      };
    }),
  };
  return { page: page as unknown as Page, selectOption, click, reads: () => readsAfterCeremony };
}

describe('browser-assisted CLI context entry', () => {
  it('preserves a public problem+json denial while omitting private problem details', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              code: 'PC-AUTH-0005',
              status: 403,
              truthState: 'DENIED',
              detail: 'private',
            }),
            { status: 403, headers: { 'Content-Type': 'application/problem+json; charset=utf-8' } },
          ),
      ),
    );
    const page = {
      evaluate: async (fn: (argument: unknown) => Promise<unknown>, argument: unknown) =>
        fn(argument),
    } as unknown as Page;
    await expect(browserRequest(page, '/api/v1/ui/transaction-workbench')).rejects.toMatchObject({
      code: 'DENIED',
      problem: { code: 'PC-AUTH-0005', status: 403, truthState: 'DENIED' },
    });
  });
  it('waits for authoritative context readback after one ceremony, rather than a truthy pending promise', async () => {
    const fixture = delayedContext();
    const session = await login(fixture.page, config);
    expect(fixture.selectOption).toHaveBeenCalledExactlyOnceWith(config.privacyDomainId);
    expect(fixture.click).toHaveBeenCalledTimes(1);
    expect(fixture.reads()).toBe(2);
    expect(session.contextMode).toBe('PARTICIPANT');
    expect(session.privacyDomainId).toBe(config.privacyDomainId);
  });

  it('rejects unavailable explicit context before requesting any authenticator action', async () => {
    const fixture = delayedContext(false);
    await expect(login(fixture.page, config)).rejects.toMatchObject({ code: 'CONTEXT' });
    expect(fixture.click).not.toHaveBeenCalled();
  });
});
