import { chromium, type BrowserContext, type Page } from '@playwright/test';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import { apiOrigin, CliError, responseError, type CliConfig } from './client.js';
import { privateDirectory } from './files.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

export interface BrowserRuntime {
  // Integration tests substitute only the external browser/authenticator driver.
  launch(profile: string): Promise<BrowserContext>;
  initialize?(context: BrowserContext, page: Page): Promise<void>;
  failure?(page: Page, errorName: string): Promise<void>;
}
const browserRuntime: BrowserRuntime = {
  launch: (profile) =>
    chromium.launchPersistentContext(profile, { headless: false, chromiumSandbox: true }),
};

const browserSessionSchema = z.object({
  authenticated: z.literal(true),
  sessionId: z.uuid(),
  principalId: z.uuid(),
  participantId: z.uuid(),
  contextMode: z.enum(['PLATFORM', 'PARTICIPANT']),
  privacyDomainId: z.uuid().optional(),
  contextEpoch: z.string(),
  availableContexts: z
    .array(z.object({ participantId: z.uuid(), privacyDomainId: z.uuid() }))
    .default([]),
});
export type BrowserSession = z.infer<typeof browserSessionSchema>;

/** Same-origin BFF transport with browser-managed HttpOnly cookies; no cookie export. */
export async function browserRequest(page: Page, path: string, body?: unknown): Promise<unknown> {
  if (!path.startsWith('/api/v1/ui/') || path.includes('://')) throw new CliError('INPUT');
  let response: { status: number; value: unknown };
  try {
    response = await page.evaluate(
      async ({ path, body }) => {
        const response = await fetch(path, {
          method: body === undefined ? 'GET' : 'POST',
          redirect: 'error',
          cache: 'no-store',
          headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
          signal: AbortSignal.timeout(20_000),
        });
        const mediaType = response.headers
          .get('content-type')
          ?.split(';', 1)[0]
          ?.trim()
          .toLowerCase();
        if (
          !['application/json', 'application/problem+json'].includes(mediaType ?? '') ||
          !response.body
        )
          throw new Error('Invalid response');
        const reader = response.body.getReader(),
          decoder = new TextDecoder();
        let text = '',
          size = 0;
        try {
          while (true) {
            const chunk = await reader.read();
            if (chunk.done) break;
            size += chunk.value.length;
            if (size > 6 * 1024 * 1024) throw new Error('Response too large');
            text += decoder.decode(chunk.value, { stream: true });
          }
          text += decoder.decode();
          return { status: response.status, value: JSON.parse(text) as unknown };
        } finally {
          await reader.cancel().catch(() => undefined);
        }
      },
      { path, body },
    );
  } catch {
    throw new CliError('TRANSPORT');
  }
  if (response.status >= 400) throw responseError(response.status, response.value);
  return response.value;
}

export async function browserSession(
  page: Page,
  config: CliConfig,
  requireContext = true,
): Promise<BrowserSession> {
  const parsed = browserSessionSchema.safeParse(
    await browserRequest(page, '/api/v1/ui/local-session'),
  );
  if (!parsed.success) throw new CliError('AUTHENTICATION');
  if (
    parsed.data.participantId !== config.participantId ||
    (requireContext &&
      (parsed.data.contextMode !== 'PARTICIPANT' ||
        parsed.data.privacyDomainId !== config.privacyDomainId))
  )
    throw new CliError('CONTEXT');
  return parsed.data;
}

export function sessionDisplay(session: BrowserSession) {
  return {
    principalId: session.principalId,
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    contextMode: session.contextMode,
  };
}

export async function completeSessionTransition(
  page: Page,
  path: string,
  method: string,
  trigger: () => Promise<void>,
  timeout = 300_000,
): Promise<void> {
  const origin = new URL(page.url()).origin;
  const [response] = await Promise.all([
    page.waitForResponse(
      (response) => {
        const url = new URL(response.url());
        return (
          response.request().method() === method && url.origin === origin && url.pathname === path
        );
      },
      { timeout },
    ),
    trigger(),
  ]);
  if (!response.ok()) throw responseError(response.status(), await response.json());
  // The owner may reload the page immediately after its response. Validate
  // the new session through fresh reads instead of unbounded completion
  // bookkeeping for the response across that navigation.
}

export async function login(page: Page, config: CliConfig): Promise<BrowserSession> {
  const started = z.object({ authorizationUri: z.url() }).safeParse(
    await browserRequest(page, '/api/v1/ui/oidc-session', {
      role: 'viewer',
      participantId: config.participantId,
      returnPath: '/develop/deployments',
      freshAuthentication: true,
      ...(config.loginHint ? { loginHint: config.loginHint } : {}),
    }),
  );
  if (!started.success) throw new CliError('RESPONSE');
  const destination = new URL(started.data.authorizationUri);
  if (destination.username || destination.password || destination.hash)
    throw new CliError('AUTHENTICATION');
  if (
    destination.protocol !== 'https:' &&
    !(
      config.localDevelopment &&
      destination.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]'].includes(destination.hostname)
    )
  )
    throw new CliError('AUTHENTICATION');
  await page.goto(destination.href);
  const deadline = Date.now() + 300_000;
  while (Date.now() < deadline) {
    if (new URL(page.url()).origin === apiOrigin(config)) {
      const parsed = browserSessionSchema.safeParse(
        await browserRequest(page, '/api/v1/ui/local-session'),
      );
      if (parsed.success) {
        const session = await browserSession(page, config, false);
        if (session.contextMode === 'PARTICIPANT') return browserSession(page, config);
        if (
          !session.availableContexts.some(
            (context) =>
              context.participantId === config.participantId &&
              context.privacyDomainId === config.privacyDomainId,
          )
        )
          throw new CliError('CONTEXT');
        await page
          .getByRole('combobox', { name: /^Participant privacy context/u })
          .selectOption(config.privacyDomainId);
        await completeSessionTransition(
          page,
          '/api/v1/ui/session/context',
          'POST',
          () =>
            page
              .getByRole('button', {
                name: 'Verify authenticator and enter Participant context',
                exact: true,
              })
              .click(),
          Math.max(1, deadline - Date.now()),
        );
        // Await actual read responses. A browser predicate returning a Promise
        // can become truthy before the WebAuthn/context transition completes.
        const readbackDeadline = Math.min(deadline, Date.now() + 30_000);
        while (Date.now() < readbackDeadline) {
          await delay(250);
          try {
            const selected = await browserSession(page, config, false);
            if (
              selected.contextMode === 'PARTICIPANT' &&
              selected.privacyDomainId === config.privacyDomainId
            )
              return selected;
          } catch (error) {
            // Context entry reloads the document. Retry only its readback,
            // never the context mutation or the authenticator assertion.
            if (
              !(error instanceof CliError) ||
              !['TRANSPORT', 'AUTHENTICATION'].includes(error.code)
            )
              throw error;
          }
        }
        throw new CliError('AUTHENTICATION');
      }
    }
    await delay(500);
  }
  throw new CliError('AUTHENTICATION');
}

export async function withBrowser<T>(
  config: CliConfig,
  profile: string,
  run: (page: Page) => Promise<T>,
  runtime = browserRuntime,
): Promise<T> {
  await promisify(execFile)(
    'bash',
    [
      'scripts/maintenance/run-bounded.sh',
      '--reuse',
      '--memory-gib',
      '2',
      '--peak-disk-gib',
      '1',
      '--',
      'true',
    ],
    { maxBuffer: 1024 * 1024 },
  );
  await privateDirectory(profile);
  let context: BrowserContext | undefined;
  let page: Page | undefined;
  try {
    context = await runtime.launch(profile);
    page = context.pages()[0] ?? (await context.newPage());
    page.setDefaultTimeout(30_000);
    await runtime.initialize?.(context, page);
    await page.goto(`${apiOrigin(config)}/develop/deployments`);
    return await run(page);
  } catch (error) {
    if (page)
      await runtime
        .failure?.(page, error instanceof Error ? error.name : 'Error')
        .catch(() => undefined);
    if (error instanceof CliError) throw error;
    throw new CliError('TRANSPORT');
  } finally {
    await context?.close();
  }
}
