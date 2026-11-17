import { lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import type { Page } from '@playwright/test';
import {
  transactionCandidate,
  transactionKindSchema,
  transactionOperation,
} from '../../admin-web/app/api/v1/ui/transaction-workbench-contract.js';
import { approvalCandidateResponseSchema } from '../../../services/module-registry/src/approval-candidate-contract.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { operationResponseSchema } from '../../../services/control-api/src/configuration/resource-contracts.js';
import { CliError, responseError, resources, type CliConfig } from './client.js';
import { readJson, writePrivateJson } from './files.js';
import {
  browserRequest,
  browserSession,
  completeSessionTransition,
  login,
  sessionDisplay,
  withBrowser,
  type BrowserRuntime,
} from './browser-session.js';

const endpoint = '/api/v1/ui/transaction-workbench';
const draftSchema = z.strictObject({
  version: z.literal(1),
  requestKey: z.uuid(),
  origin: z.url(),
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  principalId: z.uuid(),
  kind: transactionKindSchema,
  fields: z.record(z.string(), z.unknown()),
  reason: z.string().min(1).max(1024),
  checkerId: z.uuid(),
  candidateDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
  approvalId: z.uuid().optional(),
});
type Draft = z.infer<typeof draftSchema>;
const inputSchema = draftSchema.pick({ fields: true, reason: true, checkerId: true });
export function parseTransactionInput(kind: unknown, value: unknown) {
  try {
    const parsedKind = transactionKindSchema.parse(kind),
      input = inputSchema.parse(value);
    return {
      kind: parsedKind,
      ...input,
      candidateDigest: sha256(transactionCandidate(parsedKind, input.fields, input.reason).body),
    };
  } catch {
    throw new CliError('INPUT');
  }
}
const viewSchema = z.object({
  actor: z.object({
    sessionId: z.uuid(),
    principalId: z.uuid(),
    participantId: z.uuid(),
    privacyDomainId: z.uuid(),
    contextEpoch: z.string(),
  }),
  kind: transactionKindSchema,
  approval: z.object({
    approvalRequestId: z.string(),
    state: z.string(),
    makerSubjectRef: z.string(),
    checkerSubjectRef: z.string().nullable(),
  }),
  candidate: approvalCandidateResponseSchema,
  operation: operationResponseSchema
    .pick({ operationId: true, state: true, truthState: true, revision: true, updatedAt: true })
    .nullable(),
  result: z.record(z.string(), z.unknown()).nullable(),
  resultUnavailable: z.boolean(),
  operationUnavailable: z.boolean(),
});
type View = z.infer<typeof viewSchema>;

export function parseResourceRead(kindInput: string, resourceId: string, value: unknown) {
  const kind = transactionKindSchema.safeParse(kindInput);
  if (!kind.success || !z.uuid().safeParse(resourceId).success) throw new CliError('INPUT');
  const operation = transactionOperation(kind.data);
  const parsed = z
    .object({ actor: viewSchema.shape.actor, kind: z.literal(kind.data), result: operation.output })
    .safeParse(value);
  const identity =
    Object.values(resources).find((resource) => resource.collection === operation.collection)
      ?.identity ?? 'deploymentPolicyId';
  if (
    !parsed.success ||
    typeof parsed.data.result !== 'object' ||
    parsed.data.result === null ||
    Reflect.get(parsed.data.result, identity) !== `urn:openpc:resource:${resourceId}`
  )
    throw new CliError('RESPONSE');
  return parsed.data;
}

function display(view: View) {
  // The server's projected candidate redacts signed payloads. Session binding
  // and step-up material remain inside the private browser/client state.
  return {
    kind: view.kind,
    approval: view.approval,
    candidate: view.candidate,
    operation: view.operation,
    result: view.result,
    resultUnavailable: view.resultUnavailable,
    operationUnavailable: view.operationUnavailable,
  };
}

async function readApproval(page: Page, config: CliConfig, id: string): Promise<View> {
  if (!z.uuid().safeParse(id).success) throw new CliError('INPUT');
  await browserSession(page, config);
  const parsed = viewSchema.safeParse(await browserRequest(page, `${endpoint}?approvalId=${id}`));
  if (
    !parsed.success ||
    parsed.data.candidate.approvalRequestId !== `urn:openpc:resource:${id}` ||
    parsed.data.approval.approvalRequestId !== parsed.data.candidate.approvalRequestId
  )
    throw new CliError('RESPONSE');
  if (
    parsed.data.result !== null &&
    !transactionOperation(parsed.data.kind).output.safeParse(parsed.data.result).success
  )
    throw new CliError('RESPONSE');
  return parsed.data;
}

function draftPath(profile: string, key: string): string {
  if (!z.uuid().safeParse(key).success) throw new CliError('INPUT');
  return join(profile, 'openpc-requests', `${key}.json`);
}

async function loadDraft(profile: string, key: string): Promise<Draft> {
  const parsed = draftSchema.safeParse(
    await readJson(draftPath(profile, key), true, 6 * 1024 * 1024),
  );
  if (!parsed.success || parsed.data.requestKey !== key) throw new CliError('INPUT');
  const checked = parseTransactionInput(parsed.data.kind, {
    fields: parsed.data.fields,
    reason: parsed.data.reason,
    checkerId: parsed.data.checkerId,
  });
  if (checked.candidateDigest !== parsed.data.candidateDigest) throw new CliError('INPUT');
  return parsed.data;
}

async function preview(page: Page, draft: Draft): Promise<string> {
  const parsed = z
    .object({
      reviewToken: z.string(),
      preview: z.object({ candidateDigest: z.literal(draft.candidateDigest) }),
    })
    .safeParse(
      await browserRequest(page, endpoint, {
        command: 'PREVIEW',
        requestKey: draft.requestKey,
        kind: draft.kind,
        fields: draft.fields,
        reason: draft.reason,
      }),
    );
  if (!parsed.success) throw new CliError('RESPONSE');
  return parsed.data.reviewToken;
}

export function requireDraftActor(draft: Draft, actor: View['actor'], origin: string): void {
  if (
    draft.origin !== origin ||
    draft.principalId !== actor.principalId ||
    draft.participantId !== actor.participantId ||
    draft.privacyDomainId !== actor.privacyDomainId
  )
    throw new CliError('CONTEXT');
}

async function prepareUi(page: Page, view: View, id: string, reviewToken?: string): Promise<void> {
  const mode = view.kind.startsWith('cigl-') ? 'cigl' : 'deployment';
  await page.goto(
    new URL(mode === 'cigl' ? '/operate/rpc-transactions' : '/develop/deployments', page.url())
      .href,
  );
  if (reviewToken) {
    await page.evaluate(
      ({ actor, key, value }) => localStorage.setItem(key, JSON.stringify({ actor, value })),
      {
        actor: view.actor,
        key: `openpc:transaction-workbench:v1:${mode}`,
        value: { kind: view.kind, approvalId: id, reviewToken },
      },
    );
    await page.reload();
  }
  await page.getByLabel('Approval ID', { exact: true }).fill(id);
  const [response] = await Promise.all([
    page.waitForResponse(
      (response) =>
        response.request().method() === 'GET' &&
        new URL(response.url()).pathname === endpoint &&
        new URL(response.url()).searchParams.get('approvalId') === id,
    ),
    page.getByRole('button', { name: 'Read approval and result', exact: true }).click(),
  ]);
  if (response.status() !== 200) throw new CliError('DENIED');
}

/** The existing UI performs the fresh, resource-bound WebAuthn ceremony. */
async function act(page: Page, command: 'APPROVE' | 'EXECUTE'): Promise<void> {
  const button = page.getByRole('button', {
    name: command === 'APPROVE' ? 'Approve with security key' : 'Execute approved request',
    exact: true,
  });
  await button.waitFor({ state: 'visible' });
  const readyDeadline = Date.now() + 5000;
  while (!(await button.isEnabled()) && Date.now() < readyDeadline) await delay(50);
  if (!(await button.isEnabled())) throw new CliError('DENIED');
  let status: number | undefined,
    lost = false;
  let problem: Promise<unknown> | undefined;
  const matches = (request: import('@playwright/test').Request) =>
    request.method() === 'POST' &&
    new URL(request.url()).pathname === endpoint &&
    request.postDataJSON()?.command === command;
  const responseListener = (response: import('@playwright/test').Response) => {
    if (matches(response.request())) {
      status = response.status();
      if (status >= 400) problem = response.json().catch(() => undefined);
    }
  };
  const failedListener = (request: import('@playwright/test').Request) => {
    if (matches(request)) lost = true;
  };
  page.on('response', responseListener);
  page.on('requestfailed', failedListener);
  try {
    await button.click();
    const start = Date.now();
    while (Date.now() - start < 300_000) {
      if (lost) return; // Caller reads the durable original; never blind-replays.
      if (status !== undefined) {
        if (status >= 400) throw responseError(status, await problem);
        return;
      }
      if (Date.now() - start > 1000 && (await button.isEnabled()))
        throw new CliError('AUTHENTICATION');
      await delay(250);
    }
    throw new CliError('AUTHENTICATION');
  } finally {
    page.off('response', responseListener);
    page.off('requestfailed', failedListener);
  }
}

export async function runBrowser(
  args: string[],
  config: CliConfig,
  profile: string,
  write: (value: unknown) => void,
  runtime?: BrowserRuntime,
): Promise<number> {
  return withBrowser(
    config,
    profile,
    async (page) => {
      const command = args[0];
      if (command === 'login' && args.length === 1) {
        write(sessionDisplay(await login(page, config)));
        return 0;
      }
      const session = await browserSession(page, config);
      if (command === 'session' && args.length === 1) {
        write(sessionDisplay(session));
        return 0;
      }
      if (command === 'read' && args.length === 3) {
        if (
          !transactionKindSchema.safeParse(args[1]).success ||
          !z.uuid().safeParse(args[2]).success
        )
          throw new CliError('INPUT');
        const response = parseResourceRead(
          args[1]!,
          args[2]!,
          await browserRequest(
            page,
            `${endpoint}?${new URLSearchParams({ kind: args[1]!, resourceId: args[2]! })}`,
          ),
        );
        if (
          response.actor.principalId !== session.principalId ||
          response.actor.sessionId !== session.sessionId ||
          response.actor.participantId !== config.participantId ||
          response.actor.privacyDomainId !== config.privacyDomainId
        )
          throw new CliError('CONTEXT');
        write({ kind: response.kind, result: response.result });
        return 0;
      }
      if ((command === 'refresh' || command === 'logout') && args.length === 1) {
        await completeSessionTransition(
          page,
          '/api/v1/ui/local-session',
          command === 'refresh' ? 'PATCH' : 'DELETE',
          () =>
            page
              .getByRole('button', {
                name: command === 'refresh' ? 'Rotate local session' : 'Revoke local session',
                exact: true,
              })
              .click(),
          30_000,
        );
        const deadline = Date.now() + 30_000;
        while (Date.now() < deadline) {
          await delay(250);
          let status: unknown;
          try {
            status = await browserRequest(page, '/api/v1/ui/local-session');
          } catch (error) {
            if (error instanceof CliError && error.code === 'TRANSPORT') continue;
            throw error;
          }
          if (
            command === 'logout' &&
            typeof status === 'object' &&
            status !== null &&
            'authenticated' in status &&
            status.authenticated === false
          ) {
            write({ authenticated: false });
            return 0;
          }
          if (
            command === 'refresh' &&
            typeof status === 'object' &&
            status !== null &&
            'sessionId' in status &&
            status.sessionId !== session.sessionId
          ) {
            write(sessionDisplay(await browserSession(page, config)));
            return 0;
          }
        }
        throw new CliError('AUTHENTICATION');
      }
      if (
        command === 'transaction' &&
        args.length === 6 &&
        args[2] === '--input' &&
        args[4] === '--request-key'
      ) {
        const input = parseTransactionInput(
          args[1],
          await readJson(args[3]!, true, 6 * 1024 * 1024),
        );
        const key = args[5]!,
          path = draftPath(profile, key);
        const draft: Draft = {
          version: 1,
          requestKey: key,
          origin: new URL(page.url()).origin,
          participantId: config.participantId,
          privacyDomainId: config.privacyDomainId,
          principalId: session.principalId,
          ...input,
        };
        const exists = await lstat(path)
          .then(() => true)
          .catch((error: unknown) => {
            if (
              typeof error === 'object' &&
              error !== null &&
              'code' in error &&
              error.code === 'ENOENT'
            )
              return false;
            throw new CliError('INPUT');
          });
        if (exists) {
          const prior = await loadDraft(profile, key);
          const original = { ...prior };
          delete original.approvalId;
          if (sha256(original) !== sha256(draft)) throw new CliError('INPUT');
          if (prior.approvalId) {
            write({
              requestKey: key,
              ...display(await readApproval(page, config, prior.approvalId)),
            });
            return 0;
          }
        }
        await writePrivateJson(path, draft);
        const reviewToken = await preview(page, draft);
        const approval = z.object({ approvalId: z.uuid() }).safeParse(
          await browserRequest(page, endpoint, {
            command: 'REQUEST_APPROVAL',
            reviewToken,
            checkerId: draft.checkerId,
          }),
        );
        if (!approval.success) throw new CliError('RESPONSE');
        draft.approvalId = approval.data.approvalId;
        await writePrivateJson(path, draft);
        write({ requestKey: key, ...display(await readApproval(page, config, draft.approvalId)) });
        return 0;
      }
      if (['review', 'approve', 'result'].includes(command ?? '') && args[1]) {
        const id = args[1];
        let wait = 0;
        if (
          command === 'result' &&
          args.length === 4 &&
          args[2] === '--wait-seconds' &&
          /^\d{1,3}$/u.test(args[3]!)
        )
          wait = Number(args[3]);
        else if (args.length !== 2) throw new CliError('INPUT');
        if (wait > 300) throw new CliError('INPUT');
        let view = await readApproval(page, config, id);
        if (command === 'approve') {
          if (
            view.approval.checkerSubjectRef !== `urn:openpc:resource:${session.principalId}` ||
            view.approval.makerSubjectRef === view.approval.checkerSubjectRef
          )
            throw new CliError('DENIED');
          if (view.approval.state !== 'APPROVED') {
            await prepareUi(page, view, id);
            await act(page, 'APPROVE');
            view = await readApproval(page, config, id);
          }
        }
        const deadline = Date.now() + wait * 1000;
        while (
          wait &&
          !['SUCCEEDED', 'FAILED'].includes(view.operation?.state ?? '') &&
          Date.now() < deadline
        ) {
          await delay(Math.min(1000, deadline - Date.now()));
          view = await readApproval(page, config, id);
        }
        write(display(view));
        return wait && !['SUCCEEDED', 'FAILED'].includes(view.operation?.state ?? '')
          ? 6
          : view.operation?.state === 'FAILED'
            ? 4
            : 0;
      }
      if (command === 'execute' && args.length === 2) {
        const draft = await loadDraft(profile, args[1]!);
        if (!draft.approvalId) throw new CliError('INPUT');
        let view = await readApproval(page, config, draft.approvalId);
        requireDraftActor(draft, view.actor, new URL(page.url()).origin);
        if (view.candidate.candidateDigest !== draft.candidateDigest || view.kind !== draft.kind)
          throw new CliError('INPUT');
        if (view.candidate.state !== 'CONSUMED') {
          if (view.candidate.state !== 'APPROVED') throw new CliError('DENIED');
          const reviewToken = await preview(page, draft);
          await prepareUi(page, view, draft.approvalId, reviewToken);
          await act(page, 'EXECUTE');
          view = await readApproval(page, config, draft.approvalId);
        }
        write({ requestKey: draft.requestKey, ...display(view) });
        return view.operation?.state === 'FAILED' ? 4 : view.candidate.state === 'CONSUMED' ? 0 : 6;
      }
      throw new CliError('INPUT');
    },
    runtime,
  );
}
