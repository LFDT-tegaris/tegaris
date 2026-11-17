import { createServer, request as httpRequest } from 'node:http';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
const { NextRequest } = createRequire(
  new URL('../../../apps/admin-web/package.json', import.meta.url),
)('next/server');
import { expect } from 'vitest';
import {
  encodeBffSession,
  type IdentitySession,
} from '../../../apps/admin-web/app/api/v1/ui/local-runtime.js';
import {
  mutateRecoveryWorkbench,
  readRecoveryWorkbench,
} from '../../../apps/admin-web/app/api/v1/ui/local-recovery-workbench.js';
import { recoverySavedReview } from '../../../apps/admin-web/lib/recovery-workflow.js';
import {
  digest,
  type GovernanceActor,
  type publicGovernanceClient,
} from './public-governance-client.js';

/** Real public gateway, Identity, Policy and BFF; only the external authenticator is simulated. */
export async function recoveryWorkbenchClient(input: {
  identityUrl: string;
  policyUrl: string;
  internalToken: string;
  directory: string;
  publicClient: Awaited<ReturnType<typeof publicGovernanceClient>>;
  operatorId: string;
}) {
  const root = join(input.directory, 'recovery-workbench');
  await mkdir(root);
  const cookieKey = randomBytes(32).toString('hex');
  await writeFile(join(root, 'cookie'), cookieKey, { mode: 0o600 });
  await writeFile(join(root, 'internal'), input.internalToken, { mode: 0o600 });
  const gateway = createServer((request, response) => {
    const upstream = request.url?.startsWith('/api/v1/approval-requests')
      ? input.policyUrl
      : input.identityUrl;
    const outbound = httpRequest(
      `${upstream}${request.url}`,
      { method: request.method, headers: request.headers, signal: AbortSignal.timeout(10000) },
      (result) => {
        response.writeHead(result.statusCode!, result.headers);
        result.pipe(response);
      },
    );
    outbound.on('error', () => {
      response.writeHead(502);
      response.end();
    });
    request.pipe(outbound);
  });
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  const address = gateway.address();
  if (!address || typeof address === 'string') throw new Error('Gateway address is unavailable');
  const origin = `http://127.0.0.1:${address.port}`;
  const environment = {
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_PUBLIC_API_INTERNAL_URL: origin,
    OPENPC_IDENTITY_INTERNAL_URL: input.identityUrl,
    OPENPC_FACT_INTERNAL_URL: origin,
    OPENPC_POLICY_INTERNAL_URL: input.policyUrl,
    OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL: `${origin}/authorize`,
    OPENPC_IDENTITY_INTERNAL_TOKEN_FILE: join(root, 'internal'),
    OPENPC_FACT_INTERNAL_TOKEN_FILE: join(root, 'internal'),
    OPENPC_POLICY_INTERNAL_TOKEN_FILE: join(root, 'internal'),
    OPENPC_BFF_COOKIE_KEY_FILE: join(root, 'cookie'),
  };
  const saved = Object.fromEntries(Object.keys(environment).map((key) => [key, process.env[key]]));
  Object.assign(process.env, environment);
  const bffRequest = (actor: GovernanceActor, body: unknown, parameters?: URLSearchParams) =>
    new NextRequest(`${origin}/api/v1/ui/recovery-workbench${parameters ? `?${parameters}` : ''}`, {
      method: parameters ? 'GET' : 'POST',
      headers: {
        'content-type': 'application/json',
        'host': new URL(origin).host,
        origin,
        'cookie': `openpc_local_runtime_session=${encodeBffSession({ ...actor, role: actor.principalId === input.operatorId ? 'operator' : 'viewer' } as IdentitySession, Buffer.from(cookieKey))}`,
      },
      ...(parameters ? {} : { body: JSON.stringify(body) }),
    });
  const command = async (actor: GovernanceActor, body: unknown) => {
    const response = await mutateRecoveryWorkbench(bffRequest(actor, body));
    return { status: response.status, body: await response.json() };
  };
  const prepare = async (...args: Parameters<typeof input.publicClient.prepare>) => {
    const [maker, checker, path, rawBody, candidate, resourceId, revision, beforeMakerStepUp] =
      args;
    const body = rawBody as Record<string, unknown>;
    const mutation =
      path === '/v1/identity/recovery-principals'
        ? 'QUALIFY'
        : path.endsWith('/revoke')
          ? 'REVOKE'
          : path === '/v1/identity/recoveries'
            ? 'BEGIN'
            : path.endsWith('/approve')
              ? 'CUSTODY'
              : path.endsWith('/complete')
                ? 'COMPLETE'
                : 'POST_REVIEW';
    const common = {
      mutation,
      checkerPrincipalId: checker.principalId,
      reason: 'Recover subject after authenticator loss',
    };
    const previewInput =
      mutation === 'QUALIFY'
        ? {
            ...common,
            principalId: resourceId,
            credentialId: body.credentialId,
            credentialEpoch: body.credentialEpoch,
          }
        : mutation === 'REVOKE'
          ? { ...common, principalId: resourceId }
          : mutation === 'BEGIN'
            ? {
                ...common,
                recoveryId: resourceId,
                subjectId: body.subjectId,
                recoveryPrincipalId: body.recoveryPrincipalId,
                custodianPrincipalIds: body.custodianPrincipalIds,
              }
            : {
                ...common,
                recoveryId: resourceId,
                ...(mutation === 'POST_REVIEW' ? { note: body.note } : {}),
              };
    const preview = await command(maker, { command: 'PREVIEW', input: previewInput });
    if (mutation === 'COMPLETE') {
      const restricted = await readRecoveryWorkbench(
        bffRequest(maker, {}, new URLSearchParams({ lane: 'maker' })),
      );
      expect(restricted.status).toBe(200);
      expect(await restricted.json()).toMatchObject({
        approvalListAccess: 'DENIED',
        completeness: 'UNKNOWN',
      });
    }
    expect(preview.status, `${mutation} preview ${JSON.stringify(preview.body)}`).toBe(201);
    const review = recoverySavedReview.parse(preview.body);
    expect(review.review).toMatchObject({
      candidate,
      candidateDigest: digest(candidate),
      resourceId,
      expectedRevision: revision,
    });
    const submitted = await command(maker, { command: 'SUBMIT', reviewToken: review.reviewToken });
    expect(submitted.status, `${mutation} submit ${JSON.stringify(submitted.body)}`).toBe(202);
    const approvalId = (submitted.body.approval.approvalRequestId as string).slice(-36);
    const own = await readRecoveryWorkbench(
      bffRequest(maker, {}, new URLSearchParams({ lane: 'maker', approvalRequestId: approvalId })),
    );
    expect(own.status, `${mutation} maker's exact saved request`).toBe(200);
    expect(await own.json()).toHaveProperty('approvalListAccess', 'NOT_REQUESTED');
    const inbox = await readRecoveryWorkbench(
      bffRequest(checker, {}, new URLSearchParams({ lane: 'checker' })),
    );
    expect(inbox.status, `${mutation} checker inbox`).toBe(200);
    const page = await inbox.json();
    const item = page.approvals.find((entry: { approvalRequestId: string }) =>
      entry.approvalRequestId.endsWith(approvalId),
    );
    expect(item).toMatchObject({
      candidateDigest: digest(candidate),
      proposal: { candidate, approval: { reason: common.reason } },
    });
    await input.publicClient.stepUp(
      checker,
      item.stepUp.actionIntentId,
      item.stepUp.resourceId,
      item.stepUp.resourceDigest,
    );
    const approved = await command(checker, {
      command: 'APPROVE',
      approvalRequestId: approvalId,
      candidateDigest: item.candidateDigest,
      expectedRevision: item.revision,
    });
    expect(approved.status, `${mutation} approve ${JSON.stringify(approved.body)}`).toBe(202);
    await beforeMakerStepUp?.();
    await input.publicClient.stepUp(
      maker,
      review.review.stepUp.actionIntentId,
      resourceId,
      review.review.candidateDigest,
    );
    return {
      approvalId,
      commit: () =>
        command(maker, {
          command: 'COMMIT',
          reviewToken: review.reviewToken,
          approvalRequestId: approvalId,
        }),
    };
  };
  return {
    prepare,
    async close() {
      for (const [key, value] of Object.entries(saved)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      await new Promise<void>((resolve, reject) =>
        gateway.close((error) => (error ? reject(error) : resolve())),
      );
      await rm(root, { recursive: true, force: true });
    },
  };
}
