import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { functionalActorCookie } from './functional-test-profile';
import {
  authenticated,
  localRuntimeConfig,
  parsePublicCommand,
  safeProblem,
  sameOrigin,
} from './local-runtime';
import {
  mutateTransactionWorkbench,
  readTransactionWorkbench,
  functionalReviewMatches,
} from './local-transaction-workbench';
import {
  beginLocalWebAuthnAssertion,
  completeFunctionalTestAssertion,
} from './local-webauthn-runtime';

const inputSchema = z.discriminatedUnion('command', [
  z.strictObject({
    command: z.literal('PREPARE'),
    reviewToken: z.string().min(32).max(131_072),
    resourceReservationId: z.uuidv7().optional(),
  }),
  z.strictObject({
    command: z.literal('APPLY'),
    approvalId: z.uuidv7(),
    reviewToken: z.string().min(32).max(131_072),
  }),
]);
const bindingSchema = z.strictObject({
  actionIntentId: z.string(),
  actionIntentDigest: z.string(),
  resourceId: z.uuid(),
  resourceDigest: z.string(),
});
const stateSchema = z.object({
  kind: z.string(),
  approval: z.object({ makerSubjectRef: z.string() }),
  candidate: z.object({
    candidateDigest: z.string(),
    state: z.string(),
    operationRef: z.string().nullable(),
    resourceRef: z.string(),
  }),
  stepUp: bindingSchema.nullable().optional(),
});

/** Private QA orchestration; underlying proposal, approval and execution owners
 * retain their ordinary permission checks, idempotency and durable effects. */
export async function applyFunctionalTransaction(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime?.functionalTest) return safeProblem('PC-AUTH-0005', request);
  if (!sameOrigin(request)) return safeProblem('PC-AUTH-0002', request);
  if (request.headers.get('content-type')?.split(';', 1)[0]?.trim() !== 'application/json')
    return safeProblem('PC-DATA-6004', request);
  const raw = await request.text();
  if (Buffer.byteLength(raw) > 140_000) return safeProblem('PC-DATA-6004', request);
  const input = inputSchema.safeParse(parsePublicCommand(raw));
  if (!input.success) return safeProblem('PC-DATA-6004', request);
  const maker = await authenticated(request, runtime);
  if (!maker || maker.role !== 'operator') return safeProblem('PC-AUTH-0005', request);
  const derived = (path: string, role: 'operator' | 'viewer', body?: unknown, custody?: string) => {
    const headers = new Headers(request.headers);
    const cookies = (headers.get('cookie') ?? '')
      .split(';')
      .filter(
        (value) =>
          ![functionalActorCookie, 'openpc_webauthn_custody'].includes(
            value.trim().split('=', 1)[0]!,
          ),
      );
    cookies.push(`${functionalActorCookie}=${role}`);
    if (custody) cookies.push(`openpc_webauthn_custody=${custody}`);
    headers.set('cookie', cookies.join('; '));
    return new NextRequest(new URL(path, request.url), {
      method: body === undefined ? 'GET' : 'POST',
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  };
  const pending = (approvalId: string, stage: string) =>
    NextResponse.json(
      { approvalId, outcome: 'PENDING', stage },
      { status: 202, headers: { 'Cache-Control': 'no-store' } },
    );
  if (input.data.command === 'PREPARE') {
    const proposal = await mutateTransactionWorkbench(
      derived('/api/v1/ui/transaction-workbench', 'operator', {
        command: 'REQUEST_APPROVAL',
        reviewToken: input.data.reviewToken,
        checkerId: runtime.functionalTest.actors.viewer.principalId,
        ...(input.data.resourceReservationId
          ? { resourceReservationId: input.data.resourceReservationId }
          : {}),
      }),
    );
    if (!proposal.ok) return proposal;
    const proposed = z.object({ approvalId: z.uuidv7() }).safeParse(await proposal.json());
    if (!proposed.success) return safeProblem('PC-INTEGRATION-5001', request);
    return NextResponse.json(
      { approvalId: proposed.data.approvalId, outcome: 'PREPARED' },
      { status: 202, headers: { 'Cache-Control': 'no-store' } },
    );
  }
  const approvalId = input.data.approvalId;
  const read = async (role: 'operator' | 'viewer') => {
    const response = await readTransactionWorkbench(
      derived(`/api/v1/ui/transaction-workbench?approvalId=${approvalId}`, role),
    );
    if (!response.ok) return undefined;
    const result = stateSchema.safeParse(await response.json());
    return result.success ? result.data : undefined;
  };
  const prove = async (role: 'operator' | 'viewer', binding: z.infer<typeof bindingSchema>) => {
    const challenge = await beginLocalWebAuthnAssertion(
      derived('/api/v1/ui/webauthn/assertion/challenge', role, binding),
    );
    if (!challenge.ok) return false;
    const body = z
      .object({ publicKey: z.object({ challenge: z.string() }) })
      .safeParse(await challenge.json());
    const custody = challenge.cookies.get('openpc_webauthn_custody')?.value;
    if (!body.success || !custody) return false;
    const verified = await completeFunctionalTestAssertion(
      derived(
        '/api/v1/ui/webauthn/assertion/functional',
        role,
        {
          ...binding,
          challenge: body.data.publicKey.challenge,
        },
        custody,
      ),
    );
    return verified.ok;
  };
  const original = await read('operator');
  if (!original) return pending(approvalId, 'REVIEW');
  if (!functionalReviewMatches(runtime, maker, input.data.reviewToken, original))
    return safeProblem('PC-AUTH-0005', request);
  if (original.candidate.state === 'CONSUMED')
    return NextResponse.json(
      {
        approvalId,
        outcome: 'RECORDED',
        reconciled: true,
        operationRef: original.candidate.operationRef,
      },
      { headers: { 'Cache-Control': 'no-store' } },
    );
  const checker = await read('viewer');
  if (!checker) return pending(approvalId, 'REVIEW');
  if (checker.candidate.state === 'APPROVAL_REQUESTED') {
    if (!checker.stepUp || !(await prove('viewer', checker.stepUp)))
      return pending(approvalId, 'REVIEW');
    const approval = await mutateTransactionWorkbench(
      derived('/api/v1/ui/transaction-workbench', 'viewer', { command: 'APPROVE', approvalId }),
    );
    if (!approval.ok) return pending(approvalId, 'REVIEW');
  }
  const current = await read('operator');
  if (!current) return pending(approvalId, 'EXECUTION');
  if (current.candidate.state === 'CONSUMED')
    return NextResponse.json(
      {
        approvalId,
        outcome: 'RECORDED',
        reconciled: true,
        operationRef: current.candidate.operationRef,
      },
      { headers: { 'Cache-Control': 'no-store' } },
    );
  if (
    current.candidate.state !== 'APPROVED' ||
    !current.stepUp ||
    !(await prove('operator', current.stepUp))
  )
    return pending(approvalId, 'EXECUTION');
  const executed = await mutateTransactionWorkbench(
    derived('/api/v1/ui/transaction-workbench', 'operator', {
      command: 'EXECUTE',
      approvalId,
      reviewToken: input.data.reviewToken,
    }),
  );
  if (!executed.ok) return pending(approvalId, 'EXECUTION');
  return NextResponse.json(
    { approvalId, outcome: 'SUBMITTED', execution: await executed.json() },
    { status: 202, headers: { 'Cache-Control': 'no-store' } },
  );
}
