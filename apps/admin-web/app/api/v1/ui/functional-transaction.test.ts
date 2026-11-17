import { NextRequest, NextResponse } from 'next/server';
import { afterEach, expect, it, vi } from 'vitest';
import * as runtime from './local-runtime';
import * as transactions from './local-transaction-workbench';
import * as webauthn from './local-webauthn-runtime';
import { applyFunctionalTransaction } from './functional-transaction';

vi.mock('./local-runtime', async () => ({
  ...(await vi.importActual<typeof runtime>('./local-runtime')),
  localRuntimeConfig: vi.fn(),
  authenticated: vi.fn(),
}));
vi.mock('./local-transaction-workbench', () => ({
  mutateTransactionWorkbench: vi.fn(),
  readTransactionWorkbench: vi.fn(),
  functionalReviewMatches: vi.fn(),
}));
vi.mock('./local-webauthn-runtime', () => ({
  beginLocalWebAuthnAssertion: vi.fn(),
  completeFunctionalTestAssertion: vi.fn(),
}));
afterEach(() => vi.resetAllMocks());
const approvalId = '018f0000-0000-7000-8000-000000000301';
function request(
  body: unknown = { command: 'PREPARE', reviewToken: 'r'.repeat(64) },
  origin = 'http://localhost:8080',
) {
  return new NextRequest('http://localhost:8080/api/v1/ui/functional-transaction', {
    method: 'POST',
    headers: { 'host': 'localhost:8080', origin, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}
function enabled() {
  vi.mocked(runtime.localRuntimeConfig).mockResolvedValue({
    functionalTest: { actors: { viewer: { principalId: '018f0000-0000-7000-8000-000000000112' } } },
  } as unknown as runtime.LocalConfig);
  vi.mocked(runtime.authenticated).mockResolvedValue({
    role: 'operator',
  } as runtime.IdentitySession);
  vi.mocked(transactions.functionalReviewMatches).mockReturnValue(true);
}
it('denies default-off, foreign-origin, malformed and viewer submissions without proposing a change', async () => {
  vi.mocked(runtime.localRuntimeConfig).mockResolvedValue(undefined);
  expect((await applyFunctionalTransaction(request())).status).toBe(404);
  enabled();
  expect(
    (await applyFunctionalTransaction(request(undefined, 'https://foreign.example'))).status,
  ).toBeGreaterThanOrEqual(400);
  expect(
    (
      await applyFunctionalTransaction(
        request({ command: 'PREPARE', reviewToken: 'r'.repeat(64), checkerId: approvalId }),
      )
    ).status,
  ).toBeGreaterThanOrEqual(400);
  vi.mocked(runtime.authenticated).mockResolvedValue({ role: 'viewer' } as runtime.IdentitySession);
  expect((await applyFunctionalTransaction(request())).status).toBe(404);
  expect(transactions.mutateTransactionWorkbench).not.toHaveBeenCalled();
});
it('returns the durable original before any review or execution', async () => {
  enabled();
  vi.mocked(transactions.mutateTransactionWorkbench).mockResolvedValue(
    NextResponse.json({ approvalId }),
  );
  vi.mocked(transactions.readTransactionWorkbench).mockResolvedValue(
    NextResponse.json({ code: 'PC-INTEGRATION-5001' }, { status: 503 }),
  );
  const result = await applyFunctionalTransaction(request());
  expect(await result.json()).toEqual({ approvalId, outcome: 'PREPARED' });
  expect(transactions.mutateTransactionWorkbench).toHaveBeenCalledTimes(1);
  expect(webauthn.beginLocalWebAuthnAssertion).not.toHaveBeenCalled();
  expect(transactions.readTransactionWorkbench).not.toHaveBeenCalled();
});
it('reconciles a consumed original without approving or executing it again', async () => {
  enabled();
  vi.mocked(transactions.mutateTransactionWorkbench).mockResolvedValue(
    NextResponse.json({ approvalId }),
  );
  vi.mocked(transactions.readTransactionWorkbench).mockImplementation(async () =>
    NextResponse.json({
      candidate: {
        state: 'CONSUMED',
        candidateDigest: 'original',
        operationRef: 'urn:openpc:operation:original',
        resourceRef: 'urn:openpc:resource:original',
      },
      kind: 'provider-profile',
      approval: { makerSubjectRef: 'urn:openpc:resource:maker' },
      stepUp: null,
    }),
  );
  const result = await applyFunctionalTransaction(
    request({ command: 'APPLY', approvalId, reviewToken: 'r'.repeat(64) }),
  );
  expect(await result.json()).toEqual({
    approvalId,
    outcome: 'RECORDED',
    reconciled: true,
    operationRef: 'urn:openpc:operation:original',
  });
  expect(transactions.mutateTransactionWorkbench).not.toHaveBeenCalled();
  expect(webauthn.beginLocalWebAuthnAssertion).not.toHaveBeenCalled();
});

it('keeps the exact original pending when its native read is unavailable', async () => {
  enabled();
  vi.mocked(transactions.readTransactionWorkbench).mockResolvedValue(
    NextResponse.json({}, { status: 503 }),
  );
  const result = await applyFunctionalTransaction(
    request({ command: 'APPLY', approvalId, reviewToken: 'r'.repeat(64) }),
  );
  expect(await result.json()).toEqual({ approvalId, outcome: 'PENDING', stage: 'REVIEW' });
  expect(transactions.mutateTransactionWorkbench).not.toHaveBeenCalled();
});

it('denies a different preview before any automatic review or execution', async () => {
  enabled();
  vi.mocked(transactions.functionalReviewMatches).mockReturnValue(false);
  vi.mocked(transactions.readTransactionWorkbench).mockResolvedValue(
    NextResponse.json({
      kind: 'provider-profile',
      approval: { makerSubjectRef: 'maker' },
      candidate: {
        candidateDigest: 'different',
        state: 'APPROVAL_REQUESTED',
        operationRef: null,
        resourceRef: 'original',
      },
    }),
  );
  expect(
    (
      await applyFunctionalTransaction(
        request({ command: 'APPLY', approvalId, reviewToken: 'r'.repeat(64) }),
      )
    ).status,
  ).toBe(404);
  expect(transactions.mutateTransactionWorkbench).not.toHaveBeenCalled();
  expect(webauthn.beginLocalWebAuthnAssertion).not.toHaveBeenCalled();
});
