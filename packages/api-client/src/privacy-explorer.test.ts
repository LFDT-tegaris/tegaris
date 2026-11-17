import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import type { Client } from '../generated/privacy-explorer/client/types.gen.js';
import type {
  ExplorerProjectionRequestV1,
  PrivacyExplorerResultV1,
} from '../generated/privacy-explorer/types.gen.js';
import { readPrivacyExplorer } from './privacy-explorer.js';

type Fixture = Readonly<{
  request: ExplorerProjectionRequestV1;
  completeRaw: unknown;
  context: Readonly<{ profileDigest: string }>;
  expected: Readonly<{ queryDigest: string; requestDigest: string; resultDigest: string }>;
}>;
const fixture = JSON.parse(
  await readFile(
    new URL(
      '../../../tests/fixtures/privacy-explorer/i07-gate2-b3-parity-vectors.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as Fixture;
const publicResult = (): PrivacyExplorerResultV1 => ({
  schemaVersion: '1.0',
  outcome: 'COMPLETE',
  truthState: 'TRUE',
  requestDigest: fixture.expected.requestDigest,
  profileDigest: fixture.context.profileDigest,
  queryDigest: fixture.expected.queryDigest,
  resultDigest: fixture.expected.resultDigest,
  records: [
    {
      id: 'record-a',
      fields: [
        { fieldId: 'PEF-A', value: 7 },
        { fieldId: 'PEF-B', value: 'visible' },
      ],
    },
    {
      id: 'record-b',
      fields: [
        { fieldId: 'PEF-A', value: true },
        { fieldId: 'PEF-B', value: null },
      ],
    },
  ],
  page: { cursor: null, gapFree: true },
});
const canonicalJson = (value: unknown): string => {
  if (value === null || ['boolean', 'number', 'string'].includes(typeof value))
    return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(',')}}`;
};
const digest = (value: unknown) =>
  `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const refreshResultDigest = (result: PrivacyExplorerResultV1) => {
  const preimage = Object.fromEntries(
    Object.entries(result).filter(([key]) => key !== 'resultDigest'),
  );
  result.resultDigest = digest(preimage);
  return result;
};
const clientReturning = (result: unknown) => {
  const candidate = result as { data?: unknown; error?: unknown; response?: Response };
  const normalized =
    candidate.data !== undefined && candidate.response === undefined
      ? { ...candidate, response: new Response(null, { status: 200 }) }
      : candidate;
  const post = vi.fn(async (_options: unknown) => normalized);
  return { client: { post } as unknown as Client, post };
};

describe('Privacy Explorer public API client boundary', () => {
  it('calls only the generated Control API operation and validates an immutable public result', async () => {
    const transport = clientReturning({ data: publicResult(), error: undefined });
    const result = await readPrivacyExplorer(transport.client, fixture.request);
    expect(result.data).toEqual(publicResult());
    expect(Object.isFrozen(result.data)).toBe(true);
    expect(transport.post).toHaveBeenCalledOnce();
    expect(transport.post.mock.calls[0]?.[0]).toMatchObject({
      url: '/v1/privacy-explorer/projections:read',
      body: fixture.request,
    });
    expect(transport.post.mock.calls[0]?.[0]).not.toHaveProperty('providerUrl');
  });

  it('preserves a bounded public problem without deriving truth or fallback', async () => {
    const problem = {
      code: 'PC-INTEGRATION-5001',
      httpStatus: 503,
      jsonRpcCode: -32051,
      grpcStatus: 'UNAVAILABLE',
      truthState: 'UNAVAILABLE',
      retryable: true,
      disclosure: 'NON_LEAKING_INVARIANT',
      publicTitle: 'The service is unavailable',
    };
    const transport = clientReturning({
      data: undefined,
      error: problem,
      response: new Response(null, { status: 503 }),
    });
    await expect(readPrivacyExplorer(transport.client, fixture.request)).resolves.toEqual({
      problem,
    });
    expect(transport.post).toHaveBeenCalledOnce();
  });

  it.each([
    [
      'unauthenticated',
      {
        code: 'PC-AUTH-0001',
        httpStatus: 401,
        jsonRpcCode: -32041,
        grpcStatus: 'UNAUTHENTICATED',
        truthState: 'DENIED',
        retryable: false,
        disclosure: 'NON_LEAKING_INVARIANT',
        publicTitle: 'Resource is unavailable',
      },
    ],
    [
      'terminal denial',
      {
        code: 'PC-RUNTIME-3001',
        httpStatus: 403,
        jsonRpcCode: -32001,
        grpcStatus: 'PERMISSION_DENIED',
        truthState: 'DENIED',
        retryable: false,
        disclosure: 'NON_LEAKING_INVARIANT',
        publicTitle: 'Resource is unavailable',
      },
    ],
  ] as const)('preserves the exact %s HTTP-boundary problem', async (_name, problem) => {
    const transport = clientReturning({
      data: undefined,
      error: problem,
      response: new Response(null, { status: problem.httpStatus }),
    });
    await expect(readPrivacyExplorer(transport.client, fixture.request)).resolves.toEqual({
      problem,
    });
  });

  it('contains transport failures and ambiguous transport responses', async () => {
    const privateFailure = new Error('private connector URL and response body');
    const rejecting = {
      post: vi.fn(async () => Promise.reject(privateFailure)),
    } as unknown as Client;
    await expect(readPrivacyExplorer(rejecting, fixture.request)).rejects.toThrow(
      'Privacy Explorer transport failed',
    );
    await expect(readPrivacyExplorer(rejecting, fixture.request)).rejects.not.toThrow(
      privateFailure.message,
    );

    const ambiguous = clientReturning({
      data: publicResult(),
      error: {
        code: 'PC-INTEGRATION-5001',
        httpStatus: 503,
        jsonRpcCode: -32051,
        grpcStatus: 'UNAVAILABLE',
        truthState: 'UNAVAILABLE',
        retryable: true,
        disclosure: 'NON_LEAKING_INVARIANT',
        publicTitle: 'The service is unavailable',
      },
      response: new Response(null, { status: 503 }),
    });
    await expect(readPrivacyExplorer(ambiguous.client, fixture.request)).rejects.toThrow(
      'ambiguous Privacy Explorer response',
    );
  });

  it('rejects a valid result on a non-success transport status', async () => {
    const transport = clientReturning({
      data: publicResult(),
      error: undefined,
      response: new Response(null, { status: 409 }),
    });
    await expect(readPrivacyExplorer(transport.client, fixture.request)).rejects.toThrow(
      'invalid Privacy Explorer result response',
    );
  });

  it.each([
    ['malformed public result', { ...publicResult(), resultDigest: 'provider-claim' }],
    ['raw adapter result', fixture.completeRaw],
    ['provider-added field', { ...publicResult(), providerUrl: 'https://invalid' }],
  ])('rejects %s returned as public data', async (_name, data) => {
    const transport = clientReturning({ data, error: undefined });
    await expect(readPrivacyExplorer(transport.client, fixture.request)).rejects.toThrow(
      'invalid Privacy Explorer result response',
    );
  });

  it('rejects an endpoint override embedded in the public request before transport', async () => {
    const transport = clientReturning({ data: publicResult(), error: undefined });
    const request = { ...fixture.request, providerUrl: 'https://invalid' };
    await expect(
      readPrivacyExplorer(transport.client, request as ExplorerProjectionRequestV1),
    ).rejects.toThrow('invalid Privacy Explorer request');
    expect(transport.post).not.toHaveBeenCalled();
  });

  it.each([
    [
      'profile digest claim',
      (request: ExplorerProjectionRequestV1) => {
        request.exportProfile.digest = `sha256:${'b'.repeat(64)}`;
      },
    ],
    [
      'query digest claim',
      (request: ExplorerProjectionRequestV1) => {
        request.queryDigest = `sha256:${'b'.repeat(64)}`;
      },
    ],
    [
      'operation membership',
      (request: ExplorerProjectionRequestV1) => {
        request.operationId = 'PE-UNREGISTERED';
      },
    ],
    [
      'scope action binding',
      (request: ExplorerProjectionRequestV1) => {
        request.scope.action = 'different-action';
      },
    ],
    [
      'canonical profile order',
      (request: ExplorerProjectionRequestV1) => {
        request.exportProfile.allowedFieldIds.reverse();
      },
    ],
  ] as const)('rejects a schema-shaped request with a false %s', async (_name, mutate) => {
    const transport = clientReturning({ data: publicResult(), error: undefined });
    const request = structuredClone(fixture.request);
    mutate(request);
    await expect(readPrivacyExplorer(transport.client, request)).rejects.toThrow(
      'invalid Privacy Explorer request',
    );
    expect(transport.post).not.toHaveBeenCalled();
  });

  it('rejects a schema-valid result whose provider digest does not match its public bytes', async () => {
    const tampered = publicResult();
    tampered.records[0]!.fields[0]!.value = 8;
    const transport = clientReturning({ data: tampered, error: undefined });
    await expect(readPrivacyExplorer(transport.client, fixture.request)).rejects.toThrow(
      'invalid Privacy Explorer result response',
    );
  });

  it.each([
    [
      'complete result with a continuation cursor',
      (result: PrivacyExplorerResultV1) => {
        result.page.cursor = 'next';
      },
    ],
    [
      'partial result without an incompleteness marker',
      (result: PrivacyExplorerResultV1) => {
        result.outcome = 'PARTIAL';
        result.truthState = 'PARTIAL';
      },
    ],
    [
      'unknown result with gap-free coverage',
      (result: PrivacyExplorerResultV1) => {
        result.outcome = 'UNKNOWN';
        result.truthState = 'UNKNOWN';
        result.records = [];
      },
    ],
  ] as const)('rejects a self-consistent %s', async (_name, mutate) => {
    const result = publicResult();
    mutate(result);
    refreshResultDigest(result);
    const transport = clientReturning({ data: result, error: undefined });
    await expect(readPrivacyExplorer(transport.client, fixture.request)).rejects.toThrow(
      'invalid Privacy Explorer result response',
    );
  });

  it.each(['profileDigest', 'queryDigest', 'requestDigest'] as const)(
    'rejects a self-consistent result for another request by %s',
    async (field) => {
      const other = publicResult();
      other[field] = `sha256:${'d'.repeat(64)}`;
      refreshResultDigest(other);
      const transport = clientReturning({ data: other, error: undefined });
      await expect(readPrivacyExplorer(transport.client, fixture.request)).rejects.toThrow(
        'invalid Privacy Explorer result response',
      );
    },
  );

  it('rejects a cursor-A result replayed for cursor-B even when query/profile agree', async () => {
    const cursorB = structuredClone(fixture.request);
    cursorB.page.cursor = 'cursor-b';
    const transport = clientReturning({ data: publicResult(), error: undefined });
    await expect(readPrivacyExplorer(transport.client, cursorB)).rejects.toThrow(
      'invalid Privacy Explorer result response',
    );
  });

  it.each([
    [
      'raw payload fields',
      {
        code: 'PC-INTEGRATION-5001',
        httpStatus: 503,
        jsonRpcCode: -32051,
        grpcStatus: 'UNAVAILABLE',
        truthState: 'UNAVAILABLE',
        retryable: true,
        disclosure: 'NON_LEAKING_INVARIANT',
        publicTitle: 'The service is unavailable',
        providerBody: { secret: true },
      },
    ],
    [
      'mutually consistent but false problem tuple',
      {
        code: 'PC-INTEGRATION-5001',
        httpStatus: 504,
        jsonRpcCode: -32093,
        grpcStatus: 'DEADLINE_EXCEEDED',
        truthState: 'FAILED',
        retryable: false,
        disclosure: 'NON_LEAKING_INVARIANT',
        publicTitle: 'The service is unavailable',
      },
    ],
  ])('rejects malformed public problems with %s', async (_name, error) => {
    const transport = clientReturning({ data: undefined, error });
    await expect(readPrivacyExplorer(transport.client, fixture.request)).rejects.toThrow(
      'invalid Privacy Explorer problem response',
    );
  });
});
