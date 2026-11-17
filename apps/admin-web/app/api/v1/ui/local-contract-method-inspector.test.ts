import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { authenticated, localRuntimeConfig } from './local-runtime';
import { readContractMethodInspection } from './local-contract-method-inspector';

vi.mock('./local-runtime', async (original) => ({
  ...(await original<object>()),
  authenticated: vi.fn(),
  localRuntimeConfig: vi.fn(),
}));
const id = (suffix: string) => `018f0000-0000-7000-8000-${suffix.padStart(12, '0')}`;
const ref = (suffix: string) => `urn:openpc:resource:${id(suffix)}`;
const digest = `sha256:${'a'.repeat(64)}`;
const session = {
  sessionId: id('1'),
  principalId: id('2'),
  participantId: id('3'),
  privacyDomainId: id('4'),
  role: 'operator',
  contextMode: 'PARTICIPANT',
  contextEpoch: '1',
  sessionToken: 'private-token',
  stepUpVerifiedAt: null,
};
const durable = {
  policyGenerationDigest: null,
  revision: '1',
  createdAt: '2026-10-06T00:00:00.000000Z',
};
const method = {
  contractMethodPolicyId: ref('10'),
  runtimeBindingId: ref('11'),
  abiArtifactId: ref('12'),
  canonicalSignature: 'balanceOf(address)',
  selector: '0x70a08231',
  effect: 'READ',
  requiredRoles: ['reader'],
  approvalRequirement: 'NONE',
  mfaRequirement: 'NONE',
  environments: ['LOCAL'],
  argumentRuleVersionId: ref('13'),
  rpcMethodPolicyDigest: digest,
  nestedCallSetDigest: digest,
  state: 'ACTIVE',
  ...durable,
};
const binding = {
  runtimeBindingId: ref('11'),
  logicalContractId: ref('14'),
  abiArtifactId: ref('12'),
  chainId: '31337',
  networkId: 'local',
  genesisDigest: digest,
  contractAddress: `0x${'11'.repeat(20)}`,
  codeDigest: digest,
  proxyAddress: null,
  implementationAddress: null,
  implementationCodeDigest: null,
  abiDigest: digest,
  abiVersion: '1.0.0',
  transactionPolicy: null,
  state: 'BOUND',
  ...durable,
};
const contract = {
  logicalContractId: ref('14'),
  logicalName: 'token',
  displayName: 'Local token',
  ...durable,
};
const rules = {
  argumentRuleVersionId: ref('13'),
  runtimeBindingId: ref('11'),
  abiArtifactId: ref('12'),
  canonicalSignature: 'balanceOf(address)',
  version: '1.0.0',
  ruleDigest: digest,
  state: 'ACTIVE',
  namedSetVersions: [],
  rules: [
    {
      parameterPath: 'inputs[0]',
      operandType: 'ADDRESS',
      operator: 'EQ',
      values: [`0x${'11'.repeat(20)}`],
    },
  ],
  ...durable,
};
const request = (query = `methodPolicyId=${id('10')}`) =>
  new NextRequest(`http://localhost/api/v1/ui/contract-method-inspector?${query}`);
function reads() {
  return vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(method))
    .mockResolvedValueOnce(Response.json(binding))
    .mockResolvedValueOnce(Response.json(contract))
    .mockResolvedValueOnce(Response.json(rules));
}
beforeEach(() => {
  vi.mocked(authenticated).mockResolvedValue(session as Awaited<ReturnType<typeof authenticated>>);
  vi.mocked(localRuntimeConfig).mockResolvedValue({ publicApiUrl: 'http://owner' } as Awaited<
    ReturnType<typeof localRuntimeConfig>
  >);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});
afterEach(() => vi.restoreAllMocks());

it('composes the four existing authorized readers with no mutation and no cached response', async () => {
  const fetch = reads();
  const response = await readContractMethodInspection(request());
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  const view = await response.json();
  expect(view.actor.sessionId).toBe(session.sessionId);
  expect(view.method.selector).toBe('0x70a08231');
  expect(view.argumentRules.rules[0].values).toEqual(rules.rules[0]!.values);
  expect(fetch.mock.calls.map(([url]) => new URL(String(url)).pathname.split('/')[3])).toEqual([
    'contract-method-policies',
    'contract-runtime-bindings',
    'logical-contract-assets',
    'typed-argument-rule-versions',
  ]);
  for (const [, init] of fetch.mock.calls) {
    expect(init?.method).toBe('GET');
    expect(init?.body).toBeUndefined();
    expect(new Headers(init?.headers).get('openpc-participant-id')).toBe(
      `urn:openpc:participant:${session.participantId}`,
    );
  }
  expect(JSON.stringify(view)).not.toContain('private-token');
  expect(vi.mocked(process.stderr.write).mock.calls.join('')).not.toContain('private-token');
});

it('does not read owners for missing or duplicate method selection', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch');
  expect((await readContractMethodInspection(request(''))).status).toBe(400);
  expect(
    (
      await readContractMethodInspection(
        request(`methodPolicyId=${id('10')}&methodPolicyId=${id('10')}`),
      )
    ).status,
  ).toBe(400);
  expect(fetch).not.toHaveBeenCalled();
});

it('preserves an ordinary owner unavailable result without attempting other reads', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json({}, { status: 503 }));
  expect((await readContractMethodInspection(request())).status).toBe(503);
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('does not combine a method with a different argument-rule signature', async () => {
  const fetch = reads();
  fetch
    .mockReset()
    .mockResolvedValueOnce(Response.json(method))
    .mockResolvedValueOnce(Response.json(binding))
    .mockResolvedValueOnce(Response.json(contract))
    .mockResolvedValueOnce(Response.json({ ...rules, canonicalSignature: 'other(address)' }));
  expect((await readContractMethodInspection(request())).status).toBe(503);
});

it('projects validated BOOLEAN operands as explicit display strings', async () => {
  reads()
    .mockReset()
    .mockResolvedValueOnce(Response.json(method))
    .mockResolvedValueOnce(Response.json(binding))
    .mockResolvedValueOnce(Response.json(contract))
    .mockResolvedValueOnce(
      Response.json({
        ...rules,
        rules: [
          {
            parameterPath: 'inputs[0]',
            operandType: 'BOOLEAN',
            operator: 'IN',
            values: [true, false],
          },
        ],
      }),
    );
  const response = await readContractMethodInspection(request());
  expect(response.status).toBe(200);
  expect((await response.json()).argumentRules.rules[0].values).toEqual(['true', 'false']);
});

it.each(['runtime', 'selection', 'owner', 'projection', 'context'] as const)(
  'keeps %s error diagnostics correlated when the browser supplies no request IDs',
  async (stage) => {
    const fetch = reads();
    if (stage === 'runtime')
      vi.mocked(localRuntimeConfig).mockRejectedValueOnce(Error('Unavailable'));
    if (stage === 'owner') fetch.mockReset().mockResolvedValue(Response.json({}, { status: 503 }));
    if (stage === 'projection')
      fetch
        .mockReset()
        .mockResolvedValueOnce(Response.json(method))
        .mockResolvedValueOnce(Response.json(binding))
        .mockResolvedValueOnce(Response.json(contract))
        .mockResolvedValueOnce(Response.json({ ...rules, canonicalSignature: 'other(address)' }));
    if (stage === 'context')
      vi.mocked(authenticated)
        .mockResolvedValueOnce(session as Awaited<ReturnType<typeof authenticated>>)
        .mockResolvedValueOnce({ ...session, contextEpoch: '2' } as Awaited<
          ReturnType<typeof authenticated>
        >);
    const response = await readContractMethodInspection(
      request(stage === 'selection' ? '' : undefined),
    );
    expect(response.status).toBeGreaterThanOrEqual(400);
    const body = await response.json();
    const requestId = response.headers.get('x-request-id');
    const correlationId = response.headers.get('x-correlation-id');
    expect(body.traceId).toBe(requestId);
    const diagnostic = vi
      .mocked(process.stderr.write)
      .mock.calls.map(([chunk]) => String(chunk))
      .join('');
    expect(diagnostic).toContain(`|request_id=${requestId}|correlation_id=${correlationId}|`);
    for (const [, init] of fetch.mock.calls) {
      expect(new Headers(init?.headers).get('x-request-id')).toBe(requestId);
      expect(new Headers(init?.headers).get('x-correlation-id')).toBe(correlationId);
    }
  },
);

it('omits the argument-rule read when no rule version is attached', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ ...method, argumentRuleVersionId: null }))
    .mockResolvedValueOnce(Response.json(binding))
    .mockResolvedValueOnce(Response.json(contract));
  const response = await readContractMethodInspection(request());
  expect(response.status).toBe(200);
  expect((await response.json()).argumentRules).toBeNull();
  expect(fetch).toHaveBeenCalledTimes(3);
});

it('discards a completed read when the active Participant changes during loading', async () => {
  reads();
  vi.mocked(authenticated)
    .mockResolvedValueOnce(session as Awaited<ReturnType<typeof authenticated>>)
    .mockResolvedValueOnce({ ...session, contextEpoch: '2' } as Awaited<
      ReturnType<typeof authenticated>
    >);
  expect((await readContractMethodInspection(request())).status).toBe(404);
});
