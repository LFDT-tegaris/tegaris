import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { authenticated, localRuntimeConfig } from './local-runtime';
import { readContractMethodChoices } from './local-contract-method-choices';
import { sha256 } from '../../../../../../services/control-api/src/configuration/digest';

vi.mock('./local-runtime', async (original) => ({
  ...(await original<object>()),
  authenticated: vi.fn(),
  localRuntimeConfig: vi.fn(),
}));
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = (n: number) => `urn:openpc:resource:${id(n)}`;
const session = {
  sessionId: id(1),
  principalId: id(2),
  participantId: id(3),
  privacyDomainId: id(4),
  contextEpoch: '1',
  contextMode: 'PARTICIPANT',
  role: 'operator',
  sessionToken: 'private-native-token',
  stepUpVerifiedAt: null,
};
const durable = {
  revision: '9007199254740993',
  policyGenerationDigest: null,
  createdAt: '2026-10-10T00:00:00Z',
};
const func = (name: string, inputs: unknown[] = [], stateMutability = 'view') => ({
  type: 'function',
  name,
  inputs,
  outputs: [],
  stateMutability,
});
const canonicalAbi = [
  func('balanceOf', [{ name: 'account', type: 'address' }]),
  func(
    'transfer',
    [
      { name: 'to', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    'nonpayable',
  ),
  func(
    'submit',
    [
      {
        type: 'tuple[]',
        components: [
          { type: 'uint256' },
          { type: 'tuple', components: [{ type: 'address' }, { type: 'bool' }] },
        ],
      },
    ],
    'payable',
  ),
];
const fingerprint = sha256(canonicalAbi);
const abi = {
  ...durable,
  abiArtifactId: ref(12),
  abiDigest: fingerprint,
  provenance: {
    source: 'artifact',
    locator: 'private-location',
    retrievedAt: durable.createdAt,
    sourceDigest: fingerprint,
  },
  canonicalAbi,
};
const binding = {
  ...durable,
  runtimeBindingId: ref(11),
  logicalContractId: ref(10),
  abiArtifactId: ref(12),
  chainId: '31337',
  networkId: 'sandbox',
  genesisDigest: fingerprint,
  contractAddress: `0x${'11'.repeat(20)}`,
  codeDigest: fingerprint,
  proxyAddress: null,
  implementationAddress: null,
  implementationCodeDigest: null,
  abiDigest: fingerprint,
  abiVersion: '1.0',
  transactionPolicy: null,
  state: 'BOUND',
};
const request = (query = `bindingId=${id(11)}`) =>
  new NextRequest(`http://localhost/api/v1/ui/contract-method-choices?${query}`);
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(localRuntimeConfig).mockResolvedValue({ publicApiUrl: 'http://owner:8080' } as Awaited<
    ReturnType<typeof localRuntimeConfig>
  >);
  vi.mocked(authenticated).mockResolvedValue(session as Awaited<ReturnType<typeof authenticated>>);
});
afterEach(() => vi.restoreAllMocks());
function reads(a: unknown = binding, b: unknown = abi) {
  return vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(a))
    .mockResolvedValueOnce(Response.json(b));
}

it('projects exact nested/overloaded ABI choices without granting or issuing a command', async () => {
  const fetch = reads();
  const response = await readContractMethodChoices(request());
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  const body = await response.json();
  expect(body).toMatchObject({
    actor: { participantId: id(3) },
    runtimeBindingId: ref(11),
    abiArtifactId: ref(12),
    abiDigest: fingerprint,
    methods: [
      { signature: 'balanceOf(address)', selector: '0x70a08231', effect: 'READ' },
      { signature: 'transfer(address,uint256)', selector: '0xa9059cbb', effect: 'WRITE' },
      { signature: 'submit((uint256,(address,bool))[])', effect: 'WRITE' },
    ],
  });
  expect(JSON.stringify(body)).not.toMatch(
    /private-native-token|private-location|provenance|canonicalAbi/,
  );
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(authenticated).toHaveBeenCalledTimes(2);
  for (const [url, init] of fetch.mock.calls) {
    expect(String(url)).toContain('/api/v1/');
    expect(init).toMatchObject({ method: 'GET', cache: 'no-store' });
    expect(init?.body).toBeUndefined();
    expect(new Headers(init?.headers).get('OpenPC-Participant-ID')).toBe(
      `urn:openpc:participant:${id(3)}`,
    );
  }
});
it.each([
  '',
  'bindingId=bad',
  `bindingId=${id(11)}&bindingId=${id(12)}`,
  `bindingId=${id(11)}&all=true`,
])('rejects invalid query %s before owner calls', async (query) => {
  const fetch = vi.spyOn(globalThis, 'fetch');
  expect((await readContractMethodChoices(request(query))).status).toBe(400);
  expect(fetch).not.toHaveBeenCalled();
});
it.each([
  undefined,
  { ...session, contextMode: 'PLATFORM' },
  { ...session, privacyDomainId: null },
])('requires a native Participant session', async (value) => {
  vi.mocked(authenticated).mockResolvedValue(value as Awaited<ReturnType<typeof authenticated>>);
  const fetch = vi.spyOn(globalThis, 'fetch');
  expect((await readContractMethodChoices(request())).status).toBe(404);
  expect(fetch).not.toHaveBeenCalled();
});
it.each(['RETIRED', 'QUARANTINED'])('does not list methods for a %s binding', async (state) => {
  const fetch = reads({ ...binding, state });
  expect((await readContractMethodChoices(request())).status).toBe(503);
  expect(fetch).toHaveBeenCalledOnce();
});
it.each([
  [{ ...binding, runtimeBindingId: ref(19) }, abi],
  [binding, { ...abi, abiArtifactId: ref(19) }],
  [binding, { ...abi, abiDigest: `sha256:${'b'.repeat(64)}` }],
  [binding, { ...abi, canonicalAbi: [func('different')] }],
])('rejects incompatible references or fingerprint before disclosure', async (a, b) => {
  reads(a, b);
  const response = await readContractMethodChoices(request());
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain('balanceOf');
});
it.each([
  { items: [func('broken', [{ type: 'tuple' }])] },
  { items: [func('same'), func('same')] },
  {
    items: [
      func('burn', [{ type: 'uint256' }]),
      func('collate_propagate_storage', [{ type: 'bytes16' }]),
    ],
  },
])('rejects unresolvable signatures and selector collisions', async ({ items }) => {
  const hash = sha256(items);
  reads({ ...binding, abiDigest: hash }, { ...abi, abiDigest: hash, canonicalAbi: items });
  expect((await readContractMethodChoices(request())).status).toBe(503);
});
it('returns a confirmed empty method list for an ABI without functions', async () => {
  const items: unknown[] = [];
  const hash = sha256(items);
  reads({ ...binding, abiDigest: hash }, { ...abi, abiDigest: hash, canonicalAbi: items });
  expect(await (await readContractMethodChoices(request())).json()).toMatchObject({ methods: [] });
});
it.each([
  'sessionId',
  'principalId',
  'participantId',
  'privacyDomainId',
  'contextEpoch',
  'contextMode',
] as const)('withholds a completed owner read after %s changes', async (field) => {
  reads();
  vi.mocked(authenticated)
    .mockResolvedValueOnce(session as Awaited<ReturnType<typeof authenticated>>)
    .mockResolvedValueOnce({
      ...session,
      [field]: field === 'contextMode' ? 'PLATFORM' : field === 'contextEpoch' ? '2' : id(99),
    } as Awaited<ReturnType<typeof authenticated>>);
  const response = await readContractMethodChoices(request());
  expect(response.status).toBe(404);
  expect(await response.text()).not.toContain('transfer');
});
it.each([0, 1])('preserves native denial at owner read %s', async (index) => {
  const fetch = vi.spyOn(globalThis, 'fetch');
  if (index) fetch.mockResolvedValueOnce(Response.json(binding));
  fetch.mockResolvedValueOnce(
    new Response(JSON.stringify({ code: 'PC-AUTH-0005', detail: 'private-denial' }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    }),
  );
  const response = await readContractMethodChoices(request());
  expect(response.status).toBe(404);
  expect(await response.text()).not.toContain('private-denial');
  expect(fetch).toHaveBeenCalledTimes(index + 1);
});
