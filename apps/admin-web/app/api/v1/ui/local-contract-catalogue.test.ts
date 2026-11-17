import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { authenticated, localRuntimeConfig } from './local-runtime';
import { readContractCatalogue } from './local-contract-catalogue';

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
  contextEpoch: '1',
  contextMode: 'PARTICIPANT',
  role: 'operator',
  sessionToken: 'private-token',
  stepUpVerifiedAt: null,
};
const durable = {
  revision: '9007199254740993',
  policyGenerationDigest: null,
  createdAt: '2026-10-10T00:00:00.123456Z',
};
const records = {
  contracts: {
    ...durable,
    logicalContractId: ref('10'),
    logicalName: 'deposit',
    displayName: 'Deposit contract',
  },
  bindings: {
    ...durable,
    runtimeBindingId: ref('11'),
    logicalContractId: ref('10'),
    abiArtifactId: ref('12'),
    chainId: '31337',
    networkId: 'sandbox',
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
  },
  methods: {
    ...durable,
    contractMethodPolicyId: ref('13'),
    runtimeBindingId: ref('11'),
    abiArtifactId: ref('12'),
    canonicalSignature: 'balanceOf(address)',
    selector: '0x70a08231',
    effect: 'READ',
    requiredRoles: ['reader'],
    approvalRequirement: 'NONE',
    mfaRequirement: 'NONE',
    environments: ['LOCAL'],
    argumentRuleVersionId: null,
    rpcMethodPolicyDigest: digest,
    nestedCallSetDigest: digest,
    state: 'ACTIVE',
  },
  abis: {
    ...durable,
    abiArtifactId: ref('12'),
    abiDigest: digest,
    provenance: {
      source: 'Verified artifact',
      locator: 'private-build-location',
      retrievedAt: durable.createdAt,
      sourceDigest: digest,
    },
    canonicalAbi: [
      {
        type: 'function',
        name: 'balanceOf',
        inputs: [{ name: 'account', type: 'address' }],
        outputs: [{ name: '', type: 'uint256' }],
        stateMutability: 'view',
      },
    ],
  },
};
const envelope = (items: unknown[]) => ({
  items,
  nextCursor: null,
  total: String(items.length),
  completeness: 'COMPLETE',
  authorizedEmpty: items.length === 0,
  snapshotRevision: '9007199254740993',
});
const request = (query = 'kind=contracts') =>
  new NextRequest(`http://localhost/api/v1/ui/contract-catalogue?${query}`);
beforeEach(() => {
  vi.mocked(authenticated)
    .mockReset()
    .mockResolvedValue(session as Awaited<ReturnType<typeof authenticated>>);
  vi.mocked(localRuntimeConfig)
    .mockReset()
    .mockResolvedValue({ publicApiUrl: 'http://owner' } as Awaited<
      ReturnType<typeof localRuntimeConfig>
    >);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});
afterEach(() => vi.restoreAllMocks());

it.each(['contracts', 'bindings', 'methods', 'abis'] as const)(
  'reads %s only through its native owner and projects display fields',
  async (kind) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(Response.json(envelope([records[kind]])));
    const response = await readContractCatalogue(request(`kind=${kind}`));
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = await response.json();
    expect(body).toMatchObject({
      kind,
      actor: { sessionId: session.sessionId },
      total: '1',
      snapshotRevision: '9007199254740993',
      items: [{ revision: durable.revision }],
    });
    expect(JSON.stringify(body)).not.toContain('private-build-location');
    expect(JSON.stringify(body)).not.toContain('private-token');
    if (kind === 'bindings') expect(body.items[0].abiDigest).toBe(records.bindings.abiDigest);
    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0]!;
    expect(new URL(String(url)).searchParams.get('limit')).toBe('25');
    expect(init).toMatchObject({ method: 'GET', cache: 'no-store' });
    expect(init?.body).toBeUndefined();
    expect(new Headers(init?.headers).get('openpc-participant-id')).toBe(
      `urn:openpc:participant:${session.participantId}`,
    );
    expect(authenticated).toHaveBeenCalledTimes(2);
  },
);

it('identifies an ABI by its admitted methods while retaining the private locator boundary', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json(
      envelope([
        {
          ...records.abis,
          provenance: { ...records.abis.provenance, source: 'LOCAL_FIXTURE' },
        },
      ]),
    ),
  );
  const response = await readContractCatalogue(request(`kind=abis&search=${digest}`));
  expect(response.status).toBe(200);
  const body = await response.json();
  expect(body.items[0]).toMatchObject({
    label: 'balanceOf',
    source: 'LOCAL_FIXTURE',
    abiDigest: digest,
  });
  expect(JSON.stringify(body)).not.toContain('private-build-location');
  expect(JSON.stringify(body)).not.toContain('private-token');
});
it('does not imply callable methods for an event-only ABI', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json(
      envelope([
        {
          ...records.abis,
          canonicalAbi: [{ type: 'event', name: 'PaymentRecorded', inputs: [], anonymous: false }],
        },
      ]),
    ),
  );
  const response = await readContractCatalogue(request('kind=abis'));
  expect(response.status).toBe(200);
  const body = await response.json();
  expect(body.items[0]).toMatchObject({ label: 'ABI without callable methods', functions: 0 });
  expect(JSON.stringify(body)).not.toContain('private-build-location');
});
it.each([
  'kind=unknown',
  'kind=methods&kind=abis',
  'kind=contracts&parentId=bad',
  `kind=abis&parentId=${id('10')}`,
  `kind=methods&parentId=${id('11')}&search=x`,
  'kind=methods&cursor=bad',
  'kind=contracts&all=true',
])('rejects invalid query before native calls: %s', async (query) => {
  const fetch = vi.spyOn(globalThis, 'fetch');
  expect((await readContractCatalogue(request(query))).status).toBe(400);
  expect(fetch).not.toHaveBeenCalled();
  expect(authenticated).not.toHaveBeenCalled();
});
it.each(['anonymous', 'platform', 'no-privacy'] as const)(
  'fails closed for %s context',
  async (scenario) => {
    vi.mocked(authenticated).mockResolvedValue(
      (scenario === 'anonymous'
        ? undefined
        : {
            ...session,
            ...(scenario === 'platform' ? { contextMode: 'PLATFORM' } : { privacyDomainId: null }),
          }) as Awaited<ReturnType<typeof authenticated>>,
    );
    const fetch = vi.spyOn(globalThis, 'fetch');
    expect((await readContractCatalogue(request())).status).toBe(404);
    expect(fetch).not.toHaveBeenCalled();
  },
);
it.each([
  'UNKNOWN',
  'missing-total',
  'empty-lie',
  'duplicate',
  'private-field',
  'wrong-kind',
  'wrong-parent',
  'wrong-prefix',
  'small-total',
] as const)('does not expose invalid native results: %s', async (scenario) => {
  let query = 'kind=contracts';
  const body: Record<string, unknown> = envelope([records.contracts]);
  if (scenario === 'UNKNOWN') body.completeness = 'UNKNOWN';
  if (scenario === 'missing-total') body.total = null;
  if (scenario === 'empty-lie') body.authorizedEmpty = true;
  if (scenario === 'duplicate') {
    body.items = [records.contracts, records.contracts];
    body.total = '2';
  }
  if (scenario === 'private-field')
    body.items = [{ ...records.contracts, privateSecret: 'not-public' }];
  if (scenario === 'wrong-kind') body.items = [records.methods];
  if (scenario === 'wrong-parent') {
    query = `kind=bindings&parentId=${id('99')}`;
    body.items = [records.bindings];
  }
  if (scenario === 'wrong-prefix') query = 'kind=contracts&search=Foreign';
  if (scenario === 'small-total') body.total = '0';
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(body));
  const response = await readContractCatalogue(request(query));
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain('Deposit contract');
});
it('maps parent references and literal search prefixes to registered native filters', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(envelope([records.bindings])))
    .mockResolvedValueOnce(
      Response.json(envelope([{ ...records.contracts, displayName: 'A_%\\contract' }])),
    );
  expect((await readContractCatalogue(request(`kind=bindings&parentId=${id('10')}`))).status).toBe(
    200,
  );
  expect(new URL(String(fetch.mock.calls[0]![0])).searchParams.get('filter')).toBe(
    `logicalContractId:eq:${id('10')}`,
  );
  expect(
    (await readContractCatalogue(request(`kind=contracts&search=${encodeURIComponent('A_%\\')}`)))
      .status,
  ).toBe(200);
  expect(new URL(String(fetch.mock.calls[1]![0])).searchParams.get('filter')).toBe(
    'displayName:prefix:A_%\\',
  );
});
it('matches a deployed binding search against its address rather than its ABI digest', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(envelope([records.bindings])));
  const response = await readContractCatalogue(request('kind=bindings&search=0x11'));
  expect(response.status).toBe(200);
  expect((await response.json()).items[0].abiDigest).toBe(records.bindings.abiDigest);
});
it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const)(
  'rechecks native %s before returning private records',
  async (field) => {
    vi.mocked(authenticated)
      .mockResolvedValueOnce(session as Awaited<ReturnType<typeof authenticated>>)
      .mockResolvedValueOnce({
        ...session,
        [field]: field === 'contextEpoch' ? '2' : id('99'),
      } as Awaited<ReturnType<typeof authenticated>>);
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(envelope([records.contracts])));
    const response = await readContractCatalogue(request());
    expect(response.status).toBe(404);
    expect(await response.text()).not.toContain('Deposit contract');
  },
);
it.each([403, 503])(
  'preserves native denial or service failure %s without empty results',
  async (status) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({ code: status === 403 ? 'PC-AUTH-0005' : 'PC-INTEGRATION-5001' }, { status }),
    );
    const response = await readContractCatalogue(request());
    expect(response.status).toBe(status === 403 ? 404 : status);
    expect(await response.text()).not.toContain('authorizedEmpty');
  },
);
it('distinguishes a native authorized empty catalogue', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(envelope([])));
  const response = await readContractCatalogue(request());
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    items: [],
    total: '0',
    completeness: 'COMPLETE',
    authorizedEmpty: true,
  });
});
