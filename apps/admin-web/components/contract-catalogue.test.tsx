import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ContractCatalogue } from './contract-catalogue';
import { sessionTransitionEvent } from './session-transition';

const id = (suffix: string) => `018f0000-0000-7000-8000-${suffix.padStart(12, '0')}`;
const ref = (suffix: string) => `urn:openpc:resource:${id(suffix)}`;
const actor = {
  sessionId: id('1'),
  principalId: id('2'),
  participantId: id('3'),
  privacyDomainId: id('4'),
  contextEpoch: '1',
};
const contract = {
  id: ref('10'),
  label: 'Deposit contract',
  logicalName: 'deposit',
  revision: '1',
  createdAt: '2026-10-10T00:00:00Z',
};
const binding = {
  ...contract,
  id: ref('11'),
  label: `0x${'11'.repeat(20)}`,
  contractAddress: `0x${'11'.repeat(20)}`,
  logicalContractId: ref('10'),
  abiArtifactId: ref('12'),
  abiDigest: `sha256:${'a'.repeat(64)}`,
  chainId: '31337',
  networkId: 'Sandbox',
  state: 'BOUND',
};
const { logicalName: _unused, ...bindingRow } = binding;
void _unused;
const method = {
  id: ref('13'),
  label: 'transfer(address,uint256)',
  runtimeBindingId: ref('11'),
  abiArtifactId: ref('12'),
  revision: '1',
  createdAt: contract.createdAt,
  selector: '0xa9059cbb',
  effect: 'WRITE',
  state: 'ACTIVE',
  approvalRequirement: 'MAKER_CHECKER',
  mfaRequirement: 'WEBAUTHN',
};
const page = (kind = 'contracts', items: unknown[] = [contract], extra = {}) => ({
  kind,
  actor,
  items,
  total: String(items.length),
  nextCursor: null,
  snapshotRevision: '9007199254740993',
  completeness: 'COMPLETE',
  authorizedEmpty: items.length === 0,
  ...extra,
});
const props = { actor, authorityContextKey: 'context-one' };
let transitionOwner: unknown;
const captureTransition = (event: Event) => {
  const detail = (event as CustomEvent<{ phase?: string; nonce?: unknown }>).detail;
  if (detail?.phase === 'changing') transitionOwner = detail.nonce;
};
beforeEach(() => {
  transitionOwner = undefined;
  localStorage.clear();
  window.addEventListener(sessionTransitionEvent, captureTransition);
});
afterEach(() => {
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, {
        detail: { phase: 'settled', nonce: transitionOwner },
      }),
    ),
  );
  window.removeEventListener(sessionTransitionEvent, captureTransition);
  cleanup();
  vi.restoreAllMocks();
});

it('browses contract → binding → method and selects a method without a mutation', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    const kind = new URL(String(url), 'http://localhost').searchParams.get('kind');
    return Response.json(
      kind === 'bindings'
        ? page('bindings', [bindingRow])
        : kind === 'methods'
          ? page('methods', [method])
          : page(),
    );
  });
  const select = vi.fn();
  render(<ContractCatalogue {...props} onSelectMethod={select} />);
  const user = userEvent.setup();
  await user.click(
    await screen.findByRole('button', { name: 'View bindings for Deposit contract' }),
  );
  await user.click(
    await screen.findByRole('button', { name: `View methods for ${binding.contractAddress}` }),
  );
  expect(await screen.findByText('Independent approval required')).toBeVisible();
  expect(screen.getByText('Security key verification')).toBeVisible();
  await user.click(screen.getByRole('button', { name: `Select ${method.label}` }));
  expect(select).toHaveBeenCalledWith(method);
  expect(
    fetch.mock.calls.some(
      ([url]) =>
        new URL(String(url), 'http://localhost').searchParams.get('parentId') === ref('10'),
    ),
  ).toBe(true);
  expect(
    fetch.mock.calls.some(
      ([url]) =>
        new URL(String(url), 'http://localhost').searchParams.get('parentId') === ref('11'),
    ),
  ).toBe(true);
  for (const [, init] of fetch.mock.calls) expect(init?.body).toBeUndefined();
});
it('distinguishes otherwise similar ABIs and selects the exact resource without a command', async () => {
  const items = ['a', 'b'].map((digit, index) => ({
    id: ref(String(20 + index)),
    label: 'recordPayment · getPayment',
    revision: '1',
    createdAt: contract.createdAt,
    abiDigest: `sha256:${digit.repeat(64)}`,
    source: 'LOCAL_FIXTURE',
    functions: 4,
  }));
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(page('abis', items)));
  const select = vi.fn();
  render(<ContractCatalogue {...props} initialKind="abis" onSelectResource={select} />);
  await screen.findByText('aaaaaaaaaaaa…');
  expect(screen.getByText('bbbbbbbbbbbb…')).toBeVisible();
  expect(screen.getAllByText('Imported from a local file')).toHaveLength(2);
  await userEvent
    .setup()
    .click(screen.getAllByRole('button', { name: 'Use recordPayment · getPayment' })[1]!);
  expect(select).toHaveBeenCalledWith({ kind: 'abis', item: items[1] });
  for (const [, init] of fetch.mock.calls) expect(init?.body).toBeUndefined();
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, {
        detail: { phase: 'changing', nonce: 'new-account' },
      }),
    ),
  );
  expect(screen.queryByText('bbbbbbbbbbbb…')).not.toBeInTheDocument();
  expect(screen.queryByText('recordPayment · getPayment')).not.toBeInTheDocument();
});
it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const)(
  'clears private records on %s transition and rejects the previous actor',
  async (field) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json(page()));
    const { rerender } = render(<ContractCatalogue {...props} />);
    expect(await screen.findByText('Deposit contract')).toBeVisible();
    rerender(
      <ContractCatalogue
        {...props}
        actor={{ ...actor, [field]: field === 'contextEpoch' ? '2' : id('99') }}
      />,
    );
    expect(screen.queryByText('Deposit contract')).not.toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent('Contract library unavailable'),
    );
  },
);
it('cancels stale category responses and clears data on cross-tab account changes', async () => {
  let finish: (response: Response) => void = () => {};
  const pending = new Promise<Response>((resolve) => {
    finish = resolve;
  });
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    new URL(String(url), 'http://localhost').searchParams.get('kind') === 'contracts'
      ? pending
      : Response.json(page('methods', [method])),
  );
  render(<ContractCatalogue {...props} />);
  await userEvent.setup().click(screen.getByRole('button', { name: 'Methods' }));
  expect(await screen.findByText(method.label)).toBeVisible();
  await act(async () => finish(Response.json(page())));
  expect(screen.queryByText('Deposit contract')).not.toBeInTheDocument();
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, { detail: { phase: 'changing', nonce: 'public' } }),
    ),
  );
  expect(screen.queryByText(method.label)).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Refresh catalogue' })).toBeDisabled();
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, { detail: { phase: 'settled', nonce: 'public-2' } }),
    ),
  );
  expect(screen.queryByText(method.label)).not.toBeInTheDocument();
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, { detail: { phase: 'settled', nonce: 'public' } }),
    ),
  );
  expect(await screen.findByText(method.label)).toBeVisible();
});
it.each([403, 503])('does not label denied or degraded reads as empty: %s', async (status) => {
  const trace = id('701');
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(new Response(null, { status, headers: { 'x-request-id': trace } }));
  render(<ContractCatalogue {...props} headingLevel={2} />);
  const title = status === 403 ? 'Catalogue access unavailable' : 'Contract library unavailable';
  await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(title));
  expect(screen.getByRole('heading', { name: title, level: 3 })).toBeVisible();
  expect(screen.getByRole('status')).not.toHaveTextContent('No matching');
  expect(screen.getByRole('button', { name: 'Refresh catalogue' })).toBeEnabled();
  expect(screen.getByText(trace)).not.toBeVisible();
  const count = fetch.mock.calls.length;
  const user = userEvent.setup();
  const inspect = screen.getByRole('button', { name: 'Request reference' });
  await user.click(inspect);
  expect(screen.getByRole('dialog', { name: 'Request reference' })).toBeVisible();
  expect(screen.getByText(trace)).toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Close Request reference' }));
  expect(inspect).toHaveFocus();
  expect(screen.getByText(trace)).not.toBeVisible();
  expect(fetch).toHaveBeenCalledTimes(count);
});
it('uses native continuation cursors and starts a new snapshot when refreshed', async () => {
  const rows = Array.from({ length: 25 }, (_, i) => ({
    ...contract,
    id: ref(String(100 + i)),
    label: `Contract ${i}`,
  }));
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () =>
      Response.json(page('contracts', rows, { total: '26', nextCursor: 'pc2.payload.signature' })),
    );
  render(<ContractCatalogue {...props} />);
  await screen.findByText('Contract 0');
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Next page' }));
  await waitFor(() =>
    expect(
      fetch.mock.calls.some(([url]) => String(url).includes('cursor=pc2.payload.signature')),
    ).toBe(true),
  );
  await screen.findByText('Contract 0');
  await user.click(screen.getByRole('button', { name: 'Refresh catalogue' }));
  await waitFor(() => expect(String(fetch.mock.calls.at(-1)![0])).not.toContain('cursor='));
});
it('searches literal prefixes on explicit submit, including Enter inside a parent form', async () => {
  const submit = vi.fn();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () => Response.json(page('contracts', [])));
  render(
    <form onSubmit={submit}>
      <ContractCatalogue {...props} />
    </form>,
  );
  await screen.findByText('No matching resources in this authorized catalogue.');
  const user = userEvent.setup();
  await user.type(screen.getByLabelText('Contract display name prefix'), 'A_%{Enter}');
  await waitFor(() =>
    expect(
      new URL(String(fetch.mock.calls.at(-1)![0]), 'http://localhost').searchParams.get('search'),
    ).toBe('A_%'),
  );
  expect(submit).not.toHaveBeenCalled();
  expect(document.querySelectorAll('form')).toHaveLength(1);
});
it('hides results while native focus revalidation is pending', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json(page()));
  render(<ContractCatalogue {...props} />);
  await screen.findByText('Deposit contract');
  fetch.mockImplementation(() => new Promise(() => {}));
  act(() => window.dispatchEvent(new Event('focus')));
  expect(screen.queryByText('Deposit contract')).not.toBeInTheDocument();
  await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Loading catalogue'));
});

it.each(['changing', 'focus', 'denied'] as const)(
  'removes all drilldown metadata during %s invalidation',
  async (scenario) => {
    let deny = false;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (deny) return new Response(null, { status: 404 });
      return Response.json(
        new URL(String(url), 'http://localhost').searchParams.get('kind') === 'bindings'
          ? page('bindings', [bindingRow])
          : page(),
      );
    });
    render(<ContractCatalogue {...props} />);
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole('button', { name: 'View bindings for Deposit contract' }),
    );
    await screen.findByText(binding.contractAddress);
    expect(screen.queryByText('Deposit contract')).not.toBeInTheDocument();
    deny = true;
    if (scenario === 'changing')
      act(() =>
        window.dispatchEvent(
          new CustomEvent(sessionTransitionEvent, { detail: { phase: 'changing' } }),
        ),
      );
    else if (scenario === 'focus') act(() => window.dispatchEvent(new Event('focus')));
    else await user.click(screen.getByRole('button', { name: 'Refresh catalogue' }));
    expect(screen.queryByText(binding.contractAddress)).not.toBeInTheDocument();
    expect(screen.queryByText('Deposit contract')).not.toBeInTheDocument();
  },
);
it('removes draft search text immediately when account transition starts', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json(page()));
  render(<ContractCatalogue {...props} />);
  await screen.findByText('Deposit contract');
  await userEvent
    .setup()
    .type(screen.getByLabelText('Contract display name prefix'), 'Private treasury name');
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, { detail: { phase: 'changing' } }),
    ),
  );
  expect(screen.getByLabelText('Contract display name prefix')).toHaveValue('');
  expect(screen.queryByText('Deposit contract')).not.toBeInTheDocument();
});

it('clears the applied filter and cursor with its field on successful focus revalidation', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json(page()));
  render(<ContractCatalogue {...props} />);
  await screen.findByText('Deposit contract');
  await userEvent
    .setup()
    .type(screen.getByLabelText('Contract display name prefix'), 'Deposit{Enter}');
  await waitFor(() =>
    expect(
      new URL(String(fetch.mock.calls.at(-1)![0]), 'http://localhost').searchParams.get('search'),
    ).toBe('Deposit'),
  );
  act(() => window.dispatchEvent(new Event('focus')));
  await screen.findByText('Deposit contract');
  expect(screen.getByLabelText('Contract display name prefix')).toHaveValue('');
  const current = new URL(String(fetch.mock.calls.at(-1)![0]), 'http://localhost');
  expect(current.searchParams.has('search')).toBe(false);
  expect(current.searchParams.has('cursor')).toBe(false);
});

it('uses only the current native resource and keeps its protocol fields collapsed', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(page()));
  const select = vi.fn();
  render(<ContractCatalogue {...props} onSelectResource={select} selectionKinds={['contracts']} />);
  const use = await screen.findByRole('button', { name: 'Use Deposit contract' });
  expect(screen.getByText(contract.id)).not.toBeVisible();
  await userEvent.setup().click(use);
  expect(select).toHaveBeenCalledWith({ kind: 'contracts', item: contract });
  const details = screen.getByRole('button', { name: 'Technical details for Deposit contract' });
  await userEvent.setup().click(details);
  expect(screen.getByText(contract.id)).toBeVisible();
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, {
        detail: { phase: 'changing', nonce: 'selection-owner' },
      }),
    ),
  );
  expect(screen.queryByRole('button', { name: 'Use Deposit contract' })).not.toBeInTheDocument();
  expect(screen.queryByText(contract.id)).not.toBeInTheDocument();
});
it.each(['QUARANTINED', 'RETIRED'] as const)(
  'does not use a %s binding to prepare a new method',
  async (state) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json(page('bindings', [{ ...bindingRow, state }])),
    );
    const select = vi.fn();
    render(<ContractCatalogue {...props} initialKind="bindings" onSelectResource={select} />);
    const use = await screen.findByRole('button', { name: `Use ${binding.contractAddress}` });
    expect(use).toBeDisabled();
    await userEvent.setup().click(use);
    expect(select).not.toHaveBeenCalled();
  },
);
it('inherits a pending session transition after client navigation and ignores another owner’s settlement', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json(page()));
  const original = render(<ContractCatalogue {...props} />);
  await screen.findByText('Deposit contract');
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, {
        detail: { phase: 'changing', nonce: 'original-navigation' },
      }),
    ),
  );
  original.unmount();
  const before = fetch.mock.calls.length;
  render(<ContractCatalogue {...props} onSelectResource={vi.fn()} />);
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, {
        detail: { phase: 'settled', nonce: 'other-navigation' },
      }),
    ),
  );
  act(() => window.dispatchEvent(new Event('focus')));
  expect(screen.queryByText('Deposit contract')).not.toBeInTheDocument();
  expect(fetch.mock.calls).toHaveLength(before);
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, {
        detail: { phase: 'settled', nonce: 'original-navigation' },
      }),
    ),
  );
  expect(await screen.findByText('Deposit contract')).toBeVisible();
});

it('rereads the native library after a recorded outcome and discards its delayed previous page', async () => {
  let release!: (response: Response) => void;
  const pending = new Promise<Response>((resolve) => {
    release = resolve;
  });
  const current = {
    ...contract,
    label: 'Example payment registry',
    logicalName: 'example.payment-registry',
  };
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementationOnce(() => pending)
    .mockResolvedValue(Response.json(page('contracts', [current])));
  const view = (refreshToken?: string) => (
    <ContractCatalogue {...props} refreshToken={refreshToken} />
  );
  const rendered = render(view());
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
  rendered.rerender(view('original-operation-revision-3'));
  await screen.findByText('Example payment registry');
  await act(async () => release(Response.json(page())));
  expect(screen.queryByText('Deposit contract')).toBeNull();
  expect(screen.getByText('Example payment registry')).toBeVisible();
  expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
});
