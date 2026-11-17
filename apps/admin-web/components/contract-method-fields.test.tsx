import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { ContractMethodSelect, ContractRoleSelect } from './contract-method-fields';
import { notifySessionTransition } from './session-transition';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = (n: number) => `urn:openpc:resource:${id(n)}`;
const actor = {
  sessionId: id(1),
  principalId: id(2),
  participantId: id(3),
  privacyDomainId: id(4),
  contextEpoch: '1',
};
const fingerprint = `sha256:${'a'.repeat(64)}`;
const method = {
  signature: 'transfer(address,uint256)',
  selector: '0xa9059cbb',
  effect: 'WRITE' as const,
};
const methods = {
  actor,
  runtimeBindingId: ref(11),
  abiArtifactId: ref(12),
  abiDigest: fingerprint,
  methods: [method],
};
const methodProps = {
  actor,
  bindingId: ref(11),
  abiArtifactId: ref(12),
  abiDigest: fingerprint,
  value: '',
  disabled: false,
};
const role = (n = 31) => ({
  effect: {
    id: id(n),
    participantId: actor.participantId,
    roleId: `urn:openpc:role:${id(n)}`,
    displayName: `Creditor ${n}`,
    state: 'ACTIVE',
    revision: '1',
    actionIntentIds: [],
  },
});
const rolePage = (items = [role()], extra = {}) => ({
  actor,
  items,
  nextCursor: null,
  observedAt: '2026-10-10T00:00:00Z',
  authorizedEmpty: items.length === 0,
  ...extra,
});
let owner: string | undefined;
afterEach(() => {
  act(() => {
    if (owner) notifySessionTransition('settled', owner);
  });
  owner = undefined;
  cleanup();
  localStorage.clear();
  vi.restoreAllMocks();
});

it('renders the unselected method form without issuing a resource read', () => {
  const fetch = vi.spyOn(globalThis, 'fetch');
  render(
    <ContractMethodSelect
      {...methodProps}
      bindingId={undefined}
      abiArtifactId={undefined}
      abiDigest={undefined}
      onSelect={vi.fn()}
    />,
  );
  expect(screen.getByRole('combobox', { name: 'Contract method' })).toBeDisabled();
  expect(
    screen.getByText('Choose a deployed contract from the library to see its methods.'),
  ).toBeVisible();
  expect(fetch).not.toHaveBeenCalled();
});

it('selects an exact ABI method and effect with read-only requests and no defaults', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(methods));
  const onSelect = vi.fn();
  render(<ContractMethodSelect {...methodProps} onSelect={onSelect} />);
  const select = await screen.findByRole('combobox', { name: 'Contract method' });
  await screen.findByRole('option', { name: 'transfer(address,uint256) · Change state' });
  expect(select).toHaveValue('');
  expect(onSelect).not.toHaveBeenCalled();
  await userEvent.setup().selectOptions(select, method.signature);
  expect(onSelect).toHaveBeenCalledWith(method);
  expect(fetch.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});
it.each(['runtimeBindingId', 'abiArtifactId', 'abiDigest'])(
  'does not expose method choices with a mismatching %s',
  async (field) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({
        ...methods,
        [field]: field === 'abiDigest' ? `sha256:${'b'.repeat(64)}` : ref(99),
      }),
    );
    render(<ContractMethodSelect {...methodProps} onSelect={vi.fn()} />);
    await screen.findByRole('button', { name: 'Refresh method choices' });
    expect(screen.queryByRole('option', { name: /transfer/u })).not.toBeInTheDocument();
  },
);
it('withholds late method choices after the binding changes', async () => {
  let release!: (value: Response) => void;
  vi.spyOn(globalThis, 'fetch')
    .mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    )
    .mockResolvedValue(Response.json({ ...methods, runtimeBindingId: ref(21), methods: [] }));
  const view = render(<ContractMethodSelect {...methodProps} onSelect={vi.fn()} />);
  await waitFor(() => expect(release).toBeTypeOf('function'));
  view.rerender(<ContractMethodSelect {...methodProps} bindingId={ref(21)} onSelect={vi.fn()} />);
  await act(async () => release(Response.json(methods)));
  expect(screen.queryByRole('option', { name: /transfer/u })).not.toBeInTheDocument();
  await screen.findByText('The bound ABI contains no functions.');
});
it.each([403, 404, 503])(
  'keeps unavailable/denied role choices distinct from authorized empty at %s',
  async (status) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}', { status }));
    render(<ContractRoleSelect actor={actor} selected={[]} disabled={false} onChange={vi.fn()} />);
    await screen.findByText(
      'Role choices could not be confirmed. Check your account, security key verification and workspace access, then refresh.',
    );
    expect(
      screen.queryByText('No authorized active roles match this search.'),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Check account & security' })).toHaveAttribute(
      'href',
      '/home/session',
    );
    expect(screen.getByRole('combobox', { name: 'Add required role' })).toBeDisabled();
  },
);
it('uses an active role display name while selecting the unchanged native role reference', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(rolePage()));
  const change = vi.fn();
  render(<ContractRoleSelect actor={actor} selected={[]} disabled={false} onChange={change} />);
  await screen.findByRole('option', { name: 'Creditor 31' });
  expect(change).not.toHaveBeenCalled();
  await userEvent
    .setup()
    .selectOptions(
      screen.getByRole('combobox', { name: 'Add required role' }),
      role().effect.roleId,
    );
  expect(change).toHaveBeenCalledWith([role().effect.roleId]);
  expect(fetch.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});
it.each([
  rolePage([], { authorizedEmpty: false }),
  rolePage([role()], { actor: { ...actor, privacyDomainId: id(99) } }),
  rolePage([{ effect: { ...role().effect, participantId: id(99) } }]),
  rolePage([{ effect: { ...role().effect, state: 'ARCHIVED' } }]),
  rolePage([{ effect: { ...role().effect, roleId: `urn:openpc:role:${id(99)}` } }]),
  rolePage([role(), role()]),
])('does not offer roles from an incompatible owner page', async (page) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(page));
  render(<ContractRoleSelect actor={actor} selected={[]} disabled={false} onChange={vi.fn()} />);
  await screen.findByText(
    'Role choices could not be confirmed. Check your account, security key verification and workspace access, then refresh.',
  );
  expect(screen.queryByRole('option', { name: 'Creditor 31' })).not.toBeInTheDocument();
});
it('retains original unknown and duplicate selected values until an explicit removal', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(rolePage([])));
  const change = vi.fn();
  render(
    <ContractRoleSelect
      actor={actor}
      selected={[' legacy\nvalue ', 'same', 'same']}
      disabled={false}
      onChange={change}
    />,
  );
  await screen.findByText('No authorized active roles match this search.');
  expect(change).not.toHaveBeenCalled();
  expect(screen.getByText('3 required roles selected')).toBeVisible();
  await userEvent.setup().click(screen.getByRole('button', { name: 'Remove required role 2' }));
  expect(change).toHaveBeenCalledWith([' legacy\nvalue ', 'same']);
});
it('uses the current owner cursor and preserves the role search when paging', async () => {
  const items = Array.from({ length: 25 }, (_, n) => role(31 + n));
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(rolePage(items, { nextCursor: id(55) })))
    .mockResolvedValueOnce(Response.json(rolePage([role(56)])));
  render(<ContractRoleSelect actor={actor} selected={[]} disabled={false} onChange={vi.fn()} />);
  await screen.findByRole('option', { name: 'Creditor 31' });
  await userEvent.setup().click(screen.getByRole('button', { name: 'Next role page' }));
  await screen.findByRole('option', { name: 'Creditor 56' });
  expect(
    new URL(String(fetch.mock.calls[1]![0]), 'http://localhost').searchParams.get('after'),
  ).toBe(id(55));
});
it('clears role search and masks old choices before a new actor read', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(rolePage()));
  const change = vi.fn();
  const view = render(
    <ContractRoleSelect actor={actor} selected={[]} disabled={false} onChange={change} />,
  );
  await screen.findByRole('option', { name: 'Creditor 31' });
  await userEvent
    .setup()
    .type(screen.getByRole('textbox', { name: 'Find a role' }), 'PRIVATE_SEARCH');
  act(() => {
    owner = notifySessionTransition('changing');
  });
  expect(screen.queryByRole('textbox', { name: 'Find a role' })).not.toBeInTheDocument();
  const next = { ...actor, sessionId: id(99), privacyDomainId: id(98) };
  fetch.mockResolvedValue(Response.json(rolePage([], { actor: next })));
  view.rerender(
    <ContractRoleSelect actor={next} selected={[]} disabled={false} onChange={change} />,
  );
  act(() => {
    notifySessionTransition('settled', owner);
    owner = undefined;
  });
  expect(await screen.findByRole('textbox', { name: 'Find a role' })).toHaveValue('');
  expect(screen.queryByRole('option', { name: 'Creditor 31' })).not.toBeInTheDocument();
  await screen.findByText('No authorized active roles match this search.');
  expect(String(fetch.mock.calls.at(-1)![0])).not.toContain('PRIVATE_SEARCH');
  expect(change).not.toHaveBeenCalled();
});
it('does not load or display new selectors mounted during a pending transition', () => {
  act(() => {
    owner = notifySessionTransition('changing');
  });
  const fetch = vi.spyOn(globalThis, 'fetch');
  render(
    <>
      <ContractMethodSelect {...methodProps} onSelect={vi.fn()} />
      <ContractRoleSelect actor={actor} selected={[]} disabled={false} onChange={vi.fn()} />
    </>,
  );
  expect(fetch).not.toHaveBeenCalled();
  expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
});
