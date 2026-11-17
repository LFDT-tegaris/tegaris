import type { ProtectedAccessSelection } from '../lib/protected-proof-catalogue';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, expect, it, vi } from 'vitest';
import { ProtectedProofWorkflow } from './protected-proof-workflow';
import { sessionTransitionEvent } from './session-transition';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = (n: number) => `urn:openpc:resource:${id(n)}`;
const actor = {
  participantId: id(101),
  privacyDomainId: id(201),
  principalId: id(111),
  sessionId: id(301),
  contextEpoch: '1',
};
const hash = `sha256:${'a'.repeat(64)}`,
  binding = { actorKey: hash, actor };
const time = '2026-10-11T04:00:00.000000Z',
  future = '2099-10-11T04:00:00.000000Z';
const object = {
  objectRef: ref(401),
  objectVersion: '1',
  purpose: 'Investigate a signed authentication record',
  caseReference: 'CASE-001',
  retainUntil: future,
  createdAt: time,
  updatedAt: time,
};
const access: ProtectedAccessSelection['access'] = {
  accessRef: ref(402),
  participantId: `urn:openpc:participant:${actor.participantId}`,
  privacyDomainId: actor.privacyDomainId,
  object: { objectRef: object.objectRef, objectVersion: '1', objectDigest: hash },
  purpose: 'Review authentication evidence',
  caseReference: 'CASE-002',
  state: 'AVAILABLE',
  expiresAt: future,
  recipientPrincipalId: actor.principalId,
  revision: '1',
  consumptionOperationId: null,
  createdAt: time,
  updatedAt: time,
};
const selected = (value = access) => ({ ...binding, access: value, accessDigest: hash });
const page = (catalogue: 'objects' | 'access', items: unknown[], extra = {}) => ({
  ...binding,
  catalogue,
  items,
  nextCursor: null,
  total: String(items.length),
  completeness: 'COMPLETE',
  authorizedEmpty: items.length === 0,
  snapshotRevision: '1',
  ...extra,
});
const accessRow = (value = access) => ({
  accessRef: value.accessRef,
  objectRef: value.object.objectRef,
  objectVersion: value.object.objectVersion,
  purpose: value.purpose,
  caseReference: value.caseReference,
  state: value.state,
  expiresAt: value.expiresAt,
  recipientPrincipalId: value.recipientPrincipalId,
  createdAt: value.createdAt,
  updatedAt: value.updatedAt,
});
function server(options: { current?: typeof access; items?: unknown[]; delivery?: unknown } = {}) {
  const current = options.current ?? access;
  const calls: { method: string; query: string; body?: unknown }[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = new URL(input, 'http://localhost');
      calls.push({
        method: init?.method ?? 'GET',
        query: url.search,
        ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}),
      });
      if (init?.method === 'POST')
        return Response.json(options.delivery ?? { truthState: 'UNKNOWN' }, { status: 202 });
      if (url.searchParams.get('catalogue')) {
        const catalogue = url.searchParams.get('catalogue') as 'objects' | 'access';
        return Response.json(
          page(
            catalogue,
            catalogue === 'objects' ? (options.items ?? [object]) : [accessRow(current)],
          ),
        );
      }
      if (url.searchParams.get('objectId')) return Response.json({ ...binding, object });
      return Response.json(selected(current));
    }),
  );
  return calls;
}
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it('disables server-rendered delivery controls and keeps guided reference entry secondary', () => {
  const initial = document.createElement('div');
  initial.innerHTML = renderToStaticMarkup(<ProtectedProofWorkflow guided binding={binding} />);
  const enabledButtons = [...initial.querySelectorAll('button')]
    .filter((button) => !button.disabled)
    .map((button) => button.getAttribute('aria-label') ?? button.textContent);
  expect(enabledButtons).toEqual([
    'Find approved access by reference',
    'Close Find approved access by reference',
  ]);
  expect(initial.querySelector('dialog')?.open).toBe(false);
  expect(initial.querySelector('input')?.disabled).toBe(true);
});
it('selects the exact owner proof before preparing access without a business command', async () => {
  const user = userEvent.setup(),
    calls = server(),
    prepare = vi.fn();
  render(<ProtectedProofWorkflow guided binding={binding} onPrepareAccess={prepare} />);
  await user.click(await screen.findByRole('button', { name: `Review proof ${id(401)}` }));
  expect(await screen.findByRole('heading', { name: 'Selected proof' })).toHaveFocus();
  expect(screen.getByLabelText('Protected access reference')).not.toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Prepare access request' }));
  expect(prepare).toHaveBeenCalledWith(object.objectRef);
  expect(prepare).toHaveBeenCalledTimes(1);
  expect(calls.some((call) => call.query === `?objectId=${id(401)}`)).toBe(true);
  expect(calls.every((call) => call.method === 'GET')).toBe(true);
});
it('does not mark a clicked row as selected before its current owner read completes', async () => {
  const user = userEvent.setup();
  let resolve!: (value: Response) => void;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string) =>
      input.includes('objectId')
        ? new Promise<Response>((r) => {
            resolve = r;
          })
        : Response.json(page('objects', [object])),
    ),
  );
  render(<ProtectedProofWorkflow guided binding={binding} />);
  const row = await screen.findByRole('button', { name: `Review proof ${id(401)}` });
  await user.click(row);
  expect(row).not.toHaveAttribute('aria-current');
  expect(screen.queryByText('Viewing')).toBeNull();
  await act(async () => {
    resolve(Response.json({ ...binding, object }));
  });
  expect(await screen.findByRole('heading', { name: 'Selected proof' })).toHaveFocus();
  expect(row).toHaveAttribute('aria-current', 'true');
});
it('pages every loaded record without fabricating a native cursor', async () => {
  const user = userEvent.setup(),
    items = Array.from({ length: 7 }, (_, n) => ({
      ...object,
      objectRef: ref(500 + n),
      purpose: `Proof purpose ${n}`,
    })),
    calls = server({ items });
  render(<ProtectedProofWorkflow guided binding={binding} />);
  const list = await screen.findByRole('region', { name: 'Authorized protected proof records' });
  await screen.findByText('Proof purpose 0');
  expect(within(list).getAllByRole('listitem')).toHaveLength(6);
  await user.click(screen.getByRole('button', { name: 'Next displayed proofs' }));
  expect(within(list).getAllByRole('listitem')).toHaveLength(1);
  expect(screen.getByText('Proof purpose 6')).toBeVisible();
  expect(calls).toHaveLength(1);
});
it.each(['CONSUMED', 'EXPIRED', 'OTHER_RECIPIENT'] as const)(
  'withholds delivery for %s without losing readable owner status',
  async (state) => {
    const user = userEvent.setup(),
      current =
        state === 'OTHER_RECIPIENT'
          ? { ...access, recipientPrincipalId: id(112) }
          : {
              ...access,
              state,
              revision: state === 'CONSUMED' ? '2' : '1',
              consumptionOperationId: state === 'CONSUMED' ? id(403) : null,
            };
    const calls = server({ current });
    render(<ProtectedProofWorkflow guided binding={binding} />);
    await screen.findByText(object.purpose);
    await user.click(screen.getByRole('button', { name: 'Approved access' }));
    await user.click(await screen.findByRole('button', { name: `Review access ${id(402)}` }));
    expect(await screen.findByRole('heading', { name: 'Selected access' })).toHaveFocus();
    expect(screen.queryByRole('button', { name: 'Consume once and download proof' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Read current delivery status' })).toBeVisible();
    expect(calls.every((call) => call.method === 'GET')).toBe(true);
  },
);
it('reconciles an unknown delivery against the original access without automatically retrying consumption', async () => {
  const user = userEvent.setup(),
    calls = server();
  render(<ProtectedProofWorkflow guided binding={binding} />);
  await screen.findByText(object.purpose);
  await user.click(screen.getByRole('button', { name: 'Approved access' }));
  await user.click(await screen.findByRole('button', { name: `Review access ${id(402)}` }));
  await user.click(await screen.findByRole('button', { name: 'Consume once and download proof' }));
  expect(
    await screen.findByText(
      'Delivery outcome is unknown. Read the same access to reconcile it before any further action.',
    ),
  ).toBeVisible();
  const writes = calls.filter((call) => call.method === 'POST');
  expect(writes).toHaveLength(1);
  expect(writes[0]?.body).toMatchObject({ accessId: id(402), actorKey: hash, accessDigest: hash });
  await user.click(screen.getByRole('button', { name: 'Reconcile this access' }));
  expect(await screen.findByRole('heading', { name: 'Selected access' })).toHaveFocus();
  expect(calls.at(-1)?.query).toBe(`?accessId=${id(402)}`);
  expect(calls.filter((call) => call.method === 'POST')).toHaveLength(1);
});
it('withholds foreign or malformed catalogues instead of treating them as an empty authorized result', async () => {
  for (const value of [
    page('objects', [object], { actorKey: `sha256:${'b'.repeat(64)}` }),
    page('objects', [object, object]),
    page('objects', [{ ...object, objectRef: 'not-a-resource' }]),
  ]) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json(value)),
    );
    const view = render(<ProtectedProofWorkflow guided binding={binding} />);
    await screen.findByText(/could not be confirmed|workspace changed/u);
    expect(screen.queryByText(object.purpose)).toBeNull();
    expect(screen.queryByText(/No authorized/u)).toBeNull();
    view.unmount();
  }
});
it('clears protected data on a workspace transition and suppresses its late owner response', async () => {
  const user = userEvent.setup();
  let resolve!: (value: Response) => void;
  const nonce = 'proof-context-change';
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string) =>
      input.includes('objectId')
        ? new Promise<Response>((r) => {
            resolve = r;
          })
        : Response.json(page('objects', [object])),
    ),
  );
  render(<ProtectedProofWorkflow guided binding={binding} />);
  await user.click(await screen.findByRole('button', { name: `Review proof ${id(401)}` }));
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, { detail: { phase: 'changing', nonce } }),
    ),
  );
  await act(async () => {
    resolve(Response.json({ ...binding, object }));
  });
  expect(screen.queryByRole('heading', { name: 'Selected proof' })).toBeNull();
  expect(screen.queryByText(object.purpose)).toBeNull();
  act(() =>
    window.dispatchEvent(
      new CustomEvent(sessionTransitionEvent, { detail: { phase: 'settled', nonce } }),
    ),
  );
  await screen.findByText(object.purpose);
  expect(screen.queryByRole('heading', { name: 'Selected proof' })).toBeNull();
});
it('clears delivery metadata and references when the window loses focus', async () => {
  const user = userEvent.setup();
  server();
  render(<ProtectedProofWorkflow guided binding={binding} />);
  await screen.findByText(object.purpose);
  await user.click(screen.getByRole('button', { name: 'Approved access' }));
  await user.click(await screen.findByRole('button', { name: `Review access ${id(402)}` }));
  await screen.findByRole('heading', { name: 'Selected access' });
  fireEvent.blur(window);
  expect(screen.queryByRole('heading', { name: 'Selected access' })).toBeNull();
  expect(screen.getByLabelText('Protected access reference')).toHaveValue('');
});
