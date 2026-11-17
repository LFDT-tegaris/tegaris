import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { EvidenceOperationCorrelation } from './evidence-operation-correlation';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = (n: number) => `urn:openpc:resource:${id(n)}`;
const actorKey = `sha256:${'a'.repeat(64)}`;
const props = { evidenceId: ref(5), actorKey };
const time = '2026-09-25T00:00:00.123456Z';
const result = () => ({
  ...props,
  receiptId: id(6),
  recordDigest: `sha256:${'b'.repeat(64)}`,
  recordedAt: time,
  historicalRevision: '2',
  operation: {
    operationId: id(7),
    resourceRef: ref(9),
    actionIntentId: 'ACT-OPERATIONS_UPDATE_CLAIM-V1',
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    revision: '2',
    createdAt: time,
    updatedAt: time,
  },
});
let owner: (input: string, init: RequestInit) => Promise<Response>;
const calls: { input: string; init: RequestInit }[] = [];
beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
  calls.length = 0;
  owner = async () => Response.json(result());
  vi.stubGlobal(
    'fetch',
    vi.fn((input: string, init: RequestInit) => {
      calls.push({ input, init });
      return owner(input, init);
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it('reads only on activation, uses exact selectors, focuses truthful current status and persists nothing', async () => {
  const user = userEvent.setup();
  render(<EvidenceOperationCorrelation {...props} />);
  expect(calls).toHaveLength(0);
  await user.tab();
  expect(screen.getByRole('button', { name: 'Read linked operation' })).toHaveFocus();
  await user.keyboard('{Enter}');
  expect(await screen.findByRole('region', { name: 'Linked operation result' })).toHaveTextContent(
    'SUCCEEDED / SUCCESS',
  );
  expect(screen.getByRole('heading', { name: 'Current operation status' })).toHaveFocus();
  expect(
    screen.getByText(/Current object state and provider effects have not been checked/u),
  ).toBeVisible();
  expect(Object.fromEntries(new URL(calls[0]!.input, 'http://localhost').searchParams)).toEqual(
    props,
  );
  expect(calls[0]!.init).toMatchObject({ method: 'GET', cache: 'no-store', redirect: 'error' });
  expect(sessionStorage.length).toBe(0);
  expect(localStorage.length).toBe(0);
});
it.each([403, 404, 503])(
  'clears old success on a denied or unavailable reread (%s), hiding error contents',
  async (status) => {
    render(<EvidenceOperationCorrelation {...props} />);
    fireEvent.click(screen.getByRole('button'));
    await screen.findByRole('region', { name: 'Linked operation result' });
    owner = async () =>
      Response.json({ title: 'PRIVATE-KEY-CANARY', operation: result().operation }, { status });
    fireEvent.click(screen.getByRole('button'));
    expect(
      screen.queryByRole('region', { name: 'Linked operation result' }),
    ).not.toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent('unavailable in the current context'),
    );
    expect(document.body.textContent).not.toContain('PRIVATE-KEY-CANARY');
    expect(document.body.textContent).not.toContain(id(7));
  },
);
it.each(['actor', 'evidence', 'extra', 'raw-operation'])(
  'rejects an unbound or over-disclosing response: %s',
  async (kind) => {
    owner = async () =>
      Response.json({
        ...result(),
        ...(kind === 'actor' ? { actorKey: `sha256:${'c'.repeat(64)}` } : {}),
        ...(kind === 'evidence' ? { evidenceId: ref(99) } : {}),
        ...(kind === 'extra' ? { private: 'PRIVATE-KEY-CANARY' } : {}),
        ...(kind === 'raw-operation'
          ? { operation: { ...result().operation, idempotencyKey: 'PRIVATE-KEY-CANARY' } }
          : {}),
      });
    render(<EvidenceOperationCorrelation {...props} />);
    fireEvent.click(screen.getByRole('button'));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('unavailable'));
    expect(
      screen.queryByRole('region', { name: 'Linked operation result' }),
    ).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain('PRIVATE-KEY-CANARY');
  },
);
it('cancels on actor/evidence change and ignores a late successful response', async () => {
  let finish!: (value: Response) => void;
  owner = () =>
    new Promise((resolve) => {
      finish = resolve;
    });
  const mounted = render(<EvidenceOperationCorrelation {...props} />);
  fireEvent.click(screen.getByRole('button'));
  mounted.rerender(
    <EvidenceOperationCorrelation evidenceId={ref(99)} actorKey={`sha256:${'c'.repeat(64)}`} />,
  );
  expect(calls[0]!.init.signal!.aborted).toBe(true);
  await act(async () => {
    finish(Response.json(result()));
  });
  expect(screen.queryByRole('region', { name: 'Linked operation result' })).not.toBeInTheDocument();
  expect(screen.getByRole('button')).toBeEnabled();
});
it('clears on blur, aborts pending reads and does not retain stale status after re-entry', async () => {
  render(<EvidenceOperationCorrelation {...props} />);
  fireEvent.click(screen.getByRole('button'));
  await screen.findByRole('region', { name: 'Linked operation result' });
  fireEvent(window, new Event('blur'));
  expect(screen.queryByRole('region', { name: 'Linked operation result' })).not.toBeInTheDocument();
  let finish!: (value: Response) => void;
  owner = () =>
    new Promise((resolve) => {
      finish = resolve;
    });
  fireEvent.click(screen.getByRole('button'));
  fireEvent(window, new Event('blur'));
  expect(calls.at(-1)!.init.signal!.aborted).toBe(true);
  await act(async () => {
    finish(Response.json(result()));
  });
  expect(screen.queryByRole('region', { name: 'Linked operation result' })).not.toBeInTheDocument();
});
it('coalesces repeated clicks and safely rereads after a lost GET response', async () => {
  let fail!: (error: Error) => void;
  owner = () =>
    new Promise((_resolve, reject) => {
      fail = reject;
    });
  render(<EvidenceOperationCorrelation {...props} />);
  fireEvent.click(screen.getByRole('button'));
  fireEvent.click(screen.getByRole('button'));
  expect(calls).toHaveLength(1);
  await act(async () => {
    fail(new Error('PRIVATE-KEY-CANARY'));
  });
  expect(screen.getByRole('status')).toHaveTextContent('unavailable');
  expect(document.body.textContent).not.toContain('PRIVATE-KEY-CANARY');
  owner = async () =>
    Response.json({
      ...result(),
      operation: { ...result().operation, state: 'WRITE_AMBIGUITY', truthState: 'WRITE_AMBIGUITY' },
    });
  fireEvent.click(screen.getByRole('button'));
  expect(await screen.findByRole('region', { name: 'Linked operation result' })).toHaveTextContent(
    'WRITE_AMBIGUITY / WRITE_AMBIGUITY',
  );
  expect(calls.every(({ init }) => init.method === 'GET')).toBe(true);
});
