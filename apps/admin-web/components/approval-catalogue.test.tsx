import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { ApprovalCatalogue } from './approval-catalogue';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
const actor = {
  sessionId: '018f0000-0000-7000-8000-000000000001',
  principalId: '018f0000-0000-7000-8000-000000000002',
  participantId: '018f0000-0000-7000-8000-000000000003',
  privacyDomainId: '018f0000-0000-7000-8000-000000000004',
  contextEpoch: '2',
};
const ref = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000101';
const item = {
  approvalRequestId: ref,
  actionIntentId: 'ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1',
  kinds: ['evidence-export'],
  state: 'APPROVED',
  relationship: 'MAKER',
  revision: '1',
  createdAt: '2026-09-20T00:00:00.000000Z',
  updatedAt: '2026-09-21T00:00:00.000000Z',
};
const page = {
  actor,
  items: [item],
  nextCursor: null,
  total: '1',
  completeness: 'COMPLETE',
  authorizedEmpty: false,
  snapshotRevision: '4',
};
function mount(onSelect = vi.fn()) {
  render(
    <ApprovalCatalogue
      actor={actor}
      supportedKinds={['evidence-export', 'evidence-deletion-search']}
      onSelect={onSelect}
    />,
  );
  return onSelect;
}

it('selects an authorized request without creating a business command and keeps IDs secondary', async () => {
  const fetch = vi.fn(async (_url: string, _options?: RequestInit) => Response.json(page));
  vi.stubGlobal('fetch', fetch);
  const user = userEvent.setup(),
    onSelect = mount();
  const review = await screen.findByRole('button', { name: `Review request ${ref.slice(-36)}` });
  expect(review).toHaveTextContent('Review request');
  expect(review).not.toHaveTextContent(ref.slice(-36));
  expect(screen.getByText('Approved')).toBeVisible();
  expect(screen.getByText('Submitted by you')).toBeVisible();
  expect(screen.getByText(`Ref …${ref.slice(-12)}`)).toBeVisible();
  expect(screen.getByText(ref)).not.toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Request reference', hidden: true }));
  expect(screen.getByText(ref)).toBeVisible();
  await user.click(review);
  expect(onSelect).toHaveBeenCalledWith(ref.slice(-36));
  expect(fetch).toHaveBeenCalledOnce();
  expect(fetch.mock.calls[0]?.[0]).toBe('/api/v1/ui/transaction-workbench?approvals=1');
});

it('marks only the request confirmed by its owning reader as the current selection', async () => {
  const otherRef = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000102';
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      Response.json({
        ...page,
        items: [item, { ...item, approvalRequestId: otherRef }],
        total: '2',
      }),
    ),
  );
  const { rerender } = render(
    <ApprovalCatalogue actor={actor} supportedKinds={['evidence-export']} onSelect={vi.fn()} />,
  );
  const first = await screen.findByRole('button', { name: `Review request ${ref.slice(-36)}` });
  expect(screen.queryByText('Viewing')).toBeNull();
  fireEvent.click(first);
  expect(screen.queryByText('Viewing')).toBeNull();
  rerender(
    <ApprovalCatalogue
      actor={actor}
      supportedKinds={['evidence-export']}
      selectedApprovalId={otherRef}
      onSelect={vi.fn()}
    />,
  );
  expect(first).not.toHaveAttribute('aria-current');
  expect(
    screen.getByRole('button', { name: `Review request ${otherRef.slice(-36)}` }),
  ).toHaveAttribute('aria-current', 'true');
  expect(screen.getByText('Viewing')).toBeVisible();
  fireEvent.blur(window);
  expect(screen.queryByText('Viewing')).toBeNull();
});

it('does not mistake shared deletion actions for one particular data category', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      Response.json({
        ...page,
        items: [{ ...item, kinds: ['evidence-deletion-normalized', 'evidence-deletion-search'] }],
      }),
    ),
  );
  mount();
  expect(await screen.findByText('Evidence removal request')).toBeVisible();
  expect(screen.queryByText('Delete normalized projections')).toBeNull();
});

it.each([401, 403, 409, 500, 503])(
  'keeps HTTP %s distinct from an authorized empty result',
  async (status) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json({ secret: 'must not render' }, { status })),
    );
    mount();
    expect(
      await screen.findByText('Requests could not be confirmed. Refresh the list to try again.'),
    ).toBeVisible();
    expect(screen.queryByText(/No authorized requests/u)).toBeNull();
    expect(screen.queryByText('must not render')).toBeNull();
  },
);

it.each([
  { ...page, actor: { ...actor, participantId: '018f0000-0000-7000-8000-000000000005' } },
  { ...page, actor: { ...actor, privacyDomainId: '018f0000-0000-7000-8000-000000000005' } },
  { ...page, actor: { ...actor, contextEpoch: '3' } },
  { ...page, items: [item, item] },
  { ...page, authorizedEmpty: true },
  { ...page, items: [{ ...item, state: 'SUCCEEDED' }] },
])('rejects stale or malformed catalogue metadata', async (value) => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json(value)),
  );
  mount();
  await waitFor(() => expect(screen.getByRole('status')).not.toHaveTextContent('Loading'));
  expect(screen.queryByRole('button', { name: `Review request ${ref.slice(-36)}` })).toBeNull();
});

it('renders a native authorized empty page and does not turn unknown coverage into complete coverage', async () => {
  const fetch = vi.fn(async () =>
    Response.json({ ...page, items: [], total: '0', authorizedEmpty: true }),
  );
  vi.stubGlobal('fetch', fetch);
  mount();
  expect(await screen.findByText('No authorized requests in this snapshot.')).toBeVisible();
  fetch.mockImplementation(async () =>
    Response.json({
      ...page,
      items: [],
      total: null,
      authorizedEmpty: true,
      completeness: 'UNKNOWN',
    }),
  );
  fireEvent.click(screen.getByRole('button', { name: 'Refresh requests' }));
  expect(
    await screen.findByText('No requests returned. Coverage could not be confirmed.'),
  ).toBeVisible();
});

it('preserves native order across local pages and forwards only the actual cursor', async () => {
  const items = Array.from({ length: 13 }, (_, n) => ({
    ...item,
    approvalRequestId: `urn:openpc:resource:018f0000-0000-7000-8000-${String(101 + n).padStart(12, '0')}`,
  }));
  const fetch = vi.fn(async (url: string) =>
    Response.json(
      url.includes('approvalsCursor=')
        ? { ...page, items: [], total: '0', authorizedEmpty: true }
        : { ...page, items, total: '13', nextCursor: 'opaque-native-cursor' },
    ),
  );
  vi.stubGlobal('fetch', fetch);
  mount();
  const region = await screen.findByRole('region', { name: 'Recent authorized requests' });
  await within(region).findByRole('button', { name: `Review request ${ref.slice(-36)}` });
  const seen = [];
  for (let n = 0; n < 3; n++) {
    seen.push(
      ...within(region)
        .getAllByRole('button', { name: /^Review request /u })
        .map((button) => button.getAttribute('aria-label')),
    );
    if (n < 2) {
      expect(screen.getByRole('button', { name: 'Next requests' })).toBeDisabled();
      fireEvent.click(screen.getByRole('button', { name: 'Next displayed requests' }));
    }
  }
  expect(seen).toEqual(
    items.map((record) => `Review request ${record.approvalRequestId.slice(-36)}`),
  );
  expect(fetch).toHaveBeenCalledOnce();
  expect(screen.getByRole('button', { name: 'Next requests' })).toBeEnabled();
  fireEvent.click(screen.getByRole('button', { name: 'Next requests' }));
  expect(await screen.findByText('No authorized requests in this snapshot.')).toBeVisible();
  expect(fetch.mock.calls[1]?.[0]).toBe(
    '/api/v1/ui/transaction-workbench?approvals=1&approvalsCursor=opaque-native-cursor',
  );
});

it('clears private rows on blur and rejects the delayed response from a prior actor', async () => {
  const completions: ((value: Response) => void)[] = [];
  const fetch = vi.fn(async () => Response.json(page));
  vi.stubGlobal('fetch', fetch);
  const { rerender } = render(
    <ApprovalCatalogue actor={actor} supportedKinds={['evidence-export']} onSelect={vi.fn()} />,
  );
  await screen.findByText('Submitted by you');
  fireEvent.blur(window);
  expect(screen.queryByText('Submitted by you')).toBeNull();
  fetch.mockImplementation(
    () =>
      new Promise<Response>((resolve) => {
        completions.push(resolve);
      }),
  );
  fireEvent.focus(window);
  rerender(
    <ApprovalCatalogue
      actor={{ ...actor, contextEpoch: '3' }}
      supportedKinds={['evidence-export']}
      onSelect={vi.fn()}
    />,
  );
  await act(async () => {
    completions[0]?.(Response.json(page));
  });
  expect(screen.queryByText('Submitted by you')).toBeNull();
  await act(async () => {
    completions[1]?.(
      Response.json({
        ...page,
        actor: { ...actor, contextEpoch: '3' },
        items: [
          {
            ...item,
            approvalRequestId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000102',
          },
        ],
      }),
    );
  });
  expect(
    await screen.findByRole('button', {
      name: 'Review request 018f0000-0000-7000-8000-000000000102',
    }),
  ).toBeVisible();
});

it('retains unsupported request metadata without offering an invalid workflow selection', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json({ ...page, items: [{ ...item, kinds: [] }] })),
  );
  mount();
  expect(await screen.findByText('Other request')).toBeVisible();
  expect(screen.getByText('Open this request in its owning workspace.')).toBeVisible();
  expect(screen.queryByRole('button', { name: /^Review request /u })).toBeNull();
});
