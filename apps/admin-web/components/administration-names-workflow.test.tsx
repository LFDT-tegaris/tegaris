import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import { AdministrationNamesWorkflow } from './administration-names-workflow';
const actor = {
  participantId: 'participant-a',
  privacyDomainId: 'privacy-a',
  principalId: 'maker',
};
const storage = 'openpc:administration-names:v1:participant-a:privacy-a:maker';
afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.unstubAllGlobals();
});
describe('finite name restoration', () => {
  it('allows fresh planning when a previously saved name is unavailable without creating business state', async () => {
    localStorage.setItem(storage, JSON.stringify(['old-operation']));
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ actor }))
      .mockResolvedValueOnce(Response.json({ code: 'PC-POLICY-2001' }, { status: 404 }));
    vi.stubGlobal('fetch', fetch);
    render(<AdministrationNamesWorkflow />);
    expect(
      await screen.findByText(
        '1 saved names are no longer available. Reserve fresh names for new intent.',
      ),
    ).toBeVisible();
    expect(screen.getByRole('button', { name: 'Reserve reference' })).toBeEnabled();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls.every(([, options]) => !options.method)).toBe(true);
  });
  it.each([403, 500])('keeps planning disabled after a %s read failure', async (status) => {
    localStorage.setItem(storage, JSON.stringify(['old-operation']));
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValueOnce(Response.json({ actor }))
        .mockResolvedValueOnce(Response.json({ code: 'PC-AUTH-0005' }, { status })),
    );
    render(<AdministrationNamesWorkflow />);
    await screen.findByText('Name reservation unavailable. (PC-AUTH-0005)');
    expect(screen.getByRole('button', { name: 'Reserve reference' })).toBeDisabled();
  });
});

it('keeps an unused reservation reference when its review dialog closes and submits it only with the form', async () => {
  const fetcher = vi.fn(async (_input: unknown, options?: RequestInit) =>
    options?.method === 'POST'
      ? Response.json({ title: 'Reservation service unavailable.' }, { status: 503 })
      : Response.json({ actor }),
  );
  vi.stubGlobal('fetch', fetcher);
  const user = userEvent.setup();
  render(<AdministrationNamesWorkflow />);
  const submit = await screen.findByRole('button', { name: 'Reserve reference' });
  await waitFor(() => expect(submit).toBeEnabled());
  const previous = screen.getByLabelText('Previous reservation operation ID (optional)');
  expect(previous).not.toBeVisible();
  const disclosure = screen.getByRole('button', { name: 'Renew an unused reservation' });
  await user.click(disclosure);
  expect(screen.getByRole('dialog', { name: 'Renew an unused reservation' })).toBeVisible();
  await user.type(previous, 'original-unused-reservation');
  await user.click(screen.getByRole('button', { name: 'Close Renew an unused reservation' }));
  expect(previous).not.toBeVisible();
  expect(disclosure).toHaveFocus();
  expect(previous).toHaveValue('original-unused-reservation');
  expect(fetcher.mock.calls.every(([, options]) => !options?.method)).toBe(true);
  await user.type(
    screen.getByLabelText('Exact business action ID'),
    'ACT-POLICY_CREATE_APPROVAL_REQUEST-V1',
  );
  await user.type(
    screen.getByLabelText('Exact business resource ID'),
    '018f0000-0000-7000-8000-000000000001',
  );
  await user.type(screen.getByLabelText('Expected business revision'), '1');
  await user.click(submit);
  await waitFor(() =>
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1),
  );
  const call = fetcher.mock.calls.find(([, options]) => options?.method === 'POST');
  expect(JSON.parse(String(call?.[1]?.body))).toEqual(
    expect.objectContaining({
      command: 'RESERVE',
      predecessorOperationId: 'original-unused-reservation',
      purpose: 'APPROVAL_REQUEST',
      businessActionIntentId: 'ACT-POLICY_CREATE_APPROVAL_REQUEST-V1',
      businessResourceId: '018f0000-0000-7000-8000-000000000001',
      expectedBusinessRevision: '1',
    }),
  );
  await screen.findByText(/Reservation service unavailable/);
  expect(previous).toHaveValue('original-unused-reservation');
});
