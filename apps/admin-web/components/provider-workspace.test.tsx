import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SetupWorkflow } from './setup-workflow';

const actor = {
  sessionId: '018f0000-0000-7000-8000-000000000111',
  principalId: '018f0000-0000-7000-8000-000000000112',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '2',
};
const platform = {
  ...actor,
  enabled: true,
  authenticated: true,
  role: 'viewer',
  contextMode: 'PLATFORM',
  availableContexts: [
    { participantId: actor.participantId, privacyDomainId: actor.privacyDomainId },
  ],
};
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
});

it.each([
  ['signed out', { enabled: true, authenticated: false }],
  ['Platform context', platform],
])('keeps real session controls visible outside provider tools in %s', async (_, session) => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input).includes('/local-session')) return Response.json(session);
    return Response.json({}, { status: 404 });
  });
  render(<SetupWorkflow kind="providers" />);
  const signIn = await screen.findByRole('button', { name: /^(Sign in|Switch account)$/ });
  const tools = screen
    .getByRole('button', { name: 'Register or update a provider' })
    .parentElement!.querySelector('dialog')!;
  expect(signIn).toBeVisible();
  expect(tools.open).toBe(false);
  expect(tools.contains(signIn)).toBe(false);
  if (session.authenticated) {
    const context = await screen.findByRole('button', { name: 'Enter workspace' });
    expect(context).toBeVisible();
    expect(tools.contains(context)).toBe(false);
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeVisible();
  }
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it.each(['confirmed', 'foreign-context', 'uncertain'] as const)(
  'refreshes the native provider directory only for a %s effect in the current workspace',
  async (outcome) => {
    const approvalId = '018f0000-0000-7000-8000-000000000301';
    const before = {
      providerProfileId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000321',
      chainId: '31337',
      state: 'QUALIFIED',
    };
    const added = {
      providerProfileId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000322',
      chainId: '92870',
      state: 'REGISTERED',
      authority: 'NEVER_GRANTS',
      revision: '1',
    };
    let recorded = false;
    let collectionReads = 0;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes('/local-session'))
        return Response.json({ ...platform, contextMode: 'PARTICIPANT' });
      if (url.includes('setup-workbench') && url.includes('?')) {
        collectionReads++;
        return Response.json({
          actor,
          result: {
            items: recorded ? [before, added] : [before],
            nextCursor: null,
            completeness: 'COMPLETE',
            authorizedEmpty: false,
          },
        });
      }
      if (url.includes('?approvalId=')) {
        recorded = true;
        return Response.json({
          actor:
            outcome === 'foreign-context'
              ? { ...actor, privacyDomainId: approvalId, contextEpoch: '3' }
              : actor,
          kind: 'provider-profile',
          operation: {
            operationId: approvalId,
            state: outcome === 'uncertain' ? 'ACCEPTED' : 'SUCCEEDED',
            truthState: outcome === 'uncertain' ? 'UNKNOWN' : 'SUCCESS',
          },
          result: added,
        });
      }
      return Response.json({ actor });
    });
    render(<SetupWorkflow kind="providers" showSessionControls={false} />);
    await screen.findByRole('heading', { name: 'Chain 31337' });
    const beforeReads = collectionReads;
    fireEvent.click(screen.getByRole('button', { name: 'Register or update a provider' }));
    fireEvent.click(screen.getByRole('button', { name: 'Activity' }));
    fireEvent.click(screen.getByRole('button', { name: 'Recover an existing request' }));
    fireEvent.change(screen.getByLabelText('Approval ID'), { target: { value: approvalId } });
    fireEvent.click(screen.getByRole('button', { name: 'Read approval and result' }));
    if (outcome === 'confirmed') {
      await screen.findByRole('heading', { name: 'Chain 92870' });
      expect(screen.getByRole('heading', { name: 'Chain 31337' })).toBeVisible();
      expect(collectionReads).toBe(beforeReads + 1);
    } else {
      if (outcome === 'foreign-context')
        await screen.findByRole('button', { name: 'Refresh workspace' });
      else await screen.findByText(/Operation state: Accepted for processing/);
      expect(screen.queryByRole('heading', { name: 'Chain 92870' })).toBeNull();
      expect(collectionReads).toBe(beforeReads);
    }
    expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
  },
);

it('preserves expanded provider tools and unsent inputs across same-actor focus readback', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.includes('/local-session'))
      return Response.json({ ...platform, contextMode: 'PARTICIPANT' });
    if (url.includes('setup-workbench') && url.includes('?'))
      return Response.json({
        actor,
        result: { items: [], nextCursor: null, completeness: 'COMPLETE', authorizedEmpty: true },
      });
    return Response.json({ actor });
  });
  render(<SetupWorkflow kind="providers" />);
  await screen.findByText('No authorized records.');
  const summary = screen.getByRole('button', { name: 'Register or update a provider' });
  const tools = summary.parentElement!.querySelector('dialog')!;
  fireEvent.click(summary);
  const chain = await screen.findByLabelText('Chain ID');
  fireEvent.change(chain, { target: { value: '92870' } });
  const before = fetcher.mock.calls.length;
  fireEvent.focus(window);
  await waitFor(() => expect(fetcher.mock.calls.length).toBeGreaterThan(before));
  await screen.findByText('No authorized records.');
  expect(tools.open).toBe(true);
  expect(screen.getByLabelText('Chain ID')).toBe(chain);
  expect(chain).toHaveValue('92870');
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});
