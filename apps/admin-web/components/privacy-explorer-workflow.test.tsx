import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { PrivacyExplorerWorkflow } from './privacy-explorer-workflow';
import { privacyExplorerProfileFacts } from '../../../tests/privacy/i07-gate2-contract-fixture';
import { safeProblemForCondition } from '../../../services/control-api/src/privacy-explorer/problems';

vi.mock('./local-session', () => ({ LocalSessionSurface: () => null }));
const id = '018f0000-0000-7000-8000-000000000401';
const { registrationId: _, ...profile } = privacyExplorerProfileFacts(id);
void _;
const actorKey = `sha256:${'a'.repeat(64)}`;
const view = {
  actorKey,
  actor: { participantId: 'participant-a', privacyDomainId: 'privacy-a' },
  profile: {
    registrationId: `urn:openpc:resource:${id}`,
    state: 'REGISTERED',
    profile: {
      ...profile,
      sourceBinding: { productId: 'Test Explorer' },
      operationVersions: [
        {
          operationId: 'PXI-READ-GOVERNED-PROJECTION/v1',
          acceptedDataClassIds: ['CLASS-READ'],
        },
      ],
    },
  },
};
const output = (occurrenceId: string) => ({
  actorKey,
  occurrenceId,
  result: {
    outcome: 'PARTIAL',
    records: [{ id: 'per1.opaque', fields: [{ fieldId: 'PEF-A', value: 'protected-canary' }] }],
    page: { cursor: `pec1.${'b'.repeat(43)}`, gapFree: false },
  },
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
async function fill(evaluationUi = false) {
  const user = userEvent.setup();
  if (evaluationUi) await screen.findByRole('button', { name: 'Workspace details' });
  else
    await screen.findByText(
      'Enter the registered profile reference from its approved registration.',
    );
  await user.type(
    screen.getByLabelText('Registered profile reference'),
    `urn:openpc:resource:${id}`,
  );
  await user.click(screen.getByRole('button', { name: 'Load profile' }));
  await screen.findByText('Test Explorer — REGISTERED');
  await user.type(screen.getByLabelText('Purpose'), 'audit');
  await user.selectOptions(screen.getByLabelText('Data class'), 'CLASS-READ');
  await user.click(screen.getByRole('checkbox', { name: 'PEF-A' }));
  return user;
}
it.each([false, true])(
  'clears released data and continuation when intent changes with product presentation %s',
  async (evaluationUi) => {
    const fetch = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method !== 'POST')
        return Response.json(
          String(_url).includes('profileRef=') ? view : { ...view, profile: null },
        );
      const body = JSON.parse(init.body as string);
      expect(body).toMatchObject({
        actorKey,
        purpose: 'audit',
        dataClassId: 'CLASS-READ',
        projectionFields: ['PEF-A'],
        filters: [],
        cursor: null,
      });
      expect(body).not.toHaveProperty('authorizationDigest');
      return Response.json(output(body.occurrenceId));
    });
    vi.stubGlobal('fetch', fetch);
    render(<PrivacyExplorerWorkflow evaluationUi={evaluationUi} />);
    const user = await fill(evaluationUi);
    await user.click(screen.getByRole('button', { name: 'Read projection' }));
    await screen.findByText('"protected-canary"');
    expect(screen.getByRole('button', { name: 'Read next page' })).toBeEnabled();
    await user.type(screen.getByLabelText('Purpose'), '-different');
    expect(screen.queryByText('"protected-canary"')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Read next page' })).toBeDisabled();
  },
);
it.each([false, true])(
  'aborts a late protected response after focus loss with product presentation %s',
  async (evaluationUi) => {
    let resolve!: (value: Response) => void;
    let requested = '';
    let signal: AbortSignal | undefined;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method !== 'POST')
          return Response.json(
            String(_url).includes('profileRef=') ? view : { ...view, profile: null },
          );
        requested = JSON.parse(init.body as string).occurrenceId;
        signal = init.signal ?? undefined;
        return new Promise<Response>((done) => {
          resolve = done;
        });
      }),
    );
    render(<PrivacyExplorerWorkflow evaluationUi={evaluationUi} />);
    const user = await fill(evaluationUi);
    await user.click(screen.getByRole('button', { name: 'Read projection' }));
    await waitFor(() => expect(requested).not.toBe(''));
    fireEvent.blur(window);
    expect(signal?.aborted).toBe(true);
    await act(async () => {
      resolve(Response.json(output(requested)));
    });
    expect(screen.queryByText('"protected-canary"')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Read next page' })).toBeDisabled();
  },
);

it('reveals the projection only after a registered profile and preserves intent during inspection', async () => {
  const fetcher = vi.fn(async (url: RequestInfo | URL) =>
    Response.json(String(url).includes('profileRef=') ? view : { ...view, profile: null }),
  );
  vi.stubGlobal('fetch', fetcher);
  render(<PrivacyExplorerWorkflow evaluationUi showSessionControls={false} />);
  await screen.findByRole('button', { name: 'Workspace details' });
  expect(screen.getByRole('status')).toBeEmptyDOMElement();
  expect(screen.queryByRole('button', { name: 'Read projection' })).toBeNull();
  expect(screen.getByLabelText('Purpose')).toBeDisabled();
  const user = await fill(true);
  expect(screen.getByRole('button', { name: 'Read projection' })).toBeVisible();
  expect(screen.getByText(view.actor.participantId)).not.toBeVisible();
  const reads = fetcher.mock.calls.length;
  await user.click(screen.getByRole('button', { name: 'Workspace details' }));
  expect(screen.getByText(view.actor.participantId)).toBeVisible();
  fireEvent(
    screen.getByRole('dialog', { name: 'Workspace details' }),
    new Event('cancel', { cancelable: true }),
  );
  expect(screen.getByRole('button', { name: 'Workspace details' })).toHaveFocus();
  await user.click(screen.getByRole('button', { name: 'Check an earlier request' }));
  fireEvent(
    screen.getByRole('dialog', { name: 'Check an earlier request' }),
    new Event('cancel', { cancelable: true }),
  );
  expect(screen.getByRole('button', { name: 'Check an earlier request' })).toHaveFocus();
  expect(screen.getByLabelText('Purpose')).toHaveValue('audit');
  expect(screen.getByRole('checkbox', { name: 'PEF-A' })).toBeChecked();
  expect(fetcher.mock.calls).toHaveLength(reads);
});

it('renders the canonical rejected-purpose problem and clears prior protected data', async () => {
  const problem = safeProblemForCondition('EXP-ENVELOPE');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method !== 'POST')
        return Response.json(
          String(url).includes('profileRef=') ? view : { ...view, profile: null },
        );
      const body = JSON.parse(init.body as string);
      return body.purpose === 'audit'
        ? Response.json(output(body.occurrenceId))
        : Response.json(problem, { status: problem.httpStatus });
    }),
  );
  render(<PrivacyExplorerWorkflow />);
  const user = await fill();
  await user.click(screen.getByRole('button', { name: 'Read projection' }));
  await screen.findByText('"protected-canary"');
  await user.type(screen.getByLabelText('Purpose'), '-unauthorized');
  await user.click(screen.getByRole('button', { name: 'Read projection' }));
  await waitFor(() =>
    expect(screen.getByRole('status')).toHaveTextContent(
      `${problem.publicTitle} (${problem.code})`,
    ),
  );
  expect(screen.queryByText('"protected-canary"')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Read next page' })).toBeDisabled();
});
