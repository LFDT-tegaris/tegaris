import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
const stepUp = vi.hoisted(() => vi.fn());
vi.mock('@openpc/ui-shell', async (original) => ({
  ...(await original<object>()),
  performWebAuthnStepUp: stepUp,
}));
import { PolicySimulationAuthority } from './policy-simulation-authority';
import { participantAction } from '../lib/participant-action';
const actor = {
  sessionId: 'session',
  principalId: 'operator',
  contextEpoch: '1',
  contextMode: 'PARTICIPANT',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: 'privacy',
} as const;
const option = {
  assignmentId: '018f0000-0000-7000-8000-000000000111',
  envelopeId: '018f0000-0000-7000-8000-000000000112',
  principalId: '018f0000-0000-7000-8000-000000000113',
  roleId: 'reader',
  workloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000000114',
};
const proof = {
  actionIntentId: participantAction.id,
  actionIntentDigest: participantAction.digest,
  resourceId: actor.participantId,
  resourceDigest: `sha256:${'b'.repeat(64)}`,
};
const catalogue = (extra = {}) => ({
  actor,
  modules: { simulationAuthorities: [option] },
  workloads: [{ effect: { principalId: option.principalId, displayLabel: 'Treasury reader' } }],
  ...extra,
});
const onChange = vi.fn();
beforeEach(() => {
  vi.resetAllMocks();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
function reads(load: () => Promise<Response>) {
  const fetcher = vi.fn((url: string) =>
    url === '/api/v1/ui/local-session'
      ? Promise.resolve(Response.json({ ...actor, authenticated: true }))
      : load(),
  );
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}
it('shows unavailable state and lets the user recover without refreshing the whole page', async () => {
  const next = vi
    .fn()
    .mockResolvedValueOnce(new Response('', { status: 503 }))
    .mockResolvedValue(Response.json(catalogue()));
  reads(next);
  render(<PolicySimulationAuthority actor={actor} contextKey="one" onChange={onChange} />);
  await screen.findByText('Workload assignments could not be loaded. Refresh to try again.');
  expect(screen.getByLabelText('Workload')).toBeDisabled();
  await userEvent.click(screen.getByRole('button', { name: 'Refresh workload assignments' }));
  await waitFor(() =>
    expect(onChange).toHaveBeenLastCalledWith(option.workloadId, option.assignmentId),
  );
  expect(screen.getByRole('option', { name: /^Treasury reader ·/ })).toHaveValue(option.workloadId);
});
it('requires real authenticator verification before loading protected options', async () => {
  reads(
    vi
      .fn()
      .mockResolvedValueOnce(Response.json(catalogue({ requiresStepUp: proof })))
      .mockResolvedValue(Response.json(catalogue())),
  );
  render(<PolicySimulationAuthority actor={actor} contextKey="one" onChange={onChange} />);
  const button = await screen.findByRole('button', {
    name: 'Verify authenticator and load assignments',
  });
  expect(screen.getByLabelText('Workload')).toBeDisabled();
  await userEvent.click(button);
  await waitFor(() =>
    expect(onChange).toHaveBeenLastCalledWith(option.workloadId, option.assignmentId),
  );
  expect(stepUp).toHaveBeenCalledWith(
    { ...proof, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
    { resourceId: proof.resourceId, resourceDigest: proof.resourceDigest },
    expect.objectContaining({ isCurrent: expect.any(Function) }),
  );
});
it('requires an explicit assignment when more than one is eligible', async () => {
  const other = { ...option, assignmentId: '018f0000-0000-7000-8000-000000000115' };
  reads(async () =>
    Response.json(catalogue({ modules: { simulationAuthorities: [option, other] } })),
  );
  render(<PolicySimulationAuthority actor={actor} contextKey="one" onChange={onChange} />);
  await screen.findByText('Choose the workload and exact assignment to evaluate.');
  expect(onChange).toHaveBeenLastCalledWith('', '');
  await userEvent.selectOptions(screen.getByLabelText('Workload'), option.workloadId);
  expect(onChange).toHaveBeenLastCalledWith(option.workloadId, '');
  await userEvent.selectOptions(screen.getByLabelText('Role assignment'), other.assignmentId);
  expect(onChange).toHaveBeenLastCalledWith(option.workloadId, other.assignmentId);
});
it('uses display names as text and retains exact selected references', async () => {
  const label = '<img src=x onerror=alert(1)> Treasury';
  reads(async () =>
    Response.json(
      catalogue({
        workloads: undefined,
        modules: {
          simulationAuthorities: [
            {
              ...option,
              workloadDisplayLabel: label,
              roleDisplayName: 'Treasury read access',
            },
          ],
        },
      }),
    ),
  );
  render(<PolicySimulationAuthority actor={actor} contextKey="one" onChange={onChange} />);
  const application = await screen.findByRole('option', { name: new RegExp('Treasury ·') });
  expect(application).toHaveTextContent(label);
  expect(application).toHaveValue(option.workloadId);
  expect(screen.queryByRole('img')).not.toBeInTheDocument();
  expect(screen.getByRole('option', { name: /^Treasury read access ·/ })).toHaveValue(
    option.assignmentId,
  );
  expect(onChange).toHaveBeenLastCalledWith(option.workloadId, option.assignmentId);
  await userEvent.click(screen.getByRole('button', { name: 'Access references' }));
  const references = screen.getByRole('dialog', { name: 'Access references' });
  expect(references).toHaveTextContent(option.workloadId);
  expect(references).toHaveTextContent(option.assignmentId);
  expect(references).toHaveTextContent(option.roleId);
});
it('disambiguates duplicate assignment names even when their short reference suffixes collide', async () => {
  const first = {
    ...option,
    assignmentId: '018f0000-0000-7000-8000-aaa01234abcd',
    roleDisplayName: 'Treasury reader',
  };
  const second = { ...first, assignmentId: '018f0000-0000-7000-8000-bbb01234abcd' };
  reads(async () =>
    Response.json(catalogue({ modules: { simulationAuthorities: [first, second] } })),
  );
  render(<PolicySimulationAuthority actor={actor} contextKey="one" onChange={onChange} />);
  await screen.findByText('Choose the workload and exact assignment to evaluate.');
  await userEvent.selectOptions(screen.getByLabelText('Workload'), option.workloadId);
  expect(screen.getByRole('option', { name: 'Treasury reader · …aaa01234abcd' })).toHaveValue(
    first.assignmentId,
  );
  const choice = screen.getByRole('option', { name: 'Treasury reader · …bbb01234abcd' });
  await userEvent.selectOptions(screen.getByLabelText('Role assignment'), choice);
  expect(onChange).toHaveBeenLastCalledWith(option.workloadId, second.assignmentId);
});
it('keeps identically named workloads distinguishable and clears their names on a context change', async () => {
  const first = {
    ...option,
    workloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-aaa01234abcd',
    workloadDisplayLabel: 'Treasury application',
  };
  const second = {
    ...first,
    workloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-bbb01234abcd',
    assignmentId: '018f0000-0000-7000-8000-000000000115',
  };
  reads(async () =>
    Response.json(catalogue({ modules: { simulationAuthorities: [first, second] } })),
  );
  const view = render(
    <PolicySimulationAuthority actor={actor} contextKey="one" onChange={onChange} />,
  );
  const choice = await screen.findByRole('option', {
    name: 'Treasury application · …bbb01234abcd',
  });
  expect(screen.getByRole('option', { name: 'Treasury application · …aaa01234abcd' })).toHaveValue(
    first.workloadId,
  );
  await userEvent.selectOptions(screen.getByLabelText('Workload'), choice);
  expect(onChange).toHaveBeenLastCalledWith(second.workloadId, second.assignmentId);
  view.rerender(
    <PolicySimulationAuthority actor={undefined} contextKey="two" onChange={onChange} />,
  );
  await waitFor(() => expect(onChange).toHaveBeenLastCalledWith('', ''));
  expect(screen.queryByRole('option', { name: /Treasury application/ })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Access references' })).not.toBeInTheDocument();
});
it('keeps an older catalogue usable without display metadata or directory results', async () => {
  reads(async () => Response.json(catalogue({ workloads: undefined })));
  render(<PolicySimulationAuthority actor={actor} contextKey="one" onChange={onChange} />);
  expect(await screen.findByRole('option', { name: 'Workload · …00000114' })).toHaveValue(
    option.workloadId,
  );
  expect(screen.getByRole('option', { name: 'Role assignment · …00000111' })).toHaveValue(
    option.assignmentId,
  );
  expect(onChange).toHaveBeenLastCalledWith(option.workloadId, option.assignmentId);
});
it.each([
  { workloadDisplayLabel: 'x'.repeat(161) },
  { roleDisplayName: 'x'.repeat(161) },
  { workloadDisplayLabel: 42 },
  { roleDisplayName: '' },
])('rejects malformed display metadata without exposing stale choices: %j', async (change) => {
  reads(async () =>
    Response.json(catalogue({ modules: { simulationAuthorities: [{ ...option, ...change }] } })),
  );
  render(<PolicySimulationAuthority actor={actor} contextKey="one" onChange={onChange} />);
  await screen.findByText('Workload assignments could not be loaded. Refresh to try again.');
  expect(screen.getByLabelText('Workload')).toBeDisabled();
  expect(onChange).toHaveBeenLastCalledWith('', '');
});
it.each(['foreign actor', 'malformed', 'foreign proof', 'wrong action', 'wrong digest'])(
  'rejects %s catalogues',
  async (defect) => {
    const value =
      defect === 'foreign actor'
        ? catalogue({ actor: { ...actor, privacyDomainId: 'foreign' } })
        : defect === 'wrong action'
          ? catalogue({
              requiresStepUp: { ...proof, actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1' },
            })
          : defect === 'wrong digest'
            ? catalogue({
                requiresStepUp: { ...proof, actionIntentDigest: `sha256:${'a'.repeat(64)}` },
              })
            : defect === 'foreign proof'
              ? catalogue({
                  requiresStepUp: { ...proof, resourceId: '018f0000-0000-7000-8000-000000000999' },
                })
              : {};
    reads(async () => Response.json(value));
    render(<PolicySimulationAuthority actor={actor} contextKey="one" onChange={onChange} />);
    await screen.findByText('Workload assignments could not be loaded. Refresh to try again.');
    expect(onChange).toHaveBeenLastCalledWith('', '');
    expect(stepUp).not.toHaveBeenCalled();
  },
);
it('drops a late catalogue when its context changes', async () => {
  let resolve!: (value: Response) => void;
  const pending = new Promise<Response>((done) => {
    resolve = done;
  });
  reads(() => pending);
  const view = render(
    <PolicySimulationAuthority actor={actor} contextKey="one" onChange={onChange} />,
  );
  await waitFor(() =>
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('rpc-access-workbench'),
      expect.anything(),
    ),
  );
  view.rerender(
    <PolicySimulationAuthority actor={undefined} contextKey="two" onChange={onChange} />,
  );
  await act(async () => resolve(Response.json(catalogue())));
  expect(onChange).toHaveBeenLastCalledWith('', '');
  expect(screen.getByLabelText('Workload')).toBeDisabled();
});
