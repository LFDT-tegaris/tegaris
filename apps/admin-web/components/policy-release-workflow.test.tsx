import { createHash, webcrypto } from 'node:crypto';

import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { PolicyReleaseWorkflow } from './policy-release-workflow';

vi.mock('@openpc/ui-shell', () => ({ performWebAuthnStepUp: vi.fn() }));
vi.mock('./local-session', () => ({ LocalSessionSurface: () => <p>Sign in</p> }));

beforeEach(() => {
  localStorage.clear();
  vi.stubGlobal('crypto', webcrypto);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

it('lets a scoped maker prepare a release with an explicit checker despite a viewer presentation label', async () => {
  const actor = {
    role: 'viewer',
    sessionId: '018f0000-0000-7000-8000-000000000117',
    principalId: '018f0000-0000-7000-8000-000000008141',
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000007201',
    contextEpoch: '2',
  };
  const details = {
    policyVersionId: '018f0000-0000-7000-8000-000000000921',
    checkerPrincipalId: '018f0000-0000-7000-8000-000000008142',
    manifestDigest: `sha256:${'a1'.repeat(32)}`,
    dependencyClosureDigest: `sha256:${'b2'.repeat(32)}`,
    reason: 'Release the original publicly authored source policy.',
  };
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (String(input).includes('/local-session'))
      return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
    if (init?.method === 'POST') {
      expect(String(input)).toBe('/api/v1/ui/policy-release-workbench');
      return Response.json({ reviewToken: 'a'.repeat(100), review: details });
    }
    return Response.json({ actor });
  });
  const user = userEvent.setup();
  render(<PolicyReleaseWorkflow />);
  await screen.findByRole('heading', { name: 'Review and control policy authority' });
  await user.selectOptions(screen.getByLabelText('Workflow'), 'PREPARE');
  expect(screen.getByLabelText('Checker principal ID')).toHaveValue('');
  for (const [label, value] of [
    ['Policy version ID', details.policyVersionId],
    ['Checker principal ID', details.checkerPrincipalId],
    ['Policy artifact digest', details.manifestDigest],
    ['Dependency closure digest', details.dependencyClosureDigest],
    ['Business reason', details.reason],
  ])
    await user.type(screen.getByLabelText(label!), value!);
  await user.click(screen.getByRole('button', { name: 'Review release details' }));
  await screen.findByRole('heading', { name: 'Release review' });
  expect(screen.getByText(details.checkerPrincipalId)).toBeInTheDocument();
  const mutations = fetchMock.mock.calls.filter((call) => call[1]?.method === 'POST');
  expect(mutations).toHaveLength(1);
  expect(JSON.parse(String(mutations[0]?.[1]?.body))).toEqual({
    command: 'PREVIEW',
    ...details,
  });
  expect(
    screen.queryByRole('button', { name: 'Approve with security key' }),
  ).not.toBeInTheDocument();
  await waitFor(() =>
    expect(screen.getByLabelText('Request type')).toHaveValue('policy-activation-renewal'),
  );
});

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
type Actor = {
  role: 'viewer' | 'operator';
  sessionId: string;
  principalId: string;
  participantId: string;
  privacyDomainId: string;
  contextEpoch: string;
};
const actor: Actor = {
  role: 'viewer',
  sessionId: id(1),
  principalId: id(2),
  participantId: id(3),
  privacyDomainId: id(4),
  contextEpoch: '1',
};
const selectors = { approvalId: id(11), releaseId: id(12), occurrenceId: id(13) };
const digest = `sha256:${'a'.repeat(64)}`;
const originalSaved = {
  review: {
    reviewToken: 's'.repeat(100),
    review: {
      policyVersionId: id(31),
      checkerPrincipalId: id(32),
      manifestDigest: digest,
      dependencyClosureDigest: `sha256:${'b'.repeat(64)}`,
      reason: 'Publish the exact originally approved artifact.',
    },
  },
  ...selectors,
};
const storageKey = 'openpc:policy-release-workflow:v2';
function seed(value: unknown = originalSaved, a = actor) {
  const binding = {
    sessionId: a.sessionId,
    principalId: a.principalId,
    participantId: a.participantId,
    privacyDomainId: a.privacyDomainId,
    contextEpoch: a.contextEpoch,
  };
  const original = JSON.stringify({ actor: binding, value });
  localStorage.setItem(storageKey, original);
  return original;
}
function session(a = actor) {
  return { ...a, authenticated: true, contextMode: 'PARTICIPANT' };
}
function step(resourceId: string) {
  return {
    actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
    actionIntentDigest: digest,
    resourceId,
    resourceDigest: digest,
  };
}
function workbench(selected = selectors, a = actor, occurrenceState = 'ACTIVE_MATCHED') {
  return {
    actor: a,
    ...(selected.approvalId
      ? {
          approval: {
            approvalRequestId: `urn:openpc:resource:${selected.approvalId}`,
            candidateDigest: digest,
            state: 'APPROVED',
            revision: '1',
            makerSubjectRef: `urn:openpc:resource:${id(9)}`,
            checkerSubjectRef: `urn:openpc:resource:${a.principalId}`,
          },
          approvalStepUp: step(selected.approvalId),
        }
      : {}),
    ...(selected.releaseId
      ? {
          release: {
            releaseBundleId: `urn:openpc:resource:${selected.releaseId}`,
            manifestDigest: digest,
            dependencyClosureDigest: digest,
            state: 'DRAFT',
            revision: '1',
          },
          publishStepUp: step(selected.releaseId),
        }
      : {}),
    ...(selected.occurrenceId
      ? {
          occurrence: {
            activationOccurrenceId: `urn:openpc:resource:${selected.occurrenceId}`,
            releaseBundleId: `urn:openpc:resource:${selected.releaseId}`,
            targetGenerationDigest: digest,
            exactCohortDigest: digest,
            state: occurrenceState,
            revision: '1',
          },
          occurrenceStepUp: step(selected.occurrenceId),
        }
      : {}),
  };
}
function deferred<T = Response>() {
  let resolve!: (value: T) => void, reject!: (cause: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
function reads(
  policy: (url: string) => Response | Promise<Response>,
  localSession: () => Response | Promise<Response> = () => Response.json(session()),
) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    if (init?.method === 'POST') throw new Error('Unexpected mutation');
    if (String(url).endsWith('/local-session')) return localSession();
    if (String(url).includes('/policy-release-workbench')) return policy(String(url));
    return Response.json({ actor });
  });
}
async function makerRefresh() {
  const user = userEvent.setup();
  await user.selectOptions(await screen.findByLabelText('Workflow'), 'PREPARE');
  await user.click(screen.getByRole('button', { name: 'Refresh policy workflow' }));
}
it('keeps release preparation inline while workspace inspection preserves the unsent draft', async () => {
  const fetcher = reads(() =>
    Response.json(workbench({ approvalId: '', releaseId: '', occurrenceId: '' })),
  );
  const user = userEvent.setup();
  render(<PolicyReleaseWorkflow evaluationUi showSessionControls={false} />);
  await screen.findByRole('heading', { name: 'Policy workspace' });
  await user.selectOptions(screen.getByLabelText('Workflow'), 'PREPARE');
  await user.type(screen.getByLabelText('Business reason'), 'Publish the reviewed payment policy.');
  expect(screen.getByRole('button', { name: 'Review release details' })).toBeVisible();
  expect(screen.getByText(actor.principalId)).not.toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Workspace details' }));
  const dialog = screen.getByRole('dialog', { name: 'Workspace details' });
  expect(within(dialog).getByText(actor.principalId)).toBeVisible();
  fireEvent(
    screen.getByRole('dialog', { name: 'Workspace details' }),
    new Event('cancel', { cancelable: true }),
  );
  expect(screen.queryByRole('dialog', { name: 'Workspace details' })).toBeNull();
  expect(screen.getByRole('button', { name: 'Workspace details' })).toHaveFocus();
  expect(screen.getByLabelText('Business reason')).toHaveValue(
    'Publish the reviewed payment policy.',
  );
  expect(fetcher.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
});

it('switches policy tasks without unmounting drafts or submitting either request', async () => {
  const fetcher = reads(() =>
    Response.json(workbench({ approvalId: '', releaseId: '', occurrenceId: '' })),
  );
  const user = userEvent.setup();
  const { rerender } = render(<PolicyReleaseWorkflow evaluationUi showSessionControls={false} />);
  await screen.findByRole('heading', { name: 'Policy workspace' });
  await user.selectOptions(screen.getByLabelText('Workflow'), 'PREPARE');
  const reason = screen.getByLabelText('Business reason');
  await user.type(reason, 'Publish the independently reviewed policy.');
  const renewal = await screen.findByLabelText('Request type');
  expect(renewal).not.toBeVisible();
  expect(screen.getByRole('link', { name: 'Releases & approvals' })).toHaveAttribute(
    'aria-current',
    'page',
  );
  expect(screen.getByRole('link', { name: 'Activation renewal' })).toHaveAttribute(
    'href',
    '/govern/policy-releases?view=activation-renewal',
  );
  rerender(
    <PolicyReleaseWorkflow
      evaluationUi
      showSessionControls={false}
      activeTask="activation-renewal"
    />,
  );
  expect(reason).not.toBeVisible();
  expect(renewal).toBeVisible();
  expect(screen.getByRole('link', { name: 'Activation renewal' })).toHaveAttribute(
    'aria-current',
    'page',
  );
  const renewalReason = screen.getByLabelText('Reason', { exact: true });
  await user.type(renewalReason, 'Renew the existing published policy.');
  rerender(<PolicyReleaseWorkflow evaluationUi showSessionControls={false} />);
  expect(screen.getByLabelText('Business reason')).toBe(reason);
  expect(reason).toBeVisible();
  expect(reason).toHaveValue('Publish the independently reviewed policy.');
  rerender(
    <PolicyReleaseWorkflow
      evaluationUi
      showSessionControls={false}
      activeTask="activation-renewal"
    />,
  );
  expect(screen.getByLabelText('Reason', { exact: true })).toBe(renewalReason);
  expect(renewalReason).toHaveValue('Renew the existing published policy.');
  expect(fetcher.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
});

it('requires an explicit independent checker for the original synthetic maker binding', async () => {
  const originalMaker: Actor = {
    ...actor,
    role: 'operator',
    principalId: id(111),
    participantId: id(101),
    privacyDomainId: id(201),
  };
  const fetcher = reads(
    () =>
      Response.json(workbench({ approvalId: '', releaseId: '', occurrenceId: '' }, originalMaker)),
    () => Response.json(session(originalMaker)),
  );
  render(<PolicyReleaseWorkflow evaluationUi showSessionControls={false} />);
  await screen.findByRole('heading', { name: 'Policy workspace' });
  expect(screen.getByLabelText('Checker principal ID')).toHaveValue('');
  for (const [label, value] of [
    ['Policy version ID', id(31)],
    ['Policy artifact digest', digest],
    ['Dependency closure digest', digest],
    ['Business reason', 'Publish the reviewed policy.'],
  ])
    fireEvent.change(screen.getByLabelText(label!), { target: { value } });
  await userEvent.setup().click(screen.getByRole('button', { name: 'Review release details' }));
  expect(screen.getByLabelText('Checker principal ID')).toBeInvalid();
  expect(fetcher.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
});

it('retains the original sealed release and operation references across task selection', async () => {
  const original = seed();
  const fetcher = reads(() => Response.json(workbench()));
  const { rerender } = render(<PolicyReleaseWorkflow evaluationUi showSessionControls={false} />);
  await screen.findByRole('heading', { name: 'Policy workspace' });
  rerender(
    <PolicyReleaseWorkflow
      evaluationUi
      showSessionControls={false}
      activeTask="activation-renewal"
    />,
  );
  expect(localStorage.getItem(storageKey)).toBe(original);
  rerender(<PolicyReleaseWorkflow evaluationUi showSessionControls={false} />);
  expect(localStorage.getItem(storageKey)).toBe(original);
  expect(fetcher.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
});

it.each([
  null,
  [],
  { authenticated: 'true' },
  { ...session(), principalId: undefined },
  { ...session(), contextEpoch: '-1' },
  { ...session(), role: 'administrator' },
])(
  'treats malformed session as unknown and retries with GET without deleting original review: %o',
  async (invalid) => {
    const original = seed();
    let valid = false;
    const fetcher = reads(
      () => Response.json(workbench()),
      () => Response.json(valid ? session() : invalid),
    );
    render(<PolicyReleaseWorkflow />);
    await screen.findByRole('alert');
    expect(
      screen.queryByRole('region', { name: 'Current policy context' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText('Sign in')).not.toBeInTheDocument();
    expect(localStorage.getItem(storageKey)).toBe(original);
    valid = true;
    await userEvent.setup().click(screen.getByRole('button', { name: 'Refresh policy workflow' }));
    expect(await screen.findByRole('region', { name: 'Current policy context' })).toBeVisible();
    expect(fetcher.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
  },
);
it.each([
  null,
  { actor },
  { actor, approval: { state: 12 } },
  { ...workbench(), release: { ...workbench().release, manifestDigest: 'private-invalid-digest' } },
  { ...workbench(), occurrence: null },
  {
    ...workbench(),
    occurrenceStepUp: { ...step(selectors.occurrenceId), resourceId: 'not-an-id' },
  },
])(
  'rejects malformed or missing selected workbench resources without rendering old actions: %o',
  async (body) => {
    const original = seed();
    let valid = false;
    reads(() => Response.json(valid ? workbench() : body));
    render(<PolicyReleaseWorkflow />);
    await screen.findByRole('alert');
    expect(
      screen.queryByRole('button', { name: 'Publish with security key' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('region', { name: 'Current policy context' }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('alert')).not.toHaveTextContent('private-invalid-digest');
    expect(localStorage.getItem(storageKey)).toBe(original);
    valid = true;
    await userEvent.setup().click(screen.getByRole('button', { name: 'Refresh policy workflow' }));
    expect(await screen.findByRole('button', { name: 'Publish with security key' })).toBeVisible();
  },
);
it('accepts compatible extra fields and new owner state strings without imposing presentation-role authority', async () => {
  seed();
  const body = workbench();
  reads(() =>
    Response.json({
      ...body,
      harmless: true,
      actor: { ...actor, label: 'viewer presentation' },
      approval: { ...body.approval, state: 'OWNER_NEW_STATE', additional: { safe: true } },
      release: { ...body.release, state: 'OWNER_NEW_STATE' },
      occurrence: { ...body.occurrence, state: 'FAILED', diagnostic: 'safe' },
      occurrenceStepUp: { ...body.occurrenceStepUp, extra: true },
    }),
  );
  render(<PolicyReleaseWorkflow />);
  expect(await screen.findByRole('button', { name: 'Recover with security key' })).toBeVisible();
  expect(screen.getAllByText('OWNER NEW STATE')).toHaveLength(2);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
it.each(['approval', 'release', 'occurrence'] as const)(
  'requires the exact selected resource URN for %s, not a matching suffix alias',
  async (field) => {
    seed();
    const keys = {
      approval: 'approvalRequestId',
      release: 'releaseBundleId',
      occurrence: 'activationOccurrenceId',
    } as const;
    const selected = {
      approval: selectors.approvalId,
      release: selectors.releaseId,
      occurrence: selectors.occurrenceId,
    };
    const body = workbench();
    reads(() =>
      Response.json({
        ...body,
        [field]: {
          ...body[field],
          [keys[field]]: `urn:other:resource:${selected[field]}`,
        },
      }),
    );
    render(<PolicyReleaseWorkflow />);
    await screen.findByText('The policy workflow does not match the selected references.');
    expect(
      screen.queryByRole('button', { name: 'Publish with security key' }),
    ).not.toBeInTheDocument();
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it.each(['approvalStepUp', 'publishStepUp', 'occurrenceStepUp'] as const)(
  'rejects a wrong UUID step-up resource in %s',
  async (field) => {
    seed();
    const body = workbench();
    reads(() => Response.json({ ...body, [field]: { ...body[field], resourceId: id(99) } }));
    render(<PolicyReleaseWorkflow />);
    await screen.findByText('The policy workflow does not match the selected references.');
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const)(
  'rejects a workbench from a different %s',
  async (field) => {
    seed();
    reads(() =>
      Response.json({
        ...workbench(),
        actor: { ...actor, [field]: field === 'contextEpoch' ? '2' : id(99) },
      }),
    );
    render(<PolicyReleaseWorkflow />);
    await screen.findByText('The policy workflow does not match the current context.');
    expect(
      screen.queryByRole('button', { name: 'Publish with security key' }),
    ).not.toBeInTheDocument();
  },
);
it.each(['denial', 'unreadable', 'transport', 'malformed'] as const)(
  'hides current private projection on %s and preserves child instances, storage and GET retry',
  async (failure) => {
    const original = seed();
    let failed = false;
    const fetcher = reads(() => {
      if (!failed) return Response.json(workbench());
      if (failure === 'denial')
        return Response.json({ title: 'Read denied', code: 'PC-AUTH-0005' }, { status: 403 });
      if (failure === 'unreadable') return new Response('not-json', { status: 200 });
      if (failure === 'malformed')
        return Response.json({ ...workbench(), approval: { state: 42 } });
      throw new Error('Policy read unavailable');
    });
    render(<PolicyReleaseWorkflow />);
    await screen.findByRole('region', { name: 'Current policy context' });
    await screen.findByLabelText('Request type');
    const reason = screen.getByLabelText('Staging reason');
    fireEvent.change(reason, { target: { value: 'Keep this original staging draft.' } });
    const before = fetcher.mock.calls.filter(([url]) =>
      String(url).endsWith('/administration-names'),
    ).length;
    failed = true;
    await makerRefresh();
    await screen.findByRole('alert');
    expect(
      screen.queryByRole('region', { name: 'Current policy context' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Release review' })).not.toBeInTheDocument();
    expect(reason).not.toBeVisible();
    expect(reason).toHaveValue('Keep this original staging draft.');
    expect(localStorage.getItem(storageKey)).toBe(original);
    failed = false;
    await userEvent.setup().click(screen.getByRole('button', { name: 'Refresh policy workflow' }));
    expect(await screen.findByRole('heading', { name: 'Release review' })).toBeVisible();
    expect(screen.getByLabelText('Staging reason')).toBe(reason);
    expect(reason).toBeVisible();
    expect(
      fetcher.mock.calls.filter(([url]) => String(url).endsWith('/administration-names')),
    ).toHaveLength(before);
    expect(fetcher.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
it.each(['success', 'failure'] as const)(
  'fences an obsolete initial session %s before any dependent policy read',
  async (outcome) => {
    seed();
    const old = deferred();
    let sessions = 0;
    let policyReads = 0;
    reads(
      () => {
        policyReads++;
        return Response.json(workbench());
      },
      () => (++sessions === 1 ? old.promise : Response.json(session())),
    );
    render(<PolicyReleaseWorkflow />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Refresh policy workflow' }));
    await screen.findByRole('region', { name: 'Current policy context' });
    await act(async () => {
      if (outcome === 'success') old.resolve(Response.json(session()));
      else old.reject(new Error('obsolete session error'));
    });
    expect(policyReads).toBe(1);
    expect(screen.getByRole('region', { name: 'Current policy context' })).toBeVisible();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);
it.each(['success', 'failure'] as const)(
  'ignores obsolete initial workbench %s after a fresh successful retry',
  async (outcome) => {
    seed();
    const old = deferred();
    let policies = 0;
    reads(() => (++policies === 1 ? old.promise : Response.json(workbench())));
    render(<PolicyReleaseWorkflow />);
    await waitFor(() => expect(policies).toBe(1));
    await userEvent.setup().click(screen.getByRole('button', { name: 'Refresh policy workflow' }));
    await screen.findByRole('region', { name: 'Current policy context' });
    await act(async () => {
      if (outcome === 'success')
        old.resolve(
          Response.json({ ...workbench(), actor: { ...actor, privacyDomainId: id(40) } }),
        );
      else old.reject(new Error('obsolete workbench error'));
    });
    expect(screen.getByRole('region', { name: 'Current policy context' })).toBeVisible();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);
it('does not allow an old successful workbench to revive a current denied projection', async () => {
  seed();
  const old = deferred();
  let policies = 0;
  reads(() =>
    ++policies === 1
      ? old.promise
      : Response.json({ title: 'Current read denied' }, { status: 403 }),
  );
  render(<PolicyReleaseWorkflow />);
  await waitFor(() => expect(policies).toBe(1));
  await userEvent.setup().click(screen.getByRole('button', { name: 'Refresh policy workflow' }));
  await screen.findByText(
    'Policy request was not authorized. Refresh the authenticated context before continuing.',
  );
  await act(async () => old.resolve(Response.json(workbench())));
  expect(screen.queryByRole('region', { name: 'Current policy context' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Refresh policy workflow' })).toBeEnabled();
});
it('fences a delayed session JSON body before dependent reads or storage restore', async () => {
  const original = seed();
  const body = deferred<unknown>();
  let sessions = 0;
  let policies = 0;
  const response = Response.json({});
  vi.spyOn(response, 'json').mockReturnValue(body.promise);
  reads(
    () => {
      policies++;
      return Response.json(workbench());
    },
    () => (++sessions === 1 ? response : Response.json(session())),
  );
  render(<PolicyReleaseWorkflow />);
  await waitFor(() => expect(response.json).toHaveBeenCalled());
  await userEvent.setup().click(screen.getByRole('button', { name: 'Refresh policy workflow' }));
  await screen.findByRole('region', { name: 'Current policy context' });
  await act(async () => body.resolve({ ...session(), principalId: id(99) }));
  expect(policies).toBe(1);
  expect(localStorage.getItem(storageKey)).toBe(original);
});
it('hides old resource controls while loading replacement selectors and reads the exact new references', async () => {
  seed();
  const pending = deferred();
  const next = { approvalId: id(21), releaseId: id(22), occurrenceId: id(23) };
  const urls: string[] = [];
  reads((url) => {
    urls.push(url);
    return urls.length === 1 ? Response.json(workbench()) : pending.promise;
  });
  render(<PolicyReleaseWorkflow />);
  await screen.findByRole('button', { name: 'Publish with security key' });
  const selectorRegion = screen.getByRole('region', {
    name: 'Review and control policy authority',
  });
  for (const [label, value] of [
    ['Approval ID', next.approvalId],
    ['Release ID', next.releaseId],
    ['Activation ID', next.occurrenceId],
  ])
    fireEvent.change(within(selectorRegion).getByLabelText(label!, { exact: true }), {
      target: { value },
    });
  await userEvent.setup().click(screen.getByRole('button', { name: 'Load policy workflow' }));
  await waitFor(() => expect(urls).toHaveLength(2));
  expect(
    screen.queryByRole('button', { name: 'Publish with security key' }),
  ).not.toBeInTheDocument();
  expect(Object.fromEntries(new URL(urls[1]!, 'http://localhost').searchParams)).toEqual(next);
  await act(async () => pending.resolve(Response.json(workbench(next))));
  expect(await screen.findByText(next.releaseId)).toBeVisible();
  expect(screen.queryByText(selectors.releaseId)).not.toBeInTheDocument();
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});
it('preserves the exact ACTIVATE body and original occurrence readback after a lost response, without replay or child remount', async () => {
  const original = seed();
  let activated = false;
  const posts: unknown[] = [],
    urls: string[] = [];
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    if (String(url).endsWith('/local-session')) return Response.json(session());
    if (String(url).includes('/policy-release-workbench')) {
      if (init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)) as unknown);
        activated = true;
        throw new TypeError('response lost');
      }
      urls.push(String(url));
      return Response.json(workbench(selectors, actor, activated ? 'ACTIVE_MATCHED' : 'REQUESTED'));
    }
    return Response.json({ actor });
  });
  render(<PolicyReleaseWorkflow />);
  await screen.findByRole('button', { name: 'Activate with security key' });
  const reason = screen.getByLabelText('Staging reason');
  fireEvent.change(reason, { target: { value: 'Retained original staging draft.' } });
  const before = fetcher.mock.calls.filter(([url]) =>
    String(url).endsWith('/administration-names'),
  ).length;
  await userEvent.setup().click(screen.getByRole('button', { name: 'Activate with security key' }));
  expect(await screen.findByRole('button', { name: 'Roll back with security key' })).toBeVisible();
  expect(posts).toEqual([{ command: 'ACTIVATE', occurrenceId: selectors.occurrenceId }]);
  expect(urls).toHaveLength(2);
  expect(
    urls.every(
      (url) =>
        new URL(url, 'http://localhost').searchParams.get('occurrenceId') ===
        selectors.occurrenceId,
    ),
  ).toBe(true);
  expect(localStorage.getItem(storageKey)).toBe(original);
  expect(screen.getByLabelText('Staging reason')).toBe(reason);
  expect(reason).toHaveValue('Retained original staging draft.');
  expect(
    fetcher.mock.calls.filter(([url]) => String(url).endsWith('/administration-names')),
  ).toHaveLength(before);
  expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
});
it.each(['session', 'workbench'] as const)(
  'aborts an unmounted %s read before further reads, state or storage effects',
  async (phase) => {
    const original = seed();
    const pending = deferred();
    let policies = 0;
    let signal: AbortSignal | null | undefined;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url).endsWith('/local-session')) {
        if (phase === 'session') {
          signal = init?.signal;
          return pending.promise;
        }
        return Response.json(session());
      }
      policies++;
      signal = init?.signal;
      return pending.promise;
    });
    const view = render(<PolicyReleaseWorkflow />);
    await waitFor(() => expect(signal).toBeDefined());
    view.unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      pending.resolve(
        Response.json(phase === 'session' ? { ...session(), principalId: id(99) } : workbench()),
      ),
    );
    expect(policies).toBe(phase === 'session' ? 0 : 1);
    expect(localStorage.getItem(storageKey)).toBe(original);
  },
);
it('preserves mounted child custody but hides it after an authoritative actor switch', async () => {
  seed();
  let changed = false;
  const next: Actor = { ...actor, privacyDomainId: id(40), contextEpoch: '2' };
  const fetcher = reads(
    () => Response.json(changed ? { actor: next } : workbench()),
    () => Response.json(session(changed ? next : actor)),
  );
  render(<PolicyReleaseWorkflow />);
  await screen.findByRole('region', { name: 'Current policy context' });
  const reason = screen.getByLabelText('Staging reason');
  fireEvent.change(reason, { target: { value: 'Original-context staging draft.' } });
  const before = fetcher.mock.calls.filter(([url]) =>
    String(url).endsWith('/administration-names'),
  ).length;
  changed = true;
  await makerRefresh();
  await screen.findByText(
    'Other workflows remain hidden until their original context is restored.',
  );
  const context = screen.getByRole('region', { name: 'Current policy context' });
  expect(within(context).getByText(next.privacyDomainId)).toBeVisible();
  expect(reason).not.toBeVisible();
  expect(reason).toHaveValue('Original-context staging draft.');
  expect(
    fetcher.mock.calls.filter(([url]) => String(url).endsWith('/administration-names')),
  ).toHaveLength(before);
  expect(fetcher.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
});

it('polls a nonterminal original occurrence after 1.5 seconds and stops after its authoritative terminal readback', async () => {
  vi.useFakeTimers();
  seed();
  let policies = 0;
  reads(() =>
    Response.json(workbench(selectors, actor, ++policies === 1 ? 'REQUESTED' : 'ACTIVE_MATCHED')),
  );
  await act(async () => {
    render(<PolicyReleaseWorkflow />);
  });
  expect(policies).toBe(1);
  await act(async () => {
    vi.advanceTimersByTime(1499);
  });
  expect(policies).toBe(1);
  await act(async () => {
    vi.advanceTimersByTime(1);
  });
  expect(policies).toBe(2);
  expect(screen.getByRole('button', { name: 'Roll back with security key' })).toBeVisible();
  await act(async () => {
    vi.advanceTimersByTime(4500);
  });
  expect(policies).toBe(2);
});
it.each(['ACTIVE_MATCHED', 'ROLLED_BACK', 'FAILED'])(
  'does not poll an already terminal %s occurrence',
  async (terminal) => {
    vi.useFakeTimers();
    seed();
    let policies = 0;
    reads(() => {
      policies++;
      return Response.json(workbench(selectors, actor, terminal));
    });
    await act(async () => {
      render(<PolicyReleaseWorkflow />);
    });
    expect(policies).toBe(1);
    await act(async () => {
      vi.advanceTimersByTime(4500);
    });
    expect(policies).toBe(1);
  },
);
it('ignores an old polling failure after a new manual read succeeds without losing child state', async () => {
  vi.useFakeTimers();
  seed();
  const old = deferred();
  let policies = 0;
  reads(() => {
    policies++;
    return policies === 2
      ? old.promise
      : Response.json(workbench(selectors, actor, policies === 1 ? 'REQUESTED' : 'ACTIVE_MATCHED'));
  });
  await act(async () => {
    render(<PolicyReleaseWorkflow />);
  });
  const reason = screen.getByLabelText('Staging reason');
  fireEvent.change(reason, { target: { value: 'Original staging custody.' } });
  await act(async () => {
    vi.advanceTimersByTime(1500);
  });
  expect(policies).toBe(2);
  await act(async () => {
    fireEvent.change(screen.getByLabelText('Workflow'), { target: { value: 'PREPARE' } });
  });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Refresh policy workflow' }));
  });
  expect(policies).toBe(3);
  await act(async () => old.reject(new Error('obsolete polling failure')));
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Release review' })).toBeVisible();
  expect(screen.getByLabelText('Staging reason')).toBe(reason);
  expect(reason).toHaveValue('Original staging custody.');
});
it('fences an in-flight background GET at ACTIVATE while preserving original command completion and readback', async () => {
  vi.useFakeTimers();
  const original = seed();
  const old = deferred(),
    post = deferred();
  let policies = 0;
  const posts: unknown[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    if (String(url).endsWith('/local-session')) return Response.json(session());
    if (String(url).includes('/policy-release-workbench')) {
      if (init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)) as unknown);
        return post.promise;
      }
      policies++;
      return policies === 2
        ? old.promise
        : Response.json(workbench(selectors, actor, policies > 2 ? 'ACTIVE_MATCHED' : 'REQUESTED'));
    }
    return Response.json({ actor });
  });
  await act(async () => {
    render(<PolicyReleaseWorkflow />);
  });
  await act(async () => {
    vi.advanceTimersByTime(1500);
  });
  expect(policies).toBe(2);
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Activate with security key' }));
  });
  expect(posts).toEqual([{ command: 'ACTIVATE', occurrenceId: selectors.occurrenceId }]);
  await act(async () => old.reject(new Error('obsolete background denial')));
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Activate with security key' })).toBeDisabled();
  await act(async () =>
    post.resolve(
      Response.json({
        truthState: 'SUCCESS',
        resourceRef: `urn:openpc:resource:${selectors.occurrenceId}`,
      }),
    ),
  );
  expect(screen.getByRole('button', { name: 'Roll back with security key' })).toBeVisible();
  expect(policies).toBe(3);
  expect(posts).toHaveLength(1);
  expect(localStorage.getItem(storageKey)).toBe(original);
});
it('keeps genuine anonymous state distinct from an unreadable session', async () => {
  reads(
    () => Response.json({ actor }),
    () => Response.json({ enabled: true, authenticated: false }),
  );
  render(<PolicyReleaseWorkflow />);
  expect(await screen.findByText('Sign in')).toBeVisible();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('keeps valid platform context selection available without starting a Participant workbench read', async () => {
  let policies = 0;
  reads(
    () => {
      policies++;
      return Response.json({ actor });
    },
    () =>
      Response.json({
        authenticated: true,
        role: 'viewer',
        contextMode: 'PLATFORM',
        availableContexts: [
          { participantId: actor.participantId, privacyDomainId: actor.privacyDomainId },
        ],
      }),
  );
  render(<PolicyReleaseWorkflow />);
  expect(await screen.findByRole('button', { name: 'Enter workspace' })).toBeVisible();
  expect(policies).toBe(0);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
it('allows corrected UUID reads after failure without disclosing old refs or deleting the sealed review', async () => {
  const original = seed();
  let denied = true;
  const urls: string[] = [];
  reads((url) => {
    urls.push(url);
    return denied
      ? Response.json({ title: 'Initial read denied' }, { status: 403 })
      : Response.json(workbench());
  });
  render(<PolicyReleaseWorkflow />);
  await screen.findByRole('alert');
  const form = screen.getByRole('region', { name: 'Read policy references' });
  expect(within(form).getByLabelText('Approval ID', { exact: true })).toHaveValue('');
  fireEvent.change(within(form).getByLabelText('Approval ID', { exact: true }), {
    target: { value: 'not-an-id' },
  });
  await userEvent.setup().click(within(form).getByRole('button', { name: 'Load policy workflow' }));
  await screen.findByText('Enter exact UUID references before reading policy state.');
  expect(urls).toHaveLength(1);
  expect(localStorage.getItem(storageKey)).toBe(original);
  for (const [label, value] of [
    ['Approval ID', selectors.approvalId],
    ['Release ID', selectors.releaseId],
    ['Activation ID', selectors.occurrenceId],
  ])
    fireEvent.change(within(form).getByLabelText(label!, { exact: true }), { target: { value } });
  denied = false;
  await userEvent.setup().click(within(form).getByRole('button', { name: 'Load policy workflow' }));
  expect(await screen.findByRole('button', { name: 'Publish with security key' })).toBeVisible();
  expect(JSON.parse(localStorage.getItem(storageKey)!).value.review).toEqual(originalSaved.review);
});
it.each(['network', 'HTTP', 'malformed JSON', 'malformed success'])(
  'keeps a child sealed staging review and %s original POST mounted through a parent GET failure and retry',
  async (failure) => {
    seed();
    const stage = deferred();
    let denied = false;
    const posts: Record<string, unknown>[] = [];
    const preview = {
      releaseBundleId: `urn:openpc:resource:${selectors.releaseId}`,
      releaseRevision: '1',
      policyVersionId: id(31),
      targetGenerationDigest: digest,
      dependencyClosureDigest: digest,
      simulationId: id(41),
      simulationInputDigest: digest,
      simulationResultDigest: digest,
      factGenerationDigest: digest,
      matchedTargetCount: '0',
      totalTargetCount: '1',
      targets: [
        {
          targetId: id(42),
          expectedRevision: '1',
          expectedPredecessorDigest: null,
          configurationDigest: digest,
          providerProfileId: id(43),
          projectionPlanId: id(44),
          configuredMatch: false,
        },
      ],
      activationPreviewDigest: digest,
    };
    const token = 't'.repeat(100);
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url).endsWith('/local-session')) return Response.json(session());
      if (String(url).includes('/policy-release-workbench')) {
        if (init?.method === 'POST') {
          const body = JSON.parse(String(init.body)) as Record<string, unknown>;
          posts.push(body);
          if (body.command === 'PREVIEW_OCCURRENCE')
            return Response.json({ stageReviewToken: token, preview }, { status: 201 });
          if (body.command === 'STAGE_OCCURRENCE') return stage.promise;
          throw new Error('Unexpected command');
        }
        return denied
          ? Response.json({ title: 'Parent read denied' }, { status: 403 })
          : Response.json(workbench());
      }
      return Response.json({ actor });
    });
    render(<PolicyReleaseWorkflow />);
    await screen.findByRole('region', { name: 'Current policy context' });
    const user = userEvent.setup();
    for (const [label, value] of [
      ['Published release ID', selectors.releaseId],
      ['Release revision', '1'],
      ['Staging reason', 'Keep the original governed stage intent.'],
    ])
      fireEvent.change(screen.getByLabelText(label!, { exact: true }), { target: { value } });
    await user.click(screen.getByRole('button', { name: 'Review current activation targets' }));
    const stageButton = await screen.findByRole('button', { name: 'Stage reviewed activation' });
    await user.click(stageButton);
    await waitFor(() => expect(posts).toHaveLength(2));
    denied = true;
    await makerRefresh();
    await screen.findByRole('alert');
    expect(stageButton).not.toBeVisible();
    await act(async () => {
      if (failure === 'network') stage.reject(new TypeError('original stage response lost'));
      else if (failure === 'HTTP')
        stage.resolve(
          Response.json(
            { title: 'PRIVATE_STAGE_TITLE', code: 'PRIVATE_STAGE_CODE' },
            { status: 403 },
          ),
        );
      else if (failure === 'malformed JSON')
        stage.resolve(
          new Response('PRIVATE_STAGE_JSON', {
            status: 202,
            headers: { 'Content-Type': 'application/json' },
          }),
        );
      else stage.resolve(Response.json({}, { status: 202 }));
    });
    denied = false;
    await user.click(screen.getByRole('button', { name: 'Refresh policy workflow' }));
    await screen.findByRole('heading', { name: 'Release review' });
    expect(screen.getByRole('button', { name: 'Stage reviewed activation' })).toBe(stageButton);
    expect(stageButton).toBeEnabled();
    expect(
      screen.getByText(
        failure === 'network'
          ? 'The staging result could not be confirmed. Read back the original operation before retrying.'
          : failure === 'HTTP'
            ? 'Policy staging was not authorized. Refresh the authenticated context before continuing.'
            : 'The policy staging response could not be confirmed. Read back the original operation before retrying.',
      ),
    ).toBeVisible();
    expect(screen.queryByText(/original stage response lost|PRIVATE_STAGE/u)).toBeNull();
    expect(screen.queryByText(/Occurrence:|activation still requires fresh approval/u)).toBeNull();
    expect(posts).toHaveLength(2);
    expect(posts[1]).toEqual({ command: 'STAGE_OCCURRENCE', stageReviewToken: token });
  },
);

const unsafePolicyMarker = 'PRIVATE_POLICY_SERVER_TRANSPORT_OR_VALIDATOR_DETAIL';
const policyUnavailable = 'The policy owner is unavailable. Refresh before continuing.';
const policyFailures = [
  {
    name: 'authorization',
    status: 403,
    message:
      'Policy request was not authorized. Refresh the authenticated context before continuing.',
  },
  {
    name: 'conflict',
    status: 409,
    message: 'Policy state changed. Refresh or read the original operation before retrying.',
  },
  {
    name: 'input',
    status: 422,
    message: 'Policy request was rejected. Check the inputs before continuing.',
  },
  { name: 'unknown code', status: 503, message: policyUnavailable },
  { name: 'transport', message: policyUnavailable },
  { name: 'unknown thrown object', message: policyUnavailable },
  { name: 'non-JSON success', message: policyUnavailable },
] as const;
function failPolicy(failure: (typeof policyFailures)[number]): Response {
  if ('status' in failure)
    return Response.json(
      { title: unsafePolicyMarker, code: unsafePolicyMarker },
      { status: failure.status },
    );
  if (failure.name === 'transport') throw new Error(unsafePolicyMarker);
  if (failure.name === 'unknown thrown object')
    throw { message: unsafePolicyMarker, details: unsafePolicyMarker };
  return new Response(unsafePolicyMarker, { status: 200 });
}
it.each(
  policyFailures.flatMap((failure) =>
    ['session', 'workbench'].map((phase) => ({ ...failure, phase })),
  ),
)(
  'hides $name at the initial policy $phase reader and preserves the original sealed review',
  async (failure) => {
    const original = seed();
    const fetcher = reads(
      () => failPolicy(failure),
      () => (failure.phase === 'session' ? failPolicy(failure) : Response.json(session())),
    );
    render(<PolicyReleaseWorkflow />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(failure.message));
    expect(document.body.textContent).not.toContain(unsafePolicyMarker);
    expect(
      screen.queryByRole('region', { name: 'Current policy context' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Publish with security key' }),
    ).not.toBeInTheDocument();
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
const policyMutationNames = {
  PREVIEW: 'Review release details',
  SUBMIT_APPROVAL: 'Request checker approval',
  CREATE_RELEASE: 'Create approved release',
  CREATE_OCCURRENCE: 'Stage target activation',
  APPROVE: 'Approve with security key',
  PUBLISH: 'Publish with security key',
  ACTIVATE: 'Activate with security key',
  ROLLBACK: 'Roll back with security key',
  RECOVER: 'Recover with security key',
  RETIRE: 'Retire release',
} as const;
type PolicyMutation = keyof typeof policyMutationNames;
function policyMutationInput(boundary: PolicyMutation) {
  const selected = {
    approvalId:
      boundary === 'PREVIEW' || boundary === 'SUBMIT_APPROVAL' ? '' : selectors.approvalId,
    releaseId: ['PREVIEW', 'SUBMIT_APPROVAL', 'CREATE_RELEASE'].includes(boundary)
      ? ''
      : selectors.releaseId,
    occurrenceId:
      boundary.startsWith('CREATE_') || boundary === 'PREVIEW' || boundary === 'SUBMIT_APPROVAL'
        ? ''
        : selectors.occurrenceId,
  };
  const saved = {
    ...(boundary === 'PREVIEW' ? {} : { review: originalSaved.review }),
    ...(selected.approvalId ? { approvalId: selected.approvalId } : {}),
    ...(selected.releaseId ? { releaseId: selected.releaseId } : {}),
    ...(selected.occurrenceId ? { occurrenceId: selected.occurrenceId } : {}),
  };
  const body = workbench(
    selected,
    actor,
    boundary === 'ACTIVATE' ? 'REQUESTED' : boundary === 'RECOVER' ? 'FAILED' : 'ACTIVE_MATCHED',
  );
  if (body.approval && boundary === 'APPROVE') body.approval.state = 'REQUESTED';
  if (body.release && boundary === 'CREATE_OCCURRENCE') body.release.state = 'PUBLISHED';
  if (body.release && boundary === 'RETIRE') body.release.state = 'ROLLED_BACK';
  return { selected, saved, body };
}
async function policyMutationControl(boundary: PolicyMutation) {
  await screen.findByLabelText('Workflow');
  const maker = ['PREVIEW', 'SUBMIT_APPROVAL', 'CREATE_RELEASE', 'CREATE_OCCURRENCE'].includes(
    boundary,
  );
  if (maker) fireEvent.change(screen.getByLabelText('Workflow'), { target: { value: 'PREPARE' } });
  const control = screen.getByRole('button', { name: policyMutationNames[boundary] });
  if (boundary === 'PREVIEW') {
    const details = originalSaved.review.review;
    for (const [label, value] of [
      ['Policy version ID', details.policyVersionId],
      ['Checker principal ID', details.checkerPrincipalId],
      ['Policy artifact digest', details.manifestDigest],
      ['Dependency closure digest', details.dependencyClosureDigest],
      ['Business reason', details.reason],
    ])
      fireEvent.change(screen.getByLabelText(label!), { target: { value } });
  }
  return control;
}
it.each(
  policyFailures.flatMap((failure) =>
    (Object.keys(policyMutationNames) as PolicyMutation[]).map((boundary) => ({
      ...failure,
      boundary,
    })),
  ),
)(
  'hides $name at policy $boundary while preserving exact commands, custody and lost-ACTIVATE reconciliation',
  async (failure) => {
    const { saved, body } = policyMutationInput(failure.boundary);
    const original = seed(saved);
    let workbenchReads = 0;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith('/local-session')) return Response.json(session());
      if (url.includes('/policy-release-workbench')) {
        if (init?.method === 'POST') return failPolicy(failure);
        workbenchReads++;
        return Response.json(body);
      }
      return Response.json({ actor });
    });
    render(<PolicyReleaseWorkflow />);
    const control = await policyMutationControl(failure.boundary);
    if (failure.boundary === 'PREVIEW') fireEvent.submit(control.closest('form')!);
    else fireEvent.click(control);
    const transportLost = failure.name === 'transport' || failure.name === 'unknown thrown object';
    const message = transportLost
      ? failure.boundary === 'ACTIVATE'
        ? 'The activation response was lost. Checking the original operation before continuing.'
        : 'The mutation response was not received.'
      : failure.message;
    await screen.findByText(message);
    if (transportLost && failure.boundary === 'ACTIVATE')
      await waitFor(() => expect(workbenchReads).toBe(2));
    expect(document.body.textContent).not.toContain(unsafePolicyMarker);
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(
      screen.queryByText(
        'Review locked. Verify the artifact and reason before requesting approval.',
      ),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/accepted by the owner\./)).not.toBeInTheDocument();
    expect(
      screen.queryByText('Approval requested from the distinct checker.'),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText('Draft release created from the exact approved artifact.'),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(
        'Activation staged for the reviewed targets. Check runtime status before using the policy.',
      ),
    ).not.toBeInTheDocument();
    const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(1);
    const command = JSON.parse(String(posts[0]![1]!.body));
    if (failure.boundary === 'PREVIEW')
      expect(command).toEqual({ command: 'PREVIEW', ...originalSaved.review.review });
    else if (failure.boundary === 'SUBMIT_APPROVAL' || failure.boundary === 'CREATE_RELEASE')
      expect(command).toEqual({
        command: failure.boundary,
        reviewToken: originalSaved.review.reviewToken,
      });
    else if (failure.boundary === 'CREATE_OCCURRENCE')
      expect(command).toEqual({
        command: 'CREATE_OCCURRENCE',
        reviewToken: originalSaved.review.reviewToken,
        releaseId: selectors.releaseId,
      });
    else if (failure.boundary === 'APPROVE')
      expect(command).toEqual({ command: 'APPROVE', approvalId: selectors.approvalId });
    else if (failure.boundary === 'PUBLISH' || failure.boundary === 'RETIRE')
      expect(command).toEqual({ command: failure.boundary, releaseId: selectors.releaseId });
    else
      expect(command).toEqual({ command: failure.boundary, occurrenceId: selectors.occurrenceId });
  },
);
it.each(['APPROVE', 'PUBLISH', 'ACTIVATE', 'ROLLBACK', 'RECOVER'] as const)(
  'hides authenticator exceptions and sends no policy %s mutation before step-up succeeds',
  async (boundary) => {
    const { saved, body } = policyMutationInput(boundary);
    const original = seed(saved);
    vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(new Error(unsafePolicyMarker));
    const fetcher = reads(() => Response.json(body));
    render(<PolicyReleaseWorkflow />);
    fireEvent.click(await policyMutationControl(boundary));
    await screen.findByText(policyUnavailable);
    expect(document.body.textContent).not.toContain(unsafePolicyMarker);
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it.each(['session validator', 'workbench validator', 'reference read', 'refresh'] as const)(
  'hides policy details from %s and preserves the original review',
  async (boundary) => {
    const original = seed();
    let fail = boundary.endsWith('validator');
    const fetcher = reads(
      () =>
        fail
          ? boundary === 'workbench validator'
            ? Response.json({ ...workbench(), approval: { candidateDigest: unsafePolicyMarker } })
            : failPolicy({ name: 'transport', message: policyUnavailable })
          : Response.json(workbench()),
      () =>
        boundary === 'session validator'
          ? Response.json({ ...session(), contextEpoch: unsafePolicyMarker })
          : Response.json(session()),
    );
    render(<PolicyReleaseWorkflow />);
    if (!fail) {
      await screen.findByLabelText('Workflow');
      fail = true;
      if (boundary === 'refresh') await makerRefresh();
      else fireEvent.click(screen.getByRole('button', { name: 'Load policy workflow' }));
    }
    const expected =
      boundary === 'session validator'
        ? 'The authenticated context response is unavailable. Refresh before continuing.'
        : boundary === 'workbench validator'
          ? 'The policy workflow response is unavailable. Refresh before continuing.'
          : policyUnavailable;
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(expected));
    expect(document.body.textContent).not.toContain(unsafePolicyMarker);
    expect(document.body.textContent).not.toContain('invalid_type');
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  },
);
it('hides policy context-selection transport details without deleting original custody or claiming activation', async () => {
  const original = seed();
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) =>
    init?.method === 'POST'
      ? failPolicy({ name: 'transport', message: policyUnavailable })
      : Response.json(
          String(input).endsWith('/local-session')
            ? {
                authenticated: true,
                sessionId: actor.sessionId,
                contextMode: 'PLATFORM',
                role: 'viewer',
                availableContexts: [
                  { participantId: actor.participantId, privacyDomainId: actor.privacyDomainId },
                ],
              }
            : { actor },
        ),
  );
  render(<PolicyReleaseWorkflow />);
  const control = await screen.findByRole('button', { name: 'Enter workspace' });
  // The initial authoritative Platform context clears Participant-bound storage as before.
  expect(localStorage.getItem(storageKey)).toBeNull();
  localStorage.setItem(storageKey, original);
  fireEvent.click(control);
  await screen.findAllByText(policyUnavailable);
  expect(document.body.textContent).not.toContain(unsafePolicyMarker);
  expect(localStorage.getItem(storageKey)).toBe(original);
  expect(screen.queryByText('Participant privacy context is active.')).not.toBeInTheDocument();
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
});

it.each([
  { participantId: id(101), privacyDomainId: id(201) },
  { participantId: id(102), privacyDomainId: id(7201) },
])(
  'binds context selection to the actual server tuple and original session: %o',
  async (context) => {
    let selected = false;
    const currentActor = { ...actor, ...context, contextEpoch: '2' };
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        expect(String(input)).toBe('/api/v1/ui/session/context');
        selected = true;
        return Response.json({ accepted: true });
      }
      if (String(input).endsWith('/local-session'))
        return Response.json(
          selected
            ? session(currentActor)
            : {
                ...session(),
                contextMode: 'PLATFORM',
                availableContexts: [{ ...context, displayLabel: 'Server context' }],
              },
        );
      return Response.json({ actor: currentActor });
    });
    render(<PolicyReleaseWorkflow />);
    fireEvent.click(await screen.findByRole('button', { name: 'Enter workspace' }));
    await waitFor(() =>
      expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1),
    );
    expect(performWebAuthnStepUp).toHaveBeenCalledWith(
      expect.objectContaining({ actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1' }),
      {
        resourceId: context.participantId,
        resourceDigest: `sha256:${createHash('sha256').update(JSON.stringify(context)).digest('hex')}`,
      },
      expect.objectContaining({ signal: expect.any(AbortSignal), isCurrent: expect.any(Function) }),
    );
    const post = fetcher.mock.calls.find(([, init]) => init?.method === 'POST')!;
    expect(JSON.parse(String(post[1]?.body))).toEqual({
      ...context,
      expectedSessionId: actor.sessionId,
    });
  },
);

it('stops a context digest completed after unmount before any ceremony or context POST', async () => {
  const held = deferred<ArrayBuffer>();
  const digestSpy = vi.spyOn(crypto.subtle, 'digest').mockReturnValueOnce(held.promise);
  const fetcher = reads(
    () => Response.json({ actor }),
    () =>
      Response.json({
        ...session(),
        contextMode: 'PLATFORM',
        availableContexts: [{ participantId: id(102), privacyDomainId: id(7201) }],
      }),
  );
  const view = render(<PolicyReleaseWorkflow />);
  const control = await screen.findByRole('button', { name: 'Enter workspace' });
  const original = seed();
  fireEvent.click(control);
  await waitFor(() => expect(digestSpy).toHaveBeenCalledOnce());
  view.unmount();
  await act(async () => held.resolve(new ArrayBuffer(32)));
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(localStorage.getItem(storageKey)).toBe(original);
});

it('requires the actual source session before starting a context-selection proof', async () => {
  const fetcher = reads(
    () => Response.json({ actor }),
    () =>
      Response.json({
        authenticated: true,
        role: 'viewer',
        contextMode: 'PLATFORM',
        availableContexts: [{ participantId: id(102), privacyDomainId: id(7201) }],
      }),
  );
  render(<PolicyReleaseWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Enter workspace' }));
  await screen.findAllByText(
    'The authenticated context response is unavailable. Refresh before continuing.',
  );
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});
it.each([200, 201])(
  'keeps a valid HTTP %s immutable policy preview and sends its exact candidate inputs once',
  async (status) => {
    const { saved, body } = policyMutationInput('PREVIEW');
    seed(saved);
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input, init) =>
        String(input).endsWith('/local-session')
          ? Response.json(session())
          : init?.method === 'POST'
            ? Response.json(originalSaved.review, { status })
            : Response.json(String(input).includes('/policy-release-workbench') ? body : { actor }),
      );
    render(<PolicyReleaseWorkflow />);
    const control = await policyMutationControl('PREVIEW');
    fireEvent.submit(control.closest('form')!);
    await screen.findByText(
      'Review locked. Verify the artifact and reason before requesting approval.',
    );
    expect(JSON.parse(localStorage.getItem(storageKey)!).value).toEqual({
      review: originalSaved.review,
    });
    expect(screen.getByRole('button', { name: 'Request checker approval' })).toBeEnabled();
    expect(
      screen.queryByRole('button', { name: 'Create approved release' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Activate with security key' }),
    ).not.toBeInTheDocument();
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  },
);

it.each(['SUBMIT_APPROVAL', 'CREATE_RELEASE', 'CREATE_OCCURRENCE'] as const)(
  'keeps the local missing-resource-ID failure for %s without inventing an identifier or progressing state',
  async (boundary) => {
    const { saved, body } = policyMutationInput(boundary);
    const original = seed(saved);
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input, init) =>
        String(input).endsWith('/local-session')
          ? Response.json(session())
          : init?.method === 'POST'
            ? Response.json({ operationId: id(99) })
            : Response.json(String(input).includes('/policy-release-workbench') ? body : { actor }),
      );
    render(<PolicyReleaseWorkflow />);
    fireEvent.click(await policyMutationControl(boundary));
    await screen.findByText(
      boundary === 'SUBMIT_APPROVAL'
        ? 'The approval owner did not return a resource identifier.'
        : boundary === 'CREATE_RELEASE'
          ? 'The release owner did not return a resource identifier.'
          : 'The activation owner did not return a resource identifier.',
    );
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    expect(
      fetcher.mock.calls.filter(
        ([input, init]) => !init?.method && String(input).includes('/policy-release-workbench'),
      ),
    ).toHaveLength(1);
  },
);
it('keeps missing server-authorized policy context as a local failure and sends no context mutation', async () => {
  const fetcher = reads(
    () => Response.json({ actor }),
    () =>
      Response.json({
        authenticated: true,
        contextMode: 'PLATFORM',
        role: 'viewer',
        availableContexts: [],
      }),
  );
  render(<PolicyReleaseWorkflow />);
  fireEvent.click(await screen.findByRole('button', { name: 'Enter workspace' }));
  await screen.findAllByText('No server-authorized Participant context is available.');
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});

function holdPolicyCeremony(phase: 'challenge' | 'navigator' | 'VERIFY') {
  const entered = deferred<void>(),
    release = deferred<void>();
  const phases: string[] = [];
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(async (_action, _binding, lifecycle) => {
    for (const currentPhase of ['challenge', 'navigator', 'VERIFY']) {
      if (lifecycle?.signal?.aborted || !lifecycle?.isCurrent?.())
        throw new DOMException('Cancelled ceremony', 'AbortError');
      phases.push(currentPhase);
      if (currentPhase === phase) {
        entered.resolve(undefined);
        await release.promise;
      }
      if (lifecycle?.signal?.aborted || !lifecycle?.isCurrent?.())
        throw new DOMException('Cancelled ceremony', 'AbortError');
    }
  });
  return { entered, release, phases };
}
it.each(['APPROVE', 'PUBLISH', 'ACTIVATE', 'ROLLBACK', 'RECOVER'] as const)(
  'cancels an unmounted policy %s ceremony before VERIFY or dependent mutation/readback',
  async (boundary) => {
    const { saved, body } = policyMutationInput(boundary);
    const original = seed(saved);
    const held = holdPolicyCeremony('navigator');
    const fetcher = reads(() => Response.json(body));
    const view = render(<PolicyReleaseWorkflow />);
    const control = await policyMutationControl(boundary);
    act(() => {
      fireEvent.click(control);
      fireEvent.click(control);
    });
    await held.entered.promise;
    expect(held.phases).toEqual(['challenge', 'navigator']);
    expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
    const lifecycle = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    expect(lifecycle.isCurrent?.()).toBe(true);
    view.unmount();
    expect(lifecycle.signal?.aborted).toBe(true);
    expect(lifecycle.isCurrent?.()).toBe(false);
    const before = fetcher.mock.calls.length;
    await act(async () => held.release.resolve(undefined));
    expect(held.phases).not.toContain('VERIFY');
    expect(fetcher.mock.calls).toHaveLength(before);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(localStorage.getItem(storageKey)).toBe(original);
  },
);
it.each(['challenge', 'navigator', 'VERIFY'] as const)(
  'cancels a held policy %s ceremony when the selected approval changes, without ACTIVATE reconciliation',
  async (phase) => {
    const { saved, body } = policyMutationInput('ACTIVATE');
    const original = seed(saved);
    const held = holdPolicyCeremony(phase);
    const fetcher = reads(() => Response.json(body));
    render(<PolicyReleaseWorkflow />);
    fireEvent.click(await policyMutationControl('ACTIVATE'));
    await held.entered.promise;
    expect(held.phases.at(-1)).toBe(phase);
    const before = fetcher.mock.calls.length;
    const selectors = screen.getByRole('button', { name: 'Load policy workflow' }).closest('form')!;
    fireEvent.change(within(selectors).getByLabelText('Approval ID'), {
      target: { value: id(55) },
    });
    const lifecycle = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    expect(lifecycle.signal?.aborted).toBe(true);
    expect(lifecycle.isCurrent?.()).toBe(false);
    await act(async () => held.release.resolve(undefined));
    expect(fetcher.mock.calls).toHaveLength(before);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(
      screen.queryByText(
        'The activation response was lost. Checking the original operation before continuing.',
      ),
    ).toBeNull();
    expect(screen.getByRole('button', { name: 'Activate with security key' })).toBeEnabled();
  },
);
it('checks policy caller ownership again when the helper returns after a selector edit', async () => {
  const { saved, body } = policyMutationInput('PUBLISH');
  const original = seed(saved),
    held = deferred<void>();
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(async () => held.promise);
  const fetcher = reads(() => Response.json(body));
  render(<PolicyReleaseWorkflow />);
  fireEvent.click(await policyMutationControl('PUBLISH'));
  await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
  fireEvent.change(screen.getByLabelText('Release ID'), { target: { value: id(56) } });
  await act(async () => held.resolve(undefined));
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(localStorage.getItem(storageKey)).toBe(original);
});
it('cancels an unmounted policy context-selection ceremony without sending a context mutation or clearing custody', async () => {
  const held = holdPolicyCeremony('challenge');
  const fetcher = reads(
    () => Response.json({ actor }),
    () =>
      Response.json({
        ...session(),
        contextMode: 'PLATFORM',
        availableContexts: [
          { participantId: actor.participantId, privacyDomainId: actor.privacyDomainId },
        ],
      }),
  );
  const view = render(<PolicyReleaseWorkflow />);
  const control = await screen.findByRole('button', { name: 'Enter workspace' });
  const original = seed();
  act(() => {
    fireEvent.click(control);
    fireEvent.click(control);
  });
  await held.entered.promise;
  expect(held.phases).toEqual(['challenge']);
  expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1);
  view.unmount();
  const before = fetcher.mock.calls.length;
  await act(async () => held.release.resolve(undefined));
  expect(held.phases).toEqual(['challenge']);
  expect(fetcher.mock.calls).toHaveLength(before);
  expect(localStorage.getItem(storageKey)).toBe(original);
});
it.each(['success', 'lost response'] as const)(
  'reconciles an already-sent ACTIVATE %s through original selectors despite an editable read field',
  async (outcome) => {
    const { saved, body } = policyMutationInput('ACTIVATE');
    const original = seed(saved),
      post = deferred();
    let completed = false;
    const posts: unknown[] = [],
      queries: string[] = [];
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url).endsWith('/local-session')) return Response.json(session());
      if (String(url).includes('/policy-release-workbench')) {
        if (init?.method === 'POST') {
          posts.push(JSON.parse(String(init.body)));
          return post.promise;
        }
        queries.push(String(url));
        return Response.json(completed ? workbench(selectors, actor, 'ACTIVE_MATCHED') : body);
      }
      return Response.json({ actor });
    });
    render(<PolicyReleaseWorkflow />);
    const control = await policyMutationControl('ACTIVATE');
    act(() => {
      fireEvent.click(control);
      fireEvent.click(control);
    });
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts).toEqual([{ command: 'ACTIVATE', occurrenceId: selectors.occurrenceId }]);
    fireEvent.change(screen.getByLabelText('Activation ID'), { target: { value: id(57) } });
    completed = true;
    await act(async () => {
      if (outcome === 'lost response')
        post.reject(new TypeError('original activation response lost'));
      else post.resolve(Response.json({ truthState: 'SUCCESS' }));
    });
    expect(
      await screen.findByRole('button', { name: 'Roll back with security key' }),
    ).toBeEnabled();
    expect(queries).toHaveLength(2);
    const originalQuery = new URL(queries[1]!, 'http://localhost').searchParams;
    expect(Object.fromEntries(originalQuery)).toEqual(selectors);
    expect(posts).toHaveLength(1);
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(document.body.textContent).not.toContain('original activation response lost');
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  },
);
it('does not reconcile or persist an unmounted ACTIVATE response loss', async () => {
  const { saved, body } = policyMutationInput('ACTIVATE');
  const original = seed(saved),
    post = deferred();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (url, init) =>
      init?.method === 'POST'
        ? post.promise
        : Response.json(
            String(url).endsWith('/local-session')
              ? session()
              : String(url).includes('/policy-release-workbench')
                ? body
                : { actor },
          ),
    );
  const view = render(<PolicyReleaseWorkflow />);
  fireEvent.click(await policyMutationControl('ACTIVATE'));
  await waitFor(() =>
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1),
  );
  view.unmount();
  const before = fetcher.mock.calls.length;
  await act(async () => post.reject(new TypeError('unmounted original response loss')));
  expect(fetcher.mock.calls).toHaveLength(before);
  expect(localStorage.getItem(storageKey)).toBe(original);
});
it.each(['success', 'failure'] as const)(
  'ignores an unmounted policy preview %s and admits its synchronous form only once',
  async (outcome) => {
    const { saved, body } = policyMutationInput('PREVIEW');
    const original = seed(saved),
      post = deferred();
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (url, init) =>
        init?.method === 'POST'
          ? post.promise
          : Response.json(
              String(url).endsWith('/local-session')
                ? session()
                : String(url).includes('/policy-release-workbench')
                  ? body
                  : { actor },
            ),
      );
    const view = render(<PolicyReleaseWorkflow />);
    const control = await policyMutationControl('PREVIEW');
    act(() => {
      fireEvent.submit(control.closest('form')!);
      fireEvent.submit(control.closest('form')!);
    });
    await waitFor(() =>
      expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1),
    );
    view.unmount();
    const before = fetcher.mock.calls.length;
    await act(async () => {
      if (outcome === 'failure') post.reject(new TypeError(unsafePolicyMarker));
      else post.resolve(Response.json(originalSaved.review));
    });
    expect(fetcher.mock.calls).toHaveLength(before);
    expect(localStorage.getItem(storageKey)).toBe(original);
  },
);
it('keeps an accepted policy preview usable when optional browser persistence throws', async () => {
  const { saved, body } = policyMutationInput('PREVIEW');
  seed(saved);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (url, init) =>
      init?.method === 'POST'
        ? Response.json(originalSaved.review)
        : Response.json(
            String(url).endsWith('/local-session')
              ? session()
              : String(url).includes('/policy-release-workbench')
                ? body
                : { actor },
          ),
    );
  render(<PolicyReleaseWorkflow />);
  const control = await policyMutationControl('PREVIEW');
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new Error(unsafePolicyMarker);
  });
  fireEvent.submit(control.closest('form')!);
  expect(await screen.findByRole('heading', { name: 'Release review' })).toBeVisible();
  expect(screen.getByRole('button', { name: 'Request checker approval' })).toBeEnabled();
  expect(document.body.textContent).not.toContain(unsafePolicyMarker);
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
});

it.each(['success', 'denial'] as const)(
  'shows loading instead of a false failure while the policy read is pending, then reports %s',
  async (outcome) => {
    const pending = deferred();
    let policyReads = 0;
    const fetcher = reads(() => {
      policyReads++;
      return pending.promise;
    });
    render(<PolicyReleaseWorkflow showSessionControls={false} evaluationUi />);
    await waitFor(() => expect(policyReads).toBe(1));
    expect(screen.getByRole('heading', { name: 'Loading workspace' })).toBeVisible();
    expect(screen.getByText('Loading approvals and release details…')).toBeVisible();
    expect(
      screen.queryByText('The policy workflow could not be loaded. Try refreshing it.'),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    await act(async () => {
      pending.resolve(
        outcome === 'success'
          ? Response.json({ actor })
          : Response.json({ title: 'Read denied', code: 'PC-AUTH-0005' }, { status: 403 }),
      );
    });
    if (outcome === 'success') {
      expect(await screen.findByRole('heading', { name: 'Policy workspace' })).toBeVisible();
      expect(
        screen.queryByText('The policy workflow could not be loaded. Try refreshing it.'),
      ).not.toBeInTheDocument();
    } else {
      expect(await screen.findByRole('alert')).toBeVisible();
      expect(
        screen.getByText('The policy workflow could not be loaded. Try refreshing it.'),
      ).toBeVisible();
    }
    expect(screen.queryByRole('heading', { name: 'Loading workspace' })).not.toBeInTheDocument();
    expect(fetcher.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
    expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  },
);
