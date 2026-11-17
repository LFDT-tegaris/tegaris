import { clearPolicyWorkflowStorage } from './policy-workflow-storage';
import { useState } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { PolicySets, type PolicySetReadValidity } from './policy-sets';
import type { PolicyWorkflowActorBinding } from './policy-workflow-storage';

const actor = {
  sessionId: '018f0000-0000-7000-8000-000000000117',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '1',
};
const id = '018f0000-0000-7000-8000-000000008301';
const resource = {
  policySetId: `urn:openpc:policy-set:${id}`,
  participantId: `urn:openpc:participant:${actor.participantId}`,
  createdAt: '2026-09-22T00:00:00.000000Z',
  updatedAt: '2026-09-22T00:00:00.000000Z',
  name: 'Initial policy',
  state: 'DRAFT',
  activeVersionDigest: null,
  revision: '1',
};
const page = (items: (typeof resource)[] = []) => ({
  items,
  nextCursor: null,
  total: String(items.length),
  completeness: 'COMPLETE',
  authorizedEmpty: items.length === 0,
  snapshotRevision: '1',
});
beforeEach(() => localStorage.clear());
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

it('reconciles an uncertain create with its original key and selects authoritative draft readback', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page()))
    .mockRejectedValueOnce(new Error('response lost'))
    .mockResolvedValueOnce(
      Response.json({ operation: { resourceRef: `urn:openpc:resource:${id}` } }),
    )
    .mockResolvedValueOnce(Response.json(resource));
  const selected = vi.fn();
  const user = userEvent.setup();
  render(<PolicySets actor={actor} selected="" onSelect={selected} />);
  await screen.findByText('No policy sets are available in this workspace.');
  await user.click(screen.getByRole('button', { name: /^Create a policy set$/u }));
  await user.type(screen.getByLabelText('New policy set name'), resource.name);
  await user.type(
    screen.getByLabelText('Reason for creating this policy set'),
    'Initial scoped policy',
  );
  await user.click(screen.getByRole('button', { name: 'Create policy set draft' }));
  await within(screen.getByRole('dialog', { name: 'Create a policy set' })).findByText(
    /result could not be confirmed/u,
  );
  await user.click(screen.getByRole('button', { name: 'Close Create a policy set' }));
  expect(screen.getByRole('button', { name: /^Create a policy set$/u })).toHaveFocus();
  await user.click(screen.getByRole('button', { name: /^Create a policy set$/u }));
  await user.click(screen.getByRole('button', { name: 'Create policy set draft' }));
  await within(screen.getByRole('dialog', { name: 'Create a policy set' })).findByText(
    'Draft created and read back. It grants no runtime authority.',
  );
  expect(fetch.mock.calls[1]![1]?.body).toBe(fetch.mock.calls[2]![1]?.body);
  expect(selected).toHaveBeenLastCalledWith(resource.policySetId);
  expect(screen.getByRole('option', { name: 'Initial policy · DRAFT' })).toBeInTheDocument();
});

it('clears authored data on context change and ignores an old-context read response', async () => {
  let resolve!: (response: Response) => void;
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementationOnce(
      () =>
        new Promise<Response>((done) => {
          resolve = done;
        }),
    )
    .mockResolvedValueOnce(Response.json(page()));
  const user = userEvent.setup();
  const selected = vi.fn();
  const view = render(<PolicySets actor={actor} selected="" onSelect={selected} />);
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
  await user.click(screen.getByRole('button', { name: /^Create a policy set$/u }));
  await user.type(screen.getByLabelText('New policy set name'), 'Private prior name');
  view.rerender(
    <PolicySets actor={{ ...actor, privacyDomainId: 'other' }} selected="" onSelect={selected} />,
  );
  await screen.findByText('No policy sets are available in this workspace.');
  expect(screen.queryByRole('dialog', { name: 'Create a policy set' })).toBeNull();
  expect(screen.getByLabelText('New policy set name')).toHaveValue('');
  await act(async () => resolve(Response.json(page([resource]))));
  expect(screen.queryByRole('option', { name: 'Initial policy · DRAFT' })).not.toBeInTheDocument();
  expect(selected).not.toHaveBeenCalled();
});

it.each(['malformed', 'foreign'] as const)(
  'reports an unusable selection for a %s public collection',
  async (mode) => {
    const validity = vi.fn();
    const response =
      mode === 'malformed'
        ? { items: [resource], nextCursor: null }
        : page([
            {
              ...resource,
              participantId: 'urn:openpc:participant:018f0000-0000-7000-8000-000000000102',
            },
          ]);
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(response));
    render(
      <PolicySets
        actor={actor}
        selected={resource.policySetId}
        onSelect={vi.fn()}
        onReadValidityChange={validity}
      />,
    );
    await screen.findByText('Policy sets could not be read in this context.');
    expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: null });
    expect(
      screen.queryByRole('option', { name: 'Initial policy · DRAFT' }),
    ).not.toBeInTheDocument();
  },
);
it('reports only the validated exact selected resource to the Composer seam', async () => {
  const validity = vi.fn();
  const selected = vi.fn();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page([resource])))
    .mockResolvedValueOnce(
      Response.json({ ...resource, policySetId: resource.policySetId.replace('8301', '8302') }),
    );
  render(
    <PolicySets
      actor={actor}
      selected={resource.policySetId}
      onSelect={selected}
      onReadValidityChange={validity}
    />,
  );
  await screen.findByText('Policy sets could not be read in this context.');
  expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: null });
  expect(selected).toHaveBeenLastCalledWith('');
});

it('does not restore an earlier selection when its detail arrives after the user clears it', async () => {
  let resolve!: (response: Response) => void;
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page([resource])))
    .mockImplementationOnce(
      () =>
        new Promise<Response>((done) => {
          resolve = done;
        }),
    );
  const select = vi.fn();
  const validity = vi.fn();
  function Caller() {
    const [selected, setSelected] = useState(resource.policySetId);
    return (
      <PolicySets
        actor={actor}
        selected={selected}
        onSelect={(value) => {
          select(value);
          setSelected(value);
        }}
        onReadValidityChange={validity}
      />
    );
  }
  const user = userEvent.setup();
  render(<Caller />);
  await screen.findByRole('option', { name: 'Initial policy · DRAFT' });
  await waitFor(() => expect(resolve).toBeDefined());
  await user.selectOptions(screen.getByLabelText('Policy set for this version'), '');
  await act(async () => resolve(Response.json(resource)));
  expect(screen.getByLabelText('Policy set for this version')).toHaveValue('');
  expect(select).toHaveBeenCalledTimes(1);
  expect(select).toHaveBeenLastCalledWith('');
  expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: '' });
});

const secondResource = {
  ...resource,
  policySetId: resource.policySetId.replace('8301', '8302'),
  name: 'Second policy',
};
const cursor = 'pc2.cGFnZQ.c2ln';
const draftStorageKey = 'openpc:policy-set-draft:v1';
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}
function ControlledPolicySets({
  initialSelected = '',
  onSelect = () => undefined,
  onValidity = () => undefined,
}: {
  initialSelected?: string;
  onSelect?: (value: string) => void;
  onValidity?: (value: PolicySetReadValidity) => void;
}) {
  const [selected, setSelected] = useState(initialSelected);
  return (
    <PolicySets
      actor={actor}
      selected={selected}
      onSelect={(value) => {
        onSelect(value);
        setSelected(value);
      }}
      onReadValidityChange={onValidity}
    />
  );
}
function boundDraft(selected = '') {
  const bound = JSON.stringify({
    actor,
    value: {
      name: 'Original draft name',
      reason: 'Original draft reason',
      requestKey: '018f0000-0000-7000-8000-000000008309',
      selected,
    },
  });
  localStorage.setItem(draftStorageKey, bound);
  return bound;
}
async function fillCreate() {
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: /^Create a policy set$/u }));
  await user.type(screen.getByLabelText('New policy set name'), secondResource.name);
  await user.type(
    screen.getByLabelText('Reason for creating this policy set'),
    'Original create intent',
  );
  return user;
}
function postCalls(fetch: { mock: { calls: Parameters<typeof globalThis.fetch>[] } }) {
  return fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
}

it.each(['success', 'failure', 'json'] as const)(
  'keeps a newer manual read when the initial %s settles late',
  async (mode) => {
    const old = deferred<Response>();
    const body = deferred<unknown>();
    const oldJson = vi.fn(() => body.promise);
    const oldResponse = new Response(null, { status: 200 });
    oldResponse.json = oldJson;
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementationOnce(() => (mode === 'json' ? Promise.resolve(oldResponse) : old.promise))
      .mockResolvedValueOnce(Response.json(page([secondResource])));
    render(<ControlledPolicySets />);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    if (mode === 'json') await waitFor(() => expect(oldJson).toHaveBeenCalledOnce());
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Refresh policy sets' }));
    await screen.findByRole('option', { name: 'Second policy · DRAFT' });
    await act(async () => {
      if (mode === 'json') body.resolve(page([resource]));
      else if (mode === 'failure') old.reject(new TypeError('Old transport failed'));
      else old.resolve(Response.json(page([resource])));
    });
    expect(
      screen.queryByRole('option', { name: 'Initial policy · DRAFT' }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Second policy · DRAFT' })).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(postCalls(fetch)).toHaveLength(0);
  },
);

it.each(['success', 'denied', 'transport', 'malformed', 'json'] as const)(
  'does not change a newer selection when an older detail %s settles',
  async (mode) => {
    const old = deferred<Response>();
    const body = deferred<unknown>();
    const oldJson = vi.fn(() => body.promise);
    const reply = new Response(null, { status: 200 });
    reply.json = oldJson;
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(page([resource, secondResource])))
      .mockImplementationOnce(() => (mode === 'json' ? Promise.resolve(reply) : old.promise));
    const select = vi.fn();
    const validity = vi.fn();
    render(
      <ControlledPolicySets
        initialSelected={resource.policySetId}
        onSelect={select}
        onValidity={validity}
      />,
    );
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
    if (mode === 'json') await waitFor(() => expect(oldJson).toHaveBeenCalledOnce());
    const user = userEvent.setup();
    await user.selectOptions(
      screen.getByLabelText('Policy set for this version'),
      secondResource.policySetId,
    );
    await act(async () => {
      if (mode === 'json') body.resolve(resource);
      else if (mode === 'transport') old.reject(new TypeError('Old detail failed'));
      else
        old.resolve(
          mode === 'denied'
            ? new Response(null, { status: 403 })
            : Response.json(mode === 'malformed' ? null : resource),
        );
    });
    expect(screen.getByLabelText('Policy set for this version')).toHaveValue(
      secondResource.policySetId,
    );
    expect(select).toHaveBeenCalledTimes(1);
    expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: secondResource.policySetId });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);

it('does not add a restored resource after the user clears the validated selection', async () => {
  boundDraft(resource.policySetId);
  const old = deferred<Response>();
  const validity = vi.fn();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page([secondResource])))
    .mockImplementationOnce(() => old.promise);
  render(<ControlledPolicySets onValidity={validity} />);
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  fireEvent.change(screen.getByLabelText('Policy set for this version'), { target: { value: '' } });
  await act(async () => old.resolve(Response.json(resource)));
  expect(screen.queryByRole('option', { name: 'Initial policy · DRAFT' })).not.toBeInTheDocument();
  expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: '' });
});

it('keeps a pagination denial unknown despite late restored detail, then retries by GET without losing custody', async () => {
  const bound = boundDraft(resource.policySetId);
  const old = deferred<Response>();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ ...page([secondResource]), nextCursor: cursor }))
    .mockImplementationOnce(() => old.promise)
    .mockResolvedValueOnce(new Response(null, { status: 403 }))
    .mockResolvedValueOnce(Response.json(page([resource])))
    .mockResolvedValueOnce(Response.json(resource));
  const select = vi.fn();
  const validity = vi.fn();
  render(<ControlledPolicySets onSelect={select} onValidity={validity} />);
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Load more policy sets' }));
  await screen.findByRole('alert');
  await act(async () => old.resolve(Response.json(resource)));
  expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: null });
  expect(select).toHaveBeenLastCalledWith('');
  expect(screen.getAllByRole('option')).toHaveLength(1);
  expect(screen.queryByText(resource.policySetId)).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Load more policy sets' })).not.toBeInTheDocument();
  expect(localStorage.getItem(draftStorageKey)).toBe(bound);
  await user.click(screen.getByRole('button', { name: 'Retry policy set reads' }));
  await waitFor(() =>
    expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: resource.policySetId }),
  );
  expect(screen.getByLabelText('Policy set for this version')).toHaveValue(resource.policySetId);
  expect(screen.getByLabelText('New policy set name')).toHaveValue('Original draft name');
  expect(screen.getByLabelText('Reason for creating this policy set')).toHaveValue(
    'Original draft reason',
  );
  expect(localStorage.getItem(draftStorageKey)).toBe(bound);
  expect(postCalls(fetch)).toHaveLength(0);
});

it.each(['success', 'failure', 'json'] as const)(
  'keeps a newer full read when an older pagination %s settles',
  async (mode) => {
    const old = deferred<Response>();
    const body = deferred<unknown>();
    const oldJson = vi.fn(() => body.promise);
    const reply = new Response(null, { status: 200 });
    reply.json = oldJson;
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json({ ...page([resource]), nextCursor: cursor }))
      .mockImplementationOnce(() => (mode === 'json' ? Promise.resolve(reply) : old.promise))
      .mockResolvedValueOnce(Response.json(page([secondResource])));
    render(<ControlledPolicySets />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Load more policy sets' }));
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
    if (mode === 'json') await waitFor(() => expect(oldJson).toHaveBeenCalledOnce());
    await user.click(screen.getByRole('button', { name: 'Refresh policy sets' }));
    await screen.findByRole('option', { name: 'Second policy · DRAFT' });
    await act(async () => {
      if (mode === 'json') body.resolve(page([resource]));
      else if (mode === 'failure') old.reject(new TypeError('Old pagination failed'));
      else old.resolve(Response.json(page([resource])));
    });
    expect(
      screen.queryByRole('option', { name: 'Initial policy · DRAFT' }),
    ).not.toBeInTheDocument();
    expect(screen.getByLabelText('Policy set for this version')).toBeEnabled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Load more policy sets' })).not.toBeInTheDocument();
    expect(postCalls(fetch)).toHaveLength(0);
  },
);

it.each(['initial', 'detail'] as const)(
  'fences the old %s read at original draft creation without dropping the POST outcome',
  async (stage) => {
    const old = deferred<Response>();
    const select = vi.fn();
    const validity = vi.fn();
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST')
        return Response.json({
          operation: {
            resourceRef: `urn:openpc:resource:${secondResource.policySetId.slice(-36)}`,
          },
        });
      const url = String(input);
      if (url.includes(encodeURIComponent(secondResource.policySetId)))
        return Response.json(secondResource);
      if (stage === 'initial' || url.includes('?policySetId=')) return old.promise;
      return Response.json(page([resource]));
    });
    render(
      <ControlledPolicySets
        initialSelected={stage === 'detail' ? resource.policySetId : ''}
        onSelect={select}
        onValidity={validity}
      />,
    );
    if (stage === 'detail') await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
    const user = await fillCreate();
    await user.click(screen.getByRole('button', { name: 'Create policy set draft' }));
    await screen.findByText('Draft created and read back. It grants no runtime authority.');
    await act(async () => old.reject(new TypeError('Old background read failed')));
    expect(screen.getByLabelText('Policy set for this version')).toHaveValue(
      secondResource.policySetId,
    );
    expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: secondResource.policySetId });
    expect(select).toHaveBeenLastCalledWith(secondResource.policySetId);
    expect(postCalls(fetch)).toHaveLength(1);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);

it('keeps the original ambiguous create key through a fenced read and manual GET refresh', async () => {
  const old = deferred<Response>();
  const post = deferred<Response>();
  let creates = 0;
  let collections = 0;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') {
      creates += 1;
      return creates === 1
        ? post.promise
        : Response.json({ operation: { resourceRef: `urn:openpc:resource:${id}` } });
    }
    if (String(input).includes('?policySetId=')) return Response.json(resource);
    collections += 1;
    return collections === 1 ? old.promise : Response.json(page());
  });
  const selected = vi.fn();
  render(<ControlledPolicySets onSelect={selected} />);
  const user = await fillCreate();
  await user.click(screen.getByRole('button', { name: 'Create policy set draft' }));
  await waitFor(() => expect(postCalls(fetch)).toHaveLength(1));
  const bound = localStorage.getItem(draftStorageKey);
  const body = postCalls(fetch)[0]![1]?.body;
  expect(screen.getByRole('button', { name: 'Refresh policy sets' })).toBeDisabled();
  await act(async () => old.resolve(Response.json(page([secondResource]))));
  expect(selected).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Create policy set draft' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Refresh policy sets' })).toBeDisabled();
  await act(async () => post.reject(new TypeError('Original POST response lost')));
  await screen.findByText(/result could not be confirmed/u);
  await user.click(screen.getByRole('button', { name: 'Refresh policy sets' }));
  await screen.findByText('No policy sets are available in this workspace.');
  expect(localStorage.getItem(draftStorageKey)).toBe(bound);
  expect(postCalls(fetch)).toHaveLength(1);
  await user.click(screen.getByRole('button', { name: 'Create policy set draft' }));
  await screen.findByText('Draft created and read back. It grants no runtime authority.');
  expect(postCalls(fetch)[1]![1]?.body).toBe(body);
  expect(selected).toHaveBeenLastCalledWith(resource.policySetId);
});

it.each(['denied', 'transport', 'json', 'malformed'] as const)(
  'retries a current initial %s by GET with the exact current edited draft',
  async (mode) => {
    boundDraft();
    const invalid = new Response(null, { status: 200 });
    invalid.json = vi.fn().mockRejectedValue(new SyntaxError('Unreadable JSON'));
    const fetch = vi.spyOn(globalThis, 'fetch');
    if (mode === 'transport') fetch.mockRejectedValueOnce(new TypeError('Read failed'));
    else
      fetch.mockResolvedValueOnce(
        mode === 'denied'
          ? new Response(null, { status: 403 })
          : mode === 'json'
            ? invalid
            : Response.json({ items: null }),
      );
    fetch.mockResolvedValueOnce(Response.json(page([resource])));
    render(<ControlledPolicySets />);
    await screen.findByRole('alert');
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /^Create a policy set$/u }));
    await user.clear(screen.getByLabelText('New policy set name'));
    await user.type(screen.getByLabelText('New policy set name'), 'Edited current draft');
    const currentBound = localStorage.getItem(draftStorageKey);
    await user.click(screen.getByRole('button', { name: 'Retry policy set reads' }));
    await screen.findByRole('option', { name: 'Initial policy · DRAFT' });
    expect(screen.getByLabelText('New policy set name')).toHaveValue('Edited current draft');
    expect(localStorage.getItem(draftStorageKey)).toBe(currentBound);
    expect(postCalls(fetch)).toHaveLength(0);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);

it.each(['denied', 'transport', 'json', 'foreign', 'alias'] as const)(
  'removes a current detail projection for %s and restores only exact GET readback',
  async (mode) => {
    const bound = boundDraft(resource.policySetId);
    const invalid = new Response(null, { status: 200 });
    invalid.json = vi.fn().mockRejectedValue(new SyntaxError('Unreadable detail'));
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(page([resource])));
    if (mode === 'transport') fetch.mockRejectedValueOnce(new TypeError('Detail failed'));
    else
      fetch.mockResolvedValueOnce(
        mode === 'denied'
          ? new Response(null, { status: 404 })
          : mode === 'json'
            ? invalid
            : Response.json(
                mode === 'foreign'
                  ? { ...resource, participantId: `urn:openpc:participant:${id}` }
                  : { ...resource, policySetId: `urn:openpc:resource:${id}` },
              ),
      );
    fetch
      .mockResolvedValueOnce(Response.json(page()))
      .mockResolvedValueOnce(Response.json(resource));
    const validity = vi.fn();
    render(<ControlledPolicySets initialSelected={resource.policySetId} onValidity={validity} />);
    await screen.findByRole('alert');
    expect(screen.queryByText(resource.policySetId)).not.toBeInTheDocument();
    expect(screen.getAllByRole('option')).toHaveLength(1);
    expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: null });
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Retry policy set reads' }));
    await waitFor(() =>
      expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: resource.policySetId }),
    );
    expect(localStorage.getItem(draftStorageKey)).toBe(bound);
    expect(screen.getByLabelText('Policy set for this version')).toHaveValue(resource.policySetId);
    expect(postCalls(fetch)).toHaveLength(0);
  },
);

it.each(['denied', 'transport', 'json', 'malformed', 'foreign'] as const)(
  'invalidates a current pagination %s and retries the collection without the old cursor',
  async (mode) => {
    const invalid = new Response(null, { status: 200 });
    invalid.json = vi.fn().mockRejectedValue(new SyntaxError('Unreadable pagination'));
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json({ ...page([resource]), nextCursor: cursor }));
    if (mode === 'transport') fetch.mockRejectedValueOnce(new TypeError('Pagination failed'));
    else
      fetch.mockResolvedValueOnce(
        mode === 'denied'
          ? new Response(null, { status: 403 })
          : mode === 'json'
            ? invalid
            : Response.json(
                mode === 'malformed'
                  ? { ...page(), nextCursor: 'invalid' }
                  : page([{ ...resource, participantId: `urn:openpc:participant:${id}` }]),
              ),
      );
    fetch.mockResolvedValueOnce(Response.json(page([secondResource])));
    const validity = vi.fn();
    render(<ControlledPolicySets onValidity={validity} />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Load more policy sets' }));
    await screen.findByRole('alert');
    expect(screen.getAllByRole('option')).toHaveLength(1);
    expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: null });
    await user.click(screen.getByRole('button', { name: 'Retry policy set reads' }));
    await screen.findByRole('option', { name: 'Second policy · DRAFT' });
    expect(fetch.mock.calls[2]![0]).toBe('/api/v1/ui/policy-sets');
    expect(postCalls(fetch)).toHaveLength(0);
  },
);

it('paginates by the opaque cursor and verifies its selected resource in the current read generation', async () => {
  let pages = 0;
  const validity = vi.fn();
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input).includes('?policySetId=')) return Response.json(resource);
    pages += 1;
    return Response.json(
      pages === 1 ? { ...page([resource]), nextCursor: cursor } : page([resource, secondResource]),
    );
  });
  render(<ControlledPolicySets initialSelected={resource.policySetId} onValidity={validity} />);
  await waitFor(() =>
    expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: resource.policySetId }),
  );
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Load more policy sets' }));
  await screen.findByRole('option', { name: 'Second policy · DRAFT' });
  await waitFor(() => expect(screen.getByLabelText('Policy set for this version')).toBeEnabled());
  expect(screen.getAllByRole('option')).toHaveLength(3);
  expect(screen.getByLabelText('Policy set for this version')).toHaveValue(resource.policySetId);
  expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: resource.policySetId });
  expect(
    fetch.mock.calls.some(
      ([url]) => String(url) === `/api/v1/ui/policy-sets?cursor=${encodeURIComponent(cursor)}`,
    ),
  ).toBe(true);
  expect(fetch.mock.calls.filter(([url]) => String(url).includes('?policySetId='))).toHaveLength(2);
});

it.each(['COMPLETE', 'UNKNOWN'] as const)(
  'accepts an empty %s public page without granting a selected resource',
  async (completeness) => {
    const validity = vi.fn();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({
        ...page(),
        completeness,
        authorizedEmpty: completeness === 'COMPLETE',
        total: completeness === 'UNKNOWN' ? null : '0',
        additiveField: { retained: true },
      }),
    );
    render(<ControlledPolicySets onValidity={validity} />);
    await screen.findByText(
      completeness === 'COMPLETE'
        ? 'No policy sets are available in this workspace.'
        : 'This page has no policy sets. More results may be available.',
    );
    expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: '' });
    expect(screen.getAllByRole('option')).toHaveLength(1);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);

it.each([
  ['items-null', { ...page(), items: null }],
  ['resource-state', page([{ ...resource, state: 'PREPARED' } as typeof resource])],
  ['resource-name', page([{ ...resource, name: '' }])],
  ['resource-revision', page([{ ...resource, revision: '0' }])],
  [
    'resource-digest',
    page([{ ...resource, activeVersionDigest: 'bad' } as unknown as typeof resource]),
  ],
  ['total-overbound', { ...page(), total: '1'.repeat(21) }],
  ['snapshot-overbound', { ...page(), snapshotRevision: '1'.repeat(21) }],
  ['cursor-overbound', { ...page(), nextCursor: `pc2.${'A'.repeat(2043)}.B` }],
  ['cursor-malformed', { ...page(), nextCursor: 'ordinary-private-cursor' }],
  [
    'missing-empty',
    { items: [], nextCursor: null, total: '0', completeness: 'COMPLETE', snapshotRevision: '1' },
  ],
  ['wrong-completeness', { ...page(), completeness: 'CERTAIN' }],
  ['root-null', null],
  ['root-array', []],
] as const)(
  'refuses the malformed public %s before rendering items or a continuation',
  async (_name, value) => {
    const validity = vi.fn();
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(value));
    render(<ControlledPolicySets onValidity={validity} />);
    await screen.findByRole('alert');
    expect(screen.getAllByRole('option')).toHaveLength(1);
    expect(screen.queryByRole('button', { name: 'Load more policy sets' })).not.toBeInTheDocument();
    expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: null });
    expect(fetch).toHaveBeenCalledTimes(1);
  },
);

it('accepts the exact public cursor and numeric lexical bounds with harmless resource additions', async () => {
  const maxCursor = `pc2.${'A'.repeat(2042)}.B`;
  expect(maxCursor).toHaveLength(2048);
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      ...page([{ ...resource, additiveField: true } as typeof resource]),
      total: '9'.repeat(20),
      snapshotRevision: '9'.repeat(20),
      nextCursor: maxCursor,
    }),
  );
  render(<ControlledPolicySets />);
  await screen.findByRole('option', { name: 'Initial policy · DRAFT' });
  expect(screen.getByRole('button', { name: 'Load more policy sets' })).toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const)(
  'blocks obsolete dependent detail after %s changes during initial JSON',
  async (field) => {
    const body = deferred<unknown>();
    const json = vi.fn(() => body.promise);
    const initial = new Response(null, { status: 200 });
    initial.json = json;
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(initial)
      .mockResolvedValueOnce(Response.json(page()));
    const selected = vi.fn();
    const validity = vi.fn();
    const view = render(
      <PolicySets
        actor={actor}
        selected={resource.policySetId}
        onSelect={selected}
        onReadValidityChange={validity}
      />,
    );
    await waitFor(() => expect(json).toHaveBeenCalledOnce());
    const changed: PolicyWorkflowActorBinding = {
      ...actor,
      [field]: field === 'contextEpoch' ? '2' : '018f0000-0000-7000-8000-000000000199',
    };
    view.rerender(
      <PolicySets
        actor={changed}
        selected=""
        onSelect={selected}
        onReadValidityChange={validity}
      />,
    );
    await screen.findByText('No policy sets are available in this workspace.');
    await act(async () => body.resolve(page([resource])));
    expect(fetch.mock.calls.filter(([url]) => String(url).includes('?policySetId='))).toHaveLength(
      0,
    );
    expect(selected).not.toHaveBeenCalled();
    expect(validity).toHaveBeenLastCalledWith({ actor: changed, policySetId: '' });
    expect(
      screen.queryByRole('option', { name: 'Initial policy · DRAFT' }),
    ).not.toBeInTheDocument();
  },
);

it.each(['actor', 'unmount'] as const)(
  'does not issue obsolete created detail after %s during the original POST JSON',
  async (mode) => {
    const body = deferred<unknown>();
    const json = vi.fn(() => body.promise);
    const receipt = new Response(null, { status: 200 });
    receipt.json = json;
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (_input, init) =>
        init?.method === 'POST' ? receipt : Response.json(page()),
      );
    const selected = vi.fn();
    const view = render(<PolicySets actor={actor} selected="" onSelect={selected} />);
    await screen.findByText('No policy sets are available in this workspace.');
    const user = await fillCreate();
    await user.click(screen.getByRole('button', { name: 'Create policy set draft' }));
    await waitFor(() => expect(json).toHaveBeenCalledOnce());
    if (mode === 'unmount') view.unmount();
    else
      view.rerender(
        <PolicySets actor={{ ...actor, contextEpoch: '2' }} selected="" onSelect={selected} />,
      );
    if (mode === 'actor')
      await screen.findByText('No policy sets are available in this workspace.');
    const bound = localStorage.getItem(draftStorageKey);
    await act(async () =>
      body.resolve({ operation: { resourceRef: `urn:openpc:resource:${id}` } }),
    );
    expect(fetch.mock.calls.filter(([url]) => String(url).includes('?policySetId='))).toHaveLength(
      0,
    );
    expect(selected).not.toHaveBeenCalled();
    expect(localStorage.getItem(draftStorageKey)).toBe(bound);
    expect(postCalls(fetch)).toHaveLength(1);
  },
);

it('drops initial JSON after unmount without a detail read, callback or storage write', async () => {
  const body = deferred<unknown>();
  const json = vi.fn(() => body.promise);
  const reply = new Response(null, { status: 200 });
  reply.json = json;
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(reply);
  const selected = vi.fn();
  const validity = vi.fn();
  const view = render(
    <PolicySets
      actor={actor}
      selected={resource.policySetId}
      onSelect={selected}
      onReadValidityChange={validity}
    />,
  );
  await waitFor(() => expect(json).toHaveBeenCalledOnce());
  view.unmount();
  selected.mockClear();
  validity.mockClear();
  const bound = localStorage.getItem(draftStorageKey);
  await act(async () => body.resolve(page([resource])));
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(selected).not.toHaveBeenCalled();
  expect(validity).not.toHaveBeenCalled();
  expect(localStorage.getItem(draftStorageKey)).toBe(bound);
});

it.each(['denied', 'json', 'wrong-id', 'foreign', 'malformed'] as const)(
  'keeps the original create unconfirmed after %s authoritative detail and reuses its exact POST',
  async (mode) => {
    const invalid = new Response(null, { status: 200 });
    invalid.json = vi.fn().mockRejectedValue(new SyntaxError('Unreadable create detail'));
    const failed =
      mode === 'denied'
        ? new Response(null, { status: 403 })
        : mode === 'json'
          ? invalid
          : Response.json(
              mode === 'wrong-id'
                ? secondResource
                : mode === 'foreign'
                  ? { ...resource, participantId: `urn:openpc:participant:${id}` }
                  : null,
            );
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(page()))
      .mockResolvedValueOnce(
        Response.json({ operation: { resourceRef: `urn:openpc:resource:${id}` } }),
      )
      .mockResolvedValueOnce(failed)
      .mockResolvedValueOnce(
        Response.json({ operation: { resourceRef: `urn:openpc:resource:${id}` } }),
      )
      .mockResolvedValueOnce(Response.json(resource));
    const selected = vi.fn();
    render(<ControlledPolicySets onSelect={selected} />);
    await screen.findByText('No policy sets are available in this workspace.');
    const user = await fillCreate();
    await user.click(screen.getByRole('button', { name: 'Create policy set draft' }));
    await screen.findByText(/result could not be confirmed/u);
    const bound = localStorage.getItem(draftStorageKey);
    expect(bound).toContain(JSON.parse(String(postCalls(fetch)[0]![1]?.body)).requestKey);
    expect(selected).not.toHaveBeenCalled();
    expect(
      screen.queryByText('Draft created and read back. It grants no runtime authority.'),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create policy set draft' }));
    await screen.findByText('Draft created and read back. It grants no runtime authority.');
    expect(postCalls(fetch)).toHaveLength(2);
    expect(postCalls(fetch)[1]![1]?.body).toBe(postCalls(fetch)[0]![1]?.body);
    expect(selected).toHaveBeenLastCalledWith(resource.policySetId);
  },
);

it('does not resurrect a selected detail JSON after a newer read denial', async () => {
  boundDraft(resource.policySetId);
  const body = deferred<unknown>();
  const json = vi.fn(() => body.promise);
  const reply = new Response(null, { status: 200 });
  reply.json = json;
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page([resource])))
    .mockResolvedValueOnce(reply)
    .mockResolvedValueOnce(new Response(null, { status: 403 }));
  const validity = vi.fn();
  render(<ControlledPolicySets onValidity={validity} />);
  await waitFor(() => expect(json).toHaveBeenCalledOnce());
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Refresh policy sets' }));
  await screen.findByRole('alert');
  await act(async () => body.resolve(resource));
  expect(screen.getAllByRole('option')).toHaveLength(1);
  expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: null });
  expect(screen.getByRole('button', { name: 'Retry policy set reads' })).toBeEnabled();
  expect(postCalls(fetch)).toHaveLength(0);
});

it.each(['DRAFT', 'ACTIVE', 'RETIRED'] as const)(
  'keeps the fixed %s owner projection and harmless fields compatible',
  async (state) => {
    const value = {
      ...resource,
      state,
      activeVersionDigest: state === 'ACTIVE' ? `sha256:${'a'.repeat(64)}` : null,
      additiveField: 'compatible',
    };
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json({ ...page(), items: [value] }));
    render(<ControlledPolicySets />);
    await screen.findByRole('option', { name: `Initial policy · ${state}` });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);

it('preserves the validated same-selection callback through refresh until current detail proves denial', async () => {
  const refreshed = deferred<Response>();
  const validity = vi.fn();
  const select = vi.fn();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page([resource])))
    .mockResolvedValueOnce(Response.json(resource))
    .mockImplementationOnce(() => refreshed.promise)
    .mockResolvedValueOnce(Response.json(resource))
    .mockResolvedValueOnce(Response.json(page()))
    .mockResolvedValueOnce(new Response(null, { status: 403 }));
  render(
    <ControlledPolicySets
      initialSelected={resource.policySetId}
      onSelect={select}
      onValidity={validity}
    />,
  );
  await waitFor(() => expect(select).toHaveBeenCalledWith(resource.policySetId));
  validity.mockClear();
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Refresh policy sets' }));
  expect(screen.getByLabelText('Policy set for this version')).toHaveValue(resource.policySetId);
  expect(validity.mock.calls.some(([value]) => value.policySetId === null)).toBe(false);
  await act(async () => refreshed.resolve(Response.json(page())));
  await waitFor(() => expect(select).toHaveBeenCalledTimes(2));
  expect(validity.mock.calls.some(([value]) => value.policySetId === null)).toBe(false);
  expect(screen.getByLabelText('Policy set for this version')).toHaveValue(resource.policySetId);
  await user.click(screen.getByRole('button', { name: 'Refresh policy sets' }));
  await screen.findByRole('alert');
  expect(validity).toHaveBeenLastCalledWith({ actor, policySetId: null });
  expect(select).toHaveBeenLastCalledWith('');
  expect(screen.getByLabelText('Policy set for this version')).toHaveValue('');
  expect(postCalls(fetch)).toHaveLength(0);
});

it.each(['create', 'detail'] as const)(
  'does not restore draft custody from a late %s after privacy cleanup',
  async (stage) => {
    const pending = deferred<Response>();
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(page()))
      .mockReturnValueOnce(
        stage === 'create'
          ? pending.promise
          : Promise.resolve(
              Response.json({ operation: { resourceRef: `urn:openpc:resource:${id}` } }),
            ),
      )
      .mockReturnValueOnce(pending.promise);
    const selected = vi.fn();
    render(<PolicySets actor={actor} selected="" onSelect={selected} />);
    await screen.findByText('No policy sets are available in this workspace.');
    const user = await fillCreate();
    await user.click(screen.getByRole('button', { name: 'Create policy set draft' }));
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(stage === 'create' ? 2 : 3));
    expect(localStorage.getItem(draftStorageKey)).not.toBeNull();
    act(() => clearPolicyWorkflowStorage());
    expect(localStorage.getItem(draftStorageKey)).toBeNull();
    selected.mockClear();
    await act(async () =>
      pending.resolve(
        Response.json(
          stage === 'create'
            ? { operation: { resourceRef: `urn:openpc:resource:${id}` } }
            : resource,
        ),
      ),
    );
    expect(localStorage.getItem(draftStorageKey)).toBeNull();
    expect(selected).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(stage === 'create' ? 2 : 3);
  },
);

it('opens and closes the creation panel without submitting or losing its unsent draft', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(page()));
  const user = userEvent.setup();
  render(<PolicySets actor={actor} selected="" onSelect={vi.fn()} />);
  await screen.findByText('No policy sets are available in this workspace.');
  const trigger = screen.getByRole('button', { name: /^Create a policy set$/u });
  expect(screen.queryByRole('dialog')).toBeNull();
  await user.click(trigger);
  const panel = screen.getByRole('dialog', { name: 'Create a policy set' });
  await user.type(within(panel).getByLabelText('New policy set name'), 'Institutional payments');
  const saved = localStorage.getItem(draftStorageKey);
  await user.click(within(panel).getByRole('button', { name: 'Close Create a policy set' }));
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(trigger).toHaveFocus();
  expect(localStorage.getItem(draftStorageKey)).toBe(saved);
  await user.click(trigger);
  expect(within(screen.getByRole('dialog')).getByLabelText('New policy set name')).toHaveValue(
    'Institutional payments',
  );
  expect(postCalls(fetch)).toHaveLength(0);
});

it('keeps creation controls out of the simulation-only view', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(page()));
  render(<PolicySets actor={actor} selected="" onSelect={vi.fn()} showCreation={false} />);
  await screen.findByText('No policy sets are available in this workspace.');
  expect(screen.queryByRole('button', { name: /^Create a policy set$/u })).toBeNull();
  expect(screen.queryByLabelText('New policy set name')).toBeNull();
  expect(
    screen.getByText('Refresh after a policy set is made available in this workspace.'),
  ).toBeVisible();
  expect(postCalls(fetch)).toHaveLength(0);
});

it('does not turn an empty page with a continuation into a complete empty collection', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json({ ...page(), nextCursor: cursor }));
  render(<PolicySets actor={actor} selected="" onSelect={vi.fn()} />);
  await screen.findByText('This page has no policy sets. More results may be available.');
  expect(screen.queryByText('No policy sets are available in this workspace.')).toBeNull();
  expect(screen.getByRole('button', { name: 'Load more policy sets' })).toBeVisible();
});
