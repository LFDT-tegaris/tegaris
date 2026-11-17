import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import {
  ModuleExtensionBoundary,
  ModuleContributionBoundary,
  useModuleExtensionLifetime,
  type ModuleExtensionRequest,
  type ModuleExtensionLifetime,
} from './module-extension-boundary';
import {
  moduleExtensionEventName,
  moduleExtensionObservationOf,
  moduleExtensionSnapshot,
  type ModuleExtensionSnapshot,
} from '../../lib/module-extensions';

// Component BFF/transport fixtures only, never real lifecycle acceptance.
const digest = (n: string) => `sha256:${n.repeat(64)}`;
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const snapshot = (): ModuleExtensionSnapshot => ({
  kind: 'MODULE_EXTENSIONS',
  query: { routeId: 'ROUTE-MODULE-LIFECYCLE' },
  binding: {
    actorKey: digest('a'),
    observationKey: digest('b'),
    participantId: id(1),
    privacyDomainId: id(2),
  },
  entries: [
    {
      moduleId: 'pc.example',
      moduleRef: `urn:openpc:resource:${id(3)}`,
      moduleVersion: '1.0.0',
      moduleDigest: digest('e'),
      moduleRevision: '3',
      uiManifestDigest: digest('f'),
      contribution: {
        contributionId: 'UICONTRIB-EXAMPLE',
        slotId: 'UISLOT-ROUTE-CONTENT',
        kind: 'REGISTERED_VIEW',
        phase: 'AFTER_DOMAIN_CONTENT',
        anchor: 'ROUTE-MODULE-LIFECYCLE',
        priority: 100,
        capabilityRequirements: [],
        routeBehavior: 'NO_ROUTE',
        actionIntents: [],
        dataQueries: [],
        viewOrFormId: 'VIEW-MODULE_LIFECYCLE',
        versionRange: '>=1.0.0 <2.0.0',
        accessibilityMetadataId: 'A11Y-EXAMPLE',
        localizationNamespace: 'openpc.example',
        unloadBehavior: 'UNMOUNT_CANCEL_CLEAR_REAUTHORIZE',
      },
    },
  ],
});
const observation = (
  type: 'CURRENT' | 'INVALIDATED' | 'REOBSERVE' = 'CURRENT',
  key = digest('b'),
  actorKey = digest('a'),
) => ({
  type,
  ...moduleExtensionObservationOf({
    ...snapshot(),
    binding: { ...snapshot().binding, actorKey, observationKey: key },
  }),
});
const streams: Stream[] = [];
class Stream {
  onerror: (() => void) | null = null;
  listeners = new Map<string, (event: MessageEvent<string>) => void>();
  closed = false;
  constructor() {
    streams.push(this);
  }
  addEventListener(name: string, callback: (event: MessageEvent<string>) => void) {
    this.listeners.set(name, callback);
  }
  close() {
    this.closed = true;
  }
  frame(value: unknown) {
    this.listeners.get(moduleExtensionEventName)?.(
      new MessageEvent('module-extensions', { data: JSON.stringify(value) }),
    );
  }
}
let ticket: ModuleExtensionRequest;
let lifetime: ModuleExtensionLifetime;
const stop = vi.fn();
function Protected() {
  lifetime = useModuleExtensionLifetime();
  const [draft, setDraft] = useState('');
  useEffect(() => {
    ticket = lifetime.beginRequest();
    return lifetime.registerCleanup(stop);
  }, [lifetime]);
  return (
    <>
      <label>
        Protected draft
        <input value={draft} onChange={(event) => setDraft(event.target.value)} />
      </label>
      <p>Protected module</p>
    </>
  );
}
function mount(contextKey = 'context-one') {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const tree = (key: string, visible = true) => (
    <QueryClientProvider client={client}>
      <ModuleExtensionBoundary
        routeId="ROUTE-MODULE-LIFECYCLE"
        contextKey={key}
        safety={<p>Sealed safety controls</p>}
      >
        {visible && (
          <ModuleContributionBoundary contributionId="UICONTRIB-EXAMPLE">
            <Protected />
          </ModuleContributionBoundary>
        )}
        <p>Independent contribution</p>
      </ModuleExtensionBoundary>
    </QueryClientProvider>
  );
  const view = render(tree(contextKey));
  return {
    ...view,
    client,
    change: (key: string) => view.rerender(tree(key)),
    remove: () => view.rerender(tree(contextKey, false)),
  };
}
async function open() {
  await waitFor(() => expect(streams.length).toBeGreaterThan(0));
  act(() => streams.at(-1)!.frame(observation()));
  await screen.findByText('Protected module');
}
beforeEach(() => {
  streams.length = 0;
  stop.mockReset();
  vi.stubGlobal('EventSource', Stream);
  vi.stubGlobal(
    'fetch',
    vi
      .fn()
      .mockImplementation(async () =>
        Response.json(snapshot(), { headers: { 'Cache-Control': 'no-store' } }),
      ),
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
it('waits for matching current observation and preserves sealed safety while loading', async () => {
  mount();
  await waitFor(() => expect(streams).toHaveLength(1));
  expect(screen.queryByText('Protected module')).toBeNull();
  expect(screen.getByText('Sealed safety controls')).toBeVisible();
  await open();
  expect(screen.getByText('Protected module')).toBeVisible();
});
it('invalidates draft/cache/subscriptions/requests and rejects late response tickets', async () => {
  const { client } = mount();
  await open();
  fireEvent.change(screen.getByLabelText('Protected draft'), {
    target: { value: 'private draft' },
  });
  client.setQueryData([...lifetime.queryKey, 'detail'], { private: 'secret' });
  const original = ticket;
  act(() => streams[0]!.frame(observation('INVALIDATED', digest('c'))));
  expect(screen.queryByLabelText('Protected draft')).toBeNull();
  expect(screen.getByText('Sealed safety controls')).toBeVisible();
  expect(original.signal.aborted).toBe(true);
  expect(original.current()).toBe(false);
  expect(stop).toHaveBeenCalledTimes(1);
  expect(streams[0]!.closed).toBe(true);
  expect(client.getQueryData([...lifetime.queryKey, 'detail'])).toBeUndefined();
  act(() => streams[0]!.frame(observation()));
  expect(screen.queryByText('Protected module')).toBeNull();
});
it('unmounts on synchronous context replacement and does not accept old observation frames', async () => {
  const view = mount();
  await open();
  const old = ticket;
  view.change('context-two');
  expect(screen.queryByText('Protected module')).toBeNull();
  expect(old.current()).toBe(false);
  act(() => streams[0]!.frame(observation()));
  expect(screen.queryByText('Protected module')).toBeNull();
});
it('discards an old HTTP response after context changed even when transport ignores abort', async () => {
  let resolve!: (response: Response) => void;
  vi.mocked(fetch).mockImplementationOnce(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  const view = mount();
  view.change('context-two');
  await waitFor(() => expect(streams).toHaveLength(1));
  await act(async () => {
    resolve(Response.json(snapshot(), { headers: { 'Cache-Control': 'no-store' } }));
  });
  expect(streams).toHaveLength(1);
  expect(screen.queryByText('Protected module')).toBeNull();
});
it('unmounts on malformed/error observations and permits only fresh readback on reconnect', async () => {
  mount();
  await open();
  act(() => streams[0]!.frame({ ...observation(), enabled: true }));
  expect(screen.queryByText('Protected module')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh module contributions' }));
  await waitFor(() => expect(streams).toHaveLength(2));
  act(() => streams[1]!.frame(observation()));
  expect(await screen.findByLabelText('Protected draft')).toHaveValue('');
  act(() => streams[1]!.onerror?.());
  expect(screen.queryByText('Protected module')).toBeNull();
});
it('retains original operation identity across teardown, without retrying the business command', async () => {
  mount();
  await open();
  const original = ticket;
  original.retainOperation({ requestId: id(10) });
  act(() => streams[0]!.onerror?.());
  original.retainOperation({ requestId: id(10), operationId: id(11) });
  fireEvent.click(screen.getByRole('button', { name: 'Refresh module contributions' }));
  await waitFor(() => expect(streams).toHaveLength(2));
  act(() => streams[1]!.frame(observation()));
  expect(lifetime.originalOperations()).toEqual([{ requestId: id(10), operationId: id(11) }]);
  expect(
    vi.mocked(fetch).mock.calls.every(([, init]) => !init?.method || init.method === 'GET'),
  ).toBe(true);
  expect(() => original.retainOperation({ requestId: id(10), operationId: id(12) })).toThrow(
    'Original module operation identity changed',
  );
});
it('fails closed when the current observation stream stalls', async () => {
  mount();
  await open();
  vi.useFakeTimers();
  act(() => streams[0]!.frame(observation()));
  act(() => vi.advanceTimersByTime(10_001));
  expect(screen.queryByText('Protected module')).toBeNull();
  expect(ticket.current()).toBe(false);
});
it('cancels and clears an unmounted contribution without discarding a healthy sibling', async () => {
  const view = mount();
  await open();
  const original = ticket;
  const key = [...lifetime.queryKey, 'detail'];
  view.client.setQueryData(key, 'private value');
  view.remove();
  expect(original.signal.aborted).toBe(true);
  expect(original.current()).toBe(false);
  expect(view.client.getQueryData(key)).toBeUndefined();
  expect(stop).toHaveBeenCalledTimes(1);
  expect(screen.getByText('Independent contribution')).toBeVisible();
  expect(streams[0]!.closed).toBe(false);
});
it('contains cleanup failure, closes the outer lifetime and preserves sealed safety', async () => {
  const view = mount();
  await open();
  stop.mockImplementationOnce(() => {
    throw new Error('private cleanup failure');
  });
  const anotherCleanup = vi.fn();
  lifetime.registerCleanup(anotherCleanup);
  expect(() => view.remove()).not.toThrow();
  expect(anotherCleanup).toHaveBeenCalledTimes(1);
  expect(streams[0]!.closed).toBe(true);
  expect(screen.queryByText('Independent contribution')).toBeNull();
  expect(screen.getByText('Sealed safety controls')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Refresh module contributions' })).toBeDisabled();
  expect(screen.queryByText('private cleanup failure')).toBeNull();
});
it('never mounts protected content when the actual BFF is unavailable', async () => {
  vi.mocked(fetch).mockResolvedValueOnce(
    Response.json({ code: 'PC-INTEGRATION-5001' }, { status: 503 }),
  );
  mount();
  await screen.findByText('Module contributions are unavailable. Refresh to reauthorize.');
  expect(streams).toHaveLength(0);
  expect(screen.queryByText('Protected module')).toBeNull();
  expect(screen.getByText('Sealed safety controls')).toBeVisible();
});
it('does not expose prior actor operation identities in a new authority context', async () => {
  const view = mount();
  await open();
  const original = ticket;
  original.retainOperation({ requestId: id(10), operationId: id(11) });
  const next = snapshot();
  next.binding.actorKey = digest('d');
  next.binding.observationKey = digest('c');
  vi.mocked(fetch).mockResolvedValueOnce(
    Response.json(next, { headers: { 'Cache-Control': 'no-store' } }),
  );
  view.change('context-two');
  await waitFor(() => expect(streams).toHaveLength(2));
  act(() => streams[1]!.frame(observation('CURRENT', digest('c'), digest('d'))));
  expect(lifetime.originalOperations()).toEqual([]);
  expect(original.current()).toBe(false);
});
it.each(['moduleRevision', 'moduleDigest', 'uiManifestDigest'] as const)(
  'rejects a changed explicit %s even with an unchanged observation token',
  async (field) => {
    mount();
    await open();
    const changed = observation();
    changed.modules[0]![field] = field === 'moduleRevision' ? '4' : digest('c');
    act(() => streams[0]!.frame(changed));
    expect(screen.queryByText('Protected module')).toBeNull();
    expect(ticket.current()).toBe(false);
  },
);
it('rejects ambiguous module identities before opening observation transport', async () => {
  const changed = snapshot();
  changed.entries.push({
    ...changed.entries[0]!,
    moduleRevision: '4',
    contribution: { ...changed.entries[0]!.contribution, contributionId: 'UICONTRIB-SECOND' },
  });
  expect(moduleExtensionSnapshot.safeParse(changed).success).toBe(false);
  vi.mocked(fetch).mockResolvedValueOnce(
    Response.json(changed, { headers: { 'Cache-Control': 'no-store' } }),
  );
  mount();
  await screen.findByText('Module contributions are unavailable. Refresh to reauthorize.');
  expect(streams).toHaveLength(0);
});
it('renews an explicitly completed observation stream without losing draft or accepting old events', async () => {
  mount();
  await open();
  const original = ticket;
  fireEvent.change(screen.getByLabelText('Protected draft'), {
    target: { value: 'current draft' },
  });
  act(() => streams[0]!.frame(observation('REOBSERVE')));
  expect(streams).toHaveLength(2);
  expect(streams[0]!.closed).toBe(true);
  act(() => streams[0]!.onerror?.());
  act(() => streams[0]!.frame(observation('INVALIDATED', digest('c'))));
  act(() => streams[1]!.frame(observation()));
  expect(screen.getByLabelText('Protected draft')).toHaveValue('current draft');
  expect(original.current()).toBe(true);
  act(() => streams[1]!.frame(observation('CURRENT', digest('c'))));
  expect(screen.queryByText('Protected module')).toBeNull();
  expect(original.current()).toBe(false);
});
