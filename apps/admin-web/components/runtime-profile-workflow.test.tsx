import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import {
  RuntimeTargetSelect,
  RuntimeProfileDirectory,
  RuntimeProfileSummary,
} from './runtime-profile-workflow';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const actor = {
  sessionId: id(111),
  principalId: id(112),
  participantId: id(101),
  privacyDomainId: id(201),
  contextEpoch: '1',
};
const target = {
  targetId: `urn:openpc:resource:${id(891)}`,
  participantId: `urn:openpc:participant:${actor.participantId}`,
  revision: '3',
  state: 'DISCOVERED',
  desiredGenerationDigest: null,
  activeGenerationDigest: null as string | null,
};
const reply = (owner = actor, items = [target]) =>
  Response.json({
    actor: owner,
    result: {
      items,
      nextCursor: null,
      completeness: 'COMPLETE',
      authorizedEmpty: items.length === 0,
    },
  });
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  localStorage.clear();
});

it('selects a scoped unactivated target with its owner revision and excludes active targets', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      reply(actor, [
        target,
        {
          ...target,
          targetId: `urn:openpc:resource:${id(892)}`,
          state: 'ACTIVE_MATCHED',
          activeGenerationDigest: `sha256:${'1'.repeat(64)}`,
        },
      ]),
    ),
  );
  const selected = vi.fn();
  render(<RuntimeTargetSelect actor={actor} value="" disabled={false} onSelect={selected} />);
  const select = await screen.findByRole('combobox', { name: 'Runtime target' });
  await waitFor(() => expect(select).toBeEnabled());
  expect(screen.queryByRole('option', { name: /00000892/u })).not.toBeInTheDocument();
  fireEvent.change(select, { target: { value: target.targetId } });
  expect(selected).toHaveBeenCalledWith({ runtimeTargetRef: target.targetId, targetRevision: '3' });
});

it.each(['actor', 'row'] as const)('does not expose a foreign %s target result', async (kind) => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      kind === 'actor'
        ? reply({ ...actor, privacyDomainId: id(202) })
        : reply(actor, [{ ...target, participantId: `urn:openpc:participant:${id(102)}` }]),
    ),
  );
  render(<RuntimeTargetSelect actor={actor} value="" disabled={false} onSelect={vi.fn()} />);
  await screen.findByText('Runtime targets could not be loaded. Refresh to try again.');
  expect(screen.getByRole('combobox', { name: 'Runtime target' })).toBeDisabled();
  expect(screen.queryByRole('option', { name: /00000891/u })).not.toBeInTheDocument();
});

it('ignores a delayed result after the actor context changes', async () => {
  let release!: (response: Response) => void;
  const old = new Promise<Response>((resolve) => {
    release = resolve;
  });
  vi.stubGlobal(
    'fetch',
    vi
      .fn()
      .mockReturnValueOnce(old)
      .mockResolvedValue(reply({ ...actor, privacyDomainId: id(202) }, [])),
  );
  const selected = vi.fn();
  const view = render(
    <RuntimeTargetSelect actor={actor} value="" disabled={false} onSelect={selected} />,
  );
  view.rerender(
    <RuntimeTargetSelect
      actor={{ ...actor, privacyDomainId: id(202) }}
      value=""
      disabled={false}
      onSelect={selected}
    />,
  );
  await screen.findByText(/No eligible targets on this page/u);
  await act(async () => {
    release(reply());
    await old;
  });
  expect(screen.queryByRole('option', { name: /00000891/u })).not.toBeInTheDocument();
  expect(selected).not.toHaveBeenCalled();
});

it('keeps failed binding reads distinct from an empty workspace', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json({ code: 'PC-AUTH-0005' }, { status: 403 })),
  );
  render(<RuntimeProfileDirectory actor={actor} disabled={false} onCreate={vi.fn()} />);
  await screen.findByText('Bindings could not be loaded. Refresh to try again.');
  expect(screen.queryByText(/No profile bindings have been recorded/u)).not.toBeInTheDocument();
});

it('describes a recorded binding without claiming runtime activation or workload access', () => {
  render(
    <RuntimeProfileSummary
      title="Recorded binding"
      value={{ targetRef: target.targetId, targetProfileId: 'example-rpc-v1' }}
    />,
  );
  expect(screen.getByText('example-rpc-v1')).toBeInTheDocument();
  expect(
    screen.getByText('This binding does not activate the runtime or grant workload access.'),
  ).toBeInTheDocument();
});
