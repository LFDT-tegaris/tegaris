import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { TransactionWorkflow } from './transaction-workflow';
import { CentralSessionContext } from './central-session-context';
import { LocalSessionSurface } from './local-session';
import { transactionWorkflowPrivacyStorageKey } from './policy-workflow-storage';
import { transactionFields } from '../lib/transaction-workflow';
import {
  notifySessionTransition,
  sessionTransitionEvent,
  sessionTransitionStorageKey,
} from './session-transition';

vi.mock('@openpc/ui-shell', async () => {
  const actual = await vi.importActual<typeof import('@openpc/ui-shell')>('@openpc/ui-shell');
  return { ...actual, performWebAuthnStepUp: vi.fn(async () => undefined) };
});

const actor = {
  sessionId: '018f0000-0000-7000-8000-000000000111',
  principalId: '018f0000-0000-7000-8000-000000000112',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '2',
};
const approvalId = '018f0000-0000-7000-8000-000000000301';
const key = 'openpc:transaction-workbench:v1:deployment';

it('reviews the visible method grant inputs through the existing workflow and invalidates an edited preview', async () => {
  const definition = {
    runtimeBindingId: `urn:openpc:resource:${approvalId}`,
    selector: '0x70a08231',
    subject: { kind: 'WORKLOAD', id: `urn:openpc:workload:${approvalId}` },
    surface: 'RAW_SUBMISSION',
    effect: 'DENY',
  };
  const commands: Record<string, unknown>[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') {
      const body = JSON.parse(String(init.body));
      commands.push(body);
      return Response.json({
        reviewToken: 'sealed-grant-review',
        preview: {
          candidate: definition,
          authority: 'NONE',
          redactedFields: [],
          candidateDigest: `sha256:${'a'.repeat(64)}`,
        },
      });
    }
    return Response.json(
      String(input).includes('/local-session')
        ? { authenticated: true, contextMode: 'PARTICIPANT', ...actor }
        : { actor },
    );
  });
  render(<TransactionWorkflow mode="cigl" initialKind="cigl-grant" showSessionControls={false} />);
  await screen.findByLabelText('Method selector');
  for (const [label, value] of [
    ['Runtime binding reference', definition.runtimeBindingId],
    ['Method selector', definition.selector],
    ['Recipient type', 'WORKLOAD'],
    ['Workload reference', definition.subject.id],
    ['Interface', definition.surface],
    ['Decision', definition.effect],
    ['Expected runtime binding revision', '18446744073709551615'],
    ['Expected method revision', '2'],
    ['Reason', 'Deny the selected workload method.'],
  ] as const)
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  expect(commands).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
  await screen.findByText('Preview prepared. Request independent approval for these exact inputs.');
  expect(commands).toHaveLength(1);
  expect(commands[0]).toMatchObject({
    command: 'PREVIEW',
    kind: 'cigl-grant',
    fields: {
      definition,
      expectedRuntimeBindingRevision: '18446744073709551615',
      expectedMethodRevision: '2',
    },
    reason: 'Deny the selected workload method.',
  });
  expect(screen.getByRole('button', { name: 'Request approval' })).toBeEnabled();
  fireEvent.change(screen.getByLabelText('Decision'), { target: { value: 'ALLOW' } });
  expect(screen.queryByRole('button', { name: 'Request approval' })).toBeNull();
  expect(commands).toHaveLength(1);
});

it('keeps contract interaction inputs inline while optional recovery preserves the unsent request', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      Response.json(
        String(input).includes('/local-session')
          ? { authenticated: true, contextMode: 'PARTICIPANT', ...actor }
          : { actor },
      ),
    );
  render(<TransactionWorkflow mode="cigl" showSessionControls={false} collapseRecoveryControls />);
  const transaction = await screen.findByLabelText('Transaction hash');
  expect(transaction).toBeVisible();
  expect(screen.getByRole('button', { name: 'Review request' })).toBeVisible();
  fireEvent.change(transaction, { target: { value: 'unsent-fixture' } });
  const original = screen.getByLabelText('Original proposal key, for unchanged request recovery');
  expect(original).not.toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Recover an existing request' }));
  expect(original).toBeVisible();
  fireEvent.change(original, { target: { value: '9388a56f-3840-402f-8035-70c824a43ba3' } });
  fireEvent.change(screen.getByLabelText('Reserved approval operation ID'), {
    target: { value: approvalId },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Close Recover an existing request' }));
  expect(screen.getByRole('button', { name: 'Recover an existing request' })).toHaveFocus();
  expect(transaction).toHaveValue('unsent-fixture');
  fireEvent.click(screen.getByRole('button', { name: 'Recover an existing request' }));
  expect(original).toHaveValue('9388a56f-3840-402f-8035-70c824a43ba3');
  expect(screen.getByLabelText('Reserved approval operation ID')).toHaveValue(approvalId);
  expect(fetcher.mock.calls.every(([, init]) => init?.method !== 'POST')).toBe(true);
});

it('stores the original before functional execution and continues it after a lost acknowledgement', async () => {
  const testKey = 'openpc:transaction-workbench:v1:providers';
  localStorage.setItem(
    testKey,
    JSON.stringify({ actor, value: { kind: 'provider-profile', reviewToken: 'r'.repeat(64) } }),
  );
  const calls: Record<string, unknown>[] = [];
  let firstApply = true;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, options?: RequestInit) => {
      const url = new URL(String(input), 'http://localhost');
      if (url.pathname.endsWith('/local-session'))
        return Response.json({ enabled: true, authenticated: true, contextMode: 'PARTICIPANT' });
      if (url.pathname.endsWith('/functional-transaction')) {
        expect(options?.signal).toBeUndefined();
        const body = JSON.parse(String(options?.body));
        calls.push(body);
        if (body.command === 'PREPARE') return Response.json({ approvalId, outcome: 'PREPARED' });
        expect(JSON.parse(localStorage.getItem(testKey)!).value.approvalId).toBe(approvalId);
        expect(body.approvalId).toBe(approvalId);
        if (firstApply) {
          firstApply = false;
          throw new TypeError('Acknowledgement lost after native execution');
        }
        return Response.json({ approvalId, outcome: 'RECORDED' });
      }
      return Response.json({ actor, functionalTest: true });
    }),
  );
  render(<TransactionWorkflow mode="providers" showSessionControls={false} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Apply change' }));
  const continuation = await screen.findByRole('button', { name: 'Continue change' });
  await waitFor(() => expect(continuation).toBeEnabled());
  expect(screen.getByRole('region', { name: 'Change progress' })).toBeVisible();
  expect(screen.getByRole('button', { name: 'Refresh result' })).toBeEnabled();
  expect(calls.map((c) => c.command)).toEqual(['PREPARE', 'APPLY']);
  fireEvent.click(continuation);
  await waitFor(() => expect(calls).toHaveLength(3));
  expect(calls.map((c) => c.command)).toEqual(['PREPARE', 'APPLY', 'APPLY']);
  expect(calls[2]?.approvalId).toBe(approvalId);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.mocked(performWebAuthnStepUp).mockReset().mockResolvedValue(undefined);
  localStorage.clear();
});

it.each([approvalId, '018f0000-0000-7000-8000-000000000302'])(
  'binds delayed execution acknowledgement %s to the original approval after its own save',
  async (acknowledgedId) => {
    const custodyKey = 'openpc:transaction-workbench:v1:wallets';
    localStorage.setItem(
      custodyKey,
      JSON.stringify({
        actor,
        value: { kind: 'wallet-binding', reviewToken: 'original-wallet-review' },
      }),
    );
    let release!: () => void;
    const acknowledgement = new Promise<void>((resolve) => {
      release = resolve;
    });
    const commands: string[] = [];
    const reads: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request, options?: RequestInit) => {
        const url = new URL(String(input), 'http://localhost');
        if (url.pathname.endsWith('/local-session'))
          return Response.json({ authenticated: true, contextMode: 'PARTICIPANT', ...actor });
        if (url.pathname.endsWith('/functional-transaction')) {
          const body = JSON.parse(String(options?.body));
          commands.push(body.command);
          if (body.command === 'PREPARE') return Response.json({ approvalId, outcome: 'PREPARED' });
          expect(body.command).toBe('APPLY');
          expect(body.approvalId).toBe(approvalId);
          await acknowledgement;
          return Response.json({ approvalId: acknowledgedId, outcome: 'SUBMITTED' });
        }
        reads.push(url.href);
        if (url.searchParams.get('approvalId') === approvalId)
          return Response.json({
            actor,
            functionalTest: true,
            kind: 'wallet-binding',
            approval: {
              approvalRequestId: `urn:openpc:resource:${approvalId}`,
              makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
              checkerSubjectRef: `urn:openpc:resource:${actor.sessionId}`,
              state: 'APPROVED',
            },
            candidate: {
              resourceRef: `urn:openpc:resource:${approvalId}`,
              state: 'CONSUMED',
              operationRef: `urn:openpc:operation:${approvalId}`,
              candidateDigest: `sha256:${'a'.repeat(64)}`,
              candidate: {},
              redactedFields: [],
            },
            result: {
              walletBindingId: approvalId,
              subjectId: actor.principalId,
              chainId: '92870',
              walletAddress: `0x${'a'.repeat(40)}`,
              participantId: actor.participantId,
              privacyDomainId: actor.privacyDomainId,
              state: 'ACTIVE',
              bindingEpoch: '1',
              revision: '1',
              operationId: approvalId,
              permissionEffect: 'NONE_WITHOUT_EFFECTIVE_AUTHORITY',
            },
          });
        return Response.json({ actor, functionalTest: true });
      }),
    );
    render(<TransactionWorkflow mode="wallets" showSessionControls={false} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Apply change' }));
    await waitFor(() =>
      expect(JSON.parse(localStorage.getItem(custodyKey)!).value.approvalId).toBe(approvalId),
    );
    await act(async () => release());
    if (acknowledgedId === approvalId)
      expect(await screen.findByRole('heading', { name: 'Wallet bound' })).toBeVisible();
    else {
      expect(
        await screen.findByText(
          'The request could not be confirmed. Read the original approval and result before retrying.',
        ),
      ).toBeVisible();
      expect(screen.queryByRole('heading', { name: 'Wallet bound' })).toBeNull();
      expect(reads.some((url) => url.includes(acknowledgedId))).toBe(false);
    }
    expect(commands).toEqual(['PREPARE', 'APPLY']);
    expect(JSON.parse(localStorage.getItem(custodyKey)!).value.approvalId).toBe(approvalId);
  },
);

it.each([
  [{ state: 'SUCCEEDED' }, 'Recorded status', 'Completed', 'Not reported'],
  [
    { admissionState: 'ACCEPTED', physicalState: 'UNKNOWN' },
    'Command admission',
    'Accepted for processing',
    'Unconfirmed',
  ],
  [
    { state: 'WRITE_AMBIGUITY', truthState: 'UNKNOWN' },
    'Recorded status',
    'Outcome uncertain',
    'Unconfirmed',
  ],
] as const)(
  'opens the actual approval and distinguishes recorded state from physical outcome: %s',
  async (result, statusLabel, statusValue, effectValue) => {
    const writes: string[] = [],
      reads: string[] = [];
    const record = {
      approvalRequestId: `urn:openpc:resource:${approvalId}`,
      actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1',
      kinds: [
        'evidence-deletion-search',
        'evidence-deletion-normalized',
        'evidence-deletion-projection-continuation',
      ],
      state: 'APPROVED',
      relationship: 'MAKER',
      revision: '1',
      createdAt: '2026-09-20T00:00:00.000000Z',
      updatedAt: '2026-09-21T00:00:00.000000Z',
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request, options?: RequestInit) => {
        const url = new URL(String(input), 'http://localhost');
        if (options?.method && options.method !== 'GET') writes.push(options.method);
        if (url.pathname.endsWith('/local-session'))
          return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
        if (url.searchParams.get('approvals') === '1')
          return Response.json({
            actor,
            items: [record],
            nextCursor: null,
            total: '1',
            completeness: 'COMPLETE',
            authorizedEmpty: false,
            snapshotRevision: '4',
          });
        const selected = url.searchParams.get('approvalId');
        if (!selected) return Response.json({ actor });
        reads.push(selected);
        return Response.json({
          actor,
          kind: 'evidence-deletion-search',
          approval: {
            approvalRequestId: record.approvalRequestId,
            makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
            checkerSubjectRef: null,
            state: 'APPROVED',
            revision: '1',
          },
          candidate: {
            state: 'CONSUMED',
            candidate: {},
            redactedFields: [],
            resourceRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000401',
            candidateDigest: `sha256:${'a'.repeat(64)}`,
            operationRef: null,
          },
          stepUp: null,
          operation: {
            operationId: '018f0000-0000-7000-8000-000000000401',
            state: 'SUCCEEDED',
            truthState: 'UNKNOWN',
          },
          result,
        });
      }),
    );
    render(<TransactionWorkflow mode="evidence" guidedRecovery showSessionControls={false} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Activity' }));
    const selected = await screen.findByRole('button', { name: `Review request ${approvalId}` });
    expect(screen.getByText('Prepare a governed request')).not.toBeVisible();
    fireEvent.click(selected);
    expect(await screen.findByText('Approval: Approved')).toBeVisible();
    expect(selected).toHaveAttribute('aria-current', 'true');
    expect(screen.getByText('Viewing')).toBeVisible();
    const outcome = screen.getByLabelText('Recorded outcome');
    expect(within(outcome).getByText(statusLabel)).toBeVisible();
    expect(within(outcome).getByText(statusValue)).toBeVisible();
    expect(within(outcome).getByText(effectValue)).toBeVisible();
    expect(screen.getByText('Operation state: Completed · Effect: Unconfirmed')).not.toBeVisible();
    expect(screen.getByRole('heading', { name: 'Selected request' })).toHaveFocus();
    expect(screen.getByLabelText('Approval ID', { exact: true })).toHaveValue(approvalId);
    expect(screen.getByLabelText('Approval ID', { exact: true })).not.toBeVisible();
    expect(screen.getByText(`sha256:${'a'.repeat(64)}`)).not.toBeVisible();
    expect(screen.queryByRole('button', { name: 'Execute approved request' })).toBeNull();
    expect(reads).toEqual([approvalId]);
    expect(writes).toEqual([]);
  },
);

it.each(['deployment', 'evidence'] as const)(
  'keeps the approval selection locked until the %s read has finished rendering',
  async (mode) => {
    const nextId = '018f0000-0000-7000-8000-000000000302';
    const requested: string[] = [];
    let release!: (value: unknown) => void;
    const pendingBody = new Promise((resolve) => {
      release = resolve;
    });
    const body = (id: string) => ({
      actor,
      kind: mode === 'evidence' ? 'evidence-deletion' : 'deployment-intent',
      approval: {
        approvalRequestId: `urn:openpc:resource:${id}`,
        makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
        state: 'CONSUMED',
      },
      candidate: { state: 'CONSUMED', candidate: {}, redactedFields: [] },
    });
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes('/local-session'))
        return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
      const id = new URL(url, 'http://localhost').searchParams.get('approvalId');
      if (!id) return Response.json({ actor });
      requested.push(id);
      const response = Response.json(body(id));
      if (id === approvalId) vi.spyOn(response, 'json').mockImplementation(() => pendingBody);
      return response;
    });
    render(<TransactionWorkflow mode={mode} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Activity' }));
    const recover = screen.queryByRole('button', { name: 'Recover an existing request' });
    if (recover) fireEvent.click(recover);
    const input = await screen.findByLabelText('Approval ID', { exact: true });
    const read = screen.getByRole('button', { name: 'Read approval and result' });
    await waitFor(() => expect(input).toBeEnabled());
    fireEvent.change(input, { target: { value: approvalId } });
    fireEvent.click(read);
    await waitFor(() => expect(requested).toEqual([approvalId]));
    expect(input).toBeDisabled();
    expect(read).toBeDisabled();
    await act(async () => release(body(approvalId)));
    await waitFor(() => expect(input).toBeEnabled());
    expect(input).toHaveValue(approvalId);
    fireEvent.change(input, { target: { value: nextId } });
    fireEvent.click(read);
    await waitFor(() => {
      expect(requested).toEqual([approvalId, nextId]);
      expect(input).toBeEnabled();
      expect(input).toHaveValue(nextId);
      const saved = JSON.parse(localStorage.getItem(`openpc:transaction-workbench:v1:${mode}`)!);
      expect(saved.value.approvalId).toBe(nextId);
    });
    expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
  },
);

it.each(['native-signout-read', 'other-tab-clear'])(
  'discards a delayed original approval readback after %s without restoring custody or replaying',
  async (cause) => {
    let signedOut = false;
    let release!: (value: Response) => void;
    const pending = new Promise<Response>((resolve) => {
      release = resolve;
    });
    localStorage.setItem(
      key,
      JSON.stringify({ actor, value: { approvalId, reviewToken: 'retained-original-review' } }),
    );
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).includes('/local-session'))
        return Response.json(
          signedOut
            ? { enabled: true, authenticated: false }
            : {
                ...actor,
                enabled: true,
                authenticated: true,
                role: 'viewer',
                contextMode: 'PARTICIPANT',
                availableContexts: [],
              },
        );
      if (String(input).includes('?approvalId=')) return pending;
      return Response.json({ actor });
    });
    render(<TransactionWorkflow mode="deployment" />);
    await waitFor(() =>
      expect(fetcher.mock.calls.some(([input]) => String(input).includes('?approvalId='))).toBe(
        true,
      ),
    );
    signedOut = true;
    if (cause === 'native-signout-read') render(<LocalSessionSurface />);
    else
      fireEvent(
        window,
        new StorageEvent('storage', {
          key: transactionWorkflowPrivacyStorageKey,
          newValue: 'another-tab-notification',
        }),
      );
    await waitFor(() => expect(localStorage.getItem(key)).toBeNull());
    await act(async () =>
      release(
        Response.json({
          actor,
          kind: 'deployment-intent',
          reviewToken: 'late-original-review',
          approval: {
            approvalRequestId: `urn:openpc:resource:${approvalId}`,
            makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
            state: 'APPROVED',
          },
          candidate: {
            candidate: { retainedDetail: 'private-original-intent' },
            state: 'APPROVED',
            redactedFields: [],
          },
        }),
      ),
    );
    expect(localStorage.getItem(key)).toBeNull();
    expect(screen.queryByText(/private-original-intent/u)).toBeNull();
    expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
  },
);

it.each([
  ['policy', 'policy-activation-renewal', ['policy-activation-renewal']],
  ['wallets', 'wallet-binding', ['wallet-binding']],
  [
    'providers',
    'provider-profile',
    ['provider-profile', 'provider-qualification', 'provider-observation-renewal'],
  ],
] as const)(
  'starts %s with the correct form and only its supported requests',
  async (mode, initial, choices) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      Response.json(
        String(input).includes('/local-session')
          ? { authenticated: true, contextMode: 'PARTICIPANT' }
          : { actor },
      ),
    );
    render(<TransactionWorkflow mode={mode} />);
    const select = await screen.findByLabelText('Request type');
    expect(select).toHaveValue(initial);
    expect(Array.from((select as HTMLSelectElement).options).map((option) => option.value)).toEqual(
      choices,
    );
  },
);

it('keeps a successful Fact admission distinct from an unresolved physical result without resubmitting', async () => {
  localStorage.setItem(
    'openpc:transaction-workbench:v1:evidence',
    JSON.stringify({ actor, value: { approvalId, reviewToken: 'retained-review' } }),
  );
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.includes('/local-session'))
      return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
    if (!url.includes('?')) return Response.json({ actor });
    return Response.json({
      actor,
      kind: 'evidence-deletion-fact',
      approval: {
        approvalRequestId: `urn:openpc:resource:${approvalId}`,
        makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
        state: 'CONSUMED',
      },
      candidate: {
        resourceRef: `urn:openpc:resource:${approvalId}`,
        candidateDigest: 'sha256:' + 'a'.repeat(64),
        state: 'CONSUMED',
        candidate: {},
        redactedFields: [],
      },
      operation: { operationId: approvalId, state: 'SUCCEEDED', truthState: 'SUCCESS' },
      result: { admissionState: 'ADMITTED', physicalState: 'UNKNOWN' },
      factRetirement: {
        factId: 'original-fact',
        candidateId: 'original-candidate',
        factGenerationId: 'original-fact-generation',
        canonicalGeneration: '18446744073709551615',
        payloadBytes: '40',
        evidenceId: `urn:openpc:resource:${approvalId}`,
        retentionPolicyId: `urn:openpc:resource:${approvalId}`,
        hostDigest: 'a'.repeat(64),
        archiveAcknowledgements: 1,
        nativeSourceCheck: 'REQUIRED_AT_ADMISSION',
      },
    });
  });
  render(<TransactionWorkflow mode="evidence" initialKind="evidence-deletion-fact" />);
  expect(
    await screen.findByText('Admission operation: SUCCEEDED · Admission result: SUCCESS'),
  ).toBeInTheDocument();
  expect(screen.getByText('Result state: ADMITTED · Effect: UNKNOWN')).toBeInTheDocument();
  expect(screen.getByText('18446744073709551615')).toBeInTheDocument();
  expect(screen.getByText(/UNKNOWN remains unresolved/u)).toBeInTheDocument();
  const execute = screen.getByRole('button', { name: 'Execute approved request' });
  expect(execute).toBeDisabled();
  fireEvent.click(execute);
  expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
});

it('reviews provider renewal without an editable fingerprint and hands its approval ID to the checker', async () => {
  const candidate = { expectedRevision: '8', replacementDigest: `sha256:${'a'.repeat(64)}` };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (String(input).includes('/local-session'))
      return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
    if (init?.method === 'POST') {
      const command = JSON.parse(String(init.body));
      if (command.command === 'PREVIEW') {
        expect(command).toMatchObject({
          kind: 'provider-observation-renewal',
          requestKey: '9388a56f-3840-402f-8035-70c824a43ba3',
          fields: {
            targetRef: `urn:openpc:resource:${approvalId}`,
            expectedRevision: '8',
          },
        });
        expect(command.fields).not.toHaveProperty('replacementDigest');
        return Response.json({
          reviewToken: 'sealed-provider-review',
          preview: {
            candidate,
            authority: 'NONE',
            redactedFields: [],
            candidateDigest: `sha256:${'a'.repeat(64)}`,
          },
        });
      }
      expect(command).toEqual({
        command: 'REQUEST_APPROVAL',
        resourceReservationId: approvalId,
        reviewToken: 'sealed-provider-review',
        checkerId: approvalId,
      });
      return Response.json({ approvalId });
    }
    if (String(input).includes('?'))
      return Response.json({
        actor,
        kind: 'provider-observation-renewal',
        approval: {
          approvalRequestId: `urn:openpc:resource:${approvalId}`,
          makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
          state: 'REQUESTED',
        },
        candidate: { candidate, state: 'APPROVAL_REQUESTED', redactedFields: [] },
        stepUp: null,
      });
    return Response.json({ actor });
  });
  render(<TransactionWorkflow mode="providers" initialKind="provider-observation-renewal" />);
  await screen.findByLabelText('Resource reference');
  expect(screen.queryByLabelText('Expected behavior fingerprint (sha256)')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Resource reference'), {
    target: { value: `urn:openpc:resource:${approvalId}` },
  });
  fireEvent.change(screen.getByLabelText('Expected revision'), { target: { value: '8' } });
  fireEvent.change(screen.getByLabelText('Reason'), {
    target: { value: 'Renew the expired provider observation.' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Recover an existing request' }));
  fireEvent.change(screen.getByLabelText('Original proposal key, for unchanged request recovery'), {
    target: { value: '9388a56f-3840-402f-8035-70c824a43ba3' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
  await screen.findByRole('button', { name: 'Request approval' });
  fireEvent.change(screen.getByLabelText('Reserved approval operation ID'), {
    target: { value: approvalId },
  });
  expect(screen.getByRole('button', { name: 'Request approval' })).toBeDisabled();
  fireEvent.click(
    screen.getByText('Enter or inspect the checker reference', { selector: 'button' }),
  );
  expect(screen.getByLabelText('Independent checker principal ID')).toBeVisible();
  fireEvent.change(screen.getByLabelText('Independent checker principal ID'), {
    target: { value: approvalId },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Request approval' }));
  await screen.findByText(
    'Approval requested. Share the approval ID with the independent checker.',
  );
  expect(screen.getByLabelText('Approval ID')).toHaveValue(approvalId);
  expect(screen.getByRole('button', { name: 'Execute approved request' })).toBeDisabled();
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(2);
});

it('clears another actor’s persisted review before offering any mutation', async () => {
  localStorage.setItem(
    key,
    JSON.stringify({ actor, value: { approvalId, reviewToken: 'private-maker-review' } }),
  );
  const other = { ...actor, principalId: approvalId, sessionId: approvalId };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input).includes('/local-session'))
      return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
    return Response.json({ actor: other });
  });
  render(<TransactionWorkflow mode="deployment" />);
  await screen.findByRole('heading', { name: 'Prepare a governed request' });
  expect(screen.getByLabelText('Approval ID')).toHaveValue('');
  expect(
    screen.queryByRole('button', { name: 'Execute approved request' }),
  ).not.toBeInTheDocument();
  expect(localStorage.getItem(key)).toBeNull();
  expect(fetcher.mock.calls.every(([, options]) => options?.method === undefined)).toBe(true);
});

it('restores uncertain committed history with readback and no automatic resubmission', async () => {
  localStorage.setItem(
    key,
    JSON.stringify({ actor, value: { approvalId, reviewToken: 'sealed-review' } }),
  );
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.includes('/local-session'))
      return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
    if (!url.includes('?')) return Response.json({ actor });
    return Response.json({
      actor,
      kind: 'deployment-submission',
      approval: {
        approvalRequestId: `urn:openpc:resource:${approvalId}`,
        makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
        state: 'APPROVED',
      },
      candidate: {
        state: 'CONSUMED',
        resourceRef: `urn:openpc:resource:${approvalId}`,
        candidateDigest: `sha256:${'a'.repeat(64)}`,
        operationRef: `urn:openpc:operation:${approvalId}`,
        candidate: {},
        redactedFields: [],
        deploymentIntent: null,
      },
      stepUp: null,
      operation: {
        operationId: approvalId,
        state: 'RUNNING',
        truthState: 'UNKNOWN',
        revision: '2',
        updatedAt: '2026-09-18T00:00:00.000Z',
      },
      result: { state: 'WRITE_AMBIGUITY', truthState: 'WRITE_AMBIGUITY' },
    });
  });
  render(<TransactionWorkflow mode="deployment" />);
  await screen.findByText('Result state: WRITE_AMBIGUITY · Effect: WRITE_AMBIGUITY');
  expect(screen.getByText('Operation state: RUNNING · Effect: UNKNOWN')).toBeInTheDocument();
  expect(screen.getByLabelText('Request type', { exact: true })).toHaveValue(
    'deployment-submission',
  );
  expect(screen.getByRole('button', { name: 'Execute approved request' })).toBeDisabled();
  expect(fetcher.mock.calls.every(([, options]) => options?.method === undefined)).toBe(true);
});

it('keeps native-value amounts lossless and rejects malformed structured definitions', () => {
  const amount = '10000000000000000000000000001';
  expect(
    transactionFields('native-value', {
      walletBindingId: 'wallet',
      executionWorkloadId: '',
      chainId: '92870',
      networkId: 'testnet',
      genesisDigest: 'genesis',
      amountMode: 'EXACT',
      maxAmountWei: amount,
      validUntil: '2026-09-18T12:00:00.000Z',
    }),
  ).toMatchObject({ maxAmountWei: amount, chainId: '92870' });
  expect(() => transactionFields('deployment-policy', { definition: '{invalid' })).toThrow(
    'valid JSON',
  );
});

it.each([false, true])(
  'never carries another approval’s review token into a loaded request (restored=%s)',
  async (restored) => {
    const nextApproval = '018f0000-0000-7000-8000-000000000302';
    localStorage.setItem(
      key,
      JSON.stringify({ actor, value: { approvalId, reviewToken: 'old-review' } }),
    );
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes('/local-session'))
        return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
      if (!url.includes('?')) return Response.json({ actor });
      const second = url.includes(nextApproval);
      return Response.json({
        actor,
        kind: 'deployment-submission',
        ...(second && restored ? { reviewToken: 'restored-exact-review' } : {}),
        approval: {
          approvalRequestId: `urn:openpc:resource:${second ? nextApproval : approvalId}`,
          makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
          state: 'APPROVED',
        },
        candidate: {
          state: 'APPROVED',
          resourceRef: `urn:openpc:resource:${approvalId}`,
          candidateDigest: `sha256:${'a'.repeat(64)}`,
          operationRef: null,
          candidate: {},
          redactedFields: [],
          deploymentIntent: null,
        },
        stepUp: {
          actionIntentId: 'action',
          actionIntentDigest: 'digest',
          resourceId: approvalId,
          resourceDigest: 'digest',
        },
      });
    });
    render(<TransactionWorkflow mode="deployment" />);
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Execute approved request' })).toBeEnabled(),
    );
    fireEvent.change(screen.getByLabelText('Approval ID', { exact: true }), {
      target: { value: nextApproval },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Read approval and result' }));
    await waitFor(() => {
      const value = JSON.parse(localStorage.getItem(key)!).value;
      expect(value.approvalId).toBe(nextApproval);
      expect(value.reviewToken).toBe(restored ? 'restored-exact-review' : undefined);
    });
    if (restored)
      expect(screen.getByRole('button', { name: 'Execute approved request' })).toBeEnabled();
    else expect(screen.getByRole('button', { name: 'Execute approved request' })).toBeDisabled();
  },
);

it('reviews only the selected hold scope and keeps future range bounds explicit', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    Response.json(
      String(input).includes('/local-session')
        ? { authenticated: true, contextMode: 'PARTICIPANT' }
        : { actor },
    ),
  );
  render(<TransactionWorkflow mode="evidence" />);
  await screen.findByRole('heading', { name: 'Prepare a governed request' });
  fireEvent.change(screen.getByLabelText('Request type', { exact: true }), {
    target: { value: 'evidence-hold' },
  });
  fireEvent.change(screen.getByLabelText('Evidence to preserve', { exact: true }), {
    target: { value: 'DIGEST' },
  });
  expect(screen.getByLabelText('Receipt digest', { exact: true })).toBeVisible();
  expect(
    screen.queryByLabelText('Evidence stream to preserve', { exact: true }),
  ).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Evidence to preserve', { exact: true }), {
    target: { value: 'SEQUENCE_RANGE' },
  });
  expect(screen.getByLabelText('Evidence stream to preserve', { exact: true })).toBeVisible();
  expect(screen.queryByLabelText('Receipt digest', { exact: true })).not.toBeInTheDocument();
  const values = {
    holdKind: 'LEGAL',
    selectorType: 'SEQUENCE_RANGE',
    streamId: 'retained',
    fromSequence: '9007199254740993',
    recordDigest: 'stale hidden input',
  };
  expect(transactionFields('evidence-hold', values)).toEqual({
    holdKind: 'LEGAL',
    selector: {
      type: 'SEQUENCE_RANGE',
      streamId: 'retained',
      fromSequence: '9007199254740993',
      throughSequence: null,
    },
  });
  expect(transactionFields('evidence-hold', { ...values, selectorType: 'PRIVACY_DOMAIN' })).toEqual(
    { holdKind: 'LEGAL', selector: { type: 'PRIVACY_DOMAIN' } },
  );
  fireEvent.change(screen.getByLabelText('Evidence to preserve', { exact: true }), {
    target: { value: 'GENERATION' },
  });
  fireEvent.change(screen.getByLabelText('Generation kind', { exact: true }), {
    target: { value: 'CANONICAL_FACT' },
  });
  expect(screen.getByLabelText('Canonical Fact generation number', { exact: true })).toBeVisible();
  expect(
    screen.queryByLabelText('Runtime configuration generation reference', { exact: true }),
  ).not.toBeInTheDocument();
  expect(
    transactionFields('evidence-hold', {
      ...values,
      selectorType: 'GENERATION',
      generationKind: 'CANONICAL_FACT',
      factProfileId: 'urn:openpc:fact-profile:018f0000-0000-7000-8000-000000000101',
      canonicalGeneration: '9007199254740993',
      generationId: 'stale hidden runtime generation',
    }),
  ).toEqual({
    holdKind: 'LEGAL',
    selector: {
      type: 'GENERATION',
      generation: {
        kind: 'CANONICAL_FACT',
        factProfileId: 'urn:openpc:fact-profile:018f0000-0000-7000-8000-000000000101',
        canonicalGeneration: '9007199254740993',
      },
    },
  });
  fireEvent.change(screen.getByLabelText('Request type', { exact: true }), {
    target: { value: 'evidence-participant-hold' },
  });
  expect(screen.queryByLabelText('Evidence to preserve', { exact: true })).not.toBeInTheDocument();
  expect(transactionFields('evidence-participant-hold', values)).toEqual({
    holdKind: 'LEGAL',
    selector: { type: 'PARTICIPANT' },
  });
});

it('keeps the approved renewal occurrence and source generation in the reviewed profile command', () => {
  const renewal = {
    activationOccurrenceRef: 'urn:openpc:resource:019963de-8824-7000-8000-000000000001',
    expectedRevision: '2',
    policyGenerationDigest: `sha256:${'ab'.repeat(32)}`,
  };
  const fields = {
    targetRef: 'target',
    expectedRevision: '16',
    expectedGenerationDigest: 'installed-capsule',
    participantEpoch: '1',
    profiles: '[]',
  };
  expect(
    transactionFields('cigl-activation', { ...fields, policyRenewal: JSON.stringify(renewal) }),
  ).toMatchObject({ policyRenewal: renewal });
  expect(transactionFields('cigl-activation', fields)).not.toHaveProperty('policyRenewal');
});

it('names selectors and structured inputs without folding options or help into their labels', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    Response.json(
      String(input).includes('/local-session')
        ? { authenticated: true, contextMode: 'PARTICIPANT' }
        : { actor },
    ),
  );
  render(<TransactionWorkflow mode="deployment" />);
  await screen.findByRole('heading', { name: 'Prepare a governed request' });
  const selector = screen.getByLabelText('Request type', { exact: true });
  expect(selector).toHaveAccessibleName('Request type');
  fireEvent.change(screen.getByLabelText('Reason', { exact: true }), {
    target: { value: 'First independently approved request.' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'New request' }));
  fireEvent.change(selector, { target: { value: 'deployment-submission' } });
  expect(screen.getByLabelText('Reason', { exact: true })).toHaveAccessibleName('Reason');
  fireEvent.change(screen.getByLabelText('Reason', { exact: true }), {
    target: { value: 'Second independently approved request.' },
  });
  expect(screen.getByLabelText('Reason', { exact: true })).toHaveValue(
    'Second independently approved request.',
  );
  fireEvent.change(selector, { target: { value: 'deployment-policy' } });
  expect(screen.getByLabelText('Deployment policy definition', { exact: true })).toBeRequired();
  expect(
    screen.getByLabelText('Deployment policy definition', { exact: true }),
  ).toHaveAccessibleDescription('Enter the exact JSON definition for review.');
  fireEvent.change(selector, { target: { value: 'native-value' } });
  const amountMode = screen.getByLabelText('Amount mode', { exact: true });
  expect(amountMode).toHaveAccessibleName('Amount mode');
  fireEvent.change(amountMode, { target: { value: 'EXACT' } });
  expect(amountMode).toHaveValue('EXACT');
});

it('shows expired history and only offers a fresh approval request to its maker', async () => {
  localStorage.setItem(
    'openpc:transaction-workbench:v1:modules',
    JSON.stringify({ actor, value: { approvalId } }),
  );
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input).includes('/local-session'))
      return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
    if (!String(input).includes('?')) return Response.json({ actor });
    return Response.json({
      actor,
      kind: 'module-registration',
      reviewToken: 'fresh-actor-review',
      approval: {
        approvalRequestId: `urn:openpc:resource:${approvalId}`,
        makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
        state: 'APPROVED',
        revision: '2',
      },
      candidate: {
        state: 'EXPIRED',
        attemptId: approvalId,
        attempt: '1',
        approvalUsable: false,
        canRequestResume: true,
        candidate: { name: 'pc.foundation.kernel' },
        redactedFields: [],
        deploymentIntent: null,
      },
      stepUp: null,
    });
  });
  render(<TransactionWorkflow mode="modules" initialKind="contract-asset" />);
  await screen.findByRole('button', { name: 'Request fresh approval' });
  expect(screen.getByText('Approval attempt 1')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Execute approved request' })).toBeDisabled();
  expect(fetcher.mock.calls.every(([, options]) => options?.method === undefined)).toBe(true);
});

const transactionEndpoint = '/api/v1/ui/transaction-workbench';

it.each([
  ['module-registration', 'REGISTERED', 'Registered', '1'],
  ['module-install', 'INSTALLED', 'Installed', '2'],
  ['module-enable', 'ACTIVE', 'Active', '3'],
] as const)(
  'renders the recorded %s outcome on original approval readback without another command',
  async (kind, state, label, revision) => {
    localStorage.setItem(
      'openpc:transaction-workbench:v1:modules',
      JSON.stringify({ actor, value: { approvalId, kind } }),
    );
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).includes('/local-session'))
        return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
      if (!String(input).includes('?')) return Response.json({ actor });
      const request = policyRequest();
      return Response.json({
        ...request,
        kind,
        candidate: { ...request.candidate, state: 'CONSUMED', approvalUsable: false },
        operation: { state: 'SUCCEEDED', truthState: 'SUCCESS' },
        result: {
          name: 'pc.config.assets',
          semanticVersion: '1.0.0',
          state,
          revision,
          manifestDigest: `sha256:${'a'.repeat(64)}`,
          updatedAt: '2026-10-11T18:05:39.700000Z',
        },
      });
    });
    render(
      <TransactionWorkflow
        mode="modules"
        initialKind="contract-asset"
        showSessionControls={false}
      />,
    );
    const outcome = await screen.findByRole('region', { name: 'Recorded outcome' });
    expect(within(outcome).getByText('pc.config.assets')).toBeVisible();
    expect(within(outcome).getByText(label)).toBeVisible();
    expect(within(outcome).getByText('Record revision').nextElementSibling).toHaveTextContent(
      revision,
    );
    expect(businessPosts(fetcher)).toHaveLength(0);
  },
);
const policyKey = 'openpc:transaction-workbench:v1:policy';
const privateDetail = 'PRIVATE_TRANSACTION_AUTHENTICATOR_STORAGE_OR_TRANSPORT';
function held<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}
function policyRequest(checker = false) {
  return {
    actor,
    kind: 'policy-activation-renewal',
    reviewToken: 'original-policy-review',
    approval: {
      approvalRequestId: `urn:openpc:resource:${approvalId}`,
      makerSubjectRef: `urn:openpc:resource:${checker ? '018f0000-0000-7000-8000-000000000901' : actor.principalId}`,
      checkerSubjectRef: checker ? `urn:openpc:resource:${actor.principalId}` : null,
      state: checker ? 'REQUESTED' : 'APPROVED',
      revision: '3',
    },
    candidate: {
      state: checker ? 'APPROVAL_REQUESTED' : 'APPROVED',
      resourceRef: `urn:openpc:resource:${approvalId}`,
      candidateDigest: `sha256:${'a'.repeat(64)}`,
      candidate: { original: true },
      redactedFields: [],
      attemptId: '018f0000-0000-7000-8000-000000000401',
      attempt: '2',
      canRequestResume: false,
      approvalUsable: true,
      makerSessionMatches: true,
    },
    stepUp: {
      actionIntentId: 'fixture-original-action',
      actionIntentDigest: `sha256:${'b'.repeat(64)}`,
      resourceId: approvalId,
      resourceDigest: `sha256:${'c'.repeat(64)}`,
    },
  };
}

it('refreshes the selected approval through readback without sending a command or changing intent', async () => {
  retainPolicy();
  let refreshed = false;
  const pending = held<Response>();
  const reads: string[] = [];
  const request = policyRequest();
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = new URL(String(input), 'http://localhost');
    if (url.pathname.endsWith('/local-session'))
      return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
    const selected = url.searchParams.get('approvalId');
    if (!selected) return Response.json({ actor });
    reads.push(selected);
    if (refreshed) return pending.promise;
    return Response.json({
      ...request,
      approval: { ...request.approval, state: 'REQUESTED' },
      candidate: { ...request.candidate, state: 'APPROVAL_REQUESTED', approvalUsable: false },
      stepUp: null,
    });
  });
  render(<TransactionWorkflow mode="policy" showSessionControls={false} />);
  const refresh = await screen.findByRole('button', { name: 'Refresh details' });
  expect(screen.getByRole('button', { name: 'Execute approved request' })).toBeDisabled();
  const original = localStorage.getItem(policyKey);
  refreshed = true;
  fireEvent.click(refresh);
  await waitFor(() => expect(reads).toEqual([approvalId, approvalId]));
  expect(refresh).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Execute approved request' })).toBeDisabled();
  await act(async () => pending.resolve(Response.json(request)));
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Execute approved request' })).toBeEnabled(),
  );
  expect(screen.getByText('Approval', { selector: 'dt' }).nextElementSibling).toHaveTextContent(
    'APPROVED',
  );
  expect(localStorage.getItem(policyKey)).toBe(original);
  expect(businessPosts(fetcher)).toHaveLength(0);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});

it('clears selected details when their refreshed owner belongs to another actor', async () => {
  retainPolicy();
  let changed = false;
  const request = policyRequest();
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = new URL(String(input), 'http://localhost');
    if (url.pathname.endsWith('/local-session'))
      return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
    if (!url.searchParams.has('approvalId')) return Response.json({ actor });
    return Response.json(
      changed
        ? { ...request, actor: { ...actor, principalId: '018f0000-0000-7000-8000-000000000901' } }
        : request,
    );
  });
  render(<TransactionWorkflow mode="policy" showSessionControls={false} />);
  const refresh = await screen.findByRole('button', { name: 'Refresh details' });
  changed = true;
  fireEvent.click(refresh);
  await waitFor(() =>
    expect(screen.queryByRole('button', { name: 'Execute approved request' })).toBeNull(),
  );
  expect(screen.queryByRole('button', { name: 'Refresh details' })).toBeNull();
  expect(businessPosts(fetcher)).toHaveLength(0);
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
});

function retainPolicy() {
  localStorage.setItem(
    policyKey,
    JSON.stringify({
      actor,
      value: {
        kind: 'policy-activation-renewal',
        approvalId,
        reviewToken: 'original-policy-review',
      },
    }),
  );
}
function policyFetch(
  read: () => unknown = () => policyRequest(),
  post: (body: Record<string, unknown>) => Response | Promise<Response> = () =>
    Response.json({ truthState: 'SUCCESS' }),
) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    if (url === '/api/v1/ui/local-session')
      return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
    if (url.startsWith(transactionEndpoint)) {
      if (init?.method === 'POST') return post(JSON.parse(String(init.body)));
      return Response.json(url.includes('?') ? read() : { actor });
    }
    return Response.json({ actor });
  });
}
function businessPosts(fetcher: ReturnType<typeof policyFetch>) {
  return fetcher.mock.calls.filter(
    ([url, init]) => String(url) === transactionEndpoint && init?.method === 'POST',
  );
}

it.each(['APPROVE', 'EXECUTE'] as const)(
  'captures the original policy %s and admits only one same-turn entry',
  async (commandName) => {
    retainPolicy();
    const pending = held<void>();
    vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
    const fetcher = policyFetch(() => policyRequest(commandName === 'APPROVE'));
    render(<TransactionWorkflow mode="policy" />);
    const control = await screen.findByRole('button', {
      name: commandName === 'APPROVE' ? 'Approve with security key' : 'Execute approved request',
    });
    const original = localStorage.getItem(policyKey);
    act(() => {
      fireEvent.click(control);
      fireEvent.click(control);
    });
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
    const request = policyRequest(commandName === 'APPROVE');
    expect(performWebAuthnStepUp).toHaveBeenCalledWith(
      { ...request.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      request.stepUp,
      { signal: expect.any(AbortSignal), isCurrent: expect.any(Function) },
    );
    expect(businessPosts(fetcher)).toHaveLength(0);
    await act(async () => pending.resolve());
    await screen.findByText(
      commandName === 'APPROVE'
        ? 'Independent approval recorded.'
        : 'Command readback refreshed. Inspect the operation and effect state below.',
    );
    expect(businessPosts(fetcher)).toHaveLength(1);
    expect(JSON.parse(String(businessPosts(fetcher)[0]![1]!.body))).toEqual({
      command: commandName,
      approvalId,
      ...(commandName === 'EXECUTE' ? { reviewToken: 'original-policy-review' } : {}),
    });
    expect(localStorage.getItem(policyKey)).toBe(original);
  },
);

it.each(['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const)(
  'denies policy EXECUTE after the authoritative %s changes during the helper',
  async (field) => {
    retainPolicy();
    const pending = held<void>();
    vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
    let changed = false;
    const fetcher = policyFetch(() => ({
      ...policyRequest(),
      actor: changed ? { ...actor, [field]: field === 'contextEpoch' ? '3' : approvalId } : actor,
    }));
    render(<TransactionWorkflow mode="policy" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
    const original = localStorage.getItem(policyKey);
    changed = true;
    await act(async () => pending.resolve());
    await screen.findByText('The active context changed. Refresh the page.');
    expect(businessPosts(fetcher)).toHaveLength(0);
    expect(localStorage.getItem(policyKey)).toBe(original);
    expect(
      screen.queryByRole('button', { name: 'Execute approved request' }),
    ).not.toBeInTheDocument();
  },
);
it.each(['revision', 'candidate', 'binding', 'review', 'checker'] as const)(
  'denies a stale policy approval %s after helper completion',
  async (change) => {
    retainPolicy();
    const pending = held<void>();
    vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
    let changed = false;
    const fetcher = policyFetch(() => {
      const request = policyRequest(true);
      if (!changed) return request;
      if (change === 'revision') request.approval.revision = '4';
      if (change === 'candidate') request.candidate.candidateDigest = `sha256:${'d'.repeat(64)}`;
      if (change === 'binding') request.stepUp.resourceDigest = `sha256:${'d'.repeat(64)}`;
      if (change === 'review') request.candidate.candidate = { original: false };
      if (change === 'checker')
        request.approval.checkerSubjectRef = `urn:openpc:resource:${approvalId}`;
      return request;
    });
    render(<TransactionWorkflow mode="policy" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve with security key' }));
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
    changed = true;
    await act(async () => pending.resolve());
    await screen.findByText(
      'The request changed. Read the original approval and result before continuing.',
    );
    expect(businessPosts(fetcher)).toHaveLength(0);
  },
);
it('does not substitute an edited approval selector into the original pending command', async () => {
  retainPolicy();
  const pending = held<void>();
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
  const fetcher = policyFetch();
  render(<TransactionWorkflow mode="policy" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
  await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
  const original = localStorage.getItem(policyKey);
  fireEvent.change(screen.getByLabelText('Approval ID', { exact: true }), {
    target: { value: '018f0000-0000-7000-8000-000000000302' },
  });
  expect(vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!.isCurrent!()).toBe(false);
  await act(async () => pending.resolve());
  expect(businessPosts(fetcher)).toHaveLength(0);
  expect(localStorage.getItem(policyKey)).toBe(original);
});
it('retires a pending policy helper before another transaction mode can restore or store its custody', async () => {
  retainPolicy();
  const pending = held<void>();
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
  const fetcher = policyFetch();
  const view = render(<TransactionWorkflow mode="policy" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
  await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
  const original = localStorage.getItem(policyKey);
  const lifecycle = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
  view.rerender(<TransactionWorkflow mode="deployment" />);
  await screen.findByLabelText('Request type', { exact: true });
  expect(lifecycle.signal!.aborted).toBe(true);
  await act(async () => pending.resolve());
  expect(businessPosts(fetcher)).toHaveLength(0);
  expect(localStorage.getItem(policyKey)).toBe(original);
  expect(localStorage.getItem(key)).toBeNull();
  expect(screen.getByLabelText('Approval ID', { exact: true })).toHaveValue('');
});

it.each(['challenge', 'navigator', 'verification'] as const)(
  'composes the actual helper and stops after unmount during held %s',
  async (phase) => {
    retainPolicy();
    const actual = await vi.importActual<typeof import('@openpc/ui-shell')>('@openpc/ui-shell');
    vi.mocked(performWebAuthnStepUp).mockImplementation(actual.performWebAuthnStepUp);
    const bytes = (text: string) => new TextEncoder().encode(text).buffer;
    class Credential {
      rawId = bytes('credential');
      response = {
        authenticatorData: bytes('authenticator'),
        clientDataJSON: bytes('client'),
        signature: bytes('signature'),
      };
    }
    const challenge = {
      publicKey: {
        challenge: 'Y2hhbGxlbmdl',
        rpId: 'localhost',
        allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
        timeout: 300000,
        userVerification: 'required',
      },
      expiresAt: new Date(Date.now() + 300_000).toISOString().replace('Z', '000Z'),
    };
    const verified = {
      status: 'verified',
      stepUpVerifiedAt: new Date().toISOString().replace('Z', '000Z'),
    };
    const pending = held<Response | Credential>();
    const get = vi.fn(async () => (phase === 'navigator' ? pending.promise : new Credential()));
    vi.stubGlobal('PublicKeyCredential', Credential);
    vi.stubGlobal('navigator', { credentials: { get } });
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url === '/api/v1/ui/webauthn/assertion/challenge')
        return phase === 'challenge'
          ? (pending.promise as Promise<Response>)
          : Response.json(challenge);
      if (url === '/api/v1/ui/webauthn/assertion/verify')
        return phase === 'verification'
          ? (pending.promise as Promise<Response>)
          : Response.json(verified);
      if (url === '/api/v1/ui/local-session')
        return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
      if (url.startsWith(transactionEndpoint))
        return Response.json(
          init?.method === 'POST'
            ? { truthState: 'SUCCESS' }
            : url.includes('?')
              ? policyRequest()
              : { actor },
        );
      return Response.json({ actor });
    });
    const view = render(<TransactionWorkflow mode="policy" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
    await waitFor(() => {
      if (phase === 'challenge')
        expect(
          fetcher.mock.calls.some(([url]) => String(url).endsWith('/assertion/challenge')),
        ).toBe(true);
      else if (phase === 'navigator') expect(get).toHaveBeenCalledTimes(1);
      else
        expect(fetcher.mock.calls.some(([url]) => String(url).endsWith('/assertion/verify'))).toBe(
          true,
        );
    });
    const original = localStorage.getItem(policyKey);
    const lifecycle = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    view.unmount();
    expect(lifecycle.signal!.aborted).toBe(true);
    await act(async () =>
      pending.resolve(
        phase === 'navigator'
          ? new Credential()
          : Response.json(phase === 'challenge' ? challenge : verified),
      ),
    );
    expect(businessPosts(fetcher)).toHaveLength(0);
    expect(get).toHaveBeenCalledTimes(phase === 'challenge' ? 0 : 1);
    expect(
      fetcher.mock.calls.filter(([url]) => String(url).endsWith('/assertion/verify')),
    ).toHaveLength(phase === 'verification' ? 1 : 0);
    expect(localStorage.getItem(policyKey)).toBe(original);
  },
);
it('reconciles a sent lost EXECUTE through the original approval and preserves UNKNOWN without another intent', async () => {
  retainPolicy();
  let sent = false;
  const fetcher = policyFetch(
    () =>
      sent
        ? {
            ...policyRequest(),
            candidate: { ...policyRequest().candidate, state: 'CONSUMED' },
            stepUp: null,
            result: { state: 'WRITE_AMBIGUITY', truthState: 'WRITE_AMBIGUITY' },
            operation: { operationId: approvalId, state: 'RUNNING', truthState: 'UNKNOWN' },
          }
        : policyRequest(),
    () => {
      sent = true;
      throw new TypeError(privateDetail);
    },
  );
  render(<TransactionWorkflow mode="policy" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
  const original = localStorage.getItem(policyKey);
  await screen.findByText('Result state: WRITE_AMBIGUITY · Effect: WRITE_AMBIGUITY');
  expect(screen.getByText('Operation state: RUNNING · Effect: UNKNOWN')).toBeInTheDocument();
  expect(
    screen.getByText(
      'The response was lost. Read the approval and original result before retrying.',
    ),
  ).toBeVisible();
  expect(businessPosts(fetcher)).toHaveLength(1);
  expect(
    fetcher.mock.calls
      .filter(([url]) => String(url).includes('?'))
      .every(
        ([url]) =>
          new URL(String(url), 'http://localhost').searchParams.get('approvalId') === approvalId,
      ),
  ).toBe(true);
  expect(localStorage.getItem(policyKey)).toBe(original);
  expect(document.body.textContent).not.toContain(privateDetail);
});
it('preserves the supported module RESUME attempt and original UNKNOWN readback before reading its stored successor', async () => {
  const moduleKey = 'openpc:transaction-workbench:v1:modules';
  localStorage.setItem(
    moduleKey,
    JSON.stringify({
      actor,
      value: { approvalId, reviewToken: 'original-module-review', kind: 'module-registration' },
    }),
  );
  const successor = '018f0000-0000-7000-8000-000000000302';
  let resumed = false;
  const request = {
    ...policyRequest(),
    kind: 'module-registration',
    reviewToken: 'original-module-review',
    candidate: { ...policyRequest().candidate, state: 'EXPIRED', canRequestResume: true },
    stepUp: null,
  };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    if (url === '/api/v1/ui/local-session')
      return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
    if (url.startsWith(transactionEndpoint)) {
      if (init?.method === 'POST') {
        resumed = true;
        return Response.json(
          { approvalId, truthState: 'UNKNOWN', reconciliation: 'READ_APPROVAL' },
          { status: 202 },
        );
      }
      return Response.json(
        !url.includes('?')
          ? { actor }
          : url.includes(successor)
            ? {
                ...request,
                reviewToken: 'successor-review',
                approval: {
                  ...request.approval,
                  approvalRequestId: `urn:openpc:resource:${successor}`,
                  state: 'REQUESTED',
                },
                candidate: { ...request.candidate, canRequestResume: false },
              }
            : {
                ...request,
                candidate: {
                  ...request.candidate,
                  ...(resumed
                    ? {
                        canRequestResume: false,
                        successorApprovalRef: `urn:openpc:resource:${successor}`,
                      }
                    : {}),
                },
              },
      );
    }
    return Response.json({ actor });
  });
  render(<TransactionWorkflow mode="modules" initialKind="contract-asset" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Request fresh approval' }));
  await screen.findByText(
    'The resume response is unavailable. Read the stored successor before continuing.',
  );
  expect(businessPosts(fetcher)).toHaveLength(1);
  expect(JSON.parse(String(businessPosts(fetcher)[0]![1]!.body))).toEqual({
    command: 'RESUME',
    approvalId,
    predecessorCandidateId: request.candidate.attemptId,
    expectedAttempt: '2',
    expectedRevision: '3',
    reason: 'Resume the unchanged request after approval expiry.',
  });
  expect(screen.getByLabelText('Approval ID', { exact: true })).toHaveValue(approvalId);
  expect(
    screen.queryByText(
      'A fresh approval request is ready. The previous attempt remains in its history.',
    ),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Read resumed request' }));
  await waitFor(() =>
    expect(screen.getByLabelText('Approval ID', { exact: true })).toHaveValue(successor),
  );
  expect(JSON.parse(localStorage.getItem(moduleKey)!).value.reviewToken).toBe('successor-review');
  expect(businessPosts(fetcher)).toHaveLength(1);
});
it('hides authenticator details while retaining the original policy custody', async () => {
  retainPolicy();
  vi.mocked(performWebAuthnStepUp).mockRejectedValueOnce(new Error(privateDetail));
  const fetcher = policyFetch();
  render(<TransactionWorkflow mode="policy" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
  const original = localStorage.getItem(policyKey);
  await screen.findByText(
    'The request could not be confirmed. Read the original approval and result before retrying.',
  );
  expect(document.body.textContent).not.toContain(privateDetail);
  expect(businessPosts(fetcher)).toHaveLength(0);
  expect(localStorage.getItem(policyKey)).toBe(original);
});

it('keeps the original command token when the BFF re-seals the same durable candidate during preflight', async () => {
  retainPolicy();
  let reads = 0;
  const fetcher = policyFetch(() => ({
    ...policyRequest(),
    reviewToken: ++reads === 1 ? 'original-policy-review' : 're-sealed-same-durable-review',
  }));
  render(<TransactionWorkflow mode="policy" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
  await screen.findByText(
    'Command readback refreshed. Inspect the operation and effect state below.',
  );
  expect(businessPosts(fetcher)).toHaveLength(1);
  expect(JSON.parse(String(businessPosts(fetcher)[0]![1]!.body))).toEqual({
    command: 'EXECUTE',
    approvalId,
    reviewToken: 'original-policy-review',
  });
});

it('retains accepted in-memory policy custody when persistence fails before approval readback', async () => {
  const preview = {
    reviewToken: 'accepted-preview-token',
    preview: {
      kind: 'policy-activation-renewal',
      candidateDigest: `sha256:${'a'.repeat(64)}`,
      candidate: { targetRef: `urn:openpc:resource:${approvalId}`, expectedRevision: '3' },
      redactedFields: [],
      authority: 'NONE',
    },
  };
  const fetcher = policyFetch(
    () => ({
      ...policyRequest(),
      reviewToken: undefined,
      approval: { ...policyRequest().approval, state: 'REQUESTED' },
      stepUp: null,
    }),
    (body) => Response.json(body.command === 'PREVIEW' ? preview : { approvalId }),
  );
  render(<TransactionWorkflow mode="policy" />);
  await screen.findByLabelText('Resource reference');
  fireEvent.change(screen.getByLabelText('Resource reference'), {
    target: { value: `urn:openpc:resource:${approvalId}` },
  });
  fireEvent.change(screen.getByLabelText('Expected revision'), { target: { value: '3' } });
  fireEvent.change(screen.getByLabelText('Reason', { exact: true }), {
    target: { value: 'Renew the original compiled policy.' },
  });
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new Error(privateDetail);
  });
  fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
  await screen.findByRole('button', { name: 'Request approval' });
  fireEvent.change(screen.getByLabelText('Independent checker principal ID'), {
    target: { value: '018f0000-0000-7000-8000-000000000901' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Request approval' }));
  await screen.findByText(
    'Approval requested. Share the approval ID with the independent checker.',
  );
  expect(screen.getByRole('button', { name: 'Execute approved request' })).toBeDisabled();
  expect(screen.queryByRole('button', { name: 'Request approval' })).not.toBeInTheDocument();
  expect(businessPosts(fetcher)).toHaveLength(2);
  expect(JSON.parse(String(businessPosts(fetcher)[1]![1]!.body))).toEqual({
    command: 'REQUEST_APPROVAL',
    reviewToken: 'accepted-preview-token',
    checkerId: '018f0000-0000-7000-8000-000000000901',
  });
  expect(document.body.textContent).not.toContain(privateDetail);
  expect(screen.getByLabelText('Approval ID', { exact: true })).toHaveValue(approvalId);
});
it('reconciles an already-sent successful EXECUTE using its original selector despite a later read-field edit', async () => {
  retainPolicy();
  const post = held<Response>();
  let sent = false;
  const fetcher = policyFetch(
    () =>
      sent
        ? {
            ...policyRequest(),
            candidate: { ...policyRequest().candidate, state: 'CONSUMED' },
            stepUp: null,
            result: { state: 'SUCCEEDED', truthState: 'SUCCESS' },
          }
        : policyRequest(),
    () => {
      sent = true;
      return post.promise;
    },
  );
  render(<TransactionWorkflow mode="policy" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
  await waitFor(() => expect(businessPosts(fetcher)).toHaveLength(1));
  fireEvent.change(screen.getByLabelText('Approval ID', { exact: true }), {
    target: { value: '018f0000-0000-7000-8000-000000000302' },
  });
  await act(async () => post.resolve(Response.json({ truthState: 'SUCCESS' })));
  await screen.findByText('Result state: SUCCEEDED · Effect: SUCCESS');
  expect(screen.getByLabelText('Approval ID', { exact: true })).toHaveValue(approvalId);
  expect(businessPosts(fetcher)).toHaveLength(1);
  expect(JSON.parse(String(businessPosts(fetcher)[0]![1]!.body))).toEqual({
    command: 'EXECUTE',
    approvalId,
    reviewToken: 'original-policy-review',
  });
  expect(
    fetcher.mock.calls
      .filter(([url]) => String(url).includes('?'))
      .every(
        ([url]) =>
          new URL(String(url), 'http://localhost').searchParams.get('approvalId') === approvalId,
      ),
  ).toBe(true);
});
it('captures the authenticated Platform actor for context selection and denies a changed session before its POST', async () => {
  const pending = held<void>();
  vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
  let changed = false;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    Response.json({
      ...actor,
      sessionId: changed ? approvalId : actor.sessionId,
      authenticated: true,
      contextMode: 'PLATFORM',
      availableContexts: [
        { participantId: actor.participantId, privacyDomainId: actor.privacyDomainId },
      ],
    }),
  );
  render(<TransactionWorkflow mode="policy" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Enter workspace' }));
  await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
  changed = true;
  await act(async () => pending.resolve());
  await screen.findByText('The active context changed. Refresh the page.');
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  expect(vi.mocked(performWebAuthnStepUp).mock.calls[0]![1]).toEqual({
    resourceId: actor.participantId,
    resourceDigest: 'sha256:21e6f6ef3dfec5acda58eebd0e07fca2e1394a9777f13157e3e514d611248700',
  });
});

it.each([
  [400, 'The request was rejected. Check the inputs before continuing.'],
  [401, 'The request was not authorized. Refresh the authenticated context before continuing.'],
  [403, 'The request was not authorized. Refresh the authenticated context before continuing.'],
  [404, 'The request was not authorized. Refresh the authenticated context before continuing.'],
  [409, 'The request changed. Read the original approval and result before continuing.'],
  [412, 'The request changed. Read the original approval and result before continuing.'],
  [422, 'The request was rejected. Check the inputs before continuing.'],
  [428, 'The request changed. Read the original approval and result before continuing.'],
  [
    503,
    'The request could not be confirmed. Read the original approval and result before retrying.',
  ],
] as const)(
  'shows safe guidance for HTTP %i and keeps original readback without replay',
  async (status, guidance) => {
    retainPolicy();
    const fetcher = policyFetch(undefined, () =>
      Response.json({ title: privateDetail, code: privateDetail }, { status }),
    );
    render(<TransactionWorkflow mode="policy" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
    const original = localStorage.getItem(policyKey);
    await screen.findByText(guidance);
    expect(document.body.textContent).not.toContain(privateDetail);
    expect(screen.getByRole('button', { name: 'Read approval and result' })).toBeEnabled();
    expect(businessPosts(fetcher)).toHaveLength(1);
    expect(localStorage.getItem(policyKey)).toBe(original);
  },
);

it.each(
  (['base', 'details'] as const).flatMap((stage) =>
    (['unchanged', 'edited', 'unmounted', 'changed actor'] as const).map(
      (interruption) => [stage, interruption] as const,
    ),
  ),
)(
  'reads original approval after refreshed step-up without replay (%s, %s)',
  async (stage, interruption) => {
    retainPolicy();
    const pending = held<Response>();
    let refreshed = false;
    let reading = false;
    let readSignal: AbortSignal | undefined;
    let originalReads = 0;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url === '/api/v1/ui/local-session')
        return Response.json({
          ...actor,
          authenticated: true,
          contextMode: 'PARTICIPANT',
          stepUpVerifiedAt: refreshed ? '2026-10-10T00:01:00Z' : '2026-10-10T00:00:00Z',
        });
      if (init?.method === 'POST') {
        refreshed = true;
        return Response.json({ title: privateDetail, code: 'PC-AUTH-0005' }, { status: 404 });
      }
      if (url.includes('?')) {
        if (reading) originalReads++;
        if (reading && stage === 'details') {
          readSignal = init?.signal ?? undefined;
          return pending.promise;
        }
        return Response.json(policyRequest());
      }
      if (reading && stage === 'base') {
        readSignal = init?.signal ?? undefined;
        return pending.promise;
      }
      return Response.json({ actor });
    });
    const view = render(<TransactionWorkflow mode="policy" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
    await screen.findByText(
      'The request was not authorized. Refresh the authenticated context before continuing.',
    );
    const original = localStorage.getItem(policyKey);
    reading = true;
    fireEvent.click(screen.getByRole('button', { name: 'Read approval and result' }));
    await waitFor(() => expect(readSignal).toBeDefined());
    const prematurelyCancelled = readSignal!.aborted;
    if (interruption === 'edited')
      fireEvent.change(screen.getByLabelText('Approval ID', { exact: true }), {
        target: { value: '018f0000-0000-7000-8000-000000000302' },
      });
    if (interruption === 'unmounted') view.unmount();
    await act(async () =>
      pending.resolve(
        Response.json({
          ...(stage === 'details' ? policyRequest() : {}),
          actor:
            interruption === 'changed actor'
              ? { ...actor, sessionId: '018f0000-0000-7000-8000-000000000222' }
              : actor,
        }),
      ),
    );
    expect(prematurelyCancelled).toBe(false);
    expect(businessPosts(fetcher)).toHaveLength(1);
    expect(document.body.textContent).not.toContain(privateDetail);
    expect(originalReads).toBe(stage === 'details' || interruption === 'unchanged' ? 1 : 0);
    if (interruption === 'unchanged') {
      expect(await screen.findByRole('button', { name: 'Execute approved request' })).toBeEnabled();
      expect(screen.getByLabelText('Approval ID', { exact: true })).toHaveValue(approvalId);
      expect(localStorage.getItem(policyKey)).toBe(original);
    } else if (interruption === 'changed actor') {
      expect(screen.queryByRole('button', { name: 'Execute approved request' })).toBeNull();
      expect(document.body.textContent).not.toContain(approvalId);
    } else expect(readSignal!.aborted).toBe(true);
  },
);

it('disables refresh while the initial authenticated context is pending', async () => {
  const pending = held<Response>();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      String(input).includes('/local-session')
        ? Response.json({ authenticated: true, contextMode: 'PARTICIPANT' })
        : pending.promise,
    );
  render(<TransactionWorkflow mode="policy" showSessionControls={false} />);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  const refresh = screen.getByRole('button', { name: 'Refresh workspace' });
  expect(refresh).toBeDisabled();
  expect(
    screen.getByRole('region', { name: 'Governed policy activation renewal' }),
  ).toHaveAttribute('aria-busy', 'true');
  expect(screen.getByText('Loading workspace…')).toBeVisible();
  fireEvent.click(refresh);
  expect(fetcher).toHaveBeenCalledTimes(2);
  await act(async () => pending.resolve(Response.json({ actor })));
  expect(await screen.findByRole('button', { name: 'New request' })).toBeEnabled();
  expect(
    screen.getByRole('region', { name: 'Governed policy activation renewal' }),
  ).toHaveAttribute('aria-busy', 'false');
  expect(screen.queryByRole('button', { name: 'Refresh workspace' })).toBeNull();
  expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
});

it('refreshes an authenticated context with no saved approval without cancelling its own read', async () => {
  let authenticated = false;
  const pending = held<Response>();
  let readSignal: AbortSignal | undefined;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (String(input) === '/api/v1/ui/local-session')
      return Response.json({
        ...actor,
        authenticated,
        contextMode: 'PARTICIPANT',
        stepUpVerifiedAt: authenticated ? '2026-10-10T00:01:00Z' : undefined,
      });
    readSignal = init?.signal ?? undefined;
    return pending.promise;
  });
  render(<TransactionWorkflow mode="policy" />);
  await screen.findByRole('button', { name: 'Refresh workspace' });
  await act(async () => undefined);
  authenticated = true;
  fireEvent.click(screen.getByRole('button', { name: 'Refresh workspace' }));
  await waitFor(() => expect(readSignal).toBeDefined());
  expect(readSignal!.aborted).toBe(false);
  await act(async () => pending.resolve(Response.json({ actor })));
  expect(await screen.findByRole('button', { name: 'New request' })).toBeEnabled();
  expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
  expect(fetcher.mock.calls.every(([url]) => !String(url).includes('approvalId='))).toBe(true);
});

it('keeps typed EXECUTE UNKNOWN on the original approval readback without inventing a candidate state or replaying', async () => {
  retainPolicy();
  const fetcher = policyFetch(undefined, () =>
    Response.json(
      { truthState: 'UNKNOWN', reconciliation: 'READ_APPROVAL', approvalId },
      { status: 202 },
    ),
  );
  render(<TransactionWorkflow mode="policy" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
  await screen.findByText(
    'The command response is unresolved. Read the original approval and result before continuing.',
  );
  expect(businessPosts(fetcher)).toHaveLength(1);
  expect(screen.getByLabelText('Approval ID', { exact: true })).toHaveValue(approvalId);
  expect(screen.queryByText('Operation state: UNKNOWN')).not.toBeInTheDocument();
  expect(
    fetcher.mock.calls
      .filter(([url]) => String(url).includes('?'))
      .every(
        ([url]) =>
          new URL(String(url), 'http://localhost').searchParams.get('approvalId') === approvalId,
      ),
  ).toBe(true);
});

it('offers reader admission through the governed runtime workflow', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    Response.json(
      String(input).includes('/local-session')
        ? { authenticated: true, contextMode: 'PARTICIPANT' }
        : { actor },
    ),
  );
  render(<TransactionWorkflow mode="runtime" showSessionControls={false} />);
  expect(screen.queryByRole('heading', { name: 'Account & workspace' })).not.toBeInTheDocument();
  const select = await screen.findByLabelText('Request type');
  expect(Array.from((select as HTMLSelectElement).options).map((option) => option.value)).toEqual([
    'indexer-admission',
  ]);
  fireEvent.change(select, { target: { value: 'indexer-admission' } });
  expect(
    screen.getByLabelText('Reader profile artifact digest (sha256)', { exact: true }),
  ).toBeVisible();
});

function notifyTransition(channel: 'event' | 'storage', phase: 'changing' | 'settled') {
  if (channel === 'event')
    fireEvent(window, new CustomEvent(sessionTransitionEvent, { detail: { phase } }));
  else
    fireEvent(
      window,
      new StorageEvent('storage', {
        key: sessionTransitionStorageKey,
        newValue: JSON.stringify({ phase, nonce: 'non-secret-notification' }),
      }),
    );
}

it.each(['event', 'storage'] as const)(
  'clears private request data on a %s transition and discards the previous read',
  async (channel) => {
    const nextActor = { ...actor, privacyDomainId: approvalId, contextEpoch: '3' };
    const pending = held<Response>();
    let hold = false,
      changed = false;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).includes('/local-session'))
        return Response.json({
          ...(changed ? nextActor : actor),
          authenticated: true,
          contextMode: 'PARTICIPANT',
        });
      if (hold && !changed) return pending.promise;
      return Response.json({ actor: changed ? nextActor : actor });
    });
    render(<TransactionWorkflow mode="providers" showSessionControls={false} />);
    const chain = await screen.findByLabelText('Chain ID');
    fireEvent.change(chain, { target: { value: 'private-unsent-A' } });
    hold = true;
    fireEvent.focus(window);
    await waitFor(() => expect(chain).not.toBeVisible());
    notifyTransition(channel, 'changing');
    expect(screen.queryByLabelText('Chain ID')).toBeNull();
    expect(screen.queryByText(/Privacy domain:/)).toBeNull();
    changed = true;
    notifyTransition(channel, 'settled');
    const current = await screen.findByLabelText('Chain ID');
    expect(current).toHaveValue('');
    await act(async () => pending.resolve(Response.json({ actor })));
    fireEvent.click(screen.getByRole('button', { name: 'Technical references' }));
    expect(screen.getByText(new RegExp(nextActor.privacyDomainId))).toBeVisible();
    expect(screen.queryByText(new RegExp(actor.privacyDomainId))).toBeNull();
    expect(screen.getByLabelText('Chain ID')).toHaveValue('');
    expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
  },
);

it.each(['event', 'storage'] as const)(
  'cancels a prepared approval on a %s transition without dispatch or custody loss',
  async (channel) => {
    retainPolicy();
    const pending = held<void>();
    vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
    const fetcher = policyFetch();
    render(<TransactionWorkflow mode="policy" showSessionControls={false} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
    const original = localStorage.getItem(policyKey);
    notifyTransition(channel, 'changing');
    expect(vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!.signal!.aborted).toBe(true);
    await act(async () => pending.resolve());
    expect(businessPosts(fetcher)).toHaveLength(0);
    expect(localStorage.getItem(policyKey)).toBe(original);
    expect(screen.queryByRole('button', { name: 'Execute approved request' })).toBeNull();
  },
);

it('clears private inputs after sign-out detected by focus without a storage notification', async () => {
  let authenticated = true;
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      Response.json(
        String(input).includes('/local-session')
          ? { ...actor, authenticated, contextMode: 'PARTICIPANT' }
          : { actor },
      ),
    );
  render(<TransactionWorkflow mode="providers" showSessionControls={false} />);
  fireEvent.change(await screen.findByLabelText('Chain ID'), {
    target: { value: 'private-unsent' },
  });
  authenticated = false;
  fireEvent.focus(window);
  await screen.findByRole('button', { name: 'Refresh workspace' });
  expect(screen.queryByLabelText('Chain ID')).toBeNull();
  authenticated = true;
  fireEvent.focus(window);
  expect(await screen.findByLabelText('Chain ID')).toHaveValue('');
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it.each(['session-null', 'actor-missing', 'actor-empty'] as const)(
  'fails closed on a malformed successful focus read: %s',
  async (failure) => {
    let malformed = false;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).includes('/local-session'))
        return Response.json(
          malformed && failure === 'session-null'
            ? null
            : { ...actor, authenticated: true, contextMode: 'PARTICIPANT' },
        );
      return Response.json(
        malformed ? (failure === 'actor-empty' ? { actor: {} } : {}) : { actor },
      );
    });
    render(<TransactionWorkflow mode="providers" showSessionControls={false} />);
    fireEvent.change(await screen.findByLabelText('Chain ID'), {
      target: { value: 'private-input' },
    });
    malformed = true;
    fireEvent.focus(window);
    await screen.findByText(
      'The request could not be confirmed. Read the original approval and result before retrying.',
    );
    expect(screen.queryByLabelText('Chain ID')).toBeNull();
    expect(screen.queryByText(/Privacy domain:/)).toBeNull();
    expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
  },
);

it.each([false, true])(
  'revalidates focus during a held helper, preserving work only for the unchanged actor (changed=%s)',
  async (changed) => {
    retainPolicy();
    const pending = held<void>();
    vi.mocked(performWebAuthnStepUp).mockImplementationOnce(() => pending.promise);
    let switched = false;
    const nextActor = { ...actor, privacyDomainId: approvalId, contextEpoch: '3' };
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (String(input).includes('/local-session'))
        return Response.json({
          ...(switched ? nextActor : actor),
          authenticated: true,
          contextMode: 'PARTICIPANT',
        });
      if (init?.method === 'POST') return Response.json({ truthState: 'SUCCESS' });
      return Response.json(
        String(input).includes('?') ? policyRequest() : { actor: switched ? nextActor : actor },
      );
    });
    render(<TransactionWorkflow mode="policy" showSessionControls={false} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
    await waitFor(() => expect(performWebAuthnStepUp).toHaveBeenCalledTimes(1));
    const original = localStorage.getItem(policyKey);
    const lifecycle = vi.mocked(performWebAuthnStepUp).mock.calls[0]![2]!;
    switched = changed;
    const count = fetcher.mock.calls.length;
    fireEvent.focus(window);
    expect(screen.getByLabelText('Approval ID', { exact: true })).not.toBeVisible();
    await waitFor(() => expect(fetcher.mock.calls.length).toBeGreaterThan(count + 2));
    await waitFor(() => expect(screen.queryByText('Loading workspace…')).toBeNull());
    expect(lifecycle.signal!.aborted).toBe(changed);
    await act(async () => pending.resolve());
    expect(businessPosts(fetcher)).toHaveLength(changed ? 0 : 1);
    expect(localStorage.getItem(policyKey)).toBe(original);
    if (changed) expect(screen.queryByText(new RegExp(actor.privacyDomainId))).toBeNull();
  },
);

it('conceals a changed actor while SENT transport completes without abort, replay or custody deletion', async () => {
  retainPolicy();
  const pending = held<Response>();
  let switched = false;
  const nextActor = { ...actor, privacyDomainId: approvalId, contextEpoch: '3' };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (String(input).includes('/local-session'))
      return Response.json({
        ...(switched ? nextActor : actor),
        authenticated: true,
        contextMode: 'PARTICIPANT',
      });
    if (init?.method === 'POST') return pending.promise;
    return Response.json(
      String(input).includes('?') ? policyRequest() : { actor: switched ? nextActor : actor },
    );
  });
  render(<TransactionWorkflow mode="policy" showSessionControls={false} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Execute approved request' }));
  await waitFor(() => expect(businessPosts(fetcher)).toHaveLength(1));
  const original = localStorage.getItem(policyKey);
  const sent = businessPosts(fetcher)[0]![1]!;
  expect(sent.signal).toBeUndefined();
  switched = true;
  fireEvent.focus(window);
  await waitFor(() => expect(screen.queryByText(new RegExp(actor.privacyDomainId))).toBeNull());
  await act(async () => pending.resolve(Response.json({ truthState: 'SUCCESS' })));
  expect(businessPosts(fetcher)).toHaveLength(1);
  expect(localStorage.getItem(policyKey)).toBe(original);
  expect(screen.queryByText(new RegExp(actor.privacyDomainId))).toBeNull();
});

it('keeps a newer focus fence concealed when the older initial full read completes', async () => {
  const full = held<Response>(),
    focus = held<Response>();
  let sessionReads = 0;
  let ownerReads = 0;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input).includes('/local-session')) {
      if (++sessionReads === 2) return focus.promise;
      return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
    }
    return ++ownerReads === 1 ? full.promise : Response.json({ actor });
  });
  render(<TransactionWorkflow mode="providers" showSessionControls={false} />);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  fireEvent.focus(window);
  await waitFor(() => expect(sessionReads).toBe(2));
  await act(async () => full.resolve(Response.json({ actor })));
  expect(screen.getByLabelText('Chain ID')).not.toBeVisible();
  expect(screen.getByText('Loading workspace…')).toBeVisible();
  await act(async () =>
    focus.resolve(Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' })),
  );
  await waitFor(() => expect(screen.getByLabelText('Chain ID')).toBeVisible());
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it('retains original stored custody when context changes during the first approval detail read', async () => {
  retainPolicy();
  const original = localStorage.getItem(policyKey);
  const pending = held<Response>();
  let changed = false;
  const nextActor = { ...actor, privacyDomainId: approvalId, contextEpoch: '3' };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input).includes('/local-session'))
      return Response.json({
        ...(changed ? nextActor : actor),
        authenticated: true,
        contextMode: 'PARTICIPANT',
      });
    if (String(input).includes('?')) return pending.promise;
    return Response.json({ actor: changed ? nextActor : actor });
  });
  render(<TransactionWorkflow mode="policy" showSessionControls={false} />);
  await waitFor(() =>
    expect(fetcher.mock.calls.some(([url]) => String(url).includes('?'))).toBe(true),
  );
  notifyTransition('storage', 'changing');
  changed = true;
  notifyTransition('storage', 'settled');
  await screen.findByRole('button', { name: 'New request' });
  expect(localStorage.getItem(policyKey)).toBe(original);
  await act(async () => pending.resolve(Response.json(policyRequest())));
  expect(localStorage.getItem(policyKey)).toBe(original);
  expect(screen.queryByText(new RegExp(actor.privacyDomainId))).toBeNull();
  expect(screen.getByLabelText('Approval ID', { exact: true })).toHaveValue('');
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it.each(['contract-binding', 'contract-method'] as const)(
  'prepares %s references from authorized catalogue records without dispatching a command',
  async (kind) => {
    const ref = (suffix: string) =>
      `urn:openpc:resource:018f0000-0000-7000-8000-${suffix.padStart(12, '0')}`;
    const digest = `sha256:${'a'.repeat(64)}`;
    const common = { revision: '1', createdAt: '2026-10-10T00:00:00Z' };
    const contract = {
      ...common,
      id: ref('10'),
      label: 'Customer payment workflow',
      logicalName: 'customer-payment',
    };
    const abi = {
      ...common,
      id: ref('12'),
      label: 'Approved repository ABI',
      abiDigest: digest,
      source: 'Approved repository ABI',
      functions: 2,
    };
    const binding = {
      ...common,
      id: ref('11'),
      label: `0x${'11'.repeat(20)}`,
      logicalContractId: ref('10'),
      abiArtifactId: ref('12'),
      abiDigest: digest,
      contractAddress: `0x${'11'.repeat(20)}`,
      chainId: '31337',
      networkId: 'Acceptance network',
      state: 'BOUND',
    };
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes('/local-session'))
        return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
      if (url.includes('/contract-catalogue')) {
        const category = new URL(url, 'http://localhost').searchParams.get('kind');
        return Response.json({
          kind: category,
          actor,
          items: [category === 'bindings' ? binding : category === 'abis' ? abi : contract],
          nextCursor: null,
          total: '1',
          completeness: 'COMPLETE',
          authorizedEmpty: false,
          snapshotRevision: '1',
        });
      }
      return Response.json({ actor });
    });
    render(<TransactionWorkflow mode="modules" initialKind={kind} showSessionControls={false} />);
    await screen.findByLabelText('Request type');
    expect(
      screen.getByRole('heading', {
        name:
          kind === 'contract-binding'
            ? 'Bind deployed contract and ABI'
            : 'Register contract method policy',
      }),
    ).toBeVisible();
    expect(screen.getByText(actor.participantId, { selector: 'dd' })).not.toBeVisible();
    expect(screen.getByLabelText('Approval ID', { exact: true })).not.toBeVisible();
    expect(screen.getByLabelText('Resource ID', { exact: true })).not.toBeVisible();
    const lookup = screen.getByRole('button', { name: 'Technical references' });
    fireEvent.click(lookup);
    expect(screen.getByLabelText('Resource ID', { exact: true })).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Create change' }));
    if (kind === 'contract-binding') {
      fireEvent.click(await screen.findByRole('button', { name: 'Use Customer payment workflow' }));
      expect(screen.getByLabelText('Logical contract resource reference')).toHaveValue(contract.id);
      expect(screen.getByLabelText('Logical contract resource reference')).not.toBeVisible();
      expect(screen.getByText('Customer payment workflow', { selector: 'p' })).toBeVisible();
      fireEvent.click(screen.getByRole('button', { name: 'ABI artifacts' }));
      fireEvent.click(await screen.findByRole('button', { name: 'Use Approved repository ABI' }));
    } else {
      await screen.findByRole('button', { name: 'View bindings for Customer payment workflow' });
      fireEvent.click(screen.getByRole('button', { name: 'Network bindings' }));
      fireEvent.click(
        await screen.findByRole('button', { name: `Use ${binding.contractAddress}` }),
      );
      expect(screen.getByLabelText('Contract runtime binding reference')).toHaveValue(binding.id);
      expect(screen.getByText('Acceptance network · ' + binding.contractAddress)).toBeVisible();
    }
    expect(screen.getByLabelText('Imported ABI resource reference')).toHaveValue(abi.id);
    expect(screen.getByLabelText(/Canonical ABI digest/u)).toHaveValue(digest);
    expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
    let transitionNonce: string | undefined;
    act(() => {
      transitionNonce = notifySessionTransition('changing');
    });
    expect(screen.queryByText('Customer payment workflow')).not.toBeInTheDocument();
    expect(
      screen.queryByText('Acceptance network · ' + binding.contractAddress),
    ).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Imported ABI resource reference')).not.toBeInTheDocument();
    act(() => {
      notifySessionTransition('settled', transitionNonce);
    });
    await screen.findByLabelText('Imported ABI resource reference');
    expect(screen.getByLabelText('Imported ABI resource reference')).toHaveValue('');
    expect(screen.getByLabelText(/Canonical ABI digest/u)).toHaveValue('');
  },
);

const methodFields = {
  runtimeBindingId: `urn:openpc:resource:${approvalId}`,
  abiArtifactId: `urn:openpc:resource:${actor.principalId}`,
  abiDigest: `sha256:${'a'.repeat(64)}`,
  canonicalSignature: 'settle(address)',
  effect: 'WRITE',
  approvalRequirement: 'MAKER_CHECKER',
  mfaRequirement: 'WEBAUTHN',
  rpcMethodPolicyDigest: `sha256:${'b'.repeat(64)}`,
  nestedCallSetDigest: `sha256:${'c'.repeat(64)}`,
};

it('reviews selected ABI method and role IDs without requiring technical entry or granting authority', async () => {
  const roleId = `urn:openpc:role:${actor.principalId}`;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const path = String(input);
    if (path.includes('/local-session'))
      return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
    if (path.includes('/contract-method-choices'))
      return Response.json({
        actor,
        runtimeBindingId: methodFields.runtimeBindingId,
        abiArtifactId: methodFields.abiArtifactId,
        abiDigest: methodFields.abiDigest,
        methods: [{ signature: 'settle(address)', selector: '0x12345678', effect: 'WRITE' }],
      });
    if (path.includes('/role-catalogue'))
      return Response.json({
        actor,
        items: [
          {
            effect: {
              id: actor.principalId,
              roleId,
              displayName: 'Settlement operator',
              participantId: actor.participantId,
              revision: '1',
              state: 'ACTIVE',
              actionIntentIds: [],
            },
          },
        ],
        nextCursor: null,
        authorizedEmpty: false,
        observedAt: '2026-10-10T00:00:00Z',
      });
    if (init?.method === 'POST') {
      const body = JSON.parse(String(init.body));
      return Response.json({
        reviewToken: 'selected-fields-review-only',
        preview: {
          kind: 'contract-method',
          candidateDigest: methodFields.abiDigest,
          candidate: body.fields,
          redactedFields: [],
          authority: 'NONE',
        },
      });
    }
    return Response.json({ actor });
  });
  render(
    <TransactionWorkflow
      mode="modules"
      initialKind="contract-method"
      initialFields={{ ...methodFields, canonicalSignature: '', effect: 'READ' }}
      showSessionControls={false}
    />,
  );
  await screen.findByRole('option', { name: 'settle(address) · Change state' });
  await screen.findByRole('option', { name: 'Settlement operator' });
  expect(businessPosts(fetcher)).toHaveLength(0);
  expect(screen.getByLabelText(/Canonical method signature/u)).not.toBeVisible();
  expect(screen.getByLabelText('Required roles', { exact: true })).not.toBeVisible();
  fireEvent.change(screen.getByRole('combobox', { name: 'Contract method' }), {
    target: { value: 'settle(address)' },
  });
  fireEvent.change(screen.getByRole('combobox', { name: 'Add required role' }), {
    target: { value: roleId },
  });
  expect(screen.getByText('Settlement operator', { selector: 'span' })).toBeVisible();
  expect(screen.getByRole('combobox', { name: 'Method effect' })).toHaveValue('WRITE');
  fireEvent.click(screen.getByRole('checkbox', { name: 'Test' }));
  fireEvent.change(screen.getByLabelText('Reason', { exact: true }), {
    target: { value: 'Review the customer settlement method policy.' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
  await screen.findByText('Preview prepared. Request independent approval for these exact inputs.');
  const posts = businessPosts(fetcher);
  expect(posts).toHaveLength(1);
  expect(JSON.parse(String(posts[0]![1]!.body))).toMatchObject({
    command: 'PREVIEW',
    kind: 'contract-method',
    fields: { ...methodFields, requiredRoles: [roleId], environments: ['TEST'] },
  });
});

it('reviews role entry and environment choices using the unchanged method request format', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (String(input).includes('/local-session'))
      return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
    if (init?.method === 'POST') {
      const body = JSON.parse(String(init.body));
      return Response.json({
        reviewToken: 'method-review-only',
        preview: {
          kind: 'contract-method',
          candidateDigest: methodFields.abiDigest,
          candidate: body.fields,
          redactedFields: [],
          authority: 'NONE',
        },
      });
    }
    return Response.json({ actor });
  });
  render(
    <TransactionWorkflow
      mode="modules"
      initialKind="contract-method"
      initialFields={methodFields}
      showSessionControls={false}
    />,
  );
  const roles = await screen.findByLabelText('Required roles', { exact: true });
  expect(roles).toHaveValue('');
  for (const name of ['Local', 'Development', 'Test', 'Production'])
    expect(screen.getByRole('checkbox', { name })).not.toBeChecked();
  fireEvent.change(roles, { target: { value: 'Debtor\n\n Creditor \n' } });
  expect(roles).toHaveValue('Debtor\n\n Creditor \n');
  fireEvent.click(screen.getByRole('checkbox', { name: 'Test' }));
  fireEvent.click(screen.getByRole('checkbox', { name: 'Development' }));
  fireEvent.click(screen.getByRole('checkbox', { name: 'Development' }));
  expect(screen.getByRole('combobox', { name: 'Execution approval' })).toHaveValue('MAKER_CHECKER');
  expect(screen.getByRole('option', { name: 'Independent maker and checker' })).toBeInTheDocument();
  expect(screen.getByRole('combobox', { name: 'Execution authentication' })).toHaveValue(
    'WEBAUTHN',
  );
  fireEvent.change(screen.getByLabelText('Reason', { exact: true }), {
    target: { value: 'Review customer settlement access.' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
  await screen.findByText('Preview prepared. Request independent approval for these exact inputs.');
  const posts = businessPosts(fetcher);
  expect(posts).toHaveLength(1);
  expect(JSON.parse(String(posts[0]![1]!.body))).toMatchObject({
    command: 'PREVIEW',
    kind: 'contract-method',
    fields: { ...methodFields, requiredRoles: ['Debtor', 'Creditor'], environments: ['TEST'] },
  });
  expect(Object.keys(JSON.parse(String(posts[0]![1]!.body)).fields).sort()).toEqual(
    [...Object.keys(methodFields), 'requiredRoles', 'environments'].sort(),
  );
});

it('clears the readable role draft and environment choices when the owning context changes', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input) =>
      Response.json(
        String(input).includes('/local-session')
          ? { ...actor, authenticated: true, contextMode: 'PARTICIPANT' }
          : { actor },
      ),
    );
  render(
    <TransactionWorkflow
      mode="modules"
      initialKind="contract-method"
      showSessionControls={false}
    />,
  );
  const roles = await screen.findByLabelText('Required roles', { exact: true });
  fireEvent.change(roles, { target: { value: 'PRIVATE_CUSTOMER_ROLE\n' } });
  fireEvent.click(screen.getByRole('checkbox', { name: 'Test' }));
  let nonce: string | undefined;
  act(() => {
    nonce = notifySessionTransition('changing');
  });
  expect(screen.queryByLabelText('Required roles', { exact: true })).not.toBeInTheDocument();
  act(() => {
    notifySessionTransition('settled', nonce);
  });
  expect(await screen.findByLabelText('Required roles', { exact: true })).toHaveValue('');
  expect(screen.getByRole('checkbox', { name: 'Test' })).not.toBeChecked();
  expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
});

it('keeps unsupported existing method arrays inspectable instead of replacing them with defaults', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
    Response.json(
      String(input).includes('/local-session')
        ? { ...actor, authenticated: true, contextMode: 'PARTICIPANT' }
        : { actor },
    ),
  );
  render(
    <TransactionWorkflow
      mode="modules"
      initialKind="contract-method"
      initialFields={{ requiredRoles: '{"unsupported":"role"}', environments: '["UNKNOWN"]' }}
      showSessionControls={false}
    />,
  );
  expect(
    await screen.findByLabelText('Required role names (JSON array)', { exact: true }),
  ).toHaveValue('{"unsupported":"role"}');
  expect(
    screen.getByLabelText(
      'Allowed environments (JSON array: LOCAL, DEVELOPMENT, TEST or PRODUCTION)',
      { exact: true },
    ),
  ).toHaveValue('["UNKNOWN"]');
  expect(screen.queryByRole('checkbox', { name: 'Production' })).not.toBeInTheDocument();
});

it.each([['Debtor\nCreditor'], [' Debtor '], ['\tDebtor'], ['Debtor\r\nCreditor']])(
  'preserves exact existing role names that cannot round-trip through line entry: %j',
  async (...roles) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      Response.json(
        String(input).includes('/local-session')
          ? { ...actor, authenticated: true, contextMode: 'PARTICIPANT' }
          : { actor },
      ),
    );
    const original = JSON.stringify(roles);
    render(
      <TransactionWorkflow
        mode="modules"
        initialKind="contract-method"
        initialFields={{ requiredRoles: original }}
        showSessionControls={false}
      />,
    );
    expect(
      await screen.findByLabelText('Required role names (JSON array)', { exact: true }),
    ).toHaveValue(original);
    expect(screen.queryByLabelText('Required roles', { exact: true })).not.toBeInTheDocument();
  },
);

const contractCheckerId = '018f0000-0000-7000-8000-000000000190';
function contractCheckerPage(binding = actor, kind: 'USER' | 'PLATFORM_OPERATOR' = 'USER') {
  return {
    actor: binding,
    items: [
      {
        effect: {
          principalId: actor.principalId,
          displayLabel: 'Current maker',
          kind,
          state: 'ACTIVE',
          revision: '1',
        },
      },
      {
        effect: {
          principalId: contractCheckerId,
          displayLabel: 'Payment reviewer',
          kind,
          state: 'ACTIVE',
          revision: '1',
        },
      },
    ],
    nextCursor: null,
    observedAt: '2026-10-10T00:00:00Z',
    authorizedEmpty: false,
  };
}
async function openContractReview(
  principals: (url: string) => Promise<Response> = async () => Response.json(contractCheckerPage()),
  mode: 'modules' | 'providers' = 'modules',
) {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    if (url.includes('/local-session'))
      return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
    if (url.includes('/principal-catalogue')) return principals(url);
    if (init?.method === 'POST') {
      const body = JSON.parse(String(init.body));
      return Response.json(
        body.command === 'PREVIEW'
          ? {
              reviewToken: 'original-contract-review',
              preview: {
                kind: mode === 'providers' ? 'provider-profile' : 'contract-asset',
                candidateDigest: `sha256:${'a'.repeat(64)}`,
                candidate:
                  mode === 'providers'
                    ? {
                        chainId: '92870',
                        endpointSecretRef: `urn:openpc:secret:${approvalId}`,
                        behaviorFingerprint: `sha256:${'a'.repeat(64)}`,
                      }
                    : {
                        logicalName: 'example.payment-registry',
                        displayName: 'Example payment registry',
                      },
                redactedFields: [],
                authority: 'NONE',
              },
            }
          : { approvalId },
      );
    }
    return Response.json({ actor });
  });
  render(
    <TransactionWorkflow
      mode={mode}
      initialKind={mode === 'modules' ? 'contract-asset' : 'provider-profile'}
      initialFields={
        mode === 'providers'
          ? {
              chainId: '92870',
              endpointSecretRef: `urn:openpc:secret:${approvalId}`,
              behaviorFingerprint: `sha256:${'a'.repeat(64)}`,
            }
          : {
              logicalName: 'example.payment-registry',
              displayName: 'Example payment registry',
            }
      }
      showSessionControls={false}
    />,
  );
  await screen.findByLabelText('Request type');
  fireEvent.change(screen.getByLabelText('Reason', { exact: true }), {
    target: { value: 'Register the customer payment application for independent review.' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
  await screen.findByRole('button', { name: 'Choose checker' });
  return fetcher;
}

it.each(['modules', 'providers'] as const)(
  'chooses a named current checker for %s review without granting approval or executing',
  async (mode) => {
    const fetcher = await openContractReview(undefined, mode);
    const request = screen.getByRole('button', { name: 'Request approval' });
    expect(request).toBeDisabled();
    expect(screen.getByLabelText('Independent checker principal ID')).not.toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Choose checker' }));
    await screen.findByText('The current maker cannot check their own change.');
    expect(screen.queryByRole('button', { name: 'Select Current maker' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Select Payment reviewer' }));
    expect(screen.getByText('Selected checker: Payment reviewer')).toBeVisible();
    expect(screen.getByLabelText('Independent checker principal ID')).toHaveValue(
      contractCheckerId,
    );
    expect(screen.getByLabelText('Independent checker principal ID')).not.toBeVisible();
    expect(
      screen.queryByRole('region', { name: 'Choose an independent checker' }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Choose checker' })).toHaveFocus();
    expect(businessPosts(fetcher)).toHaveLength(1);
    fireEvent.click(request);
    await waitFor(() => expect(businessPosts(fetcher)).toHaveLength(2));
    expect(JSON.parse(String(businessPosts(fetcher)[1]![1]!.body))).toEqual({
      command: 'REQUEST_APPROVAL',
      reviewToken: 'original-contract-review',
      checkerId: contractCheckerId,
    });
    expect(
      businessPosts(fetcher).every(
        ([, init]) => JSON.parse(String(init?.body)).command !== 'EXECUTE',
      ),
    ).toBe(true);
  },
);

it.each(['modules', 'providers'] as const)(
  'chooses an active platform operator for %s after clearing the previous user selection',
  async (mode) => {
    const fetcher = await openContractReview(async (url) => {
      const kind = new URL(url, 'http://localhost').searchParams.get('kind');
      return Response.json(
        contractCheckerPage(actor, kind === 'PLATFORM_OPERATOR' ? kind : 'USER'),
      );
    }, mode);
    fireEvent.click(screen.getByRole('button', { name: 'Choose checker' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Select Payment reviewer' }));
    expect(screen.getByRole('button', { name: 'Request approval' })).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: 'Choose checker' }));
    fireEvent.change(screen.getByLabelText('Checker account type'), {
      target: { value: 'PLATFORM_OPERATOR' },
    });
    expect(screen.getByLabelText('Independent checker principal ID')).toHaveValue('');
    expect(screen.getByRole('button', { name: 'Request approval' })).toBeDisabled();
    fireEvent.click(await screen.findByRole('button', { name: 'Select Payment reviewer' }));
    expect(screen.queryByRole('button', { name: 'Select Current maker' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Request approval' }));
    await waitFor(() => expect(businessPosts(fetcher)).toHaveLength(2));
    expect(JSON.parse(String(businessPosts(fetcher)[1]![1]!.body))).toEqual({
      command: 'REQUEST_APPROVAL',
      reviewToken: 'original-contract-review',
      checkerId: contractCheckerId,
    });
    expect(
      fetcher.mock.calls.some(([input]) => String(input).includes('kind=PLATFORM_OPERATOR')),
    ).toBe(true);
  },
);

it.each(['modules', 'providers'] as const)(
  'conceals a late user catalogue after switching the %s checker account type',
  async (mode) => {
    const pending = held<Response>();
    const fetcher = await openContractReview(
      async (url) =>
        new URL(url, 'http://localhost').searchParams.get('kind') === 'PLATFORM_OPERATOR'
          ? Response.json({
              ...contractCheckerPage(actor, 'PLATFORM_OPERATOR'),
              items: [],
              authorizedEmpty: true,
            })
          : pending.promise,
      mode,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Choose checker' }));
    fireEvent.change(screen.getByLabelText('Checker account type'), {
      target: { value: 'PLATFORM_OPERATOR' },
    });
    await screen.findByText('No authorized principals match this search.');
    await act(async () => pending.resolve(Response.json(contractCheckerPage())));
    expect(screen.queryByText('Payment reviewer')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Independent checker principal ID')).toHaveValue('');
    expect(screen.getByRole('button', { name: 'Request approval' })).toBeDisabled();
    expect(businessPosts(fetcher)).toHaveLength(1);
  },
);

it.each(['modules', 'providers'] as const)(
  'does not offer a checker from a foreign-context catalogue or submit %s approval',
  async (mode) => {
    const fetcher = await openContractReview(
      async () =>
        Response.json(
          contractCheckerPage({ ...actor, privacyDomainId: approvalId, contextEpoch: '3' }),
        ),
      mode,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Choose checker' }));
    await screen.findByText('Principal choices are unavailable. Search again.');
    expect(screen.queryByText('Payment reviewer')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Request approval' })).toBeDisabled();
    expect(screen.getByLabelText('Independent checker principal ID')).toHaveValue('');
    expect(businessPosts(fetcher)).toHaveLength(1);
  },
);

it.each(['modules', 'providers'] as const)(
  'discards pending %s checker choices and the selection on a workspace transition',
  async (mode) => {
    const pending = held<Response>();
    const fetcher = await openContractReview(() => pending.promise, mode);
    fireEvent.click(screen.getByRole('button', { name: 'Choose checker' }));
    await waitFor(() =>
      expect(
        fetcher.mock.calls.some(([input]) => String(input).includes('/principal-catalogue')),
      ).toBe(true),
    );
    let nonce: string | undefined;
    act(() => {
      nonce = notifySessionTransition('changing');
    });
    expect(
      screen.queryByRole('region', { name: 'Choose an independent checker' }),
    ).not.toBeInTheDocument();
    await act(async () => pending.resolve(Response.json(contractCheckerPage())));
    expect(screen.queryByText('Payment reviewer')).not.toBeInTheDocument();
    act(() => {
      notifySessionTransition('settled', nonce);
    });
    await screen.findByLabelText('Request type');
    expect(screen.queryByText('Selected checker: Payment reviewer')).not.toBeInTheDocument();
    expect(businessPosts(fetcher)).toHaveLength(1);
  },
);

it.each(['modules', 'providers'] as const)(
  'clears the named %s reviewer when the user starts another request without submitting',
  async (mode) => {
    const fetcher = await openContractReview(undefined, mode);
    fireEvent.click(screen.getByRole('button', { name: 'Choose checker' }));
    await screen.findByText('The current maker cannot check their own change.');
    fireEvent.click(screen.getByRole('button', { name: 'Select Payment reviewer' }));
    expect(screen.getByText('Selected checker: Payment reviewer')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'New request' }));
    expect(screen.queryByText('Selected checker: Payment reviewer')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Request approval' })).toBeNull();
    expect(businessPosts(fetcher)).toHaveLength(1);
    fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
    await screen.findByRole('button', { name: 'Request approval' });
    expect(screen.getByLabelText('Independent checker principal ID')).toHaveValue('');
    expect(screen.getByRole('button', { name: 'Request approval' })).toBeDisabled();
    expect(businessPosts(fetcher)).toHaveLength(2);
  },
);

it.each(['modules', 'providers'] as const)(
  'reviews %s separately from editing and returns unchanged inputs without another command',
  async (mode) => {
    const fetcher = await openContractReview(undefined, mode);
    const heading = screen.getByRole('heading', { name: 'Review request' });
    expect(heading).toHaveFocus();
    expect(screen.getByLabelText('Request type')).not.toBeVisible();
    expect(screen.getByLabelText('Reason', { exact: true })).not.toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Choose checker' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Select Payment reviewer' }));
    fireEvent.click(screen.getByRole('button', { name: 'Edit request' }));
    expect(screen.getByLabelText('Request type')).toHaveFocus();
    expect(screen.getByLabelText('Reason', { exact: true })).toBeVisible();
    expect(screen.getByLabelText('Reason', { exact: true })).toHaveValue(
      'Register the customer payment application for independent review.',
    );
    expect(screen.queryByRole('button', { name: 'Request approval' })).toBeNull();
    expect(screen.queryByText('Selected checker: Payment reviewer')).toBeNull();
    expect(businessPosts(fetcher)).toHaveLength(1);
    fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
    await screen.findByRole('button', { name: 'Request approval' });
    expect(screen.getByRole('heading', { name: 'Review request' })).toHaveFocus();
    expect(screen.getByRole('button', { name: 'Request approval' })).toBeDisabled();
    expect(businessPosts(fetcher)).toHaveLength(2);
    expect(businessPosts(fetcher)[1]).toEqual(businessPosts(fetcher)[0]);
  },
);

it('keeps an exact manual checker reference available without a stale display name', async () => {
  const fetcher = await openContractReview();
  fireEvent.click(screen.getByRole('button', { name: 'Choose checker' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Select Payment reviewer' }));
  fireEvent.click(
    screen.getByText('Enter or inspect the checker reference', { selector: 'button' }),
  );
  const reference = screen.getByLabelText('Independent checker principal ID');
  expect(reference).toBeVisible();
  fireEvent.change(reference, { target: { value: approvalId } });
  expect(screen.queryByText('Selected checker: Payment reviewer')).not.toBeInTheDocument();
  expect(screen.getByText('Selected checker: Checker entered by reference')).toBeVisible();
  expect(reference).toHaveValue(approvalId);
  fireEvent.click(screen.getByRole('button', { name: 'New request' }));
  expect(
    screen.queryByText('Selected checker: Checker entered by reference'),
  ).not.toBeInTheDocument();
  expect(businessPosts(fetcher)).toHaveLength(1);
});

it.each([
  ['confirmed', { enabled: true, authenticated: false }, 200, true],
  ['unavailable', { enabled: true, authenticated: false }, 503, false],
  ['malformed', { authenticated: false }, 200, false],
] as const)(
  'conceals module custody without a duplicate account panel after %s sign-in read',
  async (_label, session, status, cleared) => {
    const custodyKey = 'openpc:transaction-workbench:v1:modules';
    const retained = JSON.stringify({
      actor,
      value: { approvalId, reviewToken: 'original-private-custody' },
    });
    localStorage.setItem(custodyKey, retained);
    localStorage.setItem('openpc:rpc-platform-envelope:v1', 'protected-unrelated-value');
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(Response.json(session, { status }));
    render(
      <TransactionWorkflow
        mode="modules"
        initialKind="contract-asset"
        showSessionControls={false}
      />,
    );
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Refresh workspace' })).toBeEnabled(),
    );
    expect(localStorage.getItem(custodyKey)).toBe(cleared ? null : retained);
    expect(localStorage.getItem('openpc:rpc-platform-envelope:v1')).toBe(
      'protected-unrelated-value',
    );
    expect(screen.queryByRole('heading', { name: 'Account & workspace' })).toBeNull();
    expect(screen.queryByText('original-private-custody')).toBeNull();
    expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
  },
);

it('reviews the stored contract and its outcome in business terms while keeping native references available', async () => {
  localStorage.setItem(
    'openpc:transaction-workbench:v1:modules',
    JSON.stringify({
      actor,
      value: { approvalId, kind: 'contract-asset', reviewToken: 'retained-original-review' },
    }),
  );
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input).includes('/local-session'))
      return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
    if (String(input).includes('?approvalId='))
      return Response.json({
        actor,
        kind: 'contract-asset',
        approval: {
          approvalRequestId: `urn:openpc:resource:${approvalId}`,
          makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
          checkerSubjectRef: `urn:openpc:resource:${contractCheckerId}`,
          state: 'APPROVED',
        },
        candidate: {
          resourceRef: `urn:openpc:resource:${approvalId}`,
          state: 'CONSUMED',
          candidateDigest: 'sha256:' + 'a'.repeat(64),
          candidate: {
            logicalName: 'example.payment-registry',
            displayName: 'Example payment registry',
            reason: 'Register the payment application.',
          },
          redactedFields: [],
          operationRef: `urn:openpc:operation:${approvalId}`,
        },
        operation: {
          operationId: approvalId,
          state: 'SUCCEEDED',
          truthState: 'SUCCESS',
          revision: '3',
        },
        result: {
          logicalContractId: approvalId,
          logicalName: 'example.payment-registry',
          displayName: 'Example payment registry',
          revision: '1',
          createdAt: '2026-10-10T00:00:00Z',
          policyGenerationDigest: null,
        },
      });
    return Response.json({ actor });
  });
  render(
    <TransactionWorkflow mode="modules" initialKind="contract-asset" showSessionControls={false} />,
  );
  const review = await screen.findByRole('region', { name: 'Recorded change' });
  expect(within(review).getByText('Example payment registry')).toBeVisible();
  expect(within(review).getByText('Register the payment application.')).toBeVisible();
  const result = screen.getByRole('region', { name: 'Recorded outcome' });
  expect(within(result).getByText('Example payment registry')).toBeVisible();
  expect(within(result).getByText('Record revision').nextElementSibling).toHaveTextContent('1');
  expect(screen.getByText('Approval used')).toBeVisible();
  expect(screen.getByText('Operation state: Completed · Effect: Effect confirmed')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Execute approved request' })).toBeDisabled();
  expect(screen.getByLabelText('Request type')).not.toBeVisible();
  expect(screen.getByLabelText('Approval ID', { exact: true })).not.toBeVisible();
  const references = screen.getByText('Approval and request references', { selector: 'button' });
  const digest = references.parentElement!.querySelector('dialog dd:nth-of-type(3)')!;
  expect(digest).not.toBeVisible();
  fireEvent.click(references);
  expect(digest).toBeVisible();
  expect(screen.getByText(/Registration alone grants no runtime permission/u)).toBeVisible();
  expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'New request' }));
  expect(screen.queryByRole('region', { name: 'Recorded outcome' })).toBeNull();
  expect(screen.getByLabelText('Request type')).toBeVisible();
});

function chosenAbiFile(text: string, name = 'PaymentRegistry.abi.json') {
  const bytes = new TextEncoder().encode(text);
  const file = new File([bytes], name, { type: 'application/json' });
  Object.defineProperty(file, 'arrayBuffer', {
    value: async () => bytes.buffer,
    configurable: true,
  });
  return file;
}

async function openAbiImport() {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (String(input).includes('/local-session'))
      return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
    if (init?.method === 'POST')
      return Response.json({
        reviewToken: 'original-abi-review',
        preview: {
          kind: 'contract-abi',
          candidateDigest: 'sha256:' + 'a'.repeat(64),
          candidate: { abi: [], provenance: {} },
          redactedFields: [],
          authority: 'NONE',
        },
      });
    return Response.json({ actor });
  });
  render(
    <TransactionWorkflow mode="modules" initialKind="contract-abi" showSessionControls={false} />,
  );
  await screen.findByLabelText('ABI JSON file');
  return fetcher;
}

it('separates creation from browsing and shows selection next to tasks that need it', async () => {
  await openAbiImport();
  expect(screen.getByText('Contract library', { selector: 'h2' })).not.toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Library' }));
  expect(screen.getByText('Contract library', { selector: 'h2' })).toBeVisible();
  expect(screen.getByRole('button', { name: 'Import ABI' })).toBeVisible();
  expect(screen.getByLabelText('Request type')).not.toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Create change' }));
  fireEvent.change(screen.getByLabelText('Request type'), {
    target: { value: 'contract-binding' },
  });
  expect(screen.getByText('Contract library', { selector: 'h2' })).toBeVisible();
  expect(screen.getByRole('heading', { name: 'Bind deployed contract and ABI' })).toBeVisible();
});

it('selects original ABI file bytes and local provenance without posting or assigning authority', async () => {
  const fetcher = await openAbiImport();
  const text = ' [\n {"type":"function","name":"getPaymentInfo"}\n ]\n';
  fireEvent.change(screen.getByLabelText('ABI JSON file'), {
    target: { files: [chosenAbiFile(text)] },
  });
  await screen.findByText('Selected artifact: PaymentRegistry.abi.json');
  expect(screen.getByLabelText('Original ABI JSON array')).toHaveValue(text);
  expect(screen.getByLabelText('Original ABI JSON array')).not.toBeVisible();
  expect(screen.getByLabelText('Source type')).toHaveValue('LOCAL_FIXTURE');
  expect(screen.getByLabelText('Source type')).toBeVisible();
  expect(screen.getByLabelText('Source retrieved at (UTC timestamp)')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Replace ABI file' })).toBeVisible();
  expect(screen.getByLabelText('ABI JSON file')).not.toBeVisible();
  expect(screen.getByRole('option', { name: 'Local artifact' })).toBeInTheDocument();
  expect(screen.getByLabelText('Source location or artifact reference')).toHaveValue(
    'PaymentRegistry.abi.json',
  );
  expect(
    Date.parse(
      (screen.getByLabelText('Source retrieved at (UTC timestamp)') as HTMLInputElement).value,
    ),
  ).toBeGreaterThan(Date.now() - 5000);
  expect(businessPosts(fetcher)).toHaveLength(0);
  fireEvent.change(screen.getByLabelText('Reason', { exact: true }), {
    target: { value: 'Import the exact customer payment ABI for independent review.' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
  await screen.findByRole('button', { name: 'Choose checker' });
  const body = JSON.parse(String(businessPosts(fetcher)[0]![1]!.body));
  expect(body.command).toBe('PREVIEW');
  expect(body.kind).toBe('contract-abi');
  expect(body.fields.abiSource).toBe(text);
  expect(body.fields.locator).toBe('PaymentRegistry.abi.json');
});

it('invalidates an old ABI review when replacement file loading fails without approving the old request', async () => {
  const fetcher = await openAbiImport();
  fireEvent.change(screen.getByLabelText('ABI JSON file'), {
    target: { files: [chosenAbiFile('[{}]')] },
  });
  await screen.findByText('Selected artifact: PaymentRegistry.abi.json');
  fireEvent.change(screen.getByLabelText('Reason', { exact: true }), {
    target: { value: 'Review the original ABI.' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
  await screen.findByRole('button', { name: 'Choose checker' });
  fireEvent.change(screen.getByLabelText('ABI JSON file'), {
    target: { files: [chosenAbiFile('{}', 'Invalid.json')] },
  });
  await screen.findByText(/The ABI could not be loaded/u);
  expect(screen.queryByRole('button', { name: 'Request approval' })).toBeNull();
  expect(screen.queryByText('Selected artifact: Invalid.json')).toBeNull();
  expect(businessPosts(fetcher)).toHaveLength(1);
});

it('drops a delayed ABI file read during an account transition without restoring private inputs or posting', async () => {
  const fetcher = await openAbiImport(),
    pending = held<ArrayBuffer>();
  const file = chosenAbiFile('[{}]');
  Object.defineProperty(file, 'arrayBuffer', { value: () => pending.promise });
  fireEvent.change(screen.getByLabelText('ABI JSON file'), { target: { files: [file] } });
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Review request' })).toBeDisabled(),
  );
  let nonce: string | undefined;
  act(() => {
    nonce = notifySessionTransition('changing');
  });
  await act(async () => pending.resolve(new TextEncoder().encode('[{}]').buffer));
  expect(screen.queryByText('Selected artifact: PaymentRegistry.abi.json')).toBeNull();
  act(() => {
    notifySessionTransition('settled', nonce);
  });
  await screen.findByLabelText('ABI JSON file');
  expect(screen.getByLabelText('Original ABI JSON array')).toHaveValue('');
  expect(businessPosts(fetcher)).toHaveLength(0);
});

it('keeps required source fields visible so validation cannot hide an incomplete import', async () => {
  const fetcher = await openAbiImport();
  const source = screen.getByLabelText('Source location or artifact reference');
  expect(source).toBeVisible();
  fireEvent.invalid(source);
  expect(source).toBeVisible();
  expect(businessPosts(fetcher)).toHaveLength(0);
});

it('opens the native file chooser from the visible ABI action and clears its label on context change', async () => {
  const fetcher = await openAbiImport();
  const input = screen.getByLabelText('ABI JSON file'),
    clicked = vi.spyOn(input, 'click');
  fireEvent.click(screen.getByRole('button', { name: 'Choose ABI file' }));
  expect(clicked).toHaveBeenCalledOnce();
  fireEvent.change(input, { target: { files: [chosenAbiFile('[{}]')] } });
  await screen.findByRole('button', { name: 'Replace ABI file' });
  let nonce: string | undefined;
  act(() => {
    nonce = notifySessionTransition('changing');
  });
  expect(screen.queryByText('Selected artifact: PaymentRegistry.abi.json')).toBeNull();
  act(() => {
    notifySessionTransition('settled', nonce);
  });
  await screen.findByRole('button', { name: 'Choose ABI file' });
  expect(businessPosts(fetcher)).toHaveLength(0);
});

it('clears the previous contract task guidance and reason when the request type changes', async () => {
  const fetcher = await openAbiImport();
  fireEvent.change(screen.getByLabelText('ABI JSON file'), {
    target: { files: [chosenAbiFile('[{}]')] },
  });
  await screen.findByText(
    'ABI file loaded. Review its source details and request independent approval.',
  );
  fireEvent.change(screen.getByLabelText('Reason', { exact: true }), {
    target: { value: 'Import this specific ABI.' },
  });
  fireEvent.change(screen.getByLabelText('Request type'), {
    target: { value: 'contract-binding' },
  });
  expect(
    screen.queryByText(
      'ABI file loaded. Review its source details and request independent approval.',
    ),
  ).toBeNull();
  expect(screen.queryByText('Selected artifact: PaymentRegistry.abi.json')).toBeNull();
  expect(screen.getByLabelText('Reason', { exact: true })).toHaveValue('');
  expect(businessPosts(fetcher)).toHaveLength(0);
});

it('prepares governed proof access with a read-only selected source and human UTC expiry input', async () => {
  const selectedRef = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000401';
  const previews: Record<string, unknown>[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string, init?: RequestInit) => {
      if (input.includes('/local-session'))
        return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
      if (init?.method === 'POST') {
        const body = JSON.parse(String(init.body));
        expect(body.command).toBe('PREVIEW');
        previews.push(body);
        return Response.json({
          reviewToken: 'sealed-proof-review',
          preview: {
            candidate: body.fields,
            candidateDigest: `sha256:${'a'.repeat(64)}`,
            redactedFields: [],
            authority: 'NONE',
          },
        });
      }
      return Response.json({ actor });
    }),
  );
  render(
    <TransactionWorkflow
      mode="evidence"
      guidedRecovery
      initialKind="protected-proof-access"
      initialFields={{ objectRef: selectedRef }}
    />,
  );
  const source = await screen.findByLabelText('Protected object reference');
  expect(source).toHaveValue(selectedRef);
  expect(source).toHaveAttribute('readonly');
  expect(source).not.toBeVisible();
  fireEvent.change(screen.getByLabelText('Protected access purpose'), {
    target: { value: 'Review disputed authentication' },
  });
  fireEvent.change(screen.getByLabelText('Case reference'), { target: { value: 'CASE-503' } });
  const expiry = screen.getByLabelText('Access expires at (UTC, within five minutes)');
  expect(expiry).toHaveAttribute('type', 'datetime-local');
  fireEvent.change(expiry, { target: { value: '2026-10-11T04:45:00.250' } });
  fireEvent.change(screen.getByLabelText('Reason'), {
    target: { value: 'Investigate the selected signed source' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
  await waitFor(() => expect(previews).toHaveLength(1));
  expect(previews[0]?.fields).toMatchObject({
    objectRef: selectedRef,
    purpose: 'Review disputed authentication',
    caseReference: 'CASE-503',
    expiresAt: '2026-10-11T04:45:00.250000Z',
  });
});

it.each([
  ['SUCCEEDED', 'SUCCESS', 'Recorded change'],
  ['RUNNING', 'UNKNOWN', 'Submitted change'],
  ['FAILED', 'FAILURE', 'Submitted change'],
] as const)(
  'shows a consumed provider request as %s without presenting another preparation form',
  async (operationState, truthState, title) => {
    const custodyKey = 'openpc:transaction-workbench:v1:providers';
    localStorage.setItem(
      custodyKey,
      JSON.stringify({
        actor,
        value: {
          approvalId,
          kind: 'provider-qualification',
          reviewToken: 'original-provider-review',
        },
      }),
    );
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).includes('/local-session'))
        return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
      if (String(input).includes('?approvalId='))
        return Response.json({
          actor,
          kind: 'provider-qualification',
          approval: {
            approvalRequestId: `urn:openpc:resource:${approvalId}`,
            makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
            checkerSubjectRef: `urn:openpc:resource:${contractCheckerId}`,
            state: 'APPROVED',
          },
          candidate: {
            resourceRef: `urn:openpc:resource:${approvalId}`,
            state: 'CONSUMED',
            candidateDigest: 'sha256:' + 'a'.repeat(64),
            candidate: {
              targetRef: `urn:openpc:resource:${approvalId}`,
              expectedRevision: '2',
              inputDigest: 'sha256:' + 'b'.repeat(64),
              reason: 'Qualify the observed test endpoint.',
            },
            redactedFields: [],
            operationRef: `urn:openpc:operation:${approvalId}`,
          },
          operation: { operationId: approvalId, state: operationState, truthState, revision: '3' },
          ...(truthState === 'SUCCESS'
            ? { result: { chainId: '92870', state: 'QUALIFIED', revision: '4' } }
            : {}),
        });
      return Response.json({ actor });
    });
    render(<TransactionWorkflow mode="providers" showSessionControls={false} />);
    const review = await screen.findByRole('region', { name: title });
    expect(within(review).getByText('Qualify the observed test endpoint.')).toBeVisible();
    expect(screen.queryByRole('region', { name: 'Change under review' })).toBeNull();
    const requestType = screen.getByLabelText('Request type');
    expect(requestType).toBeInTheDocument();
    expect(requestType).not.toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Create change' }));
    expect(requestType).not.toBeVisible();
    expect(screen.getByRole('button', { name: 'Execute approved request' })).toBeDisabled();
    expect(JSON.parse(localStorage.getItem(custodyKey)!).value.approvalId).toBe(approvalId);
    expect(JSON.parse(localStorage.getItem(custodyKey)!).value.reviewToken).toBe(
      'original-provider-review',
    );
    expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
    if (truthState === 'SUCCESS') {
      expect(screen.getByRole('region', { name: 'Recorded outcome' })).toContainElement(
        screen.getByText('Qualified'),
      );
      fireEvent.click(screen.getByRole('button', { name: 'New request' }));
      expect(screen.queryByRole('region', { name: 'Recorded outcome' })).toBeNull();
      expect(requestType).toBeVisible();
      expect(requestType).toBeEnabled();
    } else {
      expect(screen.queryByRole('region', { name: 'Recorded outcome' })).toBeNull();
      expect(screen.queryByText('Qualified')).toBeNull();
    }
  },
);

it('shows a consumed wallet binding from its native receipt when no queue operation exists', async () => {
  localStorage.setItem(
    'openpc:transaction-workbench:v1:wallets',
    JSON.stringify({
      actor,
      value: { approvalId, kind: 'wallet-binding', reviewToken: 'original-wallet-review' },
    }),
  );
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input).includes('/local-session'))
      return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
    if (String(input).includes('?approvalId='))
      return Response.json({
        actor,
        kind: 'wallet-binding',
        approval: {
          approvalRequestId: `urn:openpc:resource:${approvalId}`,
          makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
          checkerSubjectRef: `urn:openpc:resource:${actor.sessionId}`,
          state: 'APPROVED',
        },
        candidate: {
          resourceRef: `urn:openpc:resource:${approvalId}`,
          state: 'CONSUMED',
          operationRef: `urn:openpc:operation:${approvalId}`,
          candidateDigest: `sha256:${'a'.repeat(64)}`,
          candidate: {},
          redactedFields: [],
        },
        operation: null,
        result: {
          walletBindingId: approvalId,
          subjectId: actor.principalId,
          chainId: '92870',
          walletAddress: `0x${'a'.repeat(40)}`,
          participantId: actor.participantId,
          privacyDomainId: actor.privacyDomainId,
          state: 'ACTIVE',
          bindingEpoch: '1',
          revision: '1',
          operationId: approvalId,
          permissionEffect: 'NONE_WITHOUT_EFFECTIVE_AUTHORITY',
        },
      });
    return Response.json({ actor });
  });
  render(<TransactionWorkflow mode="wallets" showSessionControls={false} />);
  const outcome = await screen.findByRole('region', { name: 'Recorded outcome' });
  expect(within(outcome).getByRole('heading', { name: 'Wallet bound' })).toBeVisible();
  expect(within(outcome).getByText(`0x${'a'.repeat(40)}`)).toBeVisible();
  expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'New request' }));
  expect(screen.queryByRole('region', { name: 'Recorded outcome' })).toBeNull();
});

it('starts in the native contract library and preserves unsent inputs across workflow navigation', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input).includes('/local-session'))
      return Response.json({ authenticated: true, contextMode: 'PARTICIPANT' });
    return Response.json({ actor });
  });
  const { container } = render(<TransactionWorkflow mode="modules" showSessionControls={false} />);
  const start = await screen.findByRole('button', { name: 'New contract' });
  expect(screen.getByRole('button', { name: 'Library' })).toHaveAttribute('aria-current', 'page');
  expect(screen.getByLabelText('Request type')).not.toBeVisible();
  expect(container.querySelectorAll('details')).toHaveLength(0);
  fireEvent.click(start);
  const name = screen.getByLabelText('Logical contract name');
  fireEvent.change(name, { target: { value: 'example.payment' } });
  fireEvent.click(screen.getByRole('button', { name: 'Activity' }));
  expect(name).not.toBeVisible();
  expect(screen.getByRole('button', { name: 'Recover an existing request' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Create change' }));
  expect(screen.getByLabelText('Logical contract name')).toBe(name);
  expect(name).toHaveValue('example.payment');
  expect(businessPosts(fetcher)).toHaveLength(0);
});

it('cannot clear unresolved original custody during a held native context recheck', async () => {
  retainPolicy();
  const pending = held<Response>();
  let hold = false;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const path = String(input);
    if (path.includes('/local-session'))
      return Response.json({ ...actor, authenticated: true, contextMode: 'PARTICIPANT' });
    if (path.includes('?approvalId=')) return Response.json(policyRequest());
    if (hold) {
      hold = false;
      return pending.promise;
    }
    return Response.json({ actor });
  });
  render(<TransactionWorkflow mode="policy" showSessionControls={false} />);
  const action = await screen.findByRole('button', { name: 'New request' });
  await waitFor(() => expect(action).toBeEnabled());
  const original = localStorage.getItem(policyKey);
  hold = true;
  fireEvent.focus(window);
  await waitFor(() => expect(action).toBeDisabled());
  fireEvent.click(action);
  expect(localStorage.getItem(policyKey)).toBe(original);
  await act(async () => pending.resolve(Response.json({ actor })));
  await waitFor(() => expect(screen.getByRole('button', { name: 'New request' })).toBeEnabled());
  expect(localStorage.getItem(policyKey)).toBe(original);
  expect(businessPosts(fetcher)).toHaveLength(0);
});

it('offers account-owned workspace verification in a central console without starting an inline transition', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      ...actor,
      authenticated: true,
      contextMode: 'PLATFORM',
      availableContexts: [
        { participantId: actor.participantId, privacyDomainId: actor.privacyDomainId },
      ],
    }),
  );
  render(
    <CentralSessionContext.Provider value={true}>
      <TransactionWorkflow mode="policy" />
    </CentralSessionContext.Provider>,
  );
  expect(await screen.findByRole('link', { name: 'Choose workspace' })).toHaveAttribute(
    'href',
    '/home/session',
  );
  expect(screen.getByRole('heading', { name: 'Choose an organization workspace' })).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Enter workspace' })).toBeNull();
  expect(performWebAuthnStepUp).not.toHaveBeenCalled();
  expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
});
