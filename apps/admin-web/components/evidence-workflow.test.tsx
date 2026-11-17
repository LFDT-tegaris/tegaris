import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, expect, it, vi } from 'vitest';
import { EvidenceWorkflow } from './evidence-workflow';

vi.mock('./evidence-operation-correlation', () => ({
  EvidenceOperationCorrelation: ({
    evidenceId,
    actorKey,
  }: {
    evidenceId: string;
    actorKey: string;
  }) => (
    <div aria-label="Operation correlation binding" data-actor-key={actorKey}>
      {evidenceId}
    </div>
  ),
}));

vi.mock('./transaction-workflow', () => ({
  TransactionWorkflow: ({
    initialFields,
    initialKind,
    guidedRecovery,
    showApprovalCatalogue,
  }: {
    initialFields?: Record<string, string>;
    initialKind?: string;
    guidedRecovery?: boolean;
    showApprovalCatalogue?: boolean;
  }) => (
    <div
      aria-label="Governed export binding"
      data-kind={initialKind}
      data-guided-recovery={String(guidedRecovery)}
      data-catalogue-enabled={String(showApprovalCatalogue)}
    >
      <button type="button">Read governed request</button>
      {initialFields?.targetRef ??
        initialFields?.evidenceId ??
        initialFields?.deletionJobId ??
        initialFields?.objectRef}
    </div>
  ),
}));
const id = '018f0000-0000-7000-8000-000000000401',
  ref = `urn:openpc:resource:${id}`,
  hash = `sha256:${'a'.repeat(64)}`;
const actor = { participantId: 'participant', privacyDomainId: 'privacy' },
  actorKey = 'scope';
const page = { items: [], authorizedEmpty: true, nextCursor: null };
const view = {
  actor,
  actorKey,
  records: {
    ...page,
    authorizedEmpty: false,
    items: [
      {
        evidenceId: ref,
        sequence: '3',
        evidenceClass: 'EFFECT',
        recordDigest: hash,
        occurredAt: '2026-09-21T00:00:00.000000Z',
      },
    ],
  },
  exports: page,
  recordsUnavailable: false,
  exportsUnavailable: false,
};

it('keeps server-rendered evidence controls disabled before hydration can handle clicks', () => {
  const initial = document.createElement('div');
  initial.innerHTML = renderToStaticMarkup(
    <EvidenceWorkflow evaluationUi showSessionControls={false} />,
  );
  const tasks = initial.querySelector('[aria-label="Evidence tasks"]');
  expect(tasks?.querySelectorAll('button')).toHaveLength(6);
  for (const button of tasks?.querySelectorAll('button') ?? []) expect(button).toBeDisabled();
  const refresh = [...initial.querySelectorAll('button')].find(
    (button) => button.textContent === 'Refresh evidence',
  );
  expect(refresh).toBeDisabled();
  expect(initial.querySelector('[aria-label="Evidence request controls"]')).toBeDisabled();
});

it('keeps request controls unavailable until the scoped catalogue finishes loading', async () => {
  let release!: (value: Response) => void;
  const pending = new Promise<Response>((resolve) => {
    release = resolve;
  });
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(pending)
    .mockResolvedValueOnce(
      Response.json(
        { type: 'about:blank', title: 'Evidence is unavailable.', status: 503 },
        { status: 503 },
      ),
    );
  vi.stubGlobal('fetch', fetch);
  render(<EvidenceWorkflow showSessionControls={false} />);
  const read = screen.getByRole('button', { name: 'Read governed request' });
  expect(read).toBeDisabled();
  expect(screen.queryByRole('region', { name: 'Evidence catalogue' })).toBeNull();
  await act(async () => release(Response.json(view)));
  await screen.findByRole('region', { name: 'Evidence catalogue' });
  expect(screen.getByRole('button', { name: 'Read governed request' })).toBeEnabled();
  // A failed catalogue refresh must finish loading too; the request workflow
  // retains its own authentication and approval-read permission checks.
  fireEvent.click(screen.getByRole('button', { name: 'Refresh evidence' }));
  expect(screen.getByRole('button', { name: 'Read governed request' })).toBeDisabled();
  await screen.findByText('Evidence is unavailable.');
  expect(screen.getByRole('button', { name: 'Read governed request' })).toBeEnabled();
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('keeps evidence review and export prominent while retention controls remain available', async () => {
  const user = userEvent.setup();
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json(view)),
  );
  render(<EvidenceWorkflow evaluationUi />);
  expect(
    await screen.findByRole('button', { name: 'Read provenance for sequence 3' }),
  ).toBeVisible();
  expect(screen.getByRole('button', { name: 'Select sequence 3 for export' })).toBeVisible();
  const summary = screen.getByRole('button', {
    name: 'Record details and retention for sequence 3',
  });
  const details = summary.parentElement!.querySelector('dialog')!;
  expect(details).not.toHaveAttribute('open');
  await user.click(summary);
  expect(screen.getByRole('button', { name: 'Check local deletion for sequence 3' })).toBeVisible();
  expect(screen.getByText(`Evidence reference: ${ref}`)).toBeVisible();
  await user.click(
    screen.getByRole('button', { name: 'Close Record details and retention for sequence 3' }),
  );
  expect(details).not.toHaveAttribute('open');
  expect(screen.getByRole('button', { name: 'Select sequence 3 for export' })).toBeVisible();
});

it('pages authorized records and deletion history without dispatching another request', async () => {
  const user = userEvent.setup();
  const reference = (n: number) =>
    `urn:openpc:resource:018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  const fetch = vi.fn(async () =>
    Response.json({
      ...view,
      records: {
        ...view.records,
        items: Array.from({ length: 10 }, (_, n) => ({
          ...view.records.items[0],
          evidenceId: reference(n + 1),
          sequence: String(n + 1),
        })),
      },
      deletions: {
        ...page,
        items: Array.from({ length: 14 }, (_, n) => ({
          deletionJobId: reference(n + 101),
          state: 'SUCCEEDED',
          deletedCount: 1,
          deletedBytes: 16,
          beforeDigest: hash,
          afterDigest: hash,
          receiptDigest: hash,
          selection: {
            version: 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1',
            source: { runtimeConfigurationInputId: id, configurationDigest: hash },
          },
        })),
      },
    }),
  );
  vi.stubGlobal('fetch', fetch);
  render(<EvidenceWorkflow evaluationUi showSessionControls={false} />);
  const records = await screen.findByRole('region', { name: 'Evidence catalogue' });
  expect(within(records).getAllByRole('listitem')).toHaveLength(6);
  expect(within(records).getByText('Showing 1–6 of 10 loaded records')).toBeVisible();
  const nextRecords = within(records).getByRole('button', { name: 'Next displayed records' });
  nextRecords.focus();
  await user.keyboard('{Enter}');
  expect(within(records).getAllByRole('listitem')).toHaveLength(4);
  expect(
    within(records).getByRole('button', { name: 'Read provenance for sequence 7' }),
  ).toBeVisible();
  expect(
    within(records).queryByRole('button', { name: 'Read provenance for sequence 1' }),
  ).toBeNull();
  expect(nextRecords).toBeDisabled();
  await user.click(within(records).getByRole('button', { name: 'Previous displayed records' }));
  expect(
    within(records).getByRole('button', { name: 'Read provenance for sequence 1' }),
  ).toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Data removal' }));
  const results = screen.getByRole('region', { name: 'Local deletion results' });
  const references: string[] = [];
  for (const count of [6, 6, 2]) {
    const entries = within(results).getAllByRole('listitem');
    expect(entries).toHaveLength(count);
    for (const entry of entries) {
      expect(within(entry).getByText('Completed')).toBeVisible();
      references.push(within(entry).getByText(/^Deletion reference:/u).textContent!);
    }
    const next = within(results).getByRole('button', { name: 'Next results' });
    if (count === 2) expect(next).toBeDisabled();
    else {
      next.focus();
      await user.keyboard('{Enter}');
    }
  }
  expect(references).toEqual(
    Array.from({ length: 14 }, (_, n) => `Deletion reference: ${reference(n + 101)}`),
  );
  expect(fetch).toHaveBeenCalledTimes(1);
  fireEvent.blur(window);
  expect(screen.queryByText(/^Deletion reference:/u)).toBeNull();
  expect(screen.queryByRole('navigation', { name: 'Deletion results navigation' })).toBeNull();
  fireEvent.focus(window);
  const restored = await screen.findByRole('region', { name: 'Local deletion results' });
  expect(screen.getByRole('button', { name: 'Data removal' })).toHaveAttribute(
    'aria-pressed',
    'true',
  );
  expect(within(restored).getByText('Showing 1–6 of 14 loaded results')).toBeVisible();
  expect(within(restored).getByRole('button', { name: 'Previous results' })).toBeDisabled();
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('opens the export range from the selected owner response while retaining manual access', async () => {
  const user = userEvent.setup();
  const fetch = vi.fn(async (url: string) => {
    const selectedId = new URL(url, 'http://localhost').searchParams.get('recordId');
    if (!selectedId) return Response.json(view);
    expect(selectedId).toBe(id);
    return Response.json({
      actor,
      actorKey,
      record: {
        evidenceId: ref,
        recordDigest: hash,
        range: { streamId: 'settlement-receipts', fromSequence: '45', throughSequence: '46' },
      },
    });
  });
  vi.stubGlobal('fetch', fetch);
  render(<EvidenceWorkflow evaluationUi showSessionControls={false} />);
  await screen.findByRole('button', { name: 'Select sequence 3 for export' });
  await user.click(screen.getByRole('button', { name: 'Exports' }));
  const manual = screen.getByRole('button', {
    name: 'Enter an evidence range manually',
    hidden: true,
  });
  expect(manual.parentElement!.querySelector('dialog')).not.toHaveAttribute('open');
  expect(screen.getByLabelText('Evidence stream')).not.toBeVisible();
  await user.click(manual);
  expect(screen.getByLabelText('Evidence stream')).toBeVisible();
  await user.click(manual);
  await user.click(screen.getByRole('button', { name: 'Choose evidence records' }));
  await user.click(screen.getByRole('button', { name: 'Select sequence 3 for export' }));
  await screen.findByText('Record selected. Review the range and enter a purpose.');
  expect(screen.queryByText('Enter an evidence range manually')).toBeNull();
  expect(screen.getByLabelText('Evidence stream')).not.toBeVisible();
  expect(screen.getByLabelText('Evidence stream')).toHaveAttribute('readonly');
  expect(screen.getByLabelText('Evidence stream')).toHaveValue('settlement-receipts');
  expect(screen.getByLabelText('First sequence')).toHaveValue('45');
  expect(screen.getByLabelText('Last sequence')).toHaveValue('46');
  expect(screen.getByLabelText('Purpose')).toHaveValue('');
  await user.click(screen.getByRole('button', { name: 'Evidence source details' }));
  expect(screen.getByLabelText('Evidence stream')).toBeVisible();
  expect(screen.getByLabelText('Evidence stream')).toHaveAttribute('readonly');
  await user.click(screen.getByRole('button', { name: 'Close Evidence source details' }));
  await user.click(screen.getByRole('button', { name: 'Retention & holds' }));
  expect(screen.queryByText('Record selected. Review the range and enter a purpose.')).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Exports' }));
  expect(screen.getByText('Record selected. Review the range and enter a purpose.')).toBeVisible();
  expect(screen.getByLabelText('First sequence')).toHaveValue('45');
  expect(fetch).toHaveBeenCalledTimes(2);
  fireEvent.blur(window);
  expect(screen.queryByLabelText('Evidence stream')).toBeNull();
});
const selected = {
  actor,
  actorKey,
  selected: {
    evidenceExportId: ref,
    state: 'REQUESTED',
    requestDigest: hash,
    checkpoint: '0',
    revision: '1',
    createdAt: '2026-09-21T00:00:00.000000Z',
    updatedAt: '2026-09-21T00:00:00.000000Z',
  },
  selection: {
    range: { streamId: 'control-receipts', fromSequence: '1', throughSequence: '1' },
    records: [{ evidenceId: ref }],
  },
};

it('shows readable record times and classes while preserving exact audit metadata', async () => {
  const record = view.records?.items[0];
  if (!record) throw new Error('Record fixture is missing');
  const user = userEvent.setup();
  const fetch = vi.fn(async () => Response.json(view));
  vi.stubGlobal('fetch', fetch);
  render(<EvidenceWorkflow evaluationUi showSessionControls={false} />);
  const records = await screen.findByRole('region', { name: 'Evidence catalogue' });
  expect(within(records).getByText('Sequence 3 · Effect evidence')).toBeVisible();
  const time = records.querySelector('time');
  expect(time).toHaveAttribute('datetime', record.occurredAt);
  expect(time).toHaveTextContent('UTC');
  expect(time).not.toHaveTextContent('.000000Z');
  const exactTime = within(records).getByText(`Exact event time: ${record.occurredAt}`);
  expect(exactTime).not.toBeVisible();
  await user.click(
    within(records).getByRole('button', { name: 'Record details and retention for sequence 3' }),
  );
  expect(exactTime).toBeVisible();
  expect(within(records).getByText('Evidence class: EFFECT')).toBeVisible();
  expect(fetch).toHaveBeenCalledTimes(1);
});

it.each([
  ['REQUESTED', 'Requested'],
  ['RUNNING', 'Preparing'],
  ['SUCCEEDED', 'Completed'],
  ['FAILED', 'Failed'],
  ['BACKLOGGED', 'Waiting for processing'],
])('shows %s export status without treating a request as completion', async (state, label) => {
  const user = userEvent.setup();
  const fetch = vi.fn(async () =>
    Response.json({
      ...view,
      exports: { ...page, authorizedEmpty: false, items: [{ ...selected.selected, state }] },
    }),
  );
  vi.stubGlobal('fetch', fetch);
  render(<EvidenceWorkflow evaluationUi showSessionControls={false} />);
  await screen.findByRole('region', { name: 'Evidence catalogue' });
  await user.click(screen.getByRole('button', { name: 'Exports' }));
  const exports = screen.getByRole('region', { name: 'Export requests' });
  expect(within(exports).getByText(label, { selector: '.workflow-state-badge' })).toBeVisible();
  const review = within(exports).getByRole('button', { name: `Review export ${id}` });
  expect(review).toHaveTextContent('Review export');
  expect(review).not.toHaveTextContent(id);
  const reference = within(exports).getByText(ref);
  expect(reference).not.toBeVisible();
  await user.click(within(exports).getByRole('button', { name: 'Export reference', hidden: true }));
  expect(reference).toBeVisible();
  expect(within(exports).getByText(`Status: ${state} · Revision 1`)).toBeVisible();
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('keeps hold coverage visible while audit references stay behind expandable details', async () => {
  const user = userEvent.setup();
  const fetch = vi.fn(async () =>
    Response.json({
      ...view,
      holds: {
        ...page,
        items: [
          {
            holdId: ref,
            holdKind: 'LEGAL',
            state: 'ACTIVE',
            revision: '1',
            coverage: 'PENDING',
            selector: {
              type: 'SEQUENCE_RANGE',
              streamId: 'audit-receipts',
              fromSequence: '3',
              throughSequence: '4',
            },
            selectorDigest: hash,
            creationReceiptDigest: hash,
            releaseReceiptDigest: null,
          },
        ],
      },
    }),
  );
  vi.stubGlobal('fetch', fetch);
  render(<EvidenceWorkflow evaluationUi showSessionControls={false} />);
  await screen.findByRole('button', { name: 'Read provenance for sequence 3' });
  await user.click(screen.getByRole('button', { name: 'Retention & holds' }));
  const region = screen.getByRole('region', { name: 'Preservation holds' });
  expect(within(region).getByText(/Active holds on this page: 1/u)).toBeVisible();
  const inventory = within(region).getByRole('button', {
    name: 'Review preservation holds',
    hidden: true,
  });
  expect(inventory.parentElement!.querySelector('dialog')).not.toHaveAttribute('open');
  await user.click(inventory);
  expect(within(region).getByText(/Sink coverage PENDING/u)).toBeVisible();
  expect(within(region).getByText(`Creation receipt: ${hash}`)).not.toBeVisible();
  const audit = within(region).getByRole('button', { name: 'Hold audit details', hidden: true });
  await user.click(audit);
  expect(within(region).getByText(`Hold reference: ${ref}`)).toBeVisible();
  expect(within(region).getByText(`Creation receipt: ${hash}`)).toBeVisible();
  expect(fetch).toHaveBeenCalledTimes(1);
  fireEvent.blur(window);
  expect(screen.queryByText(`Hold reference: ${ref}`)).not.toBeInTheDocument();
});

it('returns to the first records with the receipt filter and discards the previous page', async () => {
  const user = userEvent.setup();
  const cursor = 'pc2.cGFnZQ.c2ln';
  const fetch = vi.fn(async (url: string) => {
    const query = new URL(url, 'http://localhost').searchParams;
    const later = !!query.get('recordsCursor');
    return Response.json({
      ...view,
      recordDigest: query.get('recordDigest'),
      recordsCursor: query.get('recordsCursor'),
      records: {
        ...view.records,
        nextCursor: later ? null : cursor,
        items: [
          {
            ...view.records.items[0],
            evidenceId: later ? 'urn:openpc:resource:018f0000-0000-7000-8000-000000000402' : ref,
            sequence: later ? '4' : '3',
          },
        ],
      },
    });
  });
  vi.stubGlobal('fetch', fetch);
  render(<EvidenceWorkflow showSessionControls={false} />);
  await screen.findByRole('button', { name: 'Read provenance for sequence 3' });
  await user.type(screen.getByLabelText('Find records by receipt digest'), hash);
  await user.click(screen.getByRole('button', { name: 'Find evidence' }));
  await screen.findByRole('button', { name: 'Next records' });
  await user.click(screen.getByRole('button', { name: 'Next records' }));
  await screen.findByRole('button', { name: 'Read provenance for sequence 4' });
  expect(screen.queryByRole('button', { name: 'Read provenance for sequence 3' })).toBeNull();
  const first = screen.getByRole('button', { name: 'First records' });
  first.focus();
  await user.keyboard('{Enter}');
  await screen.findByRole('button', { name: 'Read provenance for sequence 3' });
  expect(screen.queryByRole('button', { name: 'Read provenance for sequence 4' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'First records' })).toBeNull();
  expect(screen.getByLabelText('Find records by receipt digest')).toHaveValue(hash);
  const queries = fetch.mock.calls.map(([url]) => new URL(url, 'http://localhost').searchParams);
  expect(queries.at(-2)?.get('recordsCursor')).toBe(cursor);
  expect(queries.at(-1)?.has('recordsCursor')).toBe(false);
  expect(queries.at(-1)?.get('recordDigest')).toBe(hash);
});

it('renders runtime retirement by source identity without offering an evidence payload lookup', async () => {
  const user = userEvent.setup();
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      Response.json({
        ...view,
        deletions: {
          ...page,
          items: [
            {
              deletionJobId: ref,
              state: 'SUCCEEDED',
              deletedCount: 1,
              deletedBytes: 2426,
              beforeDigest: hash,
              afterDigest: hash,
              receiptDigest: hash,
              selection: {
                version: 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1',
                source: { runtimeConfigurationInputId: id, configurationDigest: hash },
              },
            },
          ],
        },
      }),
    ),
  );
  render(<EvidenceWorkflow />);
  const results = await screen.findByRole('region', { name: 'Local deletion results' });
  expect(
    within(results).getByRole('heading', { name: 'Runtime configuration artifact' }),
  ).toBeVisible();
  expect(within(results).getByText('Completed')).toBeVisible();
  const identity = within(results).getByText(/Runtime artifact retired · Input/u);
  expect(identity).not.toBeVisible();
  const summary = within(results).getByRole('button', {
    name: 'Deletion audit details',
    hidden: true,
  });
  await user.click(summary);
  expect(identity).toBeVisible();
  expect(identity.textContent).toContain(id);
  expect(within(results).getByText(`Signed receipt: ${hash}`)).toBeVisible();
  expect(within(results).queryByRole('button', { name: 'Read local payload status' })).toBeNull();
  expect(within(results).queryByText(/sequences/u)).toBeNull();
});

it('shows readable retention terms without losing exact policy evidence or approval requirements', async () => {
  const user = userEvent.setup();
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      Response.json({
        ...view,
        retentionPolicies: {
          ...page,
          items: [
            {
              retentionPolicyId: ref,
              dataClass: 'SEARCH_PROJECTION',
              state: 'ACTIVE',
              policyVersion: '2',
              retentionPeriodMs: '86400000',
              localGraceMs: '9007199254740993',
              sinkQuorum: 2,
              deletionMode: 'ROW_DELETE',
              makerCheckerRequired: true,
              activeFrom: '2026-09-21T00:00:00.000000Z',
              activeUntil: null,
              predecessorPolicyId: ref,
              policyDigest: hash,
              activationReceiptDigest: hash,
              retirementReceiptDigest: null,
            },
          ],
        },
      }),
    ),
  );
  render(<EvidenceWorkflow />);
  const policies = await screen.findByRole('region', { name: 'Retention policies' });
  expect(within(policies).getByRole('heading', { name: 'Search index' })).toBeVisible();
  expect(within(policies).getByText('Active · Version 2')).toBeVisible();
  expect(
    within(policies).getByText('Retention: 1 day · Local grace: 9007199254740993 ms'),
  ).toBeVisible();
  expect(within(policies).getByText('Independent deletion approval: Required')).toBeVisible();
  const receipt = within(policies).getByText(`Activation receipt: ${hash}`);
  expect(receipt).not.toBeVisible();
  await user.click(
    within(policies).getByRole('button', { name: 'Policy audit details', hidden: true }),
  );
  expect(receipt).toBeVisible();
  expect(within(policies).getByText(`Policy reference: ${ref}`)).toBeVisible();
  expect(
    within(policies).getByText('Retention: 86400000 ms · Local grace: 9007199254740993 ms'),
  ).toBeVisible();
  fireEvent.blur(window);
  expect(screen.queryByRole('region', { name: 'Retention policies' })).not.toBeInTheDocument();
  expect(screen.queryByText(`Activation receipt: ${hash}`)).not.toBeInTheDocument();
});

it('prepares native Fact retirement only from installed targets and active Fact policies, then clears on blur', async () => {
  const user = userEvent.setup();
  const policies = {
    ...page,
    items: [
      {
        retentionPolicyId: ref,
        policyVersion: '1.0.0',
        state: 'ACTIVE',
        dataClass: 'ADMITTED_FACT',
        deletionMode: 'ROW_DELETE',
        retentionPeriodMs: '1000',
        localGraceMs: '2000',
        sinkQuorum: 1,
      },
      {
        retentionPolicyId: 'wrong-class',
        policyVersion: '2.0.0',
        state: 'ACTIVE',
        dataClass: 'AUDIT_EVIDENCE',
        deletionMode: 'ROW_DELETE',
        retentionPeriodMs: '1000',
        localGraceMs: '2000',
      },
    ],
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      Response.json(
        url.includes('factRetirementRecordId=')
          ? {
              actor,
              actorKey,
              evidenceId: ref,
              hosts: {
                items: [
                  {
                    hostDigest: 'a'.repeat(64),
                    targetId: 'installed-fact-target',
                    store: 'openpc_facts',
                  },
                ],
                authority: 'NONE',
              },
            }
          : { ...view, retentionPolicies: policies },
      ),
    ),
  );
  render(<EvidenceWorkflow />);
  await user.click(
    await screen.findByRole('button', { name: 'Review Fact payload retirement for sequence 3' }),
  );
  const region = await screen.findByRole('region', { name: 'Prepare Fact payload retirement' });
  const prepare = within(region).getByRole('button', { name: 'Review this Fact retirement' });
  expect(prepare).toBeDisabled();
  await user.selectOptions(within(region).getByLabelText('Installed Fact target'), 'a'.repeat(64));
  expect(prepare).toBeDisabled();
  await user.selectOptions(within(region).getByLabelText('Active Fact retention policy'), ref);
  expect(
    within(region)
      .getByRole('combobox', { name: 'Active Fact retention policy' })
      .querySelectorAll('option'),
  ).toHaveLength(2);
  await user.click(prepare);
  expect(screen.getByLabelText('Governed export binding')).toHaveAttribute(
    'data-kind',
    'evidence-deletion-fact',
  );
  expect(screen.getByLabelText('Governed export binding')).toHaveTextContent(ref);
  expect(screen.getByLabelText('Governed export binding')).toBeVisible();
  fireEvent.blur(window);
  expect(
    screen.queryByRole('region', { name: 'Prepare Fact payload retirement' }),
  ).not.toBeInTheDocument();
  expect(screen.getByLabelText('Governed export binding')).not.toHaveTextContent(ref);
});

it('prepares candidate retirement only from installed targets and active candidate policies, then clears on blur', async () => {
  const user = userEvent.setup();
  const policies = {
    ...page,
    items: [
      {
        retentionPolicyId: ref,
        policyVersion: '1.0.0',
        state: 'ACTIVE',
        dataClass: 'CANDIDATE_PROJECTION',
        deletionMode: 'PROJECTION_DELETE',
        retentionPeriodMs: '1000',
        localGraceMs: '2000',
        sinkQuorum: 1,
      },
      {
        retentionPolicyId: 'wrong-class',
        policyVersion: '2.0.0',
        state: 'ACTIVE',
        dataClass: 'AUDIT_EVIDENCE',
        deletionMode: 'ROW_DELETE',
        retentionPeriodMs: '1000',
        localGraceMs: '2000',
      },
    ],
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      Response.json(
        url.includes('candidateRetirementRecordId=')
          ? {
              actor,
              actorKey,
              evidenceId: ref,
              hosts: {
                items: [
                  {
                    hostDigest: 'a'.repeat(64),
                    targetId: 'installed-candidate-target',
                    store: 'openpc_candidate_index',
                  },
                ],
                authority: 'NONE',
              },
            }
          : { ...view, retentionPolicies: policies },
      ),
    ),
  );
  render(<EvidenceWorkflow />);
  await user.click(
    await screen.findByRole('button', {
      name: 'Review candidate payload retirement for sequence 3',
    }),
  );
  const region = await screen.findByRole('region', {
    name: 'Prepare candidate payload retirement',
  });
  const prepare = within(region).getByRole('button', { name: 'Review this candidate retirement' });
  expect(prepare).toBeDisabled();
  await user.selectOptions(
    within(region).getByLabelText('Installed candidate target'),
    'a'.repeat(64),
  );
  expect(prepare).toBeDisabled();
  await user.selectOptions(within(region).getByLabelText('Active candidate retention policy'), ref);
  expect(
    within(region)
      .getByRole('combobox', { name: 'Active candidate retention policy' })
      .querySelectorAll('option'),
  ).toHaveLength(2);
  await user.click(prepare);
  expect(screen.getByLabelText('Governed export binding')).toHaveAttribute(
    'data-kind',
    'evidence-deletion-candidate',
  );
  expect(screen.getByLabelText('Governed export binding')).toHaveTextContent(ref);
  fireEvent.blur(window);
  expect(
    screen.queryByRole('region', { name: 'Prepare candidate payload retirement' }),
  ).not.toBeInTheDocument();
  expect(screen.getByLabelText('Governed export binding')).not.toHaveTextContent(ref);
});

it('refuses a foreign Fact target discovery and focuses the safe context error', async () => {
  const user = userEvent.setup();
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      Response.json(
        url.includes('factRetirementRecordId=')
          ? {
              actor,
              actorKey: 'foreign-session',
              evidenceId: ref,
              hosts: { items: [], authority: 'NONE' },
            }
          : view,
      ),
    ),
  );
  render(<EvidenceWorkflow />);
  await user.click(
    await screen.findByRole('button', { name: 'Review Fact payload retirement for sequence 3' }),
  );
  const error = await screen.findByRole('alert');
  expect(error).toHaveTextContent('Context changed. Reload the evidence catalogue.');
  expect(error).toHaveFocus();
  expect(screen.getByRole('button', { name: 'Review this Fact retirement' })).toBeDisabled();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it('does not restore a discovered range after the browser loses its active context', async () => {
  const user = userEvent.setup();
  let finish: ((response: Response) => void) | undefined;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      if (url.includes('recordId='))
        return new Promise<Response>((resolve) => {
          finish = resolve;
        });
      return Response.json({
        ...view,
        retentionPolicies: {
          ...page,
          items: [
            {
              retentionPolicyId: ref,
              dataClass: 'AUDIT_EVIDENCE',
              policyVersion: '3.0.0',
              state: 'ACTIVE',
              retentionPeriodMs: '9007199254740993',
              localGraceMs: '100',
              sinkQuorum: 2,
              deletionMode: 'ROW_DELETE',
              makerCheckerRequired: true,
              activeFrom: '2026-09-21T00:00:00.000000Z',
              activeUntil: null,
              predecessorPolicyId: null,
              policyDigest: hash,
              activationReceiptDigest: hash,
              retirementReceiptDigest: null,
            },
          ],
        },
        holds: {
          ...page,
          items: [
            {
              holdId: ref,
              holdKind: 'LEGAL',
              state: 'ACTIVE',
              revision: '1',
              coverage: 'PENDING',
              selector: {
                type: 'SEQUENCE_RANGE',
                streamId: 'private-preserved-stream',
                fromSequence: '1',
                throughSequence: null,
              },
              selectorDigest: hash,
              creationReceiptDigest: hash,
              releaseReceiptDigest: null,
            },
          ],
        },
      });
    }),
  );
  render(<EvidenceWorkflow />);
  await user.click(await screen.findByRole('button', { name: 'Select sequence 3 for export' }));
  expect(finish).toBeDefined();
  expect(screen.getByRole('region', { name: 'Preservation holds' })).toHaveTextContent(
    'private-preserved-stream',
  );
  expect(screen.getByRole('region', { name: 'Preservation holds' })).toHaveTextContent(
    `Creation receipt: ${hash}`,
  );
  expect(screen.getByRole('region', { name: 'Retention policies' })).toHaveTextContent(
    '9007199254740993 ms',
  );
  expect(screen.getByRole('region', { name: 'Retention policies' })).toHaveTextContent(
    `Activation receipt: ${hash}`,
  );
  fireEvent.blur(window);
  await act(async () =>
    finish!(
      Response.json({
        actor,
        actorKey,
        record: {
          evidenceId: ref,
          recordDigest: hash,
          range: { streamId: 'stale-private-stream', fromSequence: '3', throughSequence: '3' },
        },
      }),
    ),
  );
  expect(screen.queryByLabelText('Evidence stream')).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Preservation holds' })).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Retention policies' })).not.toBeInTheDocument();
  expect(
    screen.queryByText('Record selected. Review the range and enter a purpose.'),
  ).not.toBeInTheDocument();
  expect(
    screen.getByText('Refresh evidence to load the records available in this workspace.'),
  ).toBeVisible();
});
it.each([false, true])(
  'keeps request acceptance distinct from completion and clears results on blur (evaluation=%s)',
  async (evaluationUi) => {
    const user = userEvent.setup();
    let complete = false;
    const bodies: unknown[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === 'POST') {
          bodies.push(JSON.parse(String(init.body)));
          return Response.json({ actorKey, operation: { resourceRef: ref } });
        }
        if (url.includes('artifact=1'))
          return Response.json({
            actor,
            actorKey,
            download: { outputDigest: hash, artifact: { version: 'redacted' } },
          });
        if (url.includes('recordId='))
          return Response.json({
            actor,
            actorKey,
            record: {
              evidenceId: ref,
              recordDigest: hash,
              range: { streamId: 'discovered-effects', fromSequence: '3', throughSequence: '3' },
            },
          });
        if (url.includes('exportId='))
          return Response.json({
            ...selected,
            selected: { ...selected.selected, state: complete ? 'SUCCEEDED' : 'REQUESTED' },
          });
        return Response.json(view);
      }),
    );
    render(<EvidenceWorkflow evaluationUi={evaluationUi} />);
    if (evaluationUi) {
      expect(screen.getByLabelText('Governed export binding')).not.toBeVisible();
      expect(screen.queryByRole('list', { name: 'Evidence export steps' })).toBeNull();
      await user.click(screen.getByRole('button', { name: 'Request recovery' }));
      expect(screen.getByLabelText('Governed export binding')).toBeVisible();
      expect(screen.getByLabelText('Governed export binding')).toHaveAttribute(
        'data-catalogue-enabled',
        'true',
      );
      expect(
        screen.getByText('Review an export or recover a request', { selector: 'button' }),
      ).not.toBeVisible();
      await user.click(screen.getByRole('button', { name: 'Records' }));
      expect(screen.getByLabelText('Governed export binding')).not.toBeVisible();
      expect(screen.getByLabelText('Governed export binding')).toHaveAttribute(
        'data-catalogue-enabled',
        'false',
      );
    }
    await user.click(await screen.findByRole('button', { name: 'Select sequence 3 for export' }));
    await screen.findByText('Record selected. Review the range and enter a purpose.');
    expect(screen.getByLabelText('Evidence stream')).toHaveValue('discovered-effects');
    await user.type(screen.getByLabelText('Purpose'), 'Audit the incident');
    await user.click(screen.getByRole('button', { name: 'Create export request' }));
    await screen.findByRole('region', { name: 'Selected export' });
    expect(screen.queryByText(/^No authorized export requests\./)).not.toBeInTheDocument();
    const exportReference = within(
      screen.getByRole('region', { name: 'Export requests' }),
    ).getByText(ref);
    if (evaluationUi) {
      expect(exportReference).not.toBeVisible();
      await user.click(screen.getByRole('button', { name: 'Export reference', hidden: true }));
    }
    expect(exportReference).toBeVisible();
    expect(bodies[0]).toMatchObject({
      actorKey,
      selection: { streamId: 'discovered-effects', fromSequence: '3', throughSequence: '3' },
    });
    expect(screen.getByLabelText('Governed export binding')).toHaveTextContent(ref);
    expect(screen.getByLabelText('Governed export binding')).toBeVisible();
    if (evaluationUi) {
      await user.click(screen.getByRole('button', { name: 'Records' }));
      expect(screen.queryByRole('region', { name: 'Selected export' })).toBeNull();
      await user.click(screen.getByRole('button', { name: 'Exports' }));
      expect(screen.getByRole('region', { name: 'Selected export' })).toBeVisible();
      expect(screen.getByLabelText('Governed export binding')).toHaveTextContent(ref);
      expect(screen.getByLabelText('Purpose')).toHaveValue('Audit the incident');
      expect(bodies).toHaveLength(1);
    }
    if (evaluationUi)
      expect(
        screen.getByText('Review an export or recover a request', { selector: 'button' }),
      ).not.toBeVisible();
    expect(
      screen.queryByRole('button', { name: 'Retrieve verified export' }),
    ).not.toBeInTheDocument();
    complete = true;
    await user.click(screen.getByRole('button', { name: 'Read current export status' }));
    expect(screen.getByRole('region', { name: 'Export requests' })).toHaveTextContent('SUCCEEDED');
    await user.click(await screen.findByRole('button', { name: 'Retrieve verified export' }));
    await screen.findByRole('button', { name: 'Download export JSON' });
    fireEvent.blur(window);
    expect(screen.queryByRole('button', { name: 'Download export JSON' })).not.toBeInTheDocument();
    expect(screen.queryByText(ref)).not.toBeInTheDocument();
  },
);

it('shows the complete deletion object and blocking reasons, then binds an eligible record to approval', async () => {
  const user = userEvent.setup();
  let eligible = false;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      url.includes('deletionRecordId=')
        ? Response.json({
            actor,
            actorKey,
            plan: {
              evidenceId: ref,
              localPayload: 'RETAINED',
              eligible,
              blockers: eligible ? [] : ['ACTIVE_HOLD'],
              beforeDigest: hash,
              selection: {
                streamId: 'authentication',
                firstSequence: '1',
                throughSequence: '3',
                recordCount: 3,
                ciphertextBytes: 4096,
                retentionPolicyId: ref,
                sinkReceipts: [{}],
              },
            },
          })
        : Response.json({ ...view, deletions: page, deletionsUnavailable: false }),
    ),
  );
  render(<EvidenceWorkflow />);
  await user.click(
    await screen.findByRole('button', { name: 'Check local deletion for sequence 3' }),
  );
  const plan = await screen.findByRole('region', { name: 'Local deletion eligibility' });
  expect(within(plan).getByText(/3 records; 4096 bytes/u)).toBeInTheDocument();
  expect(within(plan).getByText(/active hold preserves/u)).toBeInTheDocument();
  expect(
    within(plan).queryByRole('button', { name: 'Prepare local deletion' }),
  ).not.toBeInTheDocument();
  eligible = true;
  await user.click(within(plan).getByRole('button', { name: 'Refresh deletion eligibility' }));
  await user.click(await screen.findByRole('button', { name: 'Prepare local deletion' }));
  expect(screen.getByLabelText('Governed export binding')).toHaveTextContent(ref);
  expect(screen.getByLabelText('Governed export binding')).toHaveAttribute(
    'data-kind',
    'evidence-deletion',
  );
  await act(async () => {
    fireEvent.blur(window);
  });
  expect(
    screen.queryByRole('region', { name: 'Local deletion eligibility' }),
  ).not.toBeInTheDocument();
  expect(screen.getByLabelText('Governed export binding')).not.toHaveTextContent(ref);
});

it.each([false, true])(
  'shows signed batch progress and terminal readback without offering another deletion (raw=%s)',
  async (raw) => {
    const user = userEvent.setup();
    let complete = false;
    const selection = {
      version: raw
        ? 'OPENPC_RAW_PROOF_DELETION_BATCH_V1'
        : 'OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1',
      ...(raw
        ? { objectRef: ref, objectVersion: '1' }
        : {
            evidenceId: ref,
            streamId: 'authentication',
            firstSequence: '3',
            throughSequence: '4',
            recordCount: 2,
          }),
      ciphertextBytes: 4096,
      retentionPolicyId: ref,
      sinkReceipts: [],
      batchIndex: 1,
      priorCursor: { deletionJobId: ref, receiptDigest: hash },
      targets: [0, 1, 2].map((index) =>
        raw
          ? { objectRef: `${ref}-${index}`, objectVersion: '1', ciphertextBytes: 4096 }
          : {
              segmentId: String(index),
              firstSequence: String(index * 2 + 1),
              throughSequence: String(index * 2 + 2),
              recordCount: 2,
              ciphertextBytes: 4096,
            },
      ),
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        url.includes(raw ? 'rawDeletionContinuationId=' : 'deletionContinuationId=')
          ? Response.json({
              actor,
              actorKey,
              plan: {
                ...(raw ? { objectRef: ref } : { evidenceId: ref }),
                localPayload: complete ? 'DELETED' : 'RETAINED',
                eligible: !complete,
                blockers: [],
                beforeDigest: complete ? null : hash,
                selection: complete ? null : selection,
                continuationState: complete ? 'COMPLETE' : 'READY',
                nextDeletionJobId: null,
              },
            })
          : Response.json({
              ...view,
              deletionsUnavailable: false,
              deletions: {
                ...page,
                items: [
                  {
                    deletionJobId: ref,
                    selection,
                    state: 'SUCCEEDED',
                    deletedCount: '1',
                    deletedBytes: '4096',
                    beforeDigest: hash,
                    afterDigest: hash,
                    receiptDigest: hash,
                  },
                ],
              },
            }),
      ),
    );
    render(<EvidenceWorkflow />);
    const continuation = await screen.findByRole('button', { name: 'Read signed continuation' });
    const results = screen.getByRole('region', { name: 'Local deletion results' });
    expect(within(results).getByText('Completed')).toBeVisible();
    expect(within(results).getByText(`Deletion reference: ${ref}`)).not.toBeVisible();
    expect(within(results).getByText(`Signed receipt: ${hash}`)).not.toBeVisible();
    expect(continuation).toBeVisible();
    await user.click(continuation);
    expect(vi.mocked(fetch).mock.calls.at(-1)?.[0]).toBe(
      `/api/v1/ui/evidence-workbench?${raw ? 'rawDeletionContinuationId' : 'deletionContinuationId'}=${id}`,
    );
    expect(await screen.findByText(/Object 2 of 3/u)).toBeInTheDocument();
    const batch = screen.getByRole('button', {
      name: 'Objects in this signed batch',
      hidden: true,
    });
    expect(batch.parentElement!.querySelector('dialog')).not.toHaveAttribute('open');
    const targets = batch.parentElement!.querySelector('dialog')!.querySelector('ol')!;
    expect(targets).not.toBeVisible();
    await user.click(batch);
    expect(targets).toBeVisible();
    expect(targets.querySelectorAll('li')).toHaveLength(3);
    expect(targets.children[0]).toHaveTextContent('Committed');
    expect(targets.children[1]).toHaveTextContent('Next');
    expect(targets.children[2]).toHaveTextContent('Remaining');
    expect(screen.getByText(`Previous signed receipt: ${hash}`)).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Prepare next deletion batch' }));
    expect(screen.getByLabelText('Governed export binding')).toHaveTextContent(ref);
    expect(screen.getByLabelText('Governed export binding')).toHaveAttribute(
      'data-kind',
      raw ? 'evidence-deletion-raw-continuation' : 'evidence-deletion-continuation',
    );
    complete = true;
    await user.click(screen.getByRole('button', { name: 'Refresh deletion eligibility' }));
    expect(await screen.findByText('Continuation: COMPLETE.')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Prepare next deletion batch' }),
    ).not.toBeInTheDocument();
    await act(async () => {
      fireEvent.blur(window);
    });
    expect(screen.queryByText('Continuation: COMPLETE.')).not.toBeInTheDocument();
  },
);

it('clears provenance when the context is lost and refuses a delayed foreign read', async () => {
  const user = userEvent.setup();
  let finish: ((response: Response) => void) | undefined;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      url.includes('provenanceRecordId=')
        ? new Promise<Response>((resolve) => {
            finish = resolve;
          })
        : Response.json(view),
    ),
  );
  render(<EvidenceWorkflow />);
  await user.click(await screen.findByRole('button', { name: 'Read provenance for sequence 3' }));
  fireEvent.blur(window);
  await act(async () =>
    finish!(
      Response.json({
        actorKey,
        provenance: { evidenceId: ref, recordDigest: hash, sourceFormat: 'foreign-source' },
      }),
    ),
  );
  expect(screen.queryByRole('region', { name: 'Evidence provenance' })).toBeNull();
  expect(screen.queryByText('foreign-source')).toBeNull();
});

it.each(['search', 'retention-policy', 'normalized', 'fact'] as const)(
  'reviews %s projection retirement, clears stale state and binds the governed action',
  async (kind) => {
    const projectionKind =
      kind === 'fact' ? 'normalized' : kind === 'retention-policy' ? 'search' : kind;
    const user = userEvent.setup();
    let eligible = false;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        url.includes(`${projectionKind}ProjectionRecordId=`)
          ? Response.json({
              actor,
              actorKey,
              plan: {
                evidenceId: ref,
                dataClass:
                  projectionKind === 'search' ? 'SEARCH_PROJECTION' : 'NORMALIZED_JSON_PROJECTION',
                projectionState: 'RETAINED',
                eligible,
                blockers: eligible ? [] : ['ACTIVE_HOLD'],
                continuationState: eligible ? 'READY' : 'BLOCKED',
                nextDeletionJobId: null,
                beforeDigest: hash,
                selection: {
                  version: 'OPENPC_PROJECTION_DELETION_BATCH_V1',
                  sourceKind:
                    kind === 'fact'
                      ? 'FACT_PROVENANCE'
                      : kind === 'normalized'
                        ? 'RPC_PRE_ADMISSION_DENIAL'
                        : kind === 'retention-policy'
                          ? 'RETENTION_POLICY_CATALOGUE'
                          : 'AUTHENTICATION_CATALOGUE',
                  evidenceId: ref,
                  dataClass:
                    projectionKind === 'search'
                      ? 'SEARCH_PROJECTION'
                      : 'NORMALIZED_JSON_PROJECTION',
                  streamId: 'projection',
                  sequence: '3',
                  projectionDigest: hash,
                  projectionBytes: 512,
                  retentionPolicyId: ref,
                  sinkReceipts: [],
                  batchIndex: 0,
                  priorCursor: null,
                  targets: [{ evidenceId: ref, recordId: ref, projectionBytes: 512 }],
                  ...(kind === 'normalized'
                    ? {
                        rpcClosure: {
                          terminalPhase: 'RELEASED',
                          terminalSequence: '5',
                          archive: { sinkReceipts: [{}] },
                        },
                      }
                    : {}),
                },
              },
            })
          : Response.json(view),
      ),
    );
    render(<EvidenceWorkflow />);
    await user.click(
      await screen.findByRole('button', {
        name: `Review ${projectionKind} projection deletion for sequence 3`,
      }),
    );
    const region = await screen.findByRole('region', { name: 'Local deletion eligibility' });
    expect(within(region).getByText(/Projection: RETAINED/u)).toBeInTheDocument();
    expect(within(region).getAllByText(/512 projection bytes/u)).toHaveLength(2);
    if (kind === 'normalized')
      expect(
        within(region).getByText(/RPC completion witness: RELEASED, sequence 5/u),
      ).toBeInTheDocument();
    if (kind === 'fact')
      expect(within(region).queryByText(/RPC completion witness/u)).not.toBeInTheDocument();
    expect(
      within(region).queryByRole('button', { name: 'Prepare first deletion batch' }),
    ).not.toBeInTheDocument();
    eligible = true;
    await user.click(within(region).getByRole('button', { name: 'Refresh deletion eligibility' }));
    await user.click(await screen.findByRole('button', { name: 'Prepare first deletion batch' }));
    expect(screen.getByLabelText('Governed export binding')).toHaveAttribute(
      'data-kind',
      `evidence-deletion-${projectionKind}`,
    );
    expect(screen.getByLabelText('Governed export binding')).toHaveTextContent(ref);
    await act(async () => fireEvent.blur(window));
    expect(
      screen.queryByRole('region', { name: 'Local deletion eligibility' }),
    ).not.toBeInTheDocument();
  },
);

it('binds raw-proof review to the entered object and clears eligibility when that input changes', async () => {
  const user = userEvent.setup();
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      url.includes('rawDeletionObjectId=')
        ? Response.json({
            actor,
            actorKey,
            plan: {
              objectRef: ref,
              localPayload: 'RETAINED',
              eligible: true,
              blockers: [],
              selection: null,
              beforeDigest: hash,
              continuationState: 'READY',
              nextDeletionJobId: null,
            },
          })
        : Response.json({ ...view, deletions: page }),
    ),
  );
  render(<EvidenceWorkflow />);
  const input = await screen.findByLabelText('Retained protected object reference');
  await user.type(input, ref);
  await user.click(screen.getByRole('button', { name: 'Check protected proof deletion' }));
  await user.click(await screen.findByRole('button', { name: 'Prepare first deletion batch' }));
  expect(screen.getByLabelText('Governed export binding')).toHaveAttribute(
    'data-kind',
    'evidence-deletion-raw',
  );
  expect(screen.getByLabelText('Governed export binding')).toHaveTextContent(ref);
  await user.clear(input);
  expect(
    screen.queryByRole('region', { name: 'Local deletion eligibility' }),
  ).not.toBeInTheDocument();
});

it.each(['VERIFIED_BUSINESS_TRANSITION', 'SOURCE_NOT_SUPPORTED'])(
  'mounts operation correlation only for a verified business receipt: %s',
  async (status) => {
    const user = userEvent.setup();
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        Response.json(
          url.includes('provenanceRecordId=')
            ? {
                actorKey,
                provenance: {
                  evidenceId: ref,
                  recordId: id,
                  recordDigest: hash,
                  status,
                  participantId: `urn:openpc:participant:${actor.participantId}`,
                  privacyDomainId: actor.privacyDomainId,
                  sourceFormat: 'COSE_SIGN1_24001_1_338',
                  custody: {
                    streamId: 'control-receipts',
                    sequence: '3',
                    segmentId: id,
                    checkpoints: [],
                  },
                },
              }
            : view,
        ),
      ),
    );
    render(<EvidenceWorkflow />);
    await user.click(await screen.findByRole('button', { name: 'Read provenance for sequence 3' }));
    await screen.findByRole('region', { name: 'Evidence provenance' });
    if (status === 'VERIFIED_BUSINESS_TRANSITION') {
      expect(screen.getByLabelText('Operation correlation binding')).toHaveTextContent(ref);
      expect(screen.getByLabelText('Operation correlation binding')).toHaveAttribute(
        'data-actor-key',
        actorKey,
      );
    } else expect(screen.queryByLabelText('Operation correlation binding')).toBeNull();
    await act(async () => {
      fireEvent.blur(window);
    });
    expect(screen.queryByLabelText('Operation correlation binding')).toBeNull();
  },
);

it('keeps task navigation local and conceals other task inputs, drafts and private data on blur', async () => {
  const user = userEvent.setup();
  const fetch = vi.fn(async () => Response.json(view));
  vi.stubGlobal('fetch', fetch);
  render(<EvidenceWorkflow evaluationUi showSessionControls={false} />);
  await screen.findByRole('region', { name: 'Evidence catalogue' });
  expect(screen.queryByRole('region', { name: 'Export requests' })).toBeNull();
  expect(screen.getByLabelText('Find records by receipt digest')).not.toBeVisible();
  expect(screen.getByLabelText('Retained protected object reference')).not.toBeVisible();
  const recovery = screen.getByRole('button', { name: 'Request recovery' });
  recovery.focus();
  await user.keyboard('{Enter}');
  expect(recovery).toHaveFocus();
  expect(recovery).toHaveAttribute('aria-pressed', 'true');
  expect(screen.queryByRole('region', { name: 'Evidence catalogue' })).toBeNull();
  const originalControls = screen.getByLabelText('Governed export binding');
  expect(originalControls).toBeVisible();
  expect(originalControls).toHaveAttribute('data-guided-recovery', 'true');
  expect(originalControls).toHaveAttribute('data-catalogue-enabled', 'true');
  await user.click(screen.getByRole('button', { name: 'Exports' }));
  await user.click(
    screen.getByRole('button', { name: 'Enter an evidence range manually', hidden: true }),
  );
  await user.type(screen.getByLabelText('Purpose'), 'An investigation');
  await user.click(screen.getByRole('button', { name: 'Retention & holds' }));
  expect(screen.getByLabelText('Purpose')).not.toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Exports' }));
  expect(screen.getByLabelText('Purpose')).toHaveValue('An investigation');
  await user.click(screen.getByRole('button', { name: 'Request recovery' }));
  expect(screen.getByLabelText('Governed export binding')).toBe(originalControls);
  expect(fetch).toHaveBeenCalledTimes(1);
  fireEvent.blur(window);
  expect(screen.queryByText(`Evidence reference: ${ref}`)).toBeNull();
  expect(screen.queryByLabelText('Purpose')).toBeNull();
  expect(screen.getByRole('button', { name: 'Request recovery' })).toHaveAttribute(
    'aria-pressed',
    'true',
  );
  fireEvent.focus(window);
  await screen.findByRole('button', { name: 'Evidence workspace details' });
  expect(screen.getByRole('button', { name: 'Request recovery' })).toHaveAttribute(
    'aria-pressed',
    'true',
  );
  expect(screen.queryByRole('region', { name: 'Evidence catalogue' })).toBeNull();
  expect(screen.getByLabelText('Governed export binding')).toBeVisible();
  expect(screen.getByLabelText('Governed export binding')).toHaveAttribute(
    'data-catalogue-enabled',
    'true',
  );
  expect(
    screen.getByText('Review an export or recover a request', { selector: 'button' }),
  ).not.toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Exports' }));
  await user.click(
    screen.getByRole('button', { name: 'Enter an evidence range manually', hidden: true }),
  );
  expect(screen.getByLabelText('Purpose')).toHaveValue('');
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('keeps failed owner reads visible across task navigation without issuing another request', async () => {
  const user = userEvent.setup();
  const fetch = vi.fn(async (url: string) =>
    url.includes('recordId=')
      ? Response.json(
          { title: 'Record unavailable.', code: 'PC-INTEGRATION-5001' },
          { status: 503 },
        )
      : Response.json(view),
  );
  vi.stubGlobal('fetch', fetch);
  render(<EvidenceWorkflow evaluationUi showSessionControls={false} />);
  await user.click(await screen.findByRole('button', { name: 'Select sequence 3 for export' }));
  await screen.findByText('Record unavailable. (PC-INTEGRATION-5001)');
  await user.click(screen.getByRole('button', { name: 'Retention & holds' }));
  expect(screen.getByText('Record unavailable. (PC-INTEGRATION-5001)')).toBeVisible();
  expect(fetch).toHaveBeenCalledTimes(2);
  fireEvent.blur(window);
  expect(screen.queryByText('Record unavailable. (PC-INTEGRATION-5001)')).toBeNull();
});

it('hands a freshly read protected proof to its governed access request without dispatching it', async () => {
  const proofActor = {
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    principalId: '018f0000-0000-7000-8000-000000000111',
    sessionId: '018f0000-0000-7000-8000-000000000301',
    contextEpoch: '1',
  };
  const proof = {
    objectRef: ref,
    objectVersion: '1',
    purpose: 'Review an authentication record',
    caseReference: 'CASE-51',
    retainUntil: '2099-10-11T04:00:00.000000Z',
    createdAt: '2026-10-11T04:00:00.000000Z',
    updatedAt: '2026-10-11T04:00:00.000000Z',
  };
  const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
    expect(init?.method).toBeUndefined();
    if (input.includes('/protected-proof-workbench?catalogue=objects'))
      return Response.json({
        actorKey: hash,
        actor: proofActor,
        catalogue: 'objects',
        items: [proof],
        authorizedEmpty: false,
        total: '1',
        completeness: 'COMPLETE',
        snapshotRevision: '1',
        nextCursor: null,
      });
    if (input.includes('/protected-proof-workbench?objectId='))
      return Response.json({ actorKey: hash, actor: proofActor, object: proof });
    return Response.json({ ...view, actorKey: hash, actor: proofActor });
  });
  vi.stubGlobal('fetch', fetcher);
  const user = userEvent.setup();
  render(<EvidenceWorkflow evaluationUi />);
  await screen.findByRole('region', { name: 'Evidence catalogue' });
  await user.click(screen.getByRole('button', { name: 'Protected proofs' }));
  await user.click(await screen.findByRole('button', { name: `Review proof ${id}` }));
  await user.click(await screen.findByRole('button', { name: 'Prepare access request' }));
  const request = screen.getByLabelText('Governed export binding');
  expect(request).toBeVisible();
  expect(request).toHaveAttribute('data-kind', 'protected-proof-access');
  expect(request).toHaveTextContent(ref);
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});
