'use client';

import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react';
import Link from 'next/link';
import { WorkflowDetails } from './workflow-details';
import { TransactionWorkflow } from './transaction-workflow';
import { FactRetirementPreparation } from './fact-retirement-preparation';
import { ProtectedProofWorkflow } from './protected-proof-workflow';
import { EvidenceProvenancePanel } from './evidence-provenance';
import { EvidenceOperationCorrelation } from './evidence-operation-correlation';
import { isSessionTransitionPending, observeSessionTransitions } from './session-transition';
import type { EvidenceProvenance } from '../../../services/control-api/src/evidence/provenance-contracts';
import type {
  EvidenceCataloguePage,
  EvidenceRequestsPage,
  EvidenceRequest,
  EvidenceSelection,
  EvidenceDownload,
  EvidenceRecordRange,
  EvidenceHoldsPage,
  RetentionPoliciesPage,
  EvidenceDeletionsPage,
  LocalEvidenceDeletionPlan,
  LocalEvidenceDeletionBatchPlan,
  RawProofDeletionPlan,
  ProjectionDeletionPlan,
} from '../app/api/v1/ui/local-evidence-workbench';

interface Binding {
  actorKey: string;
  actor: { participantId: string; privacyDomainId: string };
}
interface View extends Binding {
  recordDigest?: string | null;
  recordsCursor?: string | null;
  records: EvidenceCataloguePage | null;
  exports: EvidenceRequestsPage | null;
  recordsUnavailable: boolean;
  exportsUnavailable: boolean;
  holds?: EvidenceHoldsPage | null;
  holdsUnavailable?: boolean;
  retentionPolicies?: RetentionPoliciesPage | null;
  retentionPoliciesUnavailable?: boolean;
  deletions?: EvidenceDeletionsPage | null;
  deletionsUnavailable?: boolean;
}
interface Selected extends Binding {
  selected: EvidenceRequest;
  selection: EvidenceSelection;
}
type DeletionKind =
  | 'evidence-deletion'
  | 'evidence-deletion-batch'
  | 'evidence-deletion-continuation'
  | 'evidence-deletion-raw'
  | 'evidence-deletion-raw-continuation'
  | 'evidence-deletion-search'
  | 'evidence-deletion-normalized'
  | 'evidence-deletion-projection-continuation';
type DeletionPlan =
  | LocalEvidenceDeletionPlan
  | LocalEvidenceDeletionBatchPlan
  | RawProofDeletionPlan
  | ProjectionDeletionPlan;
const deletionQuery: Record<DeletionKind, string> = {
  'evidence-deletion': 'deletionRecordId',
  'evidence-deletion-batch': 'deletionBatchRecordId',
  'evidence-deletion-continuation': 'deletionContinuationId',
  'evidence-deletion-raw': 'rawDeletionObjectId',
  'evidence-deletion-raw-continuation': 'rawDeletionContinuationId',
  'evidence-deletion-search': 'searchProjectionRecordId',
  'evidence-deletion-normalized': 'normalizedProjectionRecordId',
  'evidence-deletion-projection-continuation': 'projectionContinuationId',
};
const deletionBlockers: Record<DeletionPlan['blockers'][number], string> = {
  UNRESOLVED_TRANSITION: 'The original RPC owner has not established a matching terminal outcome.',
  UNRESOLVED_OPERATION:
    'Reading operation status does not resolve the referenced operation or its recovery obligations.',
  WRITE_AMBIGUITY: 'An ambiguous write remains protected until its execution owner reconciles it.',
  REORG_FENCED: 'A reorg or invalidated deployment observation still protects this source.',
  STALE_SELECTION:
    'The signed selection no longer matches the current policy or object. This continuation cannot advance.',
  NO_ACTIVE_POLICY: 'No active retention policy for this data class.',
  UNSUPPORTED_MODE: 'The current policy requires a different deletion method.',
  RETENTION_NOT_ELAPSED: 'A retention, grace or storage protection deadline has not elapsed.',
  ACTIVE_HOLD: 'An active hold preserves this object, including while coverage is pending.',
  SINK_QUORUM: 'Required durable archive acknowledgements are missing.',
  INCOMPLETE_CHECKPOINT: 'Archive checkpoint coverage is incomplete.',
  UNSUPPORTED_SOURCE:
    'This source needs its finality and recovery checks before deletion is supported.',
  REFERENCES: 'References must be cleared by their owning process.',
  ALREADY_DELETED: 'This selected local data has already been deleted.',
};
const evidenceTasks = {
  records: { label: 'Records', description: 'Inspect evidence and select the records you need.' },
  exports: {
    label: 'Exports',
    description: 'Request a minimized export and track its approval and delivery.',
  },
  retention: {
    label: 'Retention & holds',
    description: 'Review the rules and preservation holds that protect stored data.',
  },
  removal: {
    label: 'Data removal',
    description: 'Check removal eligibility and review completed local deletions.',
  },
  recovery: {
    label: 'Request recovery',
    description: 'Read an existing request or continue its original approved operation.',
  },
  proofs: { label: 'Protected proofs', description: 'Review access to protected source proofs.' },
} as const;
type EvidenceTask = keyof typeof evidenceTasks;

const endpoint = '/api/v1/ui/evidence-workbench';
const fieldClass =
  'mt-1 w-full rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-2';
const buttonClass = 'rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-50';
const resourceId = (ref: string) => ref.slice(-36);
const evidenceClassLabels: Readonly<
  Record<EvidenceCataloguePage['items'][number]['evidenceClass'], string>
> = {
  AUTHENTICATION: 'Authentication',
  BUSINESS_TRANSITION: 'Business transition',
  EFFECT: 'Effect evidence',
};
const exportStateLabels: Readonly<Record<EvidenceRequest['state'], string>> = {
  REQUESTED: 'Requested',
  RUNNING: 'Preparing',
  SUCCEEDED: 'Completed',
  FAILED: 'Failed',
  BACKLOGGED: 'Waiting for processing',
};
function evidenceTime(value: string) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Time unavailable';
  return `${new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
    timeZone: 'UTC',
  }).format(date)} UTC`;
}
const dataClassLabels: Readonly<Record<string, string>> = {
  LOCAL_EVIDENCE_PAYLOAD: 'Local evidence payload',
  RAW_SOURCE_BODY: 'Protected source proof',
  NORMALIZED_JSON_PROJECTION: 'Normalized record',
  SEARCH_PROJECTION: 'Search index',
  RUNTIME_ARTIFACT: 'Runtime configuration',
  ADMITTED_FACT: 'Admitted fact',
  CANDIDATE_PROJECTION: 'Candidate projection',
  AUDIT_EVIDENCE: 'Audit evidence',
  NOTIFICATION_PAYLOAD: 'Notification payload',
  OUTBOX_INBOX: 'Message inbox and outbox',
  IDENTITY_RECORD: 'Identity record',
};
function dataClassLabel(value: string) {
  return dataClassLabels[value] ?? value;
}
function retentionDuration(value: string) {
  const milliseconds = BigInt(value);
  for (const [unit, label] of [
    [86_400_000n, 'day'],
    [3_600_000n, 'hour'],
    [60_000n, 'minute'],
    [1_000n, 'second'],
  ] as const) {
    if (milliseconds > 0n && milliseconds % unit === 0n) {
      const count = milliseconds / unit;
      return `${count} ${label}${count === 1n ? '' : 's'}`;
    }
  }
  return `${value} ms`;
}
function deletionTitle(selection: EvidenceDeletionsPage['items'][number]['selection']) {
  if (selection.version === 'OPENPC_RAW_PROOF_DELETION_BATCH_V1')
    return `Protected source proof · Version ${selection.objectVersion}`;
  if (selection.version === 'OPENPC_PROJECTION_DELETION_BATCH_V1')
    return `${dataClassLabel(selection.dataClass)} · Sequence ${selection.sequence}`;
  if (selection.version === 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1')
    return 'Runtime configuration artifact';
  return `Local evidence payload · Sequences ${selection.firstSequence}–${selection.throughSequence}`;
}
async function read<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => undefined);
  if (!response.ok)
    throw new Error(
      `${body?.title ?? 'Evidence is unavailable.'}${body?.code ? ` (${body.code})` : ''}`,
    );
  return body as T;
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object')
    return `{${Object.entries(value)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
      .join(',')}}`;
  return JSON.stringify(value);
}

function EvidenceCollectionPage({
  entries = [],
  enabled,
  busy,
  label,
  noun,
  navigationLabel,
  className,
}: Readonly<{
  entries?: readonly ReactNode[];
  enabled: boolean;
  busy: boolean;
  label: string;
  noun: string;
  navigationLabel: string;
  className: string;
}>) {
  const [page, setPage] = useState(0);
  const size = 6;
  const lastPage = Math.max(0, Math.ceil(entries.length / size) - 1);
  const currentPage = Math.min(page, lastPage);
  const start = currentPage * size;
  const paged = enabled && entries.length > size;
  return (
    <>
      {paged ? (
        <nav aria-label={`${label} navigation`} className="flex flex-wrap items-center gap-3">
          <p role="status" className="mr-auto text-sm text-[color:var(--muted)]">
            Showing {start + 1}–{Math.min(start + size, entries.length)} of {entries.length} loaded{' '}
            {noun}
          </p>
          <button
            type="button"
            className={buttonClass}
            disabled={busy || currentPage === 0}
            onClick={() => setPage(currentPage - 1)}
          >
            Previous {navigationLabel}
          </button>
          <button
            type="button"
            className={buttonClass}
            disabled={busy || currentPage === lastPage}
            onClick={() => setPage(currentPage + 1)}
          >
            Next {navigationLabel}
          </button>
        </nav>
      ) : null}
      <ul className={className}>{paged ? entries.slice(start, start + size) : entries}</ul>
    </>
  );
}

export function EvidenceWorkflow({
  showSessionControls = true,
  evaluationUi = false,
}: { readonly showSessionControls?: boolean; readonly evaluationUi?: boolean } = {}) {
  const formId = useId(),
    generation = useRef(0),
    pending = useRef<AbortController | undefined>(undefined);
  const [task, setTask] = useState<EvidenceTask>('records');
  const taskHeading = useRef<HTMLHeadingElement>(null);
  const focusTask = useRef(false);
  useEffect(() => {
    if (focusTask.current) {
      focusTask.current = false;
      taskHeading.current?.focus();
    }
  }, [task]);
  function openTask(next: EvidenceTask, moveFocus = false) {
    if (evaluationUi && moveFocus) {
      if (next === task) taskHeading.current?.focus();
      else focusTask.current = true;
    }
    setTask(next);
  }
  const [view, setView] = useState<View>(),
    [provenance, setProvenance] = useState<EvidenceProvenance>(),
    [selected, setSelected] = useState<Selected>(),
    [download, setDownload] = useState<EvidenceDownload>(),
    [deletion, setDeletion] = useState<
      Binding & {
        plan: DeletionPlan;
        kind: DeletionKind;
        reference: string;
      }
    >(),
    [prepareDeletion, setPrepareDeletion] = useState(false);
  const [proofAccessObjectRef, setProofAccessObjectRef] = useState<string>();
  const [stream, setStream] = useState(''),
    [guidedSource, setGuidedSource] = useState(false),
    [rawObjectRef, setRawObjectRef] = useState(''),
    [recordDigest, setRecordDigest] = useState(''),
    [first, setFirst] = useState('1'),
    [last, setLast] = useState('1'),
    [reason, setReason] = useState('');
  const [status, setStatusMessage] = useState(''),
    [statusTask, setStatusTask] = useState<EvidenceTask>(),
    [busy, setBusy] = useState(true);
  const setStatus = useCallback((message: string, forTask?: EvidenceTask) => {
    setStatusMessage(message);
    setStatusTask(forTask);
  }, []);
  const retry = useRef<{ input: string; key: string } | undefined>(undefined);
  const [factRetirementRecord, setFactRetirementRecord] = useState<{
    evidenceId: string;
    source: 'fact' | 'candidate';
  }>();
  const [factRetirementFields, setFactRetirementFields] = useState<{
    evidenceId: string;
    hostDigest: string;
    retentionPolicyId: string;
  }>();
  const clear = useCallback(() => {
    generation.current++;
    pending.current?.abort();
    setView(undefined);
    setStatus('');
    setProvenance(undefined);
    setRecordDigest('');
    setSelected(undefined);
    setDownload(undefined);
    setDeletion(undefined);
    setPrepareDeletion(false);
    setProofAccessObjectRef(undefined);
    setFactRetirementRecord(undefined);
    setFactRetirementFields(undefined);
    setStream('');
    setGuidedSource(false);
    setRawObjectRef('');
    setReason('');
    setFirst('1');
    setLast('1');
    setBusy(false);
  }, [setStatus]);
  const load = useCallback(
    async (parameters?: Record<string, string>) => {
      clear();
      setRecordDigest(parameters?.recordDigest ?? '');
      const current = generation.current,
        controller = new AbortController();
      pending.current = controller;
      setBusy(true);
      try {
        const next = await read<View>(
          await fetch(`${endpoint}${parameters ? `?${new URLSearchParams(parameters)}` : ''}`, {
            cache: 'no-store',
            signal: controller.signal,
          }),
        );
        if (generation.current !== current) return;
        setView(next);
        setStatus('Evidence workspace refreshed.');
      } catch (error) {
        if (generation.current === current)
          setStatus(error instanceof Error ? error.message : 'Evidence is unavailable.');
      } finally {
        if (generation.current === current) setBusy(false);
      }
    },
    [clear, setStatus],
  );
  useEffect(() => {
    if (!isSessionTransitionPending()) void load();
    const stop = observeSessionTransitions(clear, (blocked) => {
      if (!blocked) void load();
    });
    const hidden = () => {
      if (document.visibilityState !== 'visible') clear();
    };
    window.addEventListener('blur', clear);
    document.addEventListener('visibilitychange', hidden);
    return () => {
      clear();
      stop();
      window.removeEventListener('blur', clear);
      document.removeEventListener('visibilitychange', hidden);
    };
  }, [load, clear]);

  async function inspectDeletion(recordRef: string, kind: DeletionKind = 'evidence-deletion') {
    if (!view || busy) return;
    setFactRetirementRecord(undefined);
    setFactRetirementFields(undefined);
    const current = ++generation.current;
    pending.current?.abort();
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    setDeletion(undefined);
    setPrepareDeletion(false);
    setSelected(undefined);
    setDownload(undefined);
    try {
      const next = await read<Binding & { plan: DeletionPlan }>(
        await fetch(
          `${endpoint}?${new URLSearchParams({ [deletionQuery[kind]]: resourceId(recordRef) })}`,
          { cache: 'no-store', signal: controller.signal },
        ),
      );
      if (generation.current !== current) return;
      if (
        next.actorKey !== view.actorKey ||
        (kind === 'evidence-deletion' &&
          (!('evidenceId' in next.plan) || next.plan.evidenceId !== recordRef)) ||
        (kind === 'evidence-deletion-raw' &&
          (!('objectRef' in next.plan) || next.plan.objectRef !== recordRef))
      ) {
        clear();
        throw new Error('Context changed. Refresh evidence.');
      }
      setDeletion({ ...next, kind, reference: recordRef });
      openTask('removal', true);
      setStatus(
        next.plan.eligible
          ? 'Local object is eligible for an independently approved deletion request.'
          : 'continuationState' in next.plan && next.plan.continuationState === 'COMPLETE'
            ? 'Every object in the signed selection has been deleted locally.'
            : 'continuationState' in next.plan && next.plan.continuationState === 'ADVANCED'
              ? 'This cursor has already advanced. Open its committed successor.'
              : 'Local deletion is blocked. Review the current reasons.',
        'removal',
      );
    } catch (error) {
      if (generation.current === current)
        setStatus(error instanceof Error ? error.message : 'Deletion eligibility unavailable.');
    } finally {
      if (generation.current === current) setBusy(false);
    }
  }

  async function inspectProvenance(record: EvidenceCataloguePage['items'][number]) {
    if (!view || busy) return;
    const current = ++generation.current;
    pending.current?.abort();
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    setProvenance(undefined);
    try {
      const next = await read<Binding & { provenance: EvidenceProvenance }>(
        await fetch(
          `${endpoint}?${new URLSearchParams({ provenanceRecordId: resourceId(record.evidenceId) })}`,
          { cache: 'no-store', signal: controller.signal },
        ),
      );
      if (generation.current !== current) return;
      if (
        next.actorKey !== view.actorKey ||
        next.provenance.evidenceId !== record.evidenceId ||
        next.provenance.recordDigest !== record.recordDigest ||
        next.provenance.participantId !== `urn:openpc:participant:${view.actor.participantId}` ||
        next.provenance.privacyDomainId !== view.actor.privacyDomainId
      ) {
        clear();
        throw new Error('Context changed. Refresh evidence.');
      }
      setProvenance(next.provenance);
      setStatus('Provenance loaded.', 'records');
    } catch (error) {
      if (generation.current === current)
        setStatus(error instanceof Error ? error.message : 'Provenance unavailable.');
    } finally {
      if (generation.current === current) setBusy(false);
    }
  }

  async function selectRecord(record: EvidenceCataloguePage['items'][number]) {
    if (!view || busy) return;
    setFactRetirementRecord(undefined);
    setFactRetirementFields(undefined);
    const current = ++generation.current;
    pending.current?.abort();
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    setSelected(undefined);
    setDownload(undefined);
    setDeletion(undefined);
    setPrepareDeletion(false);
    setStream('');
    setGuidedSource(false);
    try {
      const next = await read<Binding & { record: EvidenceRecordRange }>(
        await fetch(
          `${endpoint}?${new URLSearchParams({ recordId: resourceId(record.evidenceId) })}`,
          {
            cache: 'no-store',
            signal: controller.signal,
          },
        ),
      );
      if (generation.current !== current) return;
      if (
        next.actorKey !== view.actorKey ||
        next.record.evidenceId !== record.evidenceId ||
        next.record.recordDigest !== record.recordDigest
      ) {
        clear();
        throw new Error('Context changed. Refresh evidence.');
      }
      setStream(next.record.range.streamId);
      setGuidedSource(true);
      openTask('exports', true);
      setFirst(next.record.range.fromSequence);
      setLast(next.record.range.throughSequence);
      setStatus('Record selected. Review the range and enter a purpose.', 'exports');
    } catch (error) {
      if (generation.current === current)
        setStatus(error instanceof Error ? error.message : 'Record unavailable.');
    } finally {
      if (generation.current === current) setBusy(false);
    }
  }

  async function select(ref: string) {
    if (!view) return false;
    setFactRetirementRecord(undefined);
    setFactRetirementFields(undefined);
    const current = ++generation.current;
    pending.current?.abort();
    const controller = new AbortController();
    pending.current = controller;
    setSelected(undefined);
    setDownload(undefined);
    setDeletion(undefined);
    setPrepareDeletion(false);
    setBusy(true);
    try {
      const next = await read<Selected>(
        await fetch(`${endpoint}?${new URLSearchParams({ exportId: resourceId(ref) })}`, {
          cache: 'no-store',
          signal: controller.signal,
        }),
      );
      if (generation.current !== current) return false;
      if (next.actorKey !== view.actorKey) {
        clear();
        throw new Error('Context changed. Refresh evidence.');
      }
      setSelected(next);
      openTask('exports', true);
      setView((previous) => {
        if (previous?.actorKey !== next.actorKey || !previous.exports) return previous;
        const existing = previous.exports.items.some(
          (item) => item.evidenceExportId === next.selected.evidenceExportId,
        );
        return {
          ...previous,
          exports: {
            ...previous.exports,
            authorizedEmpty: false,
            items: existing
              ? previous.exports.items.map((item) =>
                  item.evidenceExportId === next.selected.evidenceExportId ? next.selected : item,
                )
              : [next.selected, ...previous.exports.items],
          },
        };
      });
      setStatus(`Export request: ${next.selected.state}.`, 'exports');
      return true;
    } catch (error) {
      if (generation.current === current)
        setStatus(error instanceof Error ? error.message : 'Request unavailable.');
      return false;
    } finally {
      if (generation.current === current) setBusy(false);
    }
  }
  async function create() {
    if (!view || busy) return;
    const current = generation.current;
    setBusy(true);
    setDownload(undefined);
    setDeletion(undefined);
    setPrepareDeletion(false);
    const input = {
      actorKey: view.actorKey,
      selection: {
        streamId: stream,
        fromSequence: first,
        throughSequence: last,
        redactionProfileId: 'pc.evidence.minimized-audit.v1',
      },
      reason,
    };
    const identity = JSON.stringify(input);
    if (retry.current?.input !== identity)
      retry.current = { input: identity, key: crypto.randomUUID() };
    try {
      const result = await read<{ actorKey: string; operation: { resourceRef: string } }>(
        await fetch(endpoint, {
          method: 'POST',
          cache: 'no-store',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...input, requestKey: retry.current.key }),
        }),
      );
      if (generation.current !== current) return;
      if (result.actorKey !== view.actorKey) {
        clear();
        throw new Error('Context changed. Refresh evidence.');
      }
      if (await select(result.operation.resourceRef))
        setStatus(
          'Request created. Review its records below, then request independent approval.',
          'exports',
        );
    } catch (error) {
      if (generation.current === current)
        setStatus(
          error instanceof Error
            ? error.message
            : 'Response unavailable. Retry the unchanged request to recover it.',
        );
    } finally {
      if (generation.current === current) setBusy(false);
    }
  }
  async function retrieve() {
    if (!view || !selected || busy) return;
    const current = generation.current;
    setBusy(true);
    setDownload(undefined);
    setDeletion(undefined);
    setPrepareDeletion(false);
    try {
      const next = await read<Binding & { download: EvidenceDownload }>(
        await fetch(
          `${endpoint}?${new URLSearchParams({ exportId: resourceId(selected.selected.evidenceExportId), artifact: '1' })}`,
          { cache: 'no-store' },
        ),
      );
      if (generation.current !== current) return;
      if (next.actorKey !== view.actorKey) {
        clear();
        throw new Error('Context changed. Refresh evidence.');
      }
      setDownload(next.download);
      setStatus('The immutable redacted export is ready to download.', 'exports');
    } catch (error) {
      if (generation.current === current)
        setStatus(error instanceof Error ? error.message : 'Artifact unavailable.');
    } finally {
      if (generation.current === current) setBusy(false);
    }
  }
  function save() {
    if (!download || !selected) return;
    const url = URL.createObjectURL(
      new Blob([canonical(download.artifact)], { type: 'application/json' }),
    );
    const link = document.createElement('a');
    link.href = url;
    link.download = `evidence-${resourceId(selected.selected.evidenceExportId)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }
  const batchPlan = deletion && 'continuationState' in deletion.plan ? deletion.plan : undefined;
  return (
    <section aria-label="Evidence and exports" className="space-y-5">
      {evaluationUi ? (
        <>
          <nav aria-label="Evidence tasks" className="evidence-task-navigation">
            {(
              Object.entries(evidenceTasks) as [
                EvidenceTask,
                (typeof evidenceTasks)[EvidenceTask],
              ][]
            ).map(([key, value]) => (
              <button
                key={key}
                type="button"
                aria-pressed={task === key}
                disabled={busy}
                onClick={() => openTask(key)}
              >
                {value.label}
              </button>
            ))}
          </nav>
          <div>
            <h2 ref={taskHeading} tabIndex={-1} className="text-xl font-semibold">
              {evidenceTasks[task].label}
            </h2>
            <p className="mt-1 text-sm text-[color:var(--muted)]">
              {evidenceTasks[task].description}
            </p>
          </div>
        </>
      ) : null}
      {evaluationUi && task === 'exports' ? (
        <ol aria-label="Evidence export steps" className="workflow-steps">
          <li>
            <strong>1. Select evidence</strong>
            <span>Choose a record and the range to include.</span>
          </li>
          <li>
            <strong>2. Request and review</strong>
            <span>Explain the purpose and complete the required approvals.</span>
          </li>
          <li>
            <strong>3. Download</strong>
            <span>Retrieve the verified file after the export succeeds.</span>
          </li>
        </ol>
      ) : null}
      {!evaluationUi ? (
        <p>
          Browse evidence in the active Participant and privacy domain. Export files contain
          minimized record metadata and verifiable digests.
        </p>
      ) : null}
      <p role="status" aria-live="polite">
        {!evaluationUi || !statusTask || statusTask === task ? status : ''}
      </p>
      <button className={buttonClass} disabled={busy} onClick={() => void load()}>
        Refresh evidence
      </button>
      {view ? (
        <>
          <WorkflowDetails enabled={evaluationUi} summary="Evidence workspace details">
            <p className="break-all text-sm">
              Participant: {view.actor.participantId} · Privacy domain: {view.actor.privacyDomainId}
            </p>
          </WorkflowDetails>
          <div hidden={evaluationUi && task !== 'records'} className="space-y-5">
            <section aria-label="Evidence catalogue" className="space-y-3">
              <h2 className="text-xl font-semibold">Evidence records</h2>
              <WorkflowDetails enabled={evaluationUi} summary="Find a specific receipt">
                <form
                  className="space-y-2"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void load(recordDigest ? { recordDigest } : undefined);
                  }}
                >
                  <label htmlFor={`${formId}-record-digest`}>Find records by receipt digest</label>
                  <input
                    id={`${formId}-record-digest`}
                    className={fieldClass}
                    value={recordDigest}
                    onChange={(event) => setRecordDigest(event.target.value)}
                    pattern="sha256:[0-9a-f]{64}"
                    maxLength={71}
                  />
                  <button className={buttonClass} disabled={busy} type="submit">
                    Find evidence
                  </button>
                </form>
              </WorkflowDetails>
              {view.recordsUnavailable ? (
                <p>Evidence records are unavailable in this context.</p>
              ) : null}
              {view.records?.authorizedEmpty ? (
                <p className="workflow-empty">
                  No authorized evidence records. Run an approved workflow, then refresh to see the
                  records available to your role.
                </p>
              ) : null}
              {view.records && !view.records.authorizedEmpty ? (
                <p className="text-sm text-[color:var(--muted)]">
                  {view.records.items.length}{' '}
                  {view.records.items.length === 1 ? 'record' : 'records'} on this page
                </p>
              ) : null}
              <EvidenceCollectionPage
                key={`${view.actorKey}:${view.recordsCursor ?? ''}:${view.recordDigest ?? ''}`}
                enabled={evaluationUi}
                busy={busy}
                label="Evidence records"
                noun="records"
                navigationLabel="displayed records"
                className="space-y-2"
                entries={view.records?.items.map((record) => (
                  <li
                    key={record.evidenceId}
                    className="break-words rounded border border-[color:var(--border)] p-3"
                  >
                    <strong>
                      Sequence {record.sequence} ·{' '}
                      {evaluationUi
                        ? evidenceClassLabels[record.evidenceClass]
                        : record.evidenceClass}
                    </strong>
                    <p>
                      {evaluationUi ? (
                        <time dateTime={record.occurredAt}>{evidenceTime(record.occurredAt)}</time>
                      ) : (
                        record.occurredAt
                      )}
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <button
                        className={buttonClass}
                        disabled={busy}
                        onClick={() => void inspectProvenance(record)}
                      >
                        Read provenance for sequence {record.sequence}
                      </button>
                      <button
                        className={buttonClass}
                        disabled={busy}
                        onClick={() => void selectRecord(record)}
                      >
                        Select sequence {record.sequence} for export
                      </button>
                    </div>
                    <WorkflowDetails
                      enabled={evaluationUi}
                      summary={`Record details and retention for sequence ${record.sequence}`}
                    >
                      {evaluationUi ? (
                        <>
                          <p className="text-sm">Evidence class: {record.evidenceClass}</p>
                          <p className="text-sm">Exact event time: {record.occurredAt}</p>
                        </>
                      ) : null}
                      <p className="text-sm">Evidence reference: {record.evidenceId}</p>
                      <p className="text-sm">{record.recordDigest}</p>
                      <div className="flex flex-wrap gap-2">
                        <button
                          className={buttonClass}
                          disabled={busy}
                          onClick={() => void inspectDeletion(record.evidenceId)}
                        >
                          Check local deletion for sequence {record.sequence}
                        </button>
                        <button
                          className={buttonClass}
                          disabled={busy}
                          onClick={() =>
                            void inspectDeletion(record.evidenceId, 'evidence-deletion-batch')
                          }
                        >
                          Review deletion sequence from {record.sequence}
                        </button>
                        <button
                          className={buttonClass}
                          disabled={busy}
                          onClick={() =>
                            void inspectDeletion(record.evidenceId, 'evidence-deletion-search')
                          }
                        >
                          Review search projection deletion for sequence {record.sequence}
                        </button>
                        <button
                          className={buttonClass}
                          disabled={busy}
                          onClick={() =>
                            void inspectDeletion(record.evidenceId, 'evidence-deletion-normalized')
                          }
                        >
                          Review normalized projection deletion for sequence {record.sequence}
                        </button>
                        {record.evidenceClass === 'EFFECT' ? (
                          <button
                            className={buttonClass}
                            disabled={busy}
                            onClick={() => {
                              openTask('removal', true);
                              setFactRetirementRecord({
                                evidenceId: record.evidenceId,
                                source: 'fact',
                              });
                              setFactRetirementFields(undefined);
                              setDeletion(undefined);
                              setPrepareDeletion(false);
                              setSelected(undefined);
                            }}
                          >
                            Review Fact payload retirement for sequence {record.sequence}
                          </button>
                        ) : null}
                        {record.evidenceClass === 'EFFECT' ? (
                          <button
                            className={buttonClass}
                            disabled={busy}
                            onClick={() => {
                              openTask('removal', true);
                              setFactRetirementRecord({
                                evidenceId: record.evidenceId,
                                source: 'candidate',
                              });
                              setFactRetirementFields(undefined);
                              setDeletion(undefined);
                              setPrepareDeletion(false);
                              setSelected(undefined);
                            }}
                          >
                            Review candidate payload retirement for sequence {record.sequence}
                          </button>
                        ) : null}
                      </div>
                    </WorkflowDetails>
                  </li>
                ))}
              />
              {view.recordsCursor || view.records?.nextCursor ? (
                <nav aria-label="Evidence records pagination" className="flex flex-wrap gap-2">
                  {view.recordsCursor ? (
                    <button
                      className={buttonClass}
                      disabled={busy}
                      onClick={() =>
                        void load(
                          view.recordDigest ? { recordDigest: view.recordDigest } : undefined,
                        )
                      }
                    >
                      First records
                    </button>
                  ) : null}
                  {view.records?.nextCursor ? (
                    <button
                      className={buttonClass}
                      disabled={busy}
                      onClick={() =>
                        void load({
                          recordsCursor: view.records!.nextCursor!,
                          ...(view.recordDigest ? { recordDigest: view.recordDigest } : {}),
                        })
                      }
                    >
                      Next records
                    </button>
                  ) : null}
                </nav>
              ) : null}
            </section>
            {provenance ? <EvidenceProvenancePanel value={provenance} /> : null}
            {provenance?.status === 'VERIFIED_BUSINESS_TRANSITION' ? (
              <EvidenceOperationCorrelation
                evidenceId={provenance.evidenceId}
                actorKey={view.actorKey}
              />
            ) : null}
          </div>
          <div hidden={evaluationUi && task !== 'exports'} className="space-y-5">
            {evaluationUi && !stream ? (
              <div className="workflow-empty">
                <p>Choose an evidence record to fill its source and range.</p>
                <button
                  type="button"
                  className={buttonClass}
                  disabled={busy}
                  onClick={() => openTask('records', true)}
                >
                  Choose evidence records
                </button>
              </div>
            ) : null}
            <WorkflowDetails
              enabled={evaluationUi && !guidedSource}
              expanded={!!stream}
              summary="Enter an evidence range manually"
            >
              <form
                className="space-y-3 rounded border border-[color:var(--border)] p-4"
                onSubmit={(event) => {
                  event.preventDefault();
                  void create();
                }}
              >
                <h2 className="text-xl font-semibold">
                  {evaluationUi ? 'Prepare evidence export' : 'Select records for export'}
                </h2>
                <p>
                  {evaluationUi && guidedSource
                    ? 'The evidence source comes from your selected record. Review the range and explain the purpose.'
                    : evaluationUi
                      ? 'Enter a known evidence source and range, or choose a record in Records.'
                      : 'Select a record above to fill its stream and sequence, then adjust the range if needed.'}
                </p>
                <fieldset disabled={busy} className="grid gap-3 sm:grid-cols-2">
                  <div className={evaluationUi ? 'sm:col-span-2' : undefined}>
                    <WorkflowDetails
                      enabled={evaluationUi && guidedSource}
                      summary="Evidence source details"
                    >
                      <label htmlFor={`${formId}-stream`}>
                        Evidence stream
                        <input
                          id={`${formId}-stream`}
                          className={fieldClass}
                          required
                          readOnly={evaluationUi && guidedSource}
                          maxLength={160}
                          value={stream}
                          onChange={(event) => setStream(event.target.value)}
                        />
                      </label>
                    </WorkflowDetails>
                  </div>
                  <label htmlFor={`${formId}-from`}>
                    First sequence
                    <input
                      id={`${formId}-from`}
                      className={fieldClass}
                      required
                      inputMode="numeric"
                      pattern="[1-9][0-9]*"
                      value={first}
                      onChange={(event) => setFirst(event.target.value)}
                    />
                  </label>
                  <label htmlFor={`${formId}-through`}>
                    Last sequence
                    <input
                      id={`${formId}-through`}
                      className={fieldClass}
                      required
                      inputMode="numeric"
                      pattern="[1-9][0-9]*"
                      value={last}
                      onChange={(event) => setLast(event.target.value)}
                    />
                  </label>
                  <label
                    htmlFor={`${formId}-reason`}
                    className={evaluationUi ? 'sm:col-span-2' : undefined}
                  >
                    Purpose
                    <input
                      id={`${formId}-reason`}
                      className={fieldClass}
                      required
                      maxLength={1024}
                      value={reason}
                      onChange={(event) => setReason(event.target.value)}
                    />
                  </label>
                </fieldset>
                <p className="text-sm">
                  Choose up to 128 consecutive records. The export includes a fixed set of records
                  once requested.
                </p>
                <button className={buttonClass} disabled={busy} type="submit">
                  Create export request
                </button>
              </form>
            </WorkflowDetails>
            <section aria-label="Export requests" className="space-y-3">
              <h2 className="text-xl font-semibold">Export requests</h2>
              {view.exportsUnavailable ? (
                <p>Export requests are unavailable in this context.</p>
              ) : null}
              {view.exports?.authorizedEmpty ? (
                <p className="workflow-empty">
                  No authorized export requests. Select evidence and provide a purpose to create
                  one.
                </p>
              ) : null}
              <ul className="space-y-2">
                {view.exports?.items.map((item) => (
                  <li
                    key={item.evidenceExportId}
                    className="break-all rounded border border-[color:var(--border)] p-3"
                  >
                    {evaluationUi ? (
                      <>
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <h3 className="font-semibold">Evidence export</h3>
                          <span className="workflow-state-badge" data-state={item.state}>
                            {exportStateLabels[item.state]}
                          </span>
                        </div>
                        <p className="my-2 text-sm text-[color:var(--muted)]">
                          Requested{' '}
                          <time dateTime={item.createdAt}>{evidenceTime(item.createdAt)}</time>
                        </p>
                        <WorkflowDetails enabled summary="Export reference">
                          <p className="text-sm">{item.evidenceExportId}</p>
                          <p className="text-sm">
                            Status: {item.state} · Revision {item.revision}
                          </p>
                        </WorkflowDetails>
                      </>
                    ) : (
                      <>
                        <p>
                          {item.state} · Revision {item.revision}
                        </p>
                        <p className="text-sm">{item.evidenceExportId}</p>
                      </>
                    )}
                    <button
                      className={buttonClass}
                      aria-label={`Review export ${resourceId(item.evidenceExportId)}`}
                      disabled={busy}
                      onClick={() => void select(item.evidenceExportId)}
                    >
                      {evaluationUi
                        ? 'Review export'
                        : `Review export ${resourceId(item.evidenceExportId)}`}
                    </button>
                  </li>
                ))}
              </ul>
              {view.exports?.nextCursor ? (
                <button
                  className={buttonClass}
                  disabled={busy}
                  onClick={() => void load({ exportsCursor: view.exports!.nextCursor! })}
                >
                  Next exports
                </button>
              ) : null}
            </section>
          </div>
        </>
      ) : (
        <div className="workspace-evidence-guidance">
          <p>Refresh evidence to load the records available in this workspace.</p>
          {!showSessionControls && (
            <p>
              Manage sign-in and workspace access in{' '}
              <Link href="/home/session">Account & workspace</Link>.
            </p>
          )}
        </div>
      )}
      <div hidden={evaluationUi && task !== 'retention'} className="space-y-5">
        {view ? (
          <section
            aria-label="Preservation holds"
            className="space-y-3 rounded border border-[color:var(--border)] p-4"
          >
            <h2 className="text-xl font-semibold">Preservation holds</h2>
            <p>
              Active rules preserve existing and future matches. Verified coverage records the sink
              acknowledgement; release requires a separate approved request.
            </p>
            {view.holdsUnavailable ? <p>Holds are unavailable for this context.</p> : null}
            {view.holds?.items.length === 0 ? <p>No preservation holds.</p> : null}
            {view.holds?.items.length ? (
              <p className="text-sm">
                Active holds on this page:{' '}
                {view.holds.items.filter((hold) => hold.state === 'ACTIVE').length}. Active holds
                block deletion even while coverage is pending.
              </p>
            ) : null}
            <WorkflowDetails
              enabled={evaluationUi && !!view.holds?.items.length}
              summary="Review preservation holds"
            >
              <ul className="space-y-3">
                {view.holds?.items.map((hold) => (
                  <li key={hold.holdId} className="space-y-1 break-words">
                    <p>
                      {hold.holdKind} · {hold.state} · Revision {hold.revision} · Sink coverage{' '}
                      {hold.coverage}
                    </p>
                    <p>{describeHold(hold.selector)}</p>
                    <WorkflowDetails enabled summary="Hold audit details">
                      <p className="break-all text-sm">Hold reference: {hold.holdId}</p>
                      <p className="break-all text-sm">Selector digest: {hold.selectorDigest}</p>
                      {hold.coveragePrivacyDomainId ? (
                        <p className="break-all text-sm">
                          Coverage for privacy domain: {hold.coveragePrivacyDomainId}
                        </p>
                      ) : null}
                      {hold.selector.type === 'PARTICIPANT' ? (
                        <p className="break-all text-sm">
                          Governed in root privacy domain: {hold.governancePrivacyDomainId}. Other
                          domains require their own coverage readback.
                        </p>
                      ) : null}
                      <p className="break-all text-sm">
                        Creation receipt:{' '}
                        {hold.creationReceiptDigest ??
                          'Signed receipt reference unavailable in this context'}
                      </p>
                      {hold.state === 'RELEASED' ? (
                        <p className="break-all text-sm">
                          Release receipt:{' '}
                          {hold.releaseReceiptDigest ??
                            'Signed receipt reference unavailable in this context'}
                        </p>
                      ) : null}
                    </WorkflowDetails>
                  </li>
                ))}
              </ul>
              {view.holds?.nextCursor ? (
                <button
                  className={buttonClass}
                  disabled={busy}
                  onClick={() => void load({ holdsCursor: view.holds!.nextCursor! })}
                >
                  Next holds
                </button>
              ) : null}
            </WorkflowDetails>
          </section>
        ) : null}
        {view ? (
          <section
            aria-label="Retention policies"
            className="space-y-3 rounded border border-[color:var(--border)] p-4"
          >
            <h2 className="text-xl font-semibold">Retention policies</h2>
            <p>
              Each data class needs its own active policy. A missing or retired policy cannot
              authorize deletion; activation does not delete data.
            </p>
            {view.retentionPoliciesUnavailable ? (
              <p>Retention policies are unavailable for this context.</p>
            ) : null}
            {view.retentionPolicies?.items.length === 0 ? (
              <p>No retention policy versions.</p>
            ) : null}
            <WorkflowDetails
              enabled={evaluationUi && !!view.retentionPolicies?.items.length}
              summary="Review retention policies"
            >
              <ul className="space-y-3">
                {view.retentionPolicies?.items.map((policy) => (
                  <li
                    key={policy.retentionPolicyId}
                    className="min-w-0 space-y-3 rounded border border-[color:var(--border)] p-3"
                  >
                    <div className="flex flex-wrap items-baseline justify-between gap-2">
                      <h3 className="font-semibold">{dataClassLabel(policy.dataClass)}</h3>
                      <p className="text-sm">
                        {policy.state === 'ACTIVE' ? 'Active' : 'Retired'} · Version{' '}
                        {policy.policyVersion}
                      </p>
                    </div>
                    <p className="text-sm">
                      Retention: {retentionDuration(policy.retentionPeriodMs)} · Local grace:{' '}
                      {retentionDuration(policy.localGraceMs)}
                    </p>
                    <p className="text-sm">
                      Independent deletion approval:{' '}
                      {policy.makerCheckerRequired ? 'Required' : 'Not required by this policy'}
                    </p>
                    <WorkflowDetails enabled summary="Policy audit details">
                      <p className="break-all text-sm">
                        Policy reference: {policy.retentionPolicyId}
                      </p>
                      <p>
                        Retention: {policy.retentionPeriodMs} ms · Local grace:{' '}
                        {policy.localGraceMs} ms
                      </p>
                      <p>
                        Durable sink acknowledgements: {policy.sinkQuorum} · {policy.deletionMode}
                      </p>
                      <p className="break-all text-sm">
                        Active from {policy.activeFrom}
                        {policy.activeUntil ? ` until ${policy.activeUntil}` : ''}
                      </p>
                      {policy.predecessorPolicyId ? (
                        <p className="break-all text-sm">
                          Previous version: {policy.predecessorPolicyId}
                        </p>
                      ) : null}
                      <p className="break-all text-sm">Policy digest: {policy.policyDigest}</p>
                      <p className="break-all text-sm">
                        Activation receipt: {policy.activationReceiptDigest}
                      </p>
                      {policy.retirementReceiptDigest ? (
                        <p className="break-all text-sm">
                          Retirement receipt: {policy.retirementReceiptDigest}
                        </p>
                      ) : null}
                    </WorkflowDetails>
                  </li>
                ))}
              </ul>
              {view.retentionPolicies?.nextCursor ? (
                <button
                  className={buttonClass}
                  disabled={busy}
                  onClick={() =>
                    void load({ retentionCursor: view.retentionPolicies!.nextCursor! })
                  }
                >
                  Next retention policies
                </button>
              ) : null}
            </WorkflowDetails>
          </section>
        ) : null}
      </div>
      <div hidden={evaluationUi && task !== 'removal'} className="space-y-5">
        <WorkflowDetails enabled={evaluationUi} summary="Remove a protected source proof">
          {view ? (
            <section
              aria-label="Protected proof deletion"
              className="space-y-3 rounded border border-[color:var(--border)] p-4"
            >
              <h2 className="text-xl font-semibold">Protected proof deletion</h2>
              <p>
                Review the encrypted local copy using its retained object reference. Raw-source
                retention, exact archive checkpoints, source verification, holds and live access
                references are checked before each deletion.
              </p>
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  void inspectDeletion(rawObjectRef, 'evidence-deletion-raw');
                }}
              >
                <label htmlFor={`${formId}-raw-object`}>Retained protected object reference</label>
                <input
                  id={`${formId}-raw-object`}
                  className={fieldClass}
                  required
                  pattern="urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
                  value={rawObjectRef}
                  onChange={(event) => {
                    generation.current++;
                    pending.current?.abort();
                    setBusy(false);
                    setRawObjectRef(event.target.value);
                    setDeletion(undefined);
                    setPrepareDeletion(false);
                  }}
                />
                <button className={`${buttonClass} mt-2`} disabled={busy}>
                  Check protected proof deletion
                </button>
              </form>
            </section>
          ) : null}
        </WorkflowDetails>
        {deletion ? (
          <section
            aria-label="Local deletion eligibility"
            className="space-y-3 rounded border border-[color:var(--border)] p-4"
          >
            <h2 className="text-xl font-semibold">Local deletion eligibility</h2>
            <p>
              {'projectionState' in deletion.plan
                ? `Projection: ${deletion.plan.projectionState}. `
                : `Local ciphertext: ${deletion.plan.localPayload}. `}
              {deletion.plan.eligible
                ? 'Eligible for approval.'
                : 'continuationState' in deletion.plan &&
                    deletion.plan.continuationState === 'COMPLETE'
                  ? 'Selection complete.'
                  : 'continuationState' in deletion.plan &&
                      deletion.plan.continuationState === 'ADVANCED'
                    ? 'Cursor already advanced.'
                    : 'Deletion blocked.'}
            </p>
            <p>
              {'projectionState' in deletion.plan
                ? 'This request retires one derived projection and prevents custody recovery from recreating it. Original evidence and the minimum preservation references keep their separate lifetimes.'
                : 'This request covers one complete ciphertext object. Source records, custody metadata and other stored copies keep their separate lifetimes.'}
            </p>
            <WorkflowDetails enabled summary="Selection and archive details">
              <p className="break-all text-sm">
                Evidence reference:{' '}
                {'objectRef' in deletion.plan ? deletion.plan.objectRef : deletion.plan.evidenceId}
              </p>
              {deletion.plan.selection ? (
                <>
                  {'objectRef' in deletion.plan.selection ? (
                    <p className="break-all">
                      RAW_SOURCE_BODY · Object {deletion.plan.selection.objectRef} · Version{' '}
                      {deletion.plan.selection.objectVersion} ·{' '}
                      {deletion.plan.selection.ciphertextBytes} bytes.
                    </p>
                  ) : 'projectionDigest' in deletion.plan.selection ? (
                    <p className="break-all">
                      {deletion.plan.selection.dataClass} · {deletion.plan.selection.streamId}:
                      sequence {deletion.plan.selection.sequence};{' '}
                      {deletion.plan.selection.projectionBytes} projection bytes.
                    </p>
                  ) : (
                    <p>
                      {deletion.plan.selection.streamId}: sequences{' '}
                      {deletion.plan.selection.firstSequence}–
                      {deletion.plan.selection.throughSequence};{' '}
                      {deletion.plan.selection.recordCount} records;{' '}
                      {deletion.plan.selection.ciphertextBytes} bytes.
                    </p>
                  )}
                  <p className="break-all text-sm">
                    Policy: {deletion.plan.selection.retentionPolicyId}
                  </p>
                  <p>
                    Bound archive acknowledgements: {deletion.plan.selection.sinkReceipts.length}
                  </p>
                  {'rpcClosure' in deletion.plan.selection && deletion.plan.selection.rpcClosure ? (
                    <p className="break-all">
                      RPC completion witness: {deletion.plan.selection.rpcClosure.terminalPhase},
                      sequence {deletion.plan.selection.rpcClosure.terminalSequence}.{' '}
                      {deletion.plan.selection.rpcClosure.archive.sinkReceipts.length} bound archive
                      acknowledgements. Read completion does not establish transaction finality.
                    </p>
                  ) : null}
                  {'sourceRejections' in deletion.plan.selection &&
                  deletion.plan.selection.sourceRejections ? (
                    <p>
                      Verified rejection sources: {deletion.plan.selection.sourceRejections.length}.
                      These commands were rejected before runtime handoff. Their original signed
                      receipts remain preserved.
                    </p>
                  ) : null}
                </>
              ) : null}
            </WorkflowDetails>
            {batchPlan ? (
              <div className="space-y-2" aria-label="Signed deletion progress">
                <p>Continuation: {batchPlan.continuationState}.</p>
                {batchPlan.selection ? (
                  <>
                    <p>
                      Object {batchPlan.selection.batchIndex + 1} of{' '}
                      {batchPlan.selection.targets.length}. Each object requires its own approval
                      and fresh authentication.
                    </p>
                    <WorkflowDetails enabled summary="Objects in this signed batch">
                      <ol className="list-inside list-decimal space-y-1">
                        {batchPlan.selection.targets.map((target, index) => (
                          <li
                            key={
                              'objectRef' in target
                                ? target.objectRef
                                : 'recordId' in target
                                  ? target.recordId
                                  : target.segmentId
                            }
                            className="break-all"
                          >
                            {index < batchPlan.selection!.batchIndex
                              ? 'Committed'
                              : index === batchPlan.selection!.batchIndex
                                ? 'Next'
                                : 'Remaining'}
                            :{' '}
                            {'objectRef' in target
                              ? `Protected proof ${target.objectRef}, version ${target.objectVersion}, ${target.ciphertextBytes} bytes.`
                              : 'recordId' in target
                                ? `${target.projectionBytes} projection bytes, evidence ${target.evidenceId}.`
                                : `${target.recordCount} records, ${target.ciphertextBytes} bytes, sequences ${target.firstSequence}–${target.throughSequence}.`}
                          </li>
                        ))}
                      </ol>
                      {batchPlan.selection.priorCursor ? (
                        <p className="break-all text-sm">
                          Previous signed receipt: {batchPlan.selection.priorCursor.receiptDigest}
                        </p>
                      ) : null}
                    </WorkflowDetails>
                  </>
                ) : null}
                {batchPlan.nextDeletionJobId ? (
                  <button
                    className={buttonClass}
                    disabled={busy}
                    onClick={() =>
                      void inspectDeletion(
                        batchPlan.nextDeletionJobId!,
                        deletion.kind.startsWith('evidence-deletion-raw')
                          ? 'evidence-deletion-raw-continuation'
                          : 'projectionState' in deletion.plan
                            ? 'evidence-deletion-projection-continuation'
                            : 'evidence-deletion-continuation',
                      )
                    }
                  >
                    Follow committed continuation
                  </button>
                ) : null}
              </div>
            ) : null}
            <ul className="list-inside list-disc">
              {deletion.plan.blockers.map((blocker) => (
                <li key={blocker}>{deletionBlockers[blocker]}</li>
              ))}
            </ul>
            <button
              className={buttonClass}
              disabled={busy}
              onClick={() => void inspectDeletion(deletion.reference, deletion.kind)}
            >
              Refresh deletion eligibility
            </button>
            {deletion.plan.eligible ? (
              <button
                className={`${buttonClass} ml-2`}
                disabled={busy}
                onClick={() => setPrepareDeletion(true)}
              >
                {deletion.kind === 'evidence-deletion'
                  ? 'Prepare local deletion'
                  : deletion.kind === 'evidence-deletion-batch' ||
                      deletion.kind === 'evidence-deletion-raw' ||
                      deletion.kind === 'evidence-deletion-search' ||
                      deletion.kind === 'evidence-deletion-normalized'
                    ? 'Prepare first deletion batch'
                    : 'Prepare next deletion batch'}
              </button>
            ) : null}
          </section>
        ) : null}
        {view ? (
          <section
            aria-label="Local deletion results"
            className="space-y-3 rounded border border-[color:var(--border)] p-4"
          >
            <h2 className="text-xl font-semibold">Local deletion results</h2>
            {view.deletionsUnavailable ? (
              <p>Local deletion results are unavailable for this context.</p>
            ) : null}
            {view.deletions?.items.length === 0 ? <p>No local deletion results.</p> : null}
            <EvidenceCollectionPage
              key={view.actorKey}
              enabled={evaluationUi}
              busy={busy}
              label="Deletion results"
              noun="results"
              navigationLabel="results"
              className="grid items-start gap-3 xl:grid-cols-2"
              entries={view.deletions?.items.map((item) => (
                <li
                  key={item.deletionJobId}
                  className="min-w-0 space-y-3 rounded border border-[color:var(--border)] p-3"
                >
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <h3 className="font-semibold">{deletionTitle(item.selection)}</h3>
                    <p className="text-sm">
                      {item.state === 'SUCCEEDED' ? 'Completed' : item.state}
                    </p>
                  </div>
                  <p className="text-sm">
                    {item.deletedCount} local{' '}
                    {String(item.deletedCount) === '1' ? 'object' : 'objects'} removed ·{' '}
                    {item.deletedBytes} bytes
                  </p>
                  {'batchIndex' in item.selection ? (
                    <p className="text-sm">
                      Batch {item.selection.batchIndex + 1} of {item.selection.targets.length}{' '}
                      committed.
                    </p>
                  ) : null}
                  <div className="flex flex-wrap gap-2">
                    {item.selection.version !== 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1' ? (
                      <button
                        className={buttonClass}
                        disabled={busy}
                        onClick={() => {
                          const selection = item.selection;
                          if (selection.version === 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1')
                            return;
                          void (selection.version === 'OPENPC_RAW_PROOF_DELETION_BATCH_V1'
                            ? inspectDeletion(selection.objectRef, 'evidence-deletion-raw')
                            : selection.version === 'OPENPC_PROJECTION_DELETION_BATCH_V1'
                              ? inspectDeletion(
                                  selection.evidenceId,
                                  selection.dataClass === 'SEARCH_PROJECTION'
                                    ? 'evidence-deletion-search'
                                    : 'evidence-deletion-normalized',
                                )
                              : inspectDeletion(selection.evidenceId));
                        }}
                      >
                        {item.selection.version === 'OPENPC_PROJECTION_DELETION_BATCH_V1'
                          ? 'Read projection retirement status'
                          : 'Read local payload status'}
                      </button>
                    ) : null}
                    {'batchIndex' in item.selection ? (
                      <button
                        className={buttonClass}
                        disabled={busy}
                        onClick={() =>
                          void inspectDeletion(
                            item.deletionJobId,
                            item.selection.version === 'OPENPC_RAW_PROOF_DELETION_BATCH_V1'
                              ? 'evidence-deletion-raw-continuation'
                              : item.selection.version === 'OPENPC_PROJECTION_DELETION_BATCH_V1'
                                ? 'evidence-deletion-projection-continuation'
                                : 'evidence-deletion-continuation',
                          )
                        }
                      >
                        Read signed continuation
                      </button>
                    ) : null}
                  </div>
                  <WorkflowDetails enabled summary="Deletion audit details">
                    <p className="break-all text-sm">Deletion reference: {item.deletionJobId}</p>
                    {item.selection.version === 'OPENPC_RAW_PROOF_DELETION_BATCH_V1' ? (
                      <p className="break-all text-sm">
                        Protected proof: {item.selection.objectRef} · Version{' '}
                        {item.selection.objectVersion}
                      </p>
                    ) : item.selection.version === 'OPENPC_PROJECTION_DELETION_BATCH_V1' ? (
                      <p className="break-all text-sm">
                        {item.selection.dataClass} · {item.selection.streamId}: sequence{' '}
                        {item.selection.sequence} · Projection retired
                      </p>
                    ) : item.selection.version === 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1' ? (
                      <p className="break-all text-sm">
                        Runtime artifact retired · Input{' '}
                        {item.selection.source.runtimeConfigurationInputId}
                        {' · '}
                        {item.selection.source.configurationDigest}
                      </p>
                    ) : (
                      <p className="break-all text-sm">Stream: {item.selection.streamId}</p>
                    )}
                    <p className="break-all text-sm">Before: {item.beforeDigest}</p>
                    <p className="break-all text-sm">After: {item.afterDigest}</p>
                    <p className="break-all text-sm">Signed receipt: {item.receiptDigest}</p>
                  </WorkflowDetails>
                </li>
              ))}
            />
            {view.deletions?.nextCursor ? (
              <button
                className={buttonClass}
                disabled={busy}
                onClick={() => void load({ deletionsCursor: view.deletions!.nextCursor! })}
              >
                Next local deletions
              </button>
            ) : null}
          </section>
        ) : null}
      </div>
      <div hidden={evaluationUi && task !== 'exports'}>
        {selected ? (
          <section
            aria-label="Selected export"
            className="space-y-3 rounded border border-[color:var(--border)] p-4"
          >
            <h2 className="text-xl font-semibold">Selected export</h2>
            <p>
              {selected.selected.state} · Checkpoint {selected.selected.checkpoint}
            </p>
            <p className="break-all">{selected.selected.evidenceExportId}</p>
            <p>
              {selected.selection.range.streamId}: sequences {selected.selection.range.fromSequence}
              –{selected.selection.range.throughSequence}; {selected.selection.records.length}{' '}
              records.
            </p>
            <p className="break-all text-sm">Request digest: {selected.selected.requestDigest}</p>
            <button
              className={buttonClass}
              disabled={busy}
              onClick={() => void select(selected.selected.evidenceExportId)}
            >
              Read current export status
            </button>
            {selected.selected.state === 'SUCCEEDED' ? (
              <button className={buttonClass} disabled={busy} onClick={() => void retrieve()}>
                Retrieve verified export
              </button>
            ) : null}
            {download ? (
              <div className="space-y-2">
                <p className="break-all text-sm">SHA-256: {download.outputDigest}</p>
                <button className={buttonClass} onClick={save}>
                  Download export JSON
                </button>
              </div>
            ) : null}
          </section>
        ) : null}
      </div>
      <div hidden={evaluationUi && task !== 'removal'}>
        {view && factRetirementRecord ? (
          <FactRetirementPreparation
            key={`${view.actorKey}:${factRetirementRecord.source}:${factRetirementRecord.evidenceId}`}
            binding={view}
            evidenceId={factRetirementRecord.evidenceId}
            source={factRetirementRecord.source}
            policies={view.retentionPolicies ?? null}
            onPrepare={setFactRetirementFields}
          />
        ) : null}
      </div>
      <div hidden={evaluationUi && task !== 'proofs'}>
        <ProtectedProofWorkflow
          guided={evaluationUi}
          active={!evaluationUi || (!!view && !busy && task === 'proofs')}
          binding={evaluationUi ? view : undefined}
          onPrepareAccess={(ref) => {
            if (!view || busy) return;
            setSelected(undefined);
            setDeletion(undefined);
            setPrepareDeletion(false);
            setFactRetirementFields(undefined);
            setFactRetirementRecord(undefined);
            setProofAccessObjectRef(ref);
            openTask('proofs');
          }}
        />
      </div>
      <fieldset
        hidden={
          evaluationUi &&
          task !== 'recovery' &&
          !(task === 'exports' && !!selected) &&
          !(task === 'proofs' && !!proofAccessObjectRef) &&
          !(task === 'removal' && (prepareDeletion || !!factRetirementFields))
        }
        aria-label="Evidence request controls"
        aria-busy={busy}
        disabled={busy}
        className="min-w-0 border-0 p-0"
      >
        <WorkflowDetails
          preserveChildren
          enabled={evaluationUi && task !== 'recovery'}
          summary="Review an export or recover a request"
          expanded={
            !!selected || prepareDeletion || !!factRetirementFields || !!proofAccessObjectRef
          }
        >
          <TransactionWorkflow
            showSessionControls={showSessionControls}
            key={`${view?.actorKey ?? 'unbound'}:${proofAccessObjectRef ? `proof:${proofAccessObjectRef}` : factRetirementFields ? JSON.stringify(factRetirementFields) : prepareDeletion && deletion ? `${deletion.kind}:${deletion.reference}` : (selected?.selected.evidenceExportId ?? 'review')}`}
            initialKind={
              proofAccessObjectRef
                ? 'protected-proof-access'
                : factRetirementFields
                  ? factRetirementRecord?.source === 'candidate'
                    ? 'evidence-deletion-candidate'
                    : 'evidence-deletion-fact'
                  : prepareDeletion && deletion
                    ? deletion.kind
                    : undefined
            }
            mode="evidence"
            guidedRecovery={evaluationUi}
            showApprovalCatalogue={evaluationUi && task === 'recovery'}
            initialFields={
              (proofAccessObjectRef ? { objectRef: proofAccessObjectRef } : undefined) ??
              factRetirementFields ??
              (prepareDeletion && deletion
                ? deletion.kind.endsWith('-continuation')
                  ? { deletionJobId: deletion.reference }
                  : deletion.kind === 'evidence-deletion-raw'
                    ? { objectRef: deletion.reference }
                    : { evidenceId: deletion.reference }
                : selected
                  ? {
                      targetRef: selected.selected.evidenceExportId,
                      expectedRevision: selected.selected.revision,
                      inputDigest: selected.selected.requestDigest,
                    }
                  : undefined)
            }
          />
        </WorkflowDetails>
      </fieldset>
    </section>
  );
}

function describeHold(selector: EvidenceHoldsPage['items'][number]['selector']): string {
  switch (selector.type) {
    case 'PARTICIPANT':
      return 'Existing and future evidence across this Participant';
    case 'PRIVACY_DOMAIN':
      return 'Every record in this privacy domain';
    case 'SEQUENCE_RANGE':
      return `${selector.streamId}: sequences ${selector.fromSequence}–${selector.throughSequence ?? 'all future records'}`;
    case 'DIGEST':
      return `Receipt ${selector.recordDigest}`;
    case 'PROJECTION':
      return `Projection ${selector.projectionId}`;
    case 'FACT_TYPE_KEY':
      return `${selector.factType} · ${selector.factProfileId} · ${selector.factKeyDigest ?? 'all keys'}`;
    case 'BLOCK_RANGE':
      return `Chain ${selector.chainId} · genesis ${selector.genesisDigest} · blocks ${selector.fromBlock}–${selector.throughBlock ?? 'all future blocks'}`;
    case 'GENERATION':
      return selector.generation.kind === 'RUNTIME_CONFIGURATION'
        ? `Runtime generation ${selector.generation.generationId}`
        : `Fact profile ${selector.generation.factProfileId} · canonical generation ${selector.generation.canonicalGeneration}`;
  }
}
