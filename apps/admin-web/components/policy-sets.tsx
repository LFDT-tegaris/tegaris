'use client';

import { useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { SecondaryPanel } from './secondary-panel';
import {
  policySetDraftStorageKey as storageKey,
  policyWorkflowPrivacyRevision,
  readBoundPolicyState,
  writeBoundPolicyState,
  type PolicyWorkflowActorBinding,
} from './policy-workflow-storage';

const policySetSchema = z
  .object({
    policySetId: z
      .string()
      .regex(
        /^urn:openpc:policy-set:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      ),
    participantId: z.string(),
    name: z.string().min(1).max(160),
    state: z.enum(['DRAFT', 'ACTIVE', 'RETIRED']),
    activeVersionDigest: z
      .string()
      .regex(/^sha256:[0-9a-f]{64}$/u)
      .nullable(),
    revision: z.string().regex(/^[1-9][0-9]*$/u),
  })
  .passthrough();
const policySetPageSchema = z
  .object({
    items: z.array(policySetSchema),
    nextCursor: z
      .string()
      .max(2048)
      .regex(/^pc2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u)
      .nullable(),
    total: z
      .string()
      .regex(/^(?:0|[1-9][0-9]{0,19})$/u)
      .nullable(),
    completeness: z.enum(['COMPLETE', 'UNKNOWN']),
    authorizedEmpty: z.boolean(),
    snapshotRevision: z.string().regex(/^(?:0|[1-9][0-9]{0,19})$/u),
  })
  .passthrough();
type PolicySet = z.infer<typeof policySetSchema>;
const loadedStatus = 'Policy sets loaded.';
const emptyStatus = 'No policy sets are available in this workspace.';
const emptyPageStatus = 'This page has no policy sets. More results may be available.';
// This is a validated display projection; the public owner still authorizes commands.
export interface PolicySetReadValidity {
  readonly actor: PolicyWorkflowActorBinding;
  readonly policySetId: string | null;
}
interface DraftState {
  name: string;
  reason: string;
  requestKey: string;
  selected: string;
}
const valid = (value: unknown): value is DraftState =>
  !!value &&
  typeof value === 'object' &&
  ['name', 'reason', 'requestKey', 'selected'].every(
    (key) => typeof (value as Record<string, unknown>)[key] === 'string',
  );

export function PolicySets({
  actor,
  selected,
  onSelect,
  onReadValidityChange,
  showCreation = true,
}: {
  actor: PolicyWorkflowActorBinding;
  selected: string;
  showCreation?: boolean;
  onSelect: (id: string) => void;
  onReadValidityChange?: (value: PolicySetReadValidity) => void;
}) {
  const [items, setItems] = useState<PolicySet[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [draft, setDraft] = useState<DraftState>({
    name: '',
    reason: '',
    requestKey: '',
    selected: '',
  });
  const [status, setStatus] = useState('Loading policy sets.');
  const [readError, setReadError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [creatorOpen, setCreatorOpen] = useState(false);
  const epoch = useRef(0);
  const privacyEpoch = useRef(policyWorkflowPrivacyRevision());
  const privacyCurrent = () => privacyEpoch.current === policyWorkflowPrivacyRevision();
  const readGeneration = useRef(0);
  const mutationEpoch = useRef<number | undefined>(undefined);
  const selectionRevision = useRef(0);
  const draftRef = useRef(draft);
  const [projectionActor, setProjectionActor] = useState(actor);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;
  const selectedRef = useRef(selected);
  selectedRef.current = selected;
  const readValidityRef = useRef(onReadValidityChange);
  readValidityRef.current = onReadValidityChange;
  const readValidity = (policySetId: string | null) =>
    readValidityRef.current?.({ actor, policySetId });
  const resource = (value: unknown, expected?: string) => {
    const result = policySetSchema.parse(value);
    if (
      result.participantId !== `urn:openpc:participant:${actor.participantId}` ||
      (expected !== undefined && result.policySetId !== expected)
    )
      throw new Error();
    return result;
  };
  const pageResult = (value: unknown) => {
    const page = policySetPageSchema.parse(value);
    page.items.forEach((item) => resource(item));
    return page;
  };
  async function readPage(nextCursor?: string, restoredTarget?: string) {
    // GET generations never invalidate the epoch of an original POST attempt.
    if (!privacyCurrent() || mutationEpoch.current === epoch.current) return;
    const current = epoch.current;
    const generation = ++readGeneration.current;
    const selectedBeforeRead = selectedRef.current;
    const selectionBeforeRead = selectionRevision.current;
    const target = restoredTarget ?? (selectedBeforeRead || draftRef.current.selected);
    const previousItems = nextCursor ? items : [];
    const preserveSelectedProjection =
      restoredTarget === undefined &&
      !readError &&
      (
        ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const
      ).every((field) => projectionActor[field] === actor[field]) &&
      items.some((item) => item.policySetId === selectedBeforeRead);
    const owned = () =>
      privacyCurrent() && current === epoch.current && generation === readGeneration.current;
    const unchanged = () =>
      owned() &&
      selectedRef.current === selectedBeforeRead &&
      selectionRevision.current === selectionBeforeRead;
    setReadError(false);
    setBusy(!!nextCursor);
    if (!nextCursor) {
      if (!preserveSelectedProjection) {
        readValidity(null);
        setItems([]);
        setCursor(null);
      }
      setStatus('Loading policy sets.');
    }
    try {
      const url = nextCursor
        ? `/api/v1/ui/policy-sets?cursor=${encodeURIComponent(nextCursor)}`
        : '/api/v1/ui/policy-sets';
      const response = await fetch(url, { cache: 'no-store' });
      if (!unchanged()) return;
      if (!response.ok) throw new Error();
      const value: unknown = await response.json();
      if (!unchanged()) return;
      const page = pageResult(value);
      const values = [
        ...previousItems,
        ...page.items.filter(
          (item) => !previousItems.some((previous) => previous.policySetId === item.policySetId),
        ),
      ];
      setProjectionActor(actor);
      setItems(values);
      setCursor(page.nextCursor);
      setStatus(
        values.length || target
          ? loadedStatus
          : page.authorizedEmpty && page.completeness === 'COMPLETE' && !page.nextCursor
            ? emptyStatus
            : emptyPageStatus,
      );
      // Absence from one page is not a denial of the previously validated selection.
      if (!target || values.some((item) => item.policySetId === target)) readValidity(target || '');
      else if (!preserveSelectedProjection) readValidity(null);
      if (target) {
        policySetSchema.shape.policySetId.parse(target);
        if (!unchanged()) return;
        const detail = await fetch(
          `/api/v1/ui/policy-sets?policySetId=${encodeURIComponent(target)}`,
          { cache: 'no-store' },
        );
        if (!unchanged()) return;
        if (!detail.ok) throw new Error();
        const detailValue: unknown = await detail.json();
        if (!unchanged()) return;
        const selectedResource = resource(detailValue, target);
        setItems((currentItems) =>
          currentItems.some((item) => item.policySetId === selectedResource.policySetId)
            ? currentItems
            : [selectedResource, ...currentItems],
        );
        onSelectRef.current(selectedResource.policySetId);
        readValidity(selectedResource.policySetId);
      }
    } catch {
      if (!unchanged()) return;
      setItems([]);
      setCursor(null);
      setReadError(true);
      readValidity(null);
      onSelectRef.current('');
      setStatus(
        nextCursor
          ? 'More policy sets could not be read.'
          : 'Policy sets could not be read in this context.',
      );
    } finally {
      if (owned()) setBusy(false);
    }
  }
  useEffect(() => {
    epoch.current += 1;
    privacyEpoch.current = policyWorkflowPrivacyRevision();
    const saved = readBoundPolicyState(storageKey, actor, valid);
    setItems([]);
    setCursor(null);
    setBusy(false);
    draftRef.current = saved ?? { name: '', reason: '', requestKey: '', selected: '' };
    setDraft(draftRef.current);
    void readPage(undefined, selectedRef.current || saved?.selected || '');
    return () => {
      epoch.current += 1;
    };
  }, [actor]);
  const save = (value: DraftState) => {
    if (!privacyCurrent()) return;
    draftRef.current = value;
    setDraft(value);
    writeBoundPolicyState(storageKey, actor, value);
  };
  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!privacyCurrent() || mutationEpoch.current === epoch.current) return;
    const current = epoch.current;
    const owned = () => privacyCurrent() && current === epoch.current;
    const attempt = { ...draft, requestKey: draft.requestKey || crypto.randomUUID() };
    save(attempt);
    mutationEpoch.current = current;
    readGeneration.current += 1;
    setBusy(true);
    setStatus('Creating the draft.');
    try {
      const response = await fetch('/api/v1/ui/policy-sets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: attempt.name,
          reason: attempt.reason,
          requestKey: attempt.requestKey,
        }),
      });
      if (!response.ok) throw new Error();
      const result = (await response.json()) as { operation: { resourceRef: string } };
      if (!owned()) return;
      const reference = `urn:openpc:policy-set:${result.operation.resourceRef.slice(-36)}`;
      const detail = await fetch(
        `/api/v1/ui/policy-sets?policySetId=${encodeURIComponent(reference)}`,
        { cache: 'no-store' },
      );
      if (!owned()) return;
      if (!detail.ok) throw new Error();
      const detailValue: unknown = await detail.json();
      if (!owned()) return;
      const selectedResource = resource(detailValue, reference);
      setReadError(false);
      setProjectionActor(actor);
      setItems((values) => [
        selectedResource,
        ...values.filter((item) => item.policySetId !== reference),
      ]);
      save({ ...attempt, selected: reference });
      onSelectRef.current(reference);
      readValidity(reference);
      setStatus(
        selectedResource.state === 'DRAFT'
          ? 'Draft created and read back. It grants no runtime authority.'
          : `Policy set operation confirmed. Current state: ${selectedResource.state}.`,
      );
    } catch {
      if (owned())
        setStatus(
          'The result could not be confirmed. Retry the unchanged draft to reconcile the original operation.',
        );
    } finally {
      if (mutationEpoch.current === current) mutationEpoch.current = undefined;
      if (owned()) setBusy(false);
    }
  }
  async function more() {
    if (!cursor) return;
    await readPage(cursor);
  }
  const projectionCurrent =
    privacyCurrent() &&
    !readError &&
    (
      ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const
    ).every((field) => projectionActor[field] === actor[field]);
  const visibleItems = projectionCurrent ? items : [];
  const visibleSelected = visibleItems.some((item) => item.policySetId === selected)
    ? selected
    : '';
  const statusContent =
    status === emptyStatus || status === emptyPageStatus ? (
      <div className="policy-set-empty-state" role="status">
        <p>{status}</p>
        <p>
          {status === emptyPageStatus
            ? 'Load another page when available, or refresh to check again.'
            : showCreation
              ? 'Create a policy set to group related versions, or refresh after another set is made available.'
              : 'Refresh after a policy set is made available in this workspace.'}
        </p>
      </div>
    ) : (
      <p role={readError ? 'alert' : 'status'} className="break-words">
        {status}
      </p>
    );
  return (
    <section
      aria-labelledby="policy-sets-title"
      className="mt-5 grid min-w-0 gap-4 border-t border-[color:var(--border)] pt-4"
    >
      <div className="policy-set-header">
        <div>
          <h3 id="policy-sets-title" className="text-lg font-semibold">
            Policy sets
          </h3>
          <p>
            {showCreation
              ? 'Choose a set for this version, or create one for related policies.'
              : 'Choose the policy set you want to inspect.'}
          </p>
        </div>
        <div className="policy-set-actions">
          <button
            className="justify-self-start rounded border px-3 py-2"
            disabled={mutationEpoch.current === epoch.current}
            onClick={() => void readPage()}
            type="button"
          >
            {readError ? 'Retry policy set reads' : 'Refresh policy sets'}
          </button>
          {showCreation ? (
            <SecondaryPanel
              title="Create a policy set"
              className="policy-set-creator"
              onOpenChange={setCreatorOpen}
              closeOnChange={JSON.stringify([
                actor.sessionId,
                actor.principalId,
                actor.participantId,
                actor.privacyDomainId,
                actor.contextEpoch,
                policyWorkflowPrivacyRevision(),
              ])}
            >
              <p className="mt-2 text-sm text-[color:var(--muted)]">
                Give related policy versions a name and explain why this set is needed. Creating a
                draft does not publish or activate a policy.
              </p>
              <form onSubmit={(event) => void create(event)} className="policy-set-create-form">
                <label className="grid gap-1">
                  New policy set name
                  <input
                    required
                    maxLength={160}
                    value={draft.name}
                    disabled={busy}
                    onChange={(event) =>
                      save({ ...draft, name: event.target.value, requestKey: '' })
                    }
                    className="min-w-0 rounded border p-2"
                  />
                </label>
                <label className="grid gap-1">
                  Reason for creating this policy set
                  <textarea
                    required
                    maxLength={1024}
                    value={draft.reason}
                    disabled={busy}
                    onChange={(event) =>
                      save({ ...draft, reason: event.target.value, requestKey: '' })
                    }
                    className="min-w-0 rounded border p-2"
                  />
                </label>
                <button disabled={busy} type="submit" className="policy-set-create-submit">
                  Create policy set draft
                </button>
              </form>
              {creatorOpen ? statusContent : null}
            </SecondaryPanel>
          ) : null}
        </div>
      </div>
      <label className="grid gap-1">
        Policy set for this version
        <select
          aria-label="Policy set for this version"
          value={visibleSelected}
          disabled={busy}
          onChange={(event) => {
            if (!privacyCurrent()) return;
            selectionRevision.current += 1;
            readGeneration.current += 1;
            save({ ...draft, selected: event.target.value });
            onSelectRef.current(event.target.value);
            readValidity(
              visibleItems.some((item) => item.policySetId === event.target.value) ||
                !event.target.value
                ? event.target.value
                : null,
            );
          }}
          className="min-w-0 w-full rounded border p-2"
        >
          <option value="">Select a policy set</option>
          {visibleItems.map((item) => (
            <option key={item.policySetId} value={item.policySetId}>
              {item.name} · {item.state}
            </option>
          ))}
        </select>
      </label>
      {visibleSelected ? (
        <details className="policy-set-reference">
          <summary className="cursor-pointer font-medium">Policy reference</summary>
          <p className="mt-2 break-all font-mono">{visibleSelected}</p>
        </details>
      ) : null}
      {projectionCurrent && cursor ? (
        <button
          className="rounded border px-3 py-2"
          disabled={busy}
          onClick={() => void more()}
          type="button"
        >
          Load more policy sets
        </button>
      ) : null}
      {showCreation && creatorOpen ? null : statusContent}
    </section>
  );
}
