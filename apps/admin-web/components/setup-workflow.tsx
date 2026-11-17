'use client';
import { SecondaryPanel } from './secondary-panel';
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { z } from 'zod';
import { LocalSessionSurface } from './local-session';
import { TransactionWorkflow } from './transaction-workflow';
import { ProviderDirectory } from './provider-directory';
import { RuntimeTargetDirectory } from './runtime-target-directory';
import { sessionTransitionEvent, sessionTransitionStorageKey } from './session-transition';
import {
  readBoundPolicyState,
  writeBoundPolicyState,
  type PolicyWorkflowActorBinding,
} from './policy-workflow-storage';

type Kind =
  | 'providers'
  | 'runtime'
  | 'indexers'
  | 'projections'
  | 'projection-validation'
  | 'runtime-activation';
const ordinaryForms = {
  'runtime-activation': {
    title: 'Refresh runtime activation',
    noun: 'runtime activation',
    fields: [
      ['targetRef', 'Runtime target resource reference'],
      ['expectedRevision', 'Runtime target expected revision'],
    ],
  },
  'indexers': {
    title: 'Prepare a chain reader',
    noun: 'chain reader',
    fields: [
      ['engine', 'Reader engine'],
      ['engineVersion', 'Reader engine version'],
      ['methodProfileDigest', 'Reader profile artifact digest (sha256)'],
    ],
  },
  'projections': {
    title: 'Prepare a data view',
    noun: 'data view',
    fields: [
      ['indexerProfileId', 'Qualified reader reference'],
      ['planDigest', 'Data view artifact digest (sha256)'],
    ],
  },
  'projection-validation': {
    title: 'Validate a data view',
    noun: 'data view validation',
    fields: [
      ['targetRef', 'Data view resource reference'],
      ['expectedRevision', 'Data view expected revision'],
      ['inputDigest', 'Data view artifact digest (sha256)'],
    ],
  },
} as const;
interface Page {
  items: Record<string, unknown>[];
  nextCursor: string | null;
  completeness: 'COMPLETE' | 'UNKNOWN';
  authorizedEmpty: boolean;
}
interface Result {
  actor: PolicyWorkflowActorBinding;
  result?: Page | Record<string, unknown>;
  operation?: {
    operationId: string;
    resourceRef: string | null;
    state: string;
    truthState: string;
  };
  preview?: unknown;
  reviewToken?: string;
  truthState?: string;
}
interface Saved {
  reviewToken?: string;
  preview?: unknown;
  operationId?: string;
  resourceId?: string;
  uncertain?: boolean;
}
const endpoint = '/api/v1/ui/setup-workbench';
const field =
  'mt-1 w-full rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-2';
const button = 'rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-50';
const setupFailureMessages = {
  unavailable:
    'Setup could not be confirmed. Refresh or read the original operation before retrying.',
  authorization:
    'Setup request was not authorized. Refresh the authenticated context before continuing.',
  conflict: 'Setup state changed. Refresh or read the original operation before retrying.',
  input: 'Setup request was rejected. Check the inputs before continuing.',
  contextRequired: 'Select an authenticated Participant context first.',
  contextChanged: 'The selected context changed. Refresh before continuing.',
} as const;
function setupHttpFailure(status: number) {
  return [401, 403, 404].includes(status)
    ? setupFailureMessages.authorization
    : [409, 412, 428].includes(status)
      ? setupFailureMessages.conflict
      : [400, 422].includes(status)
        ? setupFailureMessages.input
        : setupFailureMessages.unavailable;
}
class SetupFailure extends Error {
  constructor(readonly status: number) {
    super(setupHttpFailure(status));
  }
}
class SetupContextFailure extends Error {
  constructor(readonly kind: 'contextRequired' | 'contextChanged') {
    super(setupFailureMessages[kind]);
  }
}
function failureMessage(error: unknown) {
  return error instanceof SetupFailure
    ? setupHttpFailure(error.status)
    : error instanceof SetupContextFailure
      ? setupFailureMessages[error.kind]
      : setupFailureMessages.unavailable;
}
async function read(response: Response): Promise<Result> {
  const body = await response.json().catch(() => undefined);
  if (!response.ok) throw new SetupFailure(response.status);
  if (body === undefined) throw new Error();
  return body;
}
function validSaved(value: unknown): value is Saved {
  return (
    typeof value === 'object' &&
    value !== null &&
    (!('reviewToken' in value) || typeof value.reviewToken === 'string') &&
    (!('operationId' in value) || typeof value.operationId === 'string') &&
    (!('resourceId' in value) || typeof value.resourceId === 'string') &&
    (!('uncertain' in value) || typeof value.uncertain === 'boolean')
  );
}
function ResourceLookup({ title, children }: { title?: string; children: ReactNode }) {
  return title ? (
    <SecondaryPanel title={title} className="provider-reference">
      {children}
    </SecondaryPanel>
  ) : (
    children
  );
}
export function SetupWorkflow({
  kind,
  showSessionControls = true,
  evaluationUi = false,
}: {
  kind: Kind;
  showSessionControls?: boolean;
  evaluationUi?: boolean;
}) {
  const [actor, setActor] = useState<PolicyWorkflowActorBinding>();
  const current = useRef<PolicyWorkflowActorBinding | undefined>(undefined);
  const sequence = useRef(0);
  const changing = useRef(false);
  const [result, setResult] = useState<Result>();
  const [saved, setSaved] = useState<Saved>({});
  const [status, setStatus] = useState('');
  const [reason, setReason] = useState('');
  const [fields, setFields] = useState<Record<string, string>>({});
  const ordinary =
    kind === 'indexers' ||
    kind === 'projections' ||
    kind === 'projection-validation' ||
    kind === 'runtime-activation'
      ? ordinaryForms[kind]
      : undefined;
  const noun = ordinary?.noun ?? 'runtime target';
  const [resource, setResource] = useState('');
  const [busy, setBusy] = useState(false);
  const runtimePresentation = evaluationUi && kind === 'runtime';
  const [refreshing, setRefreshing] = useState(false);
  const key = `openpc:setup:${kind}:v1`;
  const save = (value: Saved, owner: PolicyWorkflowActorBinding) => {
    if (!current.current || JSON.stringify(owner) !== JSON.stringify(current.current)) return;
    writeBoundPolicyState(key, owner, value);
    setSaved(value);
  };
  const refresh = useCallback(
    async (query?: URLSearchParams) => {
      if (changing.current) return;
      const order = ++sequence.current;
      setRefreshing(true);
      try {
        const previous = current.current;
        setResult(undefined);
        setActor(undefined);
        setSaved({});
        setStatus('');
        current.current = undefined;
        const base = await read(await fetch(endpoint, { cache: 'no-store' }));
        if (order !== sequence.current) return;
        const value = await read(
          await fetch(`${endpoint}?${query ?? new URLSearchParams({ kind })}`, {
            cache: 'no-store',
          }),
        );
        if (order !== sequence.current) return;
        const latest = await read(await fetch(endpoint, { cache: 'no-store' }));
        if (order !== sequence.current) return;
        if (
          JSON.stringify(base.actor) !== JSON.stringify(value.actor) ||
          JSON.stringify(base.actor) !== JSON.stringify(latest.actor)
        ) {
          current.current = undefined;
          setActor(undefined);
          setSaved({});
          setStatus('The selected context changed. Refresh setup before continuing.');
          return;
        }
        if (JSON.stringify(base.actor) !== JSON.stringify(previous)) {
          setResource('');
          setReason('');
          setFields({});
        }
        current.current = base.actor;
        setActor(base.actor);
        setSaved(readBoundPolicyState<Saved>(key, base.actor, validSaved) ?? {});
        setResult(value);
      } finally {
        if (order === sequence.current) setRefreshing(false);
      }
    },
    [key, kind],
  );
  const refreshRecordedProvider = useCallback(
    (recordedActor: PolicyWorkflowActorBinding) => {
      if (changing.current || JSON.stringify(recordedActor) !== JSON.stringify(current.current))
        return;
      const pending = refresh();
      const order = sequence.current;
      void pending.catch((error: unknown) => {
        if (order === sequence.current) setStatus(failureMessage(error));
      });
    },
    [refresh],
  );
  useEffect(() => {
    let mounted = true;
    const refreshCurrent = () => {
      if (changing.current) return;
      const pending = refresh();
      const order = sequence.current;
      void pending.catch((error: unknown) => {
        if (mounted && order === sequence.current) setStatus(failureMessage(error));
      });
    };
    const invalidate = () => {
      sequence.current++;
      current.current = undefined;
      setActor(undefined);
      setResult(undefined);
      setSaved({});
      setResource('');
      setReason('');
      setFields({});
      setStatus('');
      setRefreshing(false);
    };
    const transition = (notification: unknown) => {
      const parsed = z.object({ phase: z.enum(['changing', 'settled']) }).safeParse(notification);
      if (!parsed.success) return;
      invalidate();
      changing.current = parsed.data.phase === 'changing';
      if (!changing.current) refreshCurrent();
    };
    const event = (value: Event) => transition((value as CustomEvent<unknown>).detail);
    const storage = (value: StorageEvent) => {
      if (value.key !== sessionTransitionStorageKey) return;
      try {
        transition(JSON.parse(value.newValue ?? 'null'));
      } catch {
        invalidate();
        refreshCurrent();
      }
    };
    const visibility = () => {
      if (document.visibilityState === 'visible') refreshCurrent();
    };
    refreshCurrent();
    window.addEventListener('focus', refreshCurrent);
    window.addEventListener('storage', storage);
    window.addEventListener(sessionTransitionEvent, event);
    document.addEventListener('visibilitychange', visibility);
    return () => {
      mounted = false;
      sequence.current += 1;
      current.current = undefined;
      window.removeEventListener('focus', refreshCurrent);
      window.removeEventListener('storage', storage);
      window.removeEventListener(sessionTransitionEvent, event);
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [refresh]);
  async function run(action: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setStatus('');
    let order = sequence.current;
    try {
      const pending = action();
      order = sequence.current;
      await pending;
    } catch (error) {
      if (order === sequence.current) {
        setResult(undefined);
        setStatus(failureMessage(error));
      }
    } finally {
      setBusy(false);
    }
  }
  async function command(body: unknown) {
    const owner = current.current;
    if (!owner) throw new SetupContextFailure('contextRequired');
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const value = await read(response);
    if (owner !== current.current || JSON.stringify(owner) !== JSON.stringify(value.actor))
      throw new SetupContextFailure('contextChanged');
    return value;
  }
  async function prepare() {
    const value = await command({
      command: ordinary ? 'PREVIEW_INDEXER' : 'PREVIEW_RUNTIME',
      ...(ordinary ? { kind, fields } : {}),
      requestKey: crypto.randomUUID(),
      reason,
    });
    save({ reviewToken: value.reviewToken, preview: value.preview }, value.actor);
  }
  async function create() {
    if (!actor || !saved.reviewToken) return;
    const order = sequence.current;
    // Preserve the original review before any possible durable effect.
    save({ ...saved, uncertain: true }, actor);
    let value: Result;
    try {
      value = await command({
        command: ordinary ? 'EXECUTE_INDEXER' : 'CREATE_RUNTIME',
        reviewToken: saved.reviewToken,
      });
    } catch (error) {
      if (
        order === sequence.current &&
        actor === current.current &&
        error instanceof SetupFailure &&
        [400, 401, 403, 404, 409, 422, 428].includes(error.status)
      )
        save({ ...saved, uncertain: false }, actor);
      throw error;
    }
    if (!value.operation) {
      setStatus(
        'The outcome is unknown. Keep this original request and reconcile its resource or operation readback before any further submission.',
      );
      return;
    }
    save(
      {
        ...saved,
        uncertain: false,
        operationId: value.operation.operationId,
        resourceId: value.operation.resourceRef?.slice(-36),
      },
      value.actor,
    );
    setResource(value.operation.resourceRef?.slice(-36) ?? '');
    setResult(value);
    setStatus(
      kind === 'runtime-activation'
        ? 'The update was recorded. Read the target and original operation to confirm the active generation and runtime state.'
        : ordinary
          ? 'The operation was recorded. Read its resource and original operation to confirm preparation or validation. This result grants no contract access.'
          : 'The operation was recorded. Read the runtime target to inspect its current state; discovery does not establish runtime readiness.',
    );
  }
  const page = result?.result && 'items' in result.result ? (result.result as Page) : undefined;
  return (
    <section
      aria-label={ordinary?.title ?? (kind === 'providers' ? 'Provider setup' : 'Runtime setup')}
      className={`space-y-5${kind === 'providers' ? ' provider-workspace' : ''}`}
    >
      {kind !== 'providers' && showSessionControls ? <LocalSessionSurface /> : null}
      <h2 className="text-xl font-semibold">
        {ordinary?.title ?? (kind === 'providers' ? 'Registered providers' : 'Runtime targets')}
      </h2>
      <p>
        {kind === 'runtime-activation'
          ? 'Review the current activation candidate, then request its delivery. Read the target to confirm the active generation; submission alone does not establish readiness.'
          : ordinary
            ? 'Preparation remains separate from reader admission, native validation and policy activation. Only the owning services can establish readiness.'
            : kind === 'providers'
              ? 'Provider qualification is shown below. Access to contracts and data is managed separately.'
              : runtimePresentation
                ? 'Inspect the configuration and state reported for each runtime target.'
                : 'Discovery records an unready target. Authentication, configuration delivery and active-generation confirmation remain separate prerequisites.'}
      </p>
      <p role="status" aria-live="polite">
        {refreshing
          ? `Loading ${ordinary?.noun ?? (kind === 'providers' ? 'providers' : 'runtime targets')}…`
          : status}
      </p>
      {actor ? (
        kind === 'providers' || runtimePresentation ? (
          <SecondaryPanel title="Workspace details" className="provider-context">
            <p className="break-all">
              Participant: {actor.participantId} · Privacy domain: {actor.privacyDomainId}
            </p>
          </SecondaryPanel>
        ) : (
          <p className="break-all">
            Participant: {actor.participantId} · Privacy domain: {actor.privacyDomainId}
          </p>
        )
      ) : null}
      <button
        className={button}
        disabled={busy || refreshing}
        onClick={() => void run(() => refresh())}
      >
        Refresh {ordinary?.noun ?? (kind === 'providers' ? 'providers' : 'runtime targets')}
      </button>
      <ResourceLookup
        title={
          kind === 'providers'
            ? 'Find a provider by reference'
            : runtimePresentation
              ? 'Find a runtime target by reference'
              : undefined
        }
      >
        <form
          className="space-y-2"
          onSubmit={(event) => {
            event.preventDefault();
            void run(() =>
              refresh(
                new URLSearchParams({
                  kind,
                  resourceId: resource.trim().replace(/^urn:openpc:resource:/u, ''),
                }),
              ),
            );
          }}
        >
          <label className="block">
            {ordinary
              ? `${noun} reference to read`
              : kind === 'providers'
                ? 'Provider reference to read'
                : 'Runtime target reference to read'}
            <input
              className={field}
              value={actor ? resource : ''}
              onChange={(event) => setResource(event.target.value)}
              required
            />
          </label>
          <button className={button} disabled={busy || refreshing}>
            Read current resource
          </button>
        </form>
      </ResourceLookup>
      {page ? (
        <>
          <p>
            {page.items.length === 0
              ? page.authorizedEmpty && page.completeness === 'COMPLETE'
                ? evaluationUi && (kind === 'providers' || runtimePresentation)
                  ? `No ${kind === 'providers' ? 'providers' : 'runtime targets'} are available to your account in this workspace.`
                  : 'No authorized records.'
                : 'No records returned; coverage is incomplete.'
              : kind === 'providers' || runtimePresentation
                ? `${page.items.length} ${kind === 'providers' ? 'provider' : 'runtime target'}${page.items.length === 1 ? '' : 's'} on this page.${page.completeness === 'UNKNOWN' ? ' Coverage is incomplete.' : ''}`
                : `${page.items.length} records returned. Coverage: ${page.completeness}.`}
          </p>
          {page.nextCursor ? (
            <button
              className={button}
              disabled={busy || refreshing}
              onClick={() =>
                void run(() => refresh(new URLSearchParams({ kind, cursor: page.nextCursor! })))
              }
            >
              Read next page
            </button>
          ) : null}
        </>
      ) : null}
      {(kind === 'providers' || runtimePresentation) && result?.result && !page ? (
        <button
          className={button}
          disabled={busy || refreshing}
          onClick={() => void run(() => refresh())}
        >
          Back to all {kind === 'providers' ? 'providers' : 'runtime targets'}
        </button>
      ) : null}
      {kind === 'providers' && result?.result ? (
        <ProviderDirectory
          items={page ? page.items : [result.result as Record<string, unknown>]}
          busy={busy || refreshing}
          onRead={(reference) => {
            setResource(reference.slice(-36));
            void run(() =>
              refresh(new URLSearchParams({ kind, resourceId: reference.slice(-36) })),
            );
          }}
        />
      ) : runtimePresentation && result?.result ? (
        <RuntimeTargetDirectory
          items={page ? page.items : [result.result as Record<string, unknown>]}
          busy={busy || refreshing}
          onRead={(reference) => {
            setResource(reference.slice(-36));
            void run(() =>
              refresh(new URLSearchParams({ kind, resourceId: reference.slice(-36) })),
            );
          }}
        />
      ) : runtimePresentation && result?.operation ? (
        <SecondaryPanel title="Runtime discovery operation details">
          <pre tabIndex={0} className="whitespace-pre-wrap break-all text-sm">
            {JSON.stringify(result.operation, null, 2)}
          </pre>
        </SecondaryPanel>
      ) : result?.result || result?.operation ? (
        <pre
          tabIndex={0}
          className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded border p-3 text-sm"
        >
          {JSON.stringify(result.result ?? result.operation, null, 2)}
        </pre>
      ) : null}
      {kind === 'providers' ? (
        <TransactionWorkflow
          mode="providers"
          showSessionControls={showSessionControls}
          collapseRequestTools
          onRecordedResult={refreshRecordedProvider}
        />
      ) : null}
      {(kind === 'runtime' || ordinary) && actor ? (
        <section
          aria-label={ordinary ? `${ordinary.title} request` : 'Discover a runtime target'}
          className={runtimePresentation ? 'catalogue-record-card' : 'space-y-3'}
        >
          <h3 className="font-semibold">{ordinary?.title ?? 'Discover a runtime target'}</h3>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void run(prepare);
            }}
          >
            {ordinary?.fields.map(([name, label]) => (
              <label key={name} className="block">
                {label}
                {name === 'engine' ? (
                  <select
                    className={field}
                    required
                    disabled={Boolean(saved.reviewToken)}
                    value={fields[name] ?? ''}
                    onChange={(event) => setFields({ ...fields, [name]: event.target.value })}
                  >
                    <option value="">Choose an engine</option>
                    <option value="CLIENT_INDEXER">Client indexer</option>
                    <option value="EXTERNAL_ENGINE_ADAPTER">External engine adapter</option>
                  </select>
                ) : (
                  <input
                    className={field}
                    required
                    disabled={Boolean(saved.reviewToken)}
                    value={fields[name] ?? ''}
                    onChange={(event) => setFields({ ...fields, [name]: event.target.value })}
                  />
                )}
              </label>
            ))}
            <label className="block">
              {ordinary ? 'Setup reason' : 'Reason for discovery'}
              <textarea
                className={field}
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                required
                maxLength={1024}
              />
            </label>
            <button className={button} disabled={busy || Boolean(saved.reviewToken)}>
              {ordinary ? 'Review setup' : 'Review discovery'}
            </button>
          </form>
          {saved.reviewToken ? (
            <>
              <pre tabIndex={0} className="overflow-auto whitespace-pre-wrap break-all text-sm">
                {JSON.stringify(saved.preview, null, 2)}
              </pre>
              <p>
                {kind === 'runtime-activation'
                  ? 'This review binds the current candidate and target revision. The backend checks current authority and source freshness when you submit.'
                  : ordinary
                    ? 'The reviewed input cannot declare a profile qualified or a data view ready. The backend checks current authority when you submit.'
                    : 'Desired, active and xDS generations start unset. The backend checks current authority when you submit.'}
              </p>
              <button
                className={button}
                disabled={busy || saved.uncertain || Boolean(saved.operationId)}
                onClick={() => void run(create)}
              >
                {ordinary ? 'Submit reviewed setup' : 'Record discovered target'}
              </button>
              {saved.operationId ? (
                <button
                  className={button}
                  disabled={busy || refreshing}
                  onClick={() =>
                    void run(() =>
                      refresh(
                        new URLSearchParams({
                          operationId: saved.operationId!,
                          ...(ordinary ? { kind } : {}),
                        }),
                      ),
                    )
                  }
                >
                  Read original operation
                </button>
              ) : null}
              {saved.uncertain ? (
                <p role="alert">
                  The original request may have taken effect. Do not replace it or submit another
                  resource. Reconcile the original resource through the list or reference above.
                </p>
              ) : null}
              {!saved.uncertain ? (
                <button
                  className={button}
                  disabled={busy || refreshing}
                  onClick={() => save({}, actor)}
                >
                  {saved.operationId
                    ? ordinary
                      ? 'Start a separate setup request'
                      : 'Start a separate discovery'
                    : 'Discard unsubmitted review'}
                </button>
              ) : null}
            </>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}
