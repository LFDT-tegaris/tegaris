'use client';
import { useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import {
  directoryCandidate,
  directoryMemberReadback,
  directoryReadback,
  directoryState,
  savedDirectoryReview,
  type DirectoryReview,
} from '../lib/directory-workflow';
import { recoveryActor } from '../lib/recovery-workflow';
import { readBoundPolicyState, writeBoundPolicyState } from './policy-workflow-storage';
import { LocalSessionSurface } from './local-session';
import { directoryGroupReadback } from '../lib/directory-group-workflow';
import { DirectoryGroupCandidate, DirectoryGroupResult } from './directory-group-details';
const endpoint = '/api/v1/ui/directory-workbench',
  storageKey = 'openpc:directory-workflow:v1';
const panel = 'min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const field =
  'min-w-0 w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60';
type State = z.infer<typeof directoryState>;
type Reader = 'list' | 'connector' | 'group' | 'member';
type ReadAttempt = { reader: Reader; generation: number; controller: AbortController };
const sessionSchema = recoveryActor
  .partial()
  .extend({ authenticated: z.boolean(), contextMode: z.string().optional() })
  .passthrough();
type DirectoryReceipt = {
  truthState: 'SUCCESS' | 'WRITE_AMBIGUITY';
  operationId?: string;
  readback?: z.infer<typeof directoryReadback> | z.infer<typeof directoryGroupReadback>;
  requiresReauthentication?: boolean;
};
class SupersededRead extends Error {
  constructor() {
    super('The directory context changed. Refresh directory approvals.');
  }
}
class UnknownReadContext extends Error {}
const readUnavailable = 'The directory read is unavailable. Retry the same read.';
const contextUnavailable =
  'The directory context is unavailable or changed. Refresh directory approvals.';
const sameActor = (left: State['actor'] | undefined, right: State['actor'] | undefined) =>
  !!left &&
  !!right &&
  left.sessionId === right.sessionId &&
  left.principalId === right.principalId &&
  left.participantId === right.participantId &&
  left.privacyDomainId === right.privacyDomainId &&
  left.contextEpoch === right.contextEpoch;
type Change =
  | 'CREATE'
  | 'CONFIGURE'
  | 'SUSPEND'
  | 'RESUME'
  | 'RETIRE'
  | 'PROVISION'
  | 'RECONCILE'
  | 'MAP_DIRECTORY'
  | 'REFRESH_DIRECTORY';
const changes: Record<Change, string> = {
  CREATE: 'Create connector',
  CONFIGURE: 'Configure connector',
  SUSPEND: 'Suspend connector',
  RESUME: 'Resume connector',
  RETIRE: 'Retire connector',
  PROVISION: 'Provision directory member',
  RECONCILE: 'Reconcile directory member',
  MAP_DIRECTORY: 'Map directory group',
  REFRESH_DIRECTORY: 'Refresh directory group',
};
async function json(response: Response): Promise<unknown> {
  const value = await response.json().catch(() => undefined);
  if (!response.ok)
    throw new Error(
      `${value?.title ?? 'The request could not be completed.'}${value?.code ? ` (${value.code})` : ''}`,
    );
  return value;
}
function Candidate({ candidate }: { candidate: z.infer<typeof directoryCandidate> }) {
  if ('observation' in candidate) return <DirectoryGroupCandidate candidate={candidate} />;
  if ('change' in candidate) {
    const change = candidate.change;
    return (
      <div className="grid gap-1 [overflow-wrap:anywhere]">
        <p>Change: {changes[change.mutation]}</p>
        <p>Connector: {change.connectorId}</p>
        {'displayName' in change && (
          <>
            <p>Name: {change.displayName}</p>
            <p>Mass-change threshold: {change.massChangeThreshold}%</p>
            <p>Maximum external group age: {change.externalGroupFreshnessSeconds} seconds</p>
          </>
        )}
        {'profileId' in change && <p>Registered profile: {change.profileId}</p>}
        {change.mutation === 'RETIRE' && (
          <p>
            Retirement stops reconciliation permanently. Existing local memberships and grants
            remain until changed through their owners.
          </p>
        )}
      </div>
    );
  }
  return (
    <div className="grid gap-2 [overflow-wrap:anywhere]">
      <p>Change: {changes[candidate.mode]}</p>
      <p>Connector: {candidate.connectorId}</p>
      <p>
        Review class: {candidate.reviewClass === 'MASS_CHANGE' ? 'Mass change' : 'Ordinary change'}
      </p>
      <p>
        {candidate.changedMembers} changed out of {candidate.managedMembers} managed members.
      </p>
      <p>Provider observation: {candidate.observedAt}</p>
      {candidate.members.map((member) => (
        <article key={member.externalId} className={panel}>
          <h4 className="font-semibold">{member.displayName}</h4>
          <p>Exact provider ID: {member.externalId}</p>
          <p>Local principal: {member.principalId}</p>
          <p>Provider account: {member.source.userName}</p>
          <p>Provider name: {member.source.displayName}</p>
          <p>Provider version: {member.source.version}</p>
          <p>
            {candidate.mode === 'PROVISION'
              ? 'Creates a provisioned membership without activation or permissions.'
              : member.source.active
                ? 'Refreshes the binding and updates its display name.'
                : 'Offboards this membership and revokes its sessions, credentials and dependent access.'}
          </p>
        </article>
      ))}
    </div>
  );
}
export function DirectoryWorkflow() {
  const [state, setState] = useState<State>(),
    [review, setDisplayedReview] = useState<DirectoryReview>();
  const [readback, setReadback] = useState<z.infer<typeof directoryReadback>>(),
    [member, setMember] = useState<z.infer<typeof directoryMemberReadback>>();
  const [groupResult, setGroupResult] = useState<z.infer<typeof directoryGroupReadback>>(),
    [groupId, setGroupId] = useState(''),
    [externalGroupId, setExternalGroupId] = useState(''),
    [lookupGroupId, setLookupGroupId] = useState('');
  const [change, setChange] = useState<Change>('CREATE'),
    [lane, setLane] = useState<'maker' | 'checker'>('checker');
  const [connectorId, setConnectorId] = useState(''),
    [profileId, setProfileId] = useState(''),
    [displayName, setDisplayName] = useState(''),
    [threshold, setThreshold] = useState('5'),
    [freshness, setFreshness] = useState('900');
  const [externalId, setExternalId] = useState(''),
    [principalId, setPrincipalId] = useState(''),
    [memberName, setMemberName] = useState(''),
    [checker, setChecker] = useState(''),
    [reason, setReason] = useState('');
  const [lookupId, setLookupId] = useState(''),
    [lookupExternal, setLookupExternal] = useState(''),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [message, setMessage] = useState('');
  const actor = useRef<State['actor'] | undefined>(undefined),
    locked = useRef(false);
  const mounted = useRef(false);
  const manualRead = useRef<object | undefined>(undefined);
  const attempts = useRef<Partial<Record<Reader, ReadAttempt>>>({});
  const readGeneration = useRef(0);
  const alert = useRef<HTMLParagraphElement>(null);
  const reviewEvidence = useRef<DirectoryReview | undefined>(undefined);
  const originalReceipt = useRef<
    | {
        actor: State['actor'];
        reviewToken: string;
        result: DirectoryReceipt;
        message: string;
      }
    | undefined
  >(undefined);
  const [contextKnown, setContextKnown] = useState(false);
  const [readStatus, setReadStatus] = useState('');
  function setReview(value: DirectoryReview | undefined) {
    reviewEvidence.current = value;
    setDisplayedReview(value);
  }
  function retainReceipt(result: DirectoryReceipt, reviewToken: string) {
    if (!actor.current) return;
    originalReceipt.current = {
      actor: actor.current,
      reviewToken,
      result,
      message:
        result.truthState === 'SUCCESS'
          ? `Directory change committed. Operation: ${result.operationId}${result.requiresReauthentication ? ' Sign in again to read current memberships.' : ''}`
          : 'The commit outcome is uncertain. Refresh requested approvals and read the saved connector before retrying.',
    };
  }
  function restoreReceipt(currentActor: State['actor']) {
    const saved = originalReceipt.current;
    if (
      !saved ||
      !sameActor(saved.actor, currentActor) ||
      saved.reviewToken !== reviewEvidence.current?.reviewToken
    )
      return;
    setMessage(saved.message);
  }
  function invalidate(reader?: Reader) {
    for (const kind of reader ? [reader] : (Object.keys(attempts.current) as Reader[])) {
      attempts.current[kind]?.controller.abort();
      delete attempts.current[kind];
    }
  }
  function clearProjection(reader: Reader) {
    if (reader === 'list') {
      setState(undefined);
      setReadback(undefined);
      setMember(undefined);
      setGroupResult(undefined);
    }
    if (reader === 'connector') setReadback(undefined);
    if (reader === 'group') setGroupResult(undefined);
    if (reader === 'member') setMember(undefined);
  }
  function hidePrivate() {
    invalidate();
    cancelManualRead();
    setContextKnown(false);
    setState(undefined);
    setDisplayedReview(undefined);
    setReadback(undefined);
    setMember(undefined);
    setGroupResult(undefined);
    setReadStatus('');
  }
  function startRead(reader: Reader) {
    invalidate(reader);
    clearProjection(reader);
    if (reader === 'list') setContextKnown(false);
    const attempt = {
      reader,
      generation: ++readGeneration.current,
      controller: new AbortController(),
    };
    attempts.current[reader] = attempt;
    return attempt;
  }
  function current(attempt: ReadAttempt) {
    return (
      mounted.current &&
      attempts.current[attempt.reader]?.generation === attempt.generation &&
      !attempt.controller.signal.aborted
    );
  }
  async function readJson(url: string, attempt: ReadAttempt) {
    if (!current(attempt)) throw new SupersededRead();
    const response = await fetch(url, { cache: 'no-store', signal: attempt.controller.signal });
    if (!current(attempt)) throw new SupersededRead();
    if ([401, 403, 404].includes(response.status)) throw new UnknownReadContext();
    if (response.status !== 200) throw new Error(readUnavailable);
    const value: unknown = await response.json();
    if (!current(attempt)) throw new SupersededRead();
    return value;
  }
  async function readActor(attempt: ReadAttempt) {
    let value: unknown;
    try {
      value = await readJson('/api/v1/ui/local-session', attempt);
    } catch (cause) {
      if (!current(attempt)) throw new SupersededRead();
      throw cause instanceof SupersededRead ? cause : new UnknownReadContext();
    }
    const session = sessionSchema.safeParse(value);
    const bound = session.success ? recoveryActor.strip().safeParse(session.data) : undefined;
    if (
      !session.success ||
      !session.data.authenticated ||
      session.data.contextMode !== 'PARTICIPANT' ||
      !bound?.success
    )
      throw new UnknownReadContext();
    return bound.data;
  }
  async function failRead(
    attempt: ReadAttempt,
    cause: unknown,
    before?: State['actor'],
  ): Promise<never> {
    if (!current(attempt)) throw new SupersededRead();
    if (before && actor.current && !sameActor(before, actor.current))
      cause = new UnknownReadContext();
    if (!(cause instanceof UnknownReadContext) && before) {
      try {
        if (!sameActor(before, await readActor(attempt))) cause = new UnknownReadContext();
      } catch (error) {
        if (!current(attempt)) throw new SupersededRead();
        cause = error;
      }
    }
    const unknown = cause instanceof UnknownReadContext;
    if (unknown) hidePrivate();
    else {
      clearProjection(attempt.reader);
      if (before) {
        setContextKnown(true);
        if (attempt.reader === 'list') restoreReceipt(before);
      }
    }
    setReadStatus('');
    throw new Error(unknown ? contextUnavailable : readUnavailable);
  }
  async function projection<T>(
    reader: Reader,
    url: string,
    schema: z.ZodType<T>,
    matches: (value: T, actor: State['actor']) => boolean,
    apply: (value: T) => void,
  ) {
    const attempt = startRead(reader);
    const expectedActor = actor.current;
    let before: State['actor'] | undefined;
    try {
      before = await readActor(attempt);
      if (!sameActor(before, expectedActor)) throw new UnknownReadContext();
      const value = schema.parse(await readJson(url, attempt));
      const after = await readActor(attempt);
      if (!sameActor(before, after) || !sameActor(before, actor.current))
        throw new UnknownReadContext();
      if (!matches(value, before)) throw new Error(readUnavailable);
      apply(value);
    } catch (cause) {
      return failRead(attempt, cause, before);
    }
  }
  async function runRead(work: () => Promise<unknown>) {
    if (locked.current || !mounted.current) return;
    invalidate();
    const owner = {};
    manualRead.current = owner;
    locked.current = true;
    setBusy(true);
    setError('');
    setReadStatus('Reading directory state.');
    try {
      await work();
    } catch (cause) {
      if (mounted.current && !(cause instanceof SupersededRead))
        setError(cause instanceof Error ? cause.message : readUnavailable);
    } finally {
      if (manualRead.current === owner) {
        manualRead.current = undefined;
        locked.current = false;
        if (mounted.current) {
          setBusy(false);
          setReadStatus('');
        }
      }
    }
  }
  function cancelManualRead() {
    if (!manualRead.current) return;
    manualRead.current = undefined;
    locked.current = false;
    if (mounted.current) setBusy(false);
  }
  function selectRead(reader: Reader) {
    invalidate();
    cancelManualRead();
    clearProjection(reader);
    setReadStatus('');
    setError('');
  }
  function save(value: DirectoryReview) {
    if (!actor.current) return;
    setReview(value);
    writeBoundPolicyState(storageKey, actor.current, value);
  }
  function adopt(value: State) {
    if (JSON.stringify(actor.current) !== JSON.stringify(value.actor)) {
      setMessage('');
      setConnectorId('');
      setProfileId('');
      setDisplayName('');
      setExternalId('');
      setPrincipalId('');
      setMemberName('');
      setChecker('');
      setReason('');
      setGroupId('');
      setExternalGroupId('');
      setLookupId('');
      setLookupExternal('');
      setLookupGroupId('');
      actor.current = value.actor;
      setReview(
        readBoundPolicyState(
          storageKey,
          value.actor,
          (stored): stored is DirectoryReview => savedDirectoryReview.safeParse(stored).success,
        ),
      );
      setReadback(undefined);
      setMember(undefined);
      setGroupResult(undefined);
    }
    setState(value);
    setContextKnown(true);
    setDisplayedReview(reviewEvidence.current);
    restoreReceipt(value.actor);
    return value;
  }
  async function load(selected = lane, cursor?: string) {
    const attempt = startRead('list');
    const cursorActor = cursor ? actor.current : undefined;
    let before: State['actor'] | undefined;
    try {
      before = await readActor(attempt);
      if (cursor && !sameActor(before, cursorActor)) throw new UnknownReadContext();
      const value = directoryState.parse(
        await readJson(
          `${endpoint}?${new URLSearchParams({ lane: selected, ...(cursor ? { cursor } : {}) })}`,
          attempt,
        ),
      );
      const after = await readActor(attempt);
      if (!sameActor(before, value.actor) || !sameActor(before, after))
        throw new UnknownReadContext();
      const principalRef = `urn:openpc:resource:${before.principalId}`;
      if (
        !value.approvals.every(
          (item) =>
            (selected === 'maker' ? item.makerSubjectRef : item.checkerSubjectRef) === principalRef,
        )
      )
        throw new Error(readUnavailable);
      return adopt(value);
    } catch (cause) {
      return failRead(attempt, cause, before);
    }
  }
  useEffect(() => {
    mounted.current = true;
    void load('checker').catch((cause: unknown) => {
      if (mounted.current && !(cause instanceof SupersededRead))
        setError(cause instanceof Error ? cause.message : readUnavailable);
    });
    window.addEventListener('blur', hidePrivate);
    return () => {
      mounted.current = false;
      invalidate();
      window.removeEventListener('blur', hidePrivate);
    };
  }, []);
  useEffect(() => {
    if (error) alert.current?.focus();
  }, [error]);
  async function run(work: () => Promise<void>) {
    if (locked.current) return;
    locked.current = true;
    invalidate();
    setBusy(true);
    setError('');
    setMessage('');
    try {
      await work();
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : 'Read the saved operation before retrying.',
      );
    } finally {
      locked.current = false;
      setBusy(false);
    }
  }
  async function post(body: unknown) {
    return json(
      await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
    );
  }
  async function readSaved(selectedId?: string) {
    const id = selectedId ?? review?.review.resourceId;
    if (!id) return;
    if (!selectedId && review && 'observation' in review.review.candidate)
      return readSavedGroup(id);
    if (!z.uuid().safeParse(id).success) {
      selectRead('connector');
      throw new Error(readUnavailable);
    }
    await projection(
      'connector',
      `${endpoint}?connectorId=${encodeURIComponent(id)}`,
      directoryReadback,
      (value, bound) =>
        value.effect.connectorId === id && value.effect.participantId === bound.participantId,
      (result) => {
        setReadback(result);
        setLookupId(id);
      },
    );
  }
  async function readSavedGroup(id: string, cursor?: string) {
    if (!z.uuid().safeParse(id).success || (cursor && !z.uuid().safeParse(cursor).success)) {
      selectRead('group');
      throw new Error(readUnavailable);
    }
    await projection(
      'group',
      `${endpoint}?${new URLSearchParams({ groupId: id, ...(cursor ? { cursor } : {}) })}`,
      directoryGroupReadback,
      (result, bound) =>
        result.group.effect.groupId === id &&
        result.group.effect.participantId === bound.participantId,
      (value) => {
        setGroupResult(value);
        setLookupGroupId(id);
      },
    );
  }
  async function prepare() {
    if (!state) return;
    const input =
      change === 'MAP_DIRECTORY' || change === 'REFRESH_DIRECTORY'
        ? { mutation: change, groupId, connectorId, externalGroupId }
        : change === 'PROVISION' || change === 'RECONCILE'
          ? {
              mode: change,
              connectorId,
              members: [{ externalId, principalId, displayName: memberName }],
            }
          : change === 'CREATE' || change === 'CONFIGURE'
            ? {
                mutation: change,
                ...(connectorId ? { connectorId } : {}),
                ...(change === 'CREATE' ? { profileId } : {}),
                displayName,
                massChangeThreshold: Number(threshold),
                externalGroupFreshnessSeconds: Number(freshness),
              }
            : { mutation: change, connectorId };
    const next = savedDirectoryReview.parse(
      await post({
        command: 'PREPARE',
        input,
        checkerPrincipalId: checker,
        reason,
        expectedSessionId: state.actor.sessionId,
      }),
    );
    save(next);
    setConnectorId(
      'observation' in next.review.candidate
        ? next.review.candidate.connectorId
        : next.review.resourceId,
    );
    setReadback(undefined);
    setMember(undefined);
    setGroupResult(undefined);
    setMessage(
      'Review the exact change and provider observation, then request independent approval.',
    );
  }
  async function submit() {
    if (!review) return;
    const result = z
      .object({
        reviewToken: savedDirectoryReview.shape.reviewToken,
        review: savedDirectoryReview.shape.review,
        approval: z.object({ approvalRequestId: z.string() }),
      })
      .parse(await post({ command: 'SUBMIT', reviewToken: review.reviewToken }));
    save({
      reviewToken: result.reviewToken,
      review: result.review,
      approvalRequestId: result.approval.approvalRequestId.slice(-36),
    });
    setLane('maker');
    await load('maker');
    setMessage('Approval requested. The assigned checker reviews it in their own session.');
  }
  async function commit() {
    if (!review?.approvalRequestId) return;
    const fresh = await load('maker');
    if (
      !fresh.approvals.some(
        (item) =>
          item.approvalRequestId.endsWith(review.approvalRequestId!) &&
          item.proposal.state === 'CONSUMED',
      )
    )
      await performWebAuthnStepUp(
        { ...review.review.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
        review.review.stepUp,
      );
    let response: Response;
    try {
      response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command: 'COMMIT',
          reviewToken: review.reviewToken,
          approvalRequestId: review.approvalRequestId,
        }),
      });
    } catch {
      setMessage(
        'The commit response was lost. Sign in again if needed, refresh requested approvals, and read the saved connector before retrying.',
      );
      return;
    }
    const result = z
      .object({
        truthState: z.enum(['SUCCESS', 'WRITE_AMBIGUITY']),
        operationId: z.uuid().optional(),
        readback: z.union([directoryReadback, directoryGroupReadback]).optional(),
        requiresReauthentication: z.boolean().optional(),
      })
      .parse(await json(response));
    if (result.readback) {
      if ('group' in result.readback) {
        setGroupResult(result.readback);
        setLookupGroupId(result.readback.group.effect.groupId);
      } else {
        setReadback(result.readback);
        setLookupId(result.readback.effect.connectorId);
      }
    }
    setMessage(
      result.truthState === 'SUCCESS'
        ? `Directory change committed. Operation: ${result.operationId}${result.requiresReauthentication ? ' Sign in again to read current memberships.' : ''}`
        : 'The commit outcome is uncertain. Refresh requested approvals and read the saved connector before retrying.',
    );
    retainReceipt(result, review.reviewToken);
    if (!result.requiresReauthentication)
      await load('maker').catch(() => {
        setError(
          'The operation result above is retained. Sign in again to refresh current authority.',
        );
      });
  }
  const consumed = state?.approvals.some(
    (item) =>
      item.approvalRequestId.endsWith(review?.approvalRequestId ?? 'no-request') &&
      item.proposal.state === 'CONSUMED',
  );
  return (
    <section aria-label="Directory governance" className="grid min-w-0 gap-4">
      <LocalSessionSurface />
      <div className={panel}>
        <h2 className="text-xl font-semibold">Directory connectors and members</h2>
        <p>
          Review registered directory changes with an independent checker. Imported members require
          governed activation and explicit permissions.
        </p>
        <p>
          Approved direct directory groups can constrain local assignments. Create an empty local
          group first, and activate each linked member through its governed owner.
        </p>
        <p>
          A provider outage or missing result never deletes a local membership. A reviewed disabled
          account is offboarded.
        </p>
        {state && (
          <p className="[overflow-wrap:anywhere] text-sm">
            Signed-in principal: {state.actor.principalId}
          </p>
        )}
      </div>
      {error && (
        <p
          ref={alert}
          tabIndex={-1}
          role="alert"
          className="break-words text-[color:var(--danger)]"
        >
          {error}
        </p>
      )}
      {contextKnown && message && (
        <p role="status" className="[overflow-wrap:anywhere]">
          {message}
        </p>
      )}
      {readStatus && <p role="status">{readStatus}</p>}
      {state && (
        <form
          className={`${panel} grid gap-3`}
          onSubmit={(event) => {
            event.preventDefault();
            void run(prepare);
          }}
        >
          <h3 className="font-semibold">Prepare a directory change</h3>
          <label>
            Change
            <select
              className={field}
              value={change}
              disabled={busy}
              onChange={(event) => setChange(event.target.value as Change)}
            >
              {Object.entries(changes).map(([key, label]) => (
                <option key={key} value={key}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Connector ID
            <input
              className={field}
              required={change !== 'CREATE'}
              placeholder={
                change === 'CREATE' ? 'Generated when you prepare the change' : undefined
              }
              value={connectorId}
              onChange={(event) => setConnectorId(event.target.value)}
            />
          </label>
          {change === 'CREATE' && (
            <label>
              Registered directory profile
              <select
                className={field}
                required
                value={profileId}
                onChange={(event) => setProfileId(event.target.value)}
              >
                <option value="">Select a registered profile</option>
                {state?.profiles.map((profile) => (
                  <option key={profile.profileId} value={profile.profileId}>
                    {profile.label}
                  </option>
                ))}
              </select>
              {state?.profiles.length === 0 && (
                <span>No profiles are registered for this Participant.</span>
              )}
            </label>
          )}
          {(change === 'CREATE' || change === 'CONFIGURE') && (
            <>
              <label>
                Connector name
                <input
                  className={field}
                  required
                  maxLength={160}
                  value={displayName}
                  onChange={(event) => setDisplayName(event.target.value)}
                />
              </label>
              <label>
                Mass-change threshold (%)
                <input
                  className={field}
                  type="number"
                  required
                  min={0}
                  max={100}
                  value={threshold}
                  onChange={(event) => setThreshold(event.target.value)}
                />
              </label>
              <label>
                Maximum external group age (seconds)
                <input
                  className={field}
                  type="number"
                  required
                  min={60}
                  max={86400}
                  value={freshness}
                  onChange={(event) => setFreshness(event.target.value)}
                />
              </label>
            </>
          )}
          {(change === 'PROVISION' || change === 'RECONCILE') && (
            <>
              <label>
                Exact provider user ID
                <input
                  className={field}
                  required
                  maxLength={512}
                  value={externalId}
                  onChange={(event) => setExternalId(event.target.value)}
                />
              </label>
              <label>
                Local member principal ID
                <input
                  className={field}
                  required
                  value={principalId}
                  onChange={(event) => setPrincipalId(event.target.value)}
                />
              </label>
              <label>
                Local member display name
                <input
                  className={field}
                  required
                  maxLength={160}
                  value={memberName}
                  onChange={(event) => setMemberName(event.target.value)}
                />
              </label>
              <p>
                The provider must explicitly bind its immutable SCIM user ID to the registered OIDC
                subject.
              </p>
            </>
          )}
          {(change === 'MAP_DIRECTORY' || change === 'REFRESH_DIRECTORY') && (
            <>
              <label>
                Local group ID
                <input
                  className={field}
                  required
                  value={groupId}
                  onChange={(event) => setGroupId(event.target.value)}
                />
              </label>
              <label>
                Exact provider group ID
                <input
                  className={field}
                  required
                  maxLength={512}
                  value={externalGroupId}
                  onChange={(event) => setExternalGroupId(event.target.value)}
                />
              </label>
              <p>
                Use the immutable provider group ID. Nested groups and unknown or inactive local
                members cannot be projected.
              </p>
            </>
          )}
          <label>
            Checker principal ID
            <input
              className={field}
              required
              value={checker}
              onChange={(event) => setChecker(event.target.value)}
            />
          </label>
          <label>
            Reason for directory change
            <textarea
              className={field}
              required
              minLength={10}
              maxLength={1024}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </label>
          <button className={button} disabled={busy || !state}>
            Prepare directory change
          </button>
        </form>
      )}
      {state && review && (
        <div
          aria-label="Directory change review"
          className={`${panel} grid gap-3 [overflow-wrap:anywhere]`}
        >
          <h3 className="font-semibold">Review directory change</h3>
          <Candidate candidate={review.review.candidate} />
          <p>Resource revision: {review.review.expectedRevision}</p>
          <p>Checker: {review.review.checkerPrincipalId}</p>
          <p>Reason: {review.review.reason}</p>
          <p>
            Review expires:{' '}
            <time dateTime={review.review.expiresAt}>{review.review.expiresAt}</time>
          </p>
          {review.approvalRequestId && <p>Approval request: {review.approvalRequestId}</p>}
          <details>
            <summary>Verification digest</summary>
            {review.review.candidateDigest}
          </details>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className={button}
              disabled={busy || !!review.approvalRequestId || consumed}
              onClick={() => void run(submit)}
            >
              Request directory approval
            </button>
            <button
              type="button"
              className={button}
              disabled={busy || !review.approvalRequestId || consumed}
              onClick={() => void run(commit)}
            >
              Verify and commit directory change
            </button>
            <button
              type="button"
              className={button}
              disabled={busy}
              onClick={() =>
                void runRead(async () => {
                  await load('maker');
                  await readSaved();
                })
              }
            >
              {review && 'observation' in review.review.candidate
                ? 'Read saved group'
                : 'Read saved connector'}
            </button>
          </div>
        </div>
      )}
      {state && (
        <div className={`${panel} grid gap-3`}>
          <h3 className="font-semibold">Read saved directory state</h3>
          <label>
            Saved local group ID
            <input
              className={field}
              value={lookupGroupId}
              onChange={(event) => {
                selectRead('group');
                setLookupGroupId(event.target.value);
              }}
            />
          </label>
          <button
            type="button"
            className={button}
            disabled={busy || !lookupGroupId}
            onClick={() =>
              void runRead(async () => {
                await load();
                await readSavedGroup(lookupGroupId);
              })
            }
          >
            Read directory group
          </button>
          {groupResult && <DirectoryGroupResult value={groupResult} />}
          {groupResult?.group.nextCursor && (
            <button
              type="button"
              className={button}
              disabled={busy}
              onClick={() =>
                void runRead(() =>
                  readSavedGroup(groupResult.group.effect.groupId, groupResult.group.nextCursor!),
                )
              }
            >
              Next group membership page
            </button>
          )}
          <label>
            Saved connector ID
            <input
              className={field}
              value={lookupId}
              onChange={(event) => {
                selectRead('connector');
                selectRead('member');
                setLookupId(event.target.value);
              }}
            />
          </label>
          <button
            type="button"
            className={button}
            disabled={busy || !lookupId}
            onClick={() =>
              void runRead(async () => {
                await load();
                await readSaved(lookupId);
              })
            }
          >
            Read connector
          </button>
          {readback && (
            <div aria-label="Directory result" className="grid gap-1 [overflow-wrap:anywhere]">
              <p>Connector: {readback.effect.displayName}</p>
              <p>ID: {readback.effect.connectorId}</p>
              <p>
                State: {readback.effect.state} · revision {readback.effect.revision}
              </p>
              <p>Operation: {readback.effect.operationId}</p>
              <p>Mass-change threshold: {readback.effect.massChangeThreshold}%</p>
            </div>
          )}
          <label>
            Saved provider user ID
            <input
              className={field}
              value={lookupExternal}
              onChange={(event) => {
                selectRead('member');
                setLookupExternal(event.target.value);
              }}
            />
          </label>
          <button
            type="button"
            className={button}
            disabled={busy || !lookupId || !lookupExternal}
            onClick={() =>
              void runRead(async () => {
                await load();
                if (
                  !z.uuid().safeParse(lookupId).success ||
                  !directoryMemberReadback.shape.binding.shape.externalId.safeParse(lookupExternal)
                    .success
                )
                  throw new Error(readUnavailable);
                await projection(
                  'member',
                  `${endpoint}?${new URLSearchParams({ connectorId: lookupId, externalId: lookupExternal })}`,
                  directoryMemberReadback,
                  (value, bound) =>
                    value.binding.participantId === bound.participantId &&
                    value.binding.connectorId === lookupId &&
                    value.binding.externalId === lookupExternal &&
                    value.binding.principalId === value.membership.principalId,
                  setMember,
                );
              })
            }
          >
            Read directory member
          </button>
          {member && (
            <div
              aria-label="Directory member result"
              className="grid gap-1 [overflow-wrap:anywhere]"
            >
              <p>Member: {member.membership.displayLabel}</p>
              <p>Principal: {member.binding.principalId}</p>
              <p>Local state: {member.membership.state}</p>
              <p>Directory binding: {member.binding.state}</p>
              <p>Provider version: {member.binding.providerVersion}</p>
              <p>Last observation: {member.binding.observedAt}</p>
              <p>Operation: {member.binding.operationId}</p>
            </div>
          )}
        </div>
      )}
      <div className={`${panel} grid gap-3`}>
        <h3 className="font-semibold">Directory approvals</h3>
        <label>
          Approval lane
          <select
            className={field}
            value={lane}
            disabled={busy}
            onChange={(event) => {
              const selected = event.target.value as typeof lane;
              selectRead('list');
              setLane(selected);
              void runRead(async () => {
                await load(selected);
              });
            }}
          >
            <option value="checker">Assigned to me</option>
            <option value="maker">Requested by me</option>
          </select>
        </label>
        <button
          type="button"
          className={button}
          disabled={busy}
          onClick={() =>
            void runRead(async () => {
              await load();
            })
          }
        >
          Refresh directory approvals
        </button>
        {state?.approvals.length === 0 && <p>No directory approvals on this page.</p>}
        {state?.approvals.map((item) => (
          <article
            key={item.approvalRequestId}
            className={`${panel} grid gap-2 [overflow-wrap:anywhere]`}
          >
            <h4 className="font-semibold">Directory change · {item.state}</h4>
            <p>Approval request: {item.approvalRequestId}</p>
            <p>Maker: {item.makerSubjectRef}</p>
            <p>Reason: {item.proposal.approval?.reason}</p>
            <Candidate candidate={item.proposal.candidate} />
            <p>Operation: {item.proposal.operationId ?? 'Not committed'}</p>
            {lane === 'checker' && (
              <button
                type="button"
                className={button}
                disabled={busy || item.state !== 'REQUESTED'}
                onClick={() =>
                  void run(async () => {
                    await performWebAuthnStepUp(
                      { ...item.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
                      item.stepUp,
                    );
                    await post({
                      command: 'APPROVE',
                      approvalRequestId: item.approvalRequestId.slice(-36),
                      candidateDigest: item.candidateDigest,
                      expectedRevision: item.revision,
                      group: 'observation' in item.proposal.candidate,
                    });
                    await load('checker');
                    setMessage(
                      'Directory change approved. The maker must commit the reviewed change.',
                    );
                  })
                }
              >
                Approve directory change
              </button>
            )}
          </article>
        ))}
        {state?.nextCursor && (
          <button
            type="button"
            className={button}
            disabled={busy}
            onClick={() =>
              void runRead(async () => {
                await load(lane, state.nextCursor!);
              })
            }
          >
            Next approvals
          </button>
        )}
      </div>
    </section>
  );
}
