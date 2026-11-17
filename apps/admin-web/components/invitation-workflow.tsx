'use client';
import { useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import {
  invitationActor,
  invitationCandidate,
  invitationRecord,
  invitationState,
  savedInvitationReview,
} from '../lib/invitation-workflow';
import { readBoundPolicyState, writeBoundPolicyState } from './policy-workflow-storage';
import { LocalSessionSurface } from './local-session';
const endpoint = '/api/v1/ui/invitation-workbench',
  storage = 'openpc:invitation-workflow:v1';
const panel =
  'grid min-w-0 gap-3 rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const field =
  'min-w-0 w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 text-[color:var(--surface)] disabled:opacity-60';
type State = z.infer<typeof invitationState>;
type Saved = z.infer<typeof savedInvitationReview>;
type ReadAttempt = { version: number; controller: AbortController };
class SupersededRead extends Error {}
class InvitationWorkflowFailure extends Error {}
function safeFailure(cause: unknown, fallback: string) {
  return cause instanceof InvitationWorkflowFailure ? cause.message : fallback;
}
async function json(response: Response): Promise<unknown> {
  if (!response.ok)
    throw new InvitationWorkflowFailure(
      response.status === 401 || response.status === 403
        ? 'The invitation request was not authorized. Refresh the authenticated context before continuing.'
        : response.status === 409 || response.status === 412
          ? 'The invitation request could not continue with the current state. Read the invitation before retrying.'
          : 'The invitation request could not be completed. Read its current state before retrying.',
    );
  return response.json().catch(() => {
    throw new InvitationWorkflowFailure(
      'The invitation response is invalid. Refresh before continuing.',
    );
  });
}
function Candidate({ candidate }: { candidate: z.infer<typeof invitationCandidate> }) {
  const change = candidate.change;
  return (
    <div className="grid gap-1 [overflow-wrap:anywhere]">
      <p>Change: {change.mutation}</p>
      <p>Invitation: {change.invitationId}</p>
      {'displayName' in change && (
        <>
          <p>Name: {change.displayName}</p>
          <p>Exact recipient account: {change.recipientSubject}</p>
          <p>Intended role: {change.intendedRoleId}</p>
        </>
      )}
      <p>Identity provider: {candidate.issuer}</p>
      <p>Audience: {candidate.audience}</p>
      {'ttlSeconds' in change && <p>Validity: {change.ttlSeconds / 60} minutes</p>}
      <p>
        {change.mutation === 'REVOKE'
          ? 'Revocation permanently prevents acceptance.'
          : 'Acceptance creates or reuses a membership. This request grants no role or permissions.'}
      </p>
    </div>
  );
}
export function InvitationWorkflow() {
  const [state, setState] = useState<State>(),
    [review, setReview] = useState<Saved>();
  const [record, setRecord] = useState<z.infer<typeof invitationRecord>>();
  const [mutation, setMutation] = useState<'CREATE' | 'RESEND' | 'REVOKE'>('CREATE');
  const [invitationId, setInvitationId] = useState(''),
    [displayName, setDisplayName] = useState(''),
    [subject, setSubject] = useState('');
  const [roleId, setRoleId] = useState(''),
    [ttl, setTtl] = useState('1440'),
    [checkerId, setCheckerId] = useState(''),
    [reason, setReason] = useState('');
  const [lookup, setLookup] = useState(''),
    [lane, setLane] = useState<'maker' | 'checker'>('checker');
  const [loadedLane, setLoadedLane] = useState<'maker' | 'checker'>();
  const [governedBusy, setGovernedBusy] = useState(false);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [message, setMessage] = useState(''),
    [link, setLink] = useState('');
  const actor = useRef<State['actor'] | undefined>(undefined),
    locked = useRef(false);
  const mounted = useRef(false),
    generation = useRef(0),
    controller = useRef<AbortController | undefined>(undefined),
    refreshPending = useRef(false),
    selectedLane = useRef<'maker' | 'checker'>('checker');
  const token = useRef<{ raw: string; digest: string } | undefined>(undefined);
  function adopt(value: State) {
    if (JSON.stringify(actor.current) !== JSON.stringify(value.actor)) {
      actor.current = value.actor;
      token.current = undefined;
      setLink('');
      setRecord(undefined);
      setLookup('');
      setReview(
        readBoundPolicyState(
          storage,
          value.actor,
          (saved): saved is Saved => savedInvitationReview.safeParse(saved).success,
        ),
      );
    }
    setState(value);
    return value;
  }
  function invalidateRead() {
    generation.current++;
    controller.current?.abort();
    controller.current = undefined;
  }
  function startRead(): ReadAttempt {
    invalidateRead();
    const next = new AbortController();
    controller.current = next;
    return { version: generation.current, controller: next };
  }
  function current(attempt: ReadAttempt) {
    return (
      mounted.current &&
      generation.current === attempt.version &&
      !attempt.controller.signal.aborted
    );
  }
  async function readJson(url: string, attempt: ReadAttempt) {
    if (!current(attempt)) throw new SupersededRead();
    const response = await fetch(url, { cache: 'no-store', signal: attempt.controller.signal });
    if (!current(attempt)) throw new SupersededRead();
    const value = await json(response);
    if (!current(attempt)) throw new SupersededRead();
    return value;
  }
  function purgeVisible() {
    setState(undefined);
    setLoadedLane(undefined);
    setRecord(undefined);
    setLink('');
    setMessage('');
    // Keep original actor-bound review/token custody until an authoritative actor change.
  }
  function failRead(attempt: ReadAttempt, cause: unknown) {
    if (!current(attempt)) return;
    purgeVisible();
    setError(
      safeFailure(cause, 'The invitation response is unavailable. Refresh before continuing.'),
    );
  }
  async function load(selected = lane, cursor?: string, attempt = startRead()) {
    try {
      const parsed = invitationState.safeParse(
        await readJson(
          `${endpoint}?${new URLSearchParams({ lane: selected, ...(cursor ? { cursor } : {}) })}`,
          attempt,
        ),
      );
      if (!current(attempt)) throw new SupersededRead();
      if (!parsed.success)
        throw new InvitationWorkflowFailure(
          'The invitation response is invalid. Refresh before continuing.',
        );
      const value = adopt(parsed.data);
      setLoadedLane(selected);
      return value;
    } catch (cause) {
      failRead(attempt, cause);
      throw cause;
    }
  }
  function refresh() {
    if (!mounted.current) return;
    if (locked.current) {
      refreshPending.current = true;
      return;
    }
    const attempt = startRead();
    setBusy(false);
    setError('');
    void load(selectedLane.current, undefined, attempt).catch(() => {
      // load reports only the current failure; superseded reads have no visible effects.
    });
  }
  useEffect(() => {
    mounted.current = true;
    refresh();
    window.addEventListener('focus', refresh);
    return () => {
      mounted.current = false;
      invalidateRead();
      window.removeEventListener('focus', refresh);
    };
  }, []);
  async function ensureActor(expected: State['actor']) {
    const session = z
      .object({ authenticated: z.boolean(), contextMode: z.string() })
      .passthrough()
      .parse(await fetch('/api/v1/ui/local-session', { cache: 'no-store' }).then(json));
    const current = invitationActor.strip().safeParse(session);
    if (
      !session.authenticated ||
      session.contextMode !== 'PARTICIPANT' ||
      !current.success ||
      JSON.stringify(current.data) !== JSON.stringify(expected)
    ) {
      token.current = undefined;
      setLink('');
      setRecord(undefined);
      setReview(undefined);
      throw new InvitationWorkflowFailure(
        'The session or context changed. Refresh before continuing.',
      );
    }
  }
  function save(value: Saved) {
    if (actor.current) {
      setReview(value);
      writeBoundPolicyState(storage, actor.current, value);
    }
  }
  async function run(work: () => Promise<void>) {
    if (locked.current || !mounted.current) return;
    locked.current = true;
    invalidateRead();
    setGovernedBusy(true);
    setBusy(true);
    setError('');
    setMessage('');
    try {
      await work();
    } catch (cause) {
      if (mounted.current)
        setError(
          safeFailure(
            cause,
            'The operation is unavailable. Read its current state before retrying.',
          ),
        );
    } finally {
      locked.current = false;
      if (mounted.current) {
        setGovernedBusy(false);
        setBusy(false);
        if (refreshPending.current) {
          refreshPending.current = false;
          refresh();
        }
      }
    }
  }
  async function runRead(work: (attempt: ReadAttempt) => Promise<unknown>) {
    if (locked.current || !mounted.current) return;
    const attempt = startRead();
    setBusy(true);
    setError('');
    setMessage('');
    try {
      await work(attempt);
    } catch (cause) {
      failRead(attempt, cause);
    } finally {
      if (current(attempt)) setBusy(false);
    }
  }
  const post = (body: unknown) =>
    fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(json);
  async function prepare() {
    const current = await load();
    await ensureActor(current.actor);
    setLink('');
    setRecord(undefined);
    let secret: typeof token.current;
    if (mutation !== 'REVOKE') {
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      const raw = btoa(String.fromCharCode(...bytes))
        .replaceAll('+', '-')
        .replaceAll('/', '_')
        .replaceAll('=', '');
      const hashed = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw));
      secret = {
        raw,
        digest: `sha256:${Array.from(new Uint8Array(hashed), (byte) => byte.toString(16).padStart(2, '0')).join('')}`,
      };
    }
    const input =
      mutation === 'CREATE'
        ? {
            mutation,
            displayName,
            recipientSubject: subject,
            intendedRoleId: roleId,
            tokenDigest: secret!.digest,
            ttlSeconds: Number(ttl) * 60,
          }
        : mutation === 'RESEND'
          ? { mutation, invitationId, tokenDigest: secret!.digest, ttlSeconds: Number(ttl) * 60 }
          : { mutation, invitationId };
    const value = savedInvitationReview.parse(
      await post({
        command: 'PREPARE',
        input,
        reason,
        checkerPrincipalId: checkerId,
        expectedSessionId: current.actor.sessionId,
      }),
    );
    await ensureActor(current.actor);
    token.current = secret;
    save(value);
    setLookup(value.review.resourceId);
    setMessage(
      'Review the recipient, intended role and validity before requesting independent approval.',
    );
  }
  async function submit() {
    if (!review || !actor.current) return;
    const expected = actor.current;
    await ensureActor(expected);
    const value = savedInvitationReview
      .extend({ approval: z.object({ approvalRequestId: z.string() }) })
      .parse(await post({ command: 'SUBMIT', reviewToken: review.reviewToken }));
    await ensureActor(expected);
    save({
      reviewToken: value.reviewToken,
      review: value.review,
      approvalRequestId: value.approval.approvalRequestId.slice(-36),
    });
    setMessage('Independent approval requested. The invitation has not been issued yet.');
  }
  async function commit() {
    if (!review?.approvalRequestId || !actor.current) return;
    const expected = actor.current;
    await ensureActor(expected);
    const step = review.review.stepUp;
    await performWebAuthnStepUp({ ...step, stepUp: 'FRESH_WEBAUTHN_MAX_5M' }, step);
    const result = z
      .strictObject({
        truthState: z.literal('SUCCESS'),
        operationId: z.uuid(),
        readback: z.strictObject({ effect: invitationRecord }),
      })
      .parse(
        await post({
          command: 'COMMIT',
          reviewToken: review.reviewToken,
          approvalRequestId: review.approvalRequestId,
        }),
      );
    await ensureActor(expected);
    setRecord(result.readback.effect);
    setMessage(`Committed operation ${result.operationId}.`);
    setLink('');
    const change = review.review.candidate.change,
      effect = result.readback.effect;
    if (
      'tokenDigest' in change &&
      token.current?.digest === change.tokenDigest &&
      effect.state === 'PENDING' &&
      effect.operationId === result.operationId &&
      effect.revision === String(BigInt(review.review.expectedRevision) + 1n)
    ) {
      const target = new URL(
        '/govern/memberships?view=invitation-acceptance',
        window.location.origin,
      );
      target.hash = new URLSearchParams({
        invitationId: effect.invitationId,
        participantId: effect.participantId,
        privacyDomainId: effect.privacyDomainId,
        tokenVersion: effect.tokenVersion,
        token: token.current.raw,
      }).toString();
      setLink(target.href);
    }
  }
  async function read(attempt: ReadAttempt) {
    if (!actor.current) return;
    const expected = actor.current;
    const target = z.uuidv7().safeParse(lookup);
    setRecord(undefined);
    if (!target.success)
      throw new InvitationWorkflowFailure('Enter a valid invitation ID to read.');
    const parsed = z
      .strictObject({ actor: invitationActor, effect: invitationRecord })
      .safeParse(await readJson(`${endpoint}?invitationId=${target.data}`, attempt));
    if (!current(attempt)) return;
    if (!parsed.success)
      throw new InvitationWorkflowFailure(
        'The invitation response is invalid. Refresh before continuing.',
      );
    const result = parsed.data;
    const session = z
      .object({ authenticated: z.boolean(), contextMode: z.string() })
      .passthrough()
      .safeParse(await readJson('/api/v1/ui/local-session', attempt));
    if (!current(attempt)) return;
    if (!session.success)
      throw new InvitationWorkflowFailure('The session is unavailable. Refresh before continuing.');
    const latest = invitationActor.strip().safeParse(session.data);
    if (
      !session.data.authenticated ||
      session.data.contextMode !== 'PARTICIPANT' ||
      !latest.success ||
      JSON.stringify(latest.data) !== JSON.stringify(expected)
    ) {
      token.current = undefined;
      setLink('');
      setRecord(undefined);
      setReview(undefined);
      throw new InvitationWorkflowFailure(
        'The session or context changed. Refresh before continuing.',
      );
    }
    if (
      JSON.stringify(result.actor) !== JSON.stringify(expected) ||
      result.effect.invitationId !== target.data ||
      result.effect.participantId !== expected.participantId ||
      result.effect.privacyDomainId !== expected.privacyDomainId
    )
      throw new InvitationWorkflowFailure('Readback does not match this context.');
    setRecord(result.effect);
    setLink('');
  }
  async function approve(item: State['approvals'][number]) {
    if (!actor.current) return;
    const expected = actor.current;
    await ensureActor(expected);
    await performWebAuthnStepUp({ ...item.stepUp, stepUp: 'FRESH_WEBAUTHN_MAX_5M' }, item.stepUp);
    await post({
      command: 'APPROVE',
      approvalRequestId: item.approvalRequestId.slice(-36),
      candidateDigest: item.candidateDigest,
      expectedRevision: item.revision,
    });
    await ensureActor(expected);
    await load();
    setMessage('Approval recorded. The maker must commit the reviewed invitation.');
  }
  const approvalPage = loadedLane === lane ? state : undefined;
  return (
    <section className="mt-6 grid min-w-0 gap-4" aria-labelledby="invitations-heading">
      <h2 id="invitations-heading" className="text-xl font-semibold">
        Participant invitations
      </h2>
      <LocalSessionSurface />
      <p>
        Choose an exact provider account and intended role. Issuance and changes require independent
        approval. Acceptance does not activate a new membership or grant access.
      </p>
      {error && (
        <p
          role="alert"
          className="rounded border border-[color:var(--border)] p-3 [overflow-wrap:anywhere]"
        >
          {error}
        </p>
      )}
      <p role="status" className="[overflow-wrap:anywhere]">
        {message}
      </p>
      {!state && (
        <button className={button} disabled={busy} onClick={refresh}>
          Refresh invitations
        </button>
      )}
      {state && (
        <>
          <p className="[overflow-wrap:anywhere]">
            Participant: {state.actor.participantId} · Privacy domain: {state.actor.privacyDomainId}
          </p>
          <form
            className={panel}
            onSubmit={(event) => {
              event.preventDefault();
              void run(prepare);
            }}
          >
            <h3 className="font-semibold">Prepare invitation</h3>
            <label className="grid gap-1">
              Change
              <select
                value={mutation}
                onChange={(event) => setMutation(event.target.value as typeof mutation)}
                className={field}
                disabled={busy}
              >
                <option value="CREATE">Create invitation</option>
                <option value="RESEND">Resend with a new token</option>
                <option value="REVOKE">Revoke invitation</option>
              </select>
            </label>
            {mutation === 'CREATE' ? (
              <>
                <label className="grid gap-1">
                  Recipient name
                  <input
                    required
                    value={displayName}
                    onChange={(event) => setDisplayName(event.target.value)}
                    className={field}
                    maxLength={160}
                  />
                </label>
                <label className="grid gap-1">
                  Exact provider account ID
                  <input
                    required
                    value={subject}
                    onChange={(event) => setSubject(event.target.value)}
                    className={field}
                    maxLength={255}
                  />
                </label>
                <label className="grid gap-1">
                  Intended role ID
                  <input
                    required
                    value={roleId}
                    onChange={(event) => setRoleId(event.target.value)}
                    className={field}
                  />
                </label>
              </>
            ) : (
              <label className="grid gap-1">
                Invitation to change
                <input
                  required
                  value={invitationId}
                  onChange={(event) => setInvitationId(event.target.value)}
                  className={field}
                />
              </label>
            )}
            {mutation !== 'REVOKE' && (
              <label className="grid gap-1">
                Validity in minutes
                <input
                  required
                  type="number"
                  min="15"
                  max="10080"
                  value={ttl}
                  onChange={(event) => setTtl(event.target.value)}
                  className={field}
                />
              </label>
            )}
            <label className="grid gap-1">
              Independent checker principal ID
              <input
                required
                value={checkerId}
                onChange={(event) => setCheckerId(event.target.value)}
                className={field}
              />
            </label>
            <div className="grid gap-1">
              <label htmlFor="invitation-reason">Reason</label>
              <textarea
                id="invitation-reason"
                required
                minLength={10}
                maxLength={1024}
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                className={field}
              />
            </div>
            <button className={button} disabled={busy}>
              Prepare invitation
            </button>
          </form>
          {review && (
            <article className={panel} aria-label="Invitation review">
              <h3 className="font-semibold">Review invitation</h3>
              <Candidate candidate={review.review.candidate} />
              <p>Reason: {review.review.reason}</p>
              <p className="[overflow-wrap:anywhere]">
                Checker: {review.review.checkerPrincipalId}
              </p>
              <p>
                The secret stays in this tab. If you close or refresh the tab, issue a new token
                after checking the current invitation state.
              </p>
              <button
                className={button}
                disabled={busy || !!review.approvalRequestId}
                onClick={() => void run(submit)}
              >
                Request independent approval
              </button>
              {review.approvalRequestId && (
                <>
                  <p className="[overflow-wrap:anywhere]">Approval: {review.approvalRequestId}</p>
                  <button className={button} disabled={busy} onClick={() => void run(commit)}>
                    Commit approved invitation
                  </button>
                </>
              )}
            </article>
          )}
          {link && (
            <div className={panel}>
              <label className="grid gap-1">
                Invitation link
                <input
                  className={field}
                  readOnly
                  value={link}
                  onFocus={(event) => event.target.select()}
                />
              </label>
              <p>
                Share this secret link with the chosen recipient through your trusted channel. It is
                shown only in this tab.
              </p>
            </div>
          )}
          <form
            className={panel}
            onSubmit={(event) => {
              event.preventDefault();
              void runRead(read);
            }}
          >
            <h3 className="font-semibold">Read current invitation</h3>
            <label className="grid gap-1">
              Invitation ID
              <input
                required
                value={lookup}
                disabled={governedBusy}
                onChange={(event) => {
                  invalidateRead();
                  setBusy(false);
                  setError('');
                  setRecord(undefined);
                  setLookup(event.target.value);
                }}
                className={field}
              />
            </label>
            <button className={button} disabled={busy}>
              Read invitation
            </button>
          </form>
          {record && (
            <article className={`${panel} [overflow-wrap:anywhere]`} aria-label="Invitation state">
              <h3 className="font-semibold">Invitation state: {record.state}</h3>
              <p>Invitation: {record.invitationId}</p>
              <p>
                Recipient: {record.displayName} · {record.recipient.subject}
              </p>
              <p>Token version: {record.tokenVersion}</p>
              <p>Expires at: {record.expiresAt}</p>
              <p>Revision: {record.revision}</p>
              <p>Operation: {record.operationId}</p>
              <p>Intended role: {record.roleIntent.roleId} · No authority granted</p>
              {record.acceptance && (
                <>
                  <p>Accepted membership: {record.acceptance.membershipId}</p>
                  <p>Accepted at: {record.acceptance.acceptedAt}</p>
                  <a className="underline" href="/govern/memberships?view=principals">
                    Manage membership activation
                  </a>
                </>
              )}
            </article>
          )}
          <section className={panel} aria-label="Invitation approvals">
            <h3 className="font-semibold">Invitation approvals</h3>
            <label className="grid gap-1">
              Approval lane
              <select
                className={field}
                value={lane}
                disabled={governedBusy}
                onChange={(event) => {
                  const value = event.target.value as typeof lane;
                  selectedLane.current = value;
                  invalidateRead();
                  setBusy(false);
                  setError('');
                  setLoadedLane(undefined);
                  setRecord(undefined);
                  setLane(value);
                }}
              >
                <option value="checker">Assigned to me</option>
                <option value="maker">Requested by me</option>
              </select>
            </label>
            <button
              className={button}
              disabled={busy}
              onClick={() => void runRead((attempt) => load(lane, undefined, attempt))}
            >
              Refresh invitation approvals
            </button>
            {!approvalPage && <p>Refresh invitations to read the selected approval lane.</p>}
            {approvalPage?.approvals.length === 0 && <p>No invitations on this approval page.</p>}
            {approvalPage?.approvals.map((item) => (
              <article key={item.approvalRequestId} className={`${panel} [overflow-wrap:anywhere]`}>
                <h4 className="font-semibold">{item.state} invitation</h4>
                <Candidate candidate={item.proposal.candidate} />
                <p>Reason: {item.proposal.approval?.reason}</p>
                <p>Maker: {item.proposal.makerPrincipalId}</p>
                <p>Approval: {item.approvalRequestId.slice(-36)}</p>
                {lane === 'checker' && item.state === 'REQUESTED' && (
                  <button
                    className={button}
                    disabled={busy}
                    onClick={() => void run(() => approve(item))}
                  >
                    Approve invitation
                  </button>
                )}
              </article>
            ))}
            {approvalPage?.nextCursor && (
              <button
                className={button}
                disabled={busy}
                onClick={() =>
                  void runRead((attempt) => load(lane, approvalPage.nextCursor!, attempt))
                }
              >
                Next approval page
              </button>
            )}
          </section>
        </>
      )}
    </section>
  );
}
