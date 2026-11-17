'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { z } from 'zod';
import { accessReviewPage, type AccessReviewPage } from '../lib/access-review';
import { recoveryActor } from '../lib/recovery-workflow';
import { LocalSessionSurface } from './local-session';
import { WorkspaceEntry } from './workspace-entry';
import { SecondaryPanel } from './secondary-panel';

const responseSchema = z.strictObject({ actor: recoveryActor, page: accessReviewPage });
const sessionSchema = recoveryActor
  .partial()
  .extend({ authenticated: z.boolean(), contextMode: z.string().optional() })
  .passthrough();
type Session = z.infer<typeof sessionSchema>;
const panel =
  'min-w-0 rounded-2xl border border-[color:var(--border)] bg-[color:var(--surface)] p-5 sm:p-6';
const field =
  'min-h-11 min-w-0 rounded-xl border border-[color:var(--border)] bg-[color:var(--canvas)] px-3 py-2';
const button =
  'inline-flex min-h-11 w-fit items-center justify-center rounded-xl bg-[color:var(--accent)] px-4 py-2 font-medium text-[color:var(--on-primary)] disabled:opacity-60';
const accessStateLabels: Record<string, string> = {
  ACTIVE: 'Active',
  INACTIVE: 'Inactive',
  DISABLED: 'Disabled',
  SUSPENDED: 'Suspended',
  REVOKED: 'Revoked',
  RETIRED: 'Retired',
  DELETED: 'Deleted',
  PENDING: 'Pending',
};
const reasons: Record<string, string> = {
  ENVELOPE_NOT_ACTIVE: 'The authority envelope is inactive.',
  GRANT_NOT_ACTIVE: 'An assignment or delegation is inactive.',
  DELEGATION_NOT_CURRENT: 'The delegation no longer fits its parent authority.',
  ROLE_NOT_ACTIVE: 'The role is inactive.',
  GROUP_MEMBERSHIP_OR_DIRECTORY_NOT_CURRENT:
    'Group membership or its directory observation is not current.',
  PRINCIPAL_NOT_ACTIVE: 'A principal in this authority path is inactive.',
  NOT_YET_VALID: 'The grant is not yet valid.',
  VALIDITY_ENDED: 'The validity period has ended.',
  EMPTY_ADMINISTRATIVE_INTERSECTION: 'The current constraints leave no administrative access.',
};
function binding(session: Session) {
  const parsed = recoveryActor.strip().safeParse(session);
  return session.authenticated && session.contextMode === 'PARTICIPANT' && parsed.success
    ? parsed.data
    : undefined;
}
async function json(response: Response) {
  const value = await response.json().catch(() => undefined);
  if (!response.ok)
    throw new Error(
      `${value?.title ?? 'The review is unavailable.'}${value?.code ? ` (${value.code})` : ''}`,
    );
  return value;
}
type ReadAttempt = { version: number; controller: AbortController };
class SupersededRead extends Error {}
export function AccessReviewWorkflow() {
  const [session, setSession] = useState<Session>();
  const [subjectId, setSubjectId] = useState('');
  const [projection, setProjection] = useState<{
    actor: z.infer<typeof recoveryActor>;
    page: AccessReviewPage;
  }>();
  const [busy, setBusy] = useState(false),
    [status, setStatus] = useState('');
  const generation = useRef(0),
    controller = useRef<AbortController | undefined>(undefined),
    mounted = useRef(false),
    locked = useRef(false),
    refreshPending = useRef(false),
    bound = useRef<string | undefined>(undefined);
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
      attempt.version === generation.current &&
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
  async function readSession(attempt = startRead()) {
    const parsed = sessionSchema.safeParse(await readJson('/api/v1/ui/local-session', attempt));
    if (!current(attempt)) throw new SupersededRead();
    if (!parsed.success) throw new Error('The session is unavailable. Refresh before continuing.');
    const value = parsed.data;
    setSession(value);
    const key = JSON.stringify(binding(value));
    if (bound.current !== key) {
      setProjection(undefined);
      bound.current = key;
    }
    return value;
  }
  function failRead(attempt: ReadAttempt, cause: unknown, sessionUnknown = false) {
    if (!current(attempt)) return;
    setProjection(undefined);
    if (sessionUnknown) {
      setSession(undefined);
      bound.current = undefined;
    }
    setStatus(
      cause instanceof Error && !(cause instanceof z.ZodError)
        ? cause.message
        : 'The review is unavailable. Refresh before continuing.',
    );
  }
  function refresh() {
    if (!mounted.current) return;
    if (locked.current) {
      refreshPending.current = true;
      return;
    }
    const attempt = startRead();
    setBusy(false);
    setStatus('');
    void readSession(attempt).catch((cause) => failRead(attempt, cause, true));
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
  async function run(work: () => Promise<void>) {
    if (locked.current || !mounted.current) return;
    locked.current = true;
    invalidateRead();
    setBusy(true);
    setStatus('');
    try {
      await work();
    } catch (cause) {
      if (mounted.current) {
        setProjection(undefined);
        setStatus(
          cause instanceof Error && !(cause instanceof z.ZodError)
            ? cause.message
            : 'The review is unavailable. Refresh before continuing.',
        );
      }
    } finally {
      locked.current = false;
      if (mounted.current) {
        setBusy(false);
        if (refreshPending.current) {
          refreshPending.current = false;
          refresh();
        }
      }
    }
  }
  async function review(after?: string) {
    if (locked.current || !mounted.current) return;
    const attempt = startRead();
    const cursorActor = after && session ? binding(session) : undefined;
    setProjection(undefined);
    setBusy(true);
    setStatus('');
    let sessionUnknown = true;
    try {
      const before = binding(await readSession(attempt));
      if (!current(attempt)) return;
      sessionUnknown = false;
      if (!before) throw new Error('Choose an authenticated Participant privacy context.');
      if (after && JSON.stringify(cursorActor) !== JSON.stringify(before))
        throw new Error('The context changed. Refresh the review.');
      const target = z.uuid().safeParse(subjectId);
      if (!target.success) throw new Error('Enter a valid principal ID to review.');
      const parsed = responseSchema.safeParse(
        await readJson(
          `/api/v1/ui/access-review?${new URLSearchParams({ subjectId: target.data, ...(after ? { after } : {}) })}`,
          attempt,
        ),
      );
      if (!current(attempt)) return;
      if (!parsed.success)
        throw new Error('The review response is invalid. Refresh before continuing.');
      const result = parsed.data;
      sessionUnknown = true;
      const latest = binding(await readSession(attempt));
      if (!current(attempt)) return;
      sessionUnknown = false;
      if (
        JSON.stringify(before) !== JSON.stringify(result.actor) ||
        JSON.stringify(latest) !== JSON.stringify(result.actor)
      )
        throw new Error('The context changed. Refresh the review.');
      if (
        result.page.subject.id !== target.data ||
        result.page.participantId !== before.participantId ||
        result.page.privacyDomainId !== before.privacyDomainId ||
        result.page.authorizedEmpty !== (result.page.items.length === 0) ||
        (result.page.completeness === 'MORE') !== (result.page.nextCursor !== null)
      )
        throw new Error('The review does not match this principal and context.');
      setProjection({ actor: result.actor, page: result.page });
    } catch (cause) {
      failRead(attempt, cause, sessionUnknown);
    } finally {
      if (current(attempt)) setBusy(false);
    }
  }
  async function selectContext() {
    const participantId = '018f0000-0000-7000-8000-000000000101',
      privacyDomainId = '018f0000-0000-7000-8000-000000000201';
    const action = {
      actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
      actionIntentDigest: 'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
      resourceId: participantId,
      resourceDigest: 'sha256:21e6f6ef3dfec5acda58eebd0e07fca2e1394a9777f13157e3e514d611248700',
    };
    await performWebAuthnStepUp({ ...action, stepUp: 'FRESH_WEBAUTHN_MAX_5M' }, action);
    await fetch('/api/v1/ui/session/context', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ participantId, privacyDomainId }),
    }).then(json);
    await readSession();
  }
  const page =
    projection &&
    session &&
    JSON.stringify(projection.actor) === JSON.stringify(binding(session)) &&
    projection.page.subject.id === subjectId
      ? projection.page
      : undefined;
  return (
    <section className={`${panel} mt-6 space-y-4`} aria-label="Administrative access review">
      <header className="space-y-2">
        <h2 className="text-xl font-semibold">Review administrative access</h2>
        <p className="max-w-3xl text-sm leading-6 text-[color:var(--muted)]">
          Review a principal’s assignments and delegation paths against the current Participant
          envelopes. Remediation uses independent approval and fresh authentication.
        </p>
      </header>
      <p role="status" className="break-words">
        {status}
      </p>
      {!session ? (
        <button className={button} disabled={busy} onClick={refresh}>
          Refresh review session
        </button>
      ) : !session.authenticated ? (
        <LocalSessionSurface />
      ) : !binding(session) ? (
        <WorkspaceEntry disabled={busy}>
          <button className={button} disabled={busy} onClick={() => void run(selectContext)}>
            Enter workspace
          </button>
        </WorkspaceEntry>
      ) : (
        <>
          <dl
            className="grid gap-3 border-y border-[color:var(--border)] py-4 text-sm"
            aria-label="Review workspace references"
          >
            <div className="min-w-0">
              <dt className="text-[color:var(--muted)]">Organization reference</dt>
              <dd className="mt-1 break-all font-mono text-xs">{session.participantId}</dd>
            </div>
            <div className="min-w-0">
              <dt className="text-[color:var(--muted)]">Workspace reference</dt>
              <dd className="mt-1 break-all font-mono text-xs">{session.privacyDomainId}</dd>
            </div>
          </dl>
          <form
            className="grid max-w-2xl gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              void review();
            }}
          >
            <label className="grid gap-1">
              Principal ID to review
              <input
                className={field}
                required
                value={subjectId}
                onChange={(event) => {
                  invalidateRead();
                  setBusy(false);
                  setStatus('');
                  setProjection(undefined);
                  setSubjectId(event.target.value);
                }}
              />
            </label>
            <button className={button} disabled={busy} type="submit">
              Review current access
            </button>
          </form>
          {page ? (
            <div className="space-y-4">
              <dl className="grid gap-4 rounded-xl border border-[color:var(--border)] bg-[color:var(--canvas)] p-4 text-sm sm:grid-cols-2">
                <div className="min-w-0 sm:col-span-2">
                  <dt className="text-[color:var(--muted)]">Principal</dt>
                  <dd className="mt-1 break-all font-mono">{page.subject.id}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-[color:var(--muted)]">Principal state</dt>
                  <dd className="mt-1 font-medium">
                    {accessStateLabels[page.subject.state] ?? page.subject.state}
                  </dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-[color:var(--muted)]">Review observed at</dt>
                  <dd className="mt-1 break-words">
                    <time dateTime={page.observedAt}>{page.observedAt}</time>
                  </dd>
                </div>
              </dl>
              <p className="max-w-3xl text-sm leading-6 text-[color:var(--muted)]">
                This review explains grant constraints. Every action still requires a live platform
                policy, identity, privacy and context decision.
              </p>
              {page.authorizedEmpty ? (
                <p>
                  No assignments or delegation paths exist for this principal in this privacy
                  context.
                </p>
              ) : null}
              {page.items.map((item) => (
                <article
                  className={`${panel} min-w-0 space-y-3 break-words`}
                  key={item.grant.effect.id}
                >
                  <h3 className="space-y-1 font-semibold">
                    {'principalId' in item.grant.effect ? 'Assignment' : 'Delegation'}{' '}
                    <span className="block break-all font-mono text-xs font-normal text-[color:var(--muted)]">
                      {item.grant.effect.id}
                    </span>
                  </h3>
                  <p
                    className={`w-fit rounded-lg border border-[color:var(--border)] bg-[color:var(--canvas)] px-3 py-2 text-sm font-medium ${item.current ? 'text-[color:var(--accent)]' : 'text-[color:var(--warning)]'}`}
                  >
                    {item.current
                      ? 'Current within the grant constraints'
                      : 'Not current within the grant constraints'}
                  </p>
                  {item.reasons.length ? (
                    <ul className="list-disc space-y-1 pl-5 text-sm leading-6">
                      {item.reasons.map((reason) => (
                        <li key={reason}>
                          {reasons[reason] ?? 'This authority path requires investigation.'}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                  <dl className="grid gap-4 border-y border-[color:var(--border)] py-4 text-sm sm:grid-cols-2">
                    <div className="min-w-0 sm:col-span-2">
                      <dt className="text-[color:var(--muted)]">Authority envelope</dt>
                      <dd className="mt-1 break-all font-mono text-xs">{item.envelopeId}</dd>
                    </div>
                    <div className="min-w-0">
                      <dt className="text-[color:var(--muted)]">Envelope generation</dt>
                      <dd className="mt-1 font-medium">{item.envelopeEpoch}</dd>
                    </div>
                    <div className="min-w-0">
                      <dt className="text-[color:var(--muted)]">Independent approval</dt>
                      <dd className="mt-1 font-medium">
                        {item.constraints.makerCheckerRequired
                          ? 'Required'
                          : 'Not required by these grants'}
                      </dd>
                    </div>
                    <div className="min-w-0 sm:col-span-2">
                      <dt className="text-[color:var(--muted)]">Fresh authentication</dt>
                      <dd className="mt-1 font-medium">
                        {item.constraints.stepUpRequired
                          ? 'Required'
                          : 'Not required by these grants'}
                      </dd>
                    </div>
                    <div className="min-w-0">
                      <dt className="text-[color:var(--muted)]">Valid from</dt>
                      <dd className="mt-1 break-words">
                        <time dateTime={item.constraints.validFrom}>
                          {item.constraints.validFrom}
                        </time>
                      </dd>
                    </div>
                    <div className="min-w-0">
                      <dt className="text-[color:var(--muted)]">Valid until</dt>
                      <dd className="mt-1 break-words">
                        {item.constraints.validUntil ? (
                          <time dateTime={item.constraints.validUntil}>
                            {item.constraints.validUntil}
                          </time>
                        ) : (
                          'No fixed grant end'
                        )}
                      </dd>
                    </div>
                  </dl>
                  <SecondaryPanel title="Administrative actions, resources and authority path">
                    <p className="mt-2">
                      Actions: {item.constraints.actionIntentIds.join(', ') || 'None'}
                    </p>
                    <p>Resources: {item.constraints.resourceIds.join(', ') || 'None'}</p>
                    <p>Risk classes: {item.constraints.riskClasses.join(', ') || 'None'}</p>
                    <ol className="list-decimal pl-5">
                      {item.ancestry.map((grant) => (
                        <li key={grant.id}>
                          {grant.kind === 'assignment' ? 'Assignment' : 'Delegation'} {grant.id} ·
                          revision {grant.revision} ·{' '}
                          {accessStateLabels[grant.state] ?? grant.state}
                        </li>
                      ))}
                    </ol>
                  </SecondaryPanel>
                  {item.remediation ? (
                    <Link
                      className="inline-flex min-h-11 items-center text-sm font-medium underline underline-offset-4"
                      href={`/govern/memberships?view=grants&grantId=${item.remediation.id}&kind=${item.remediation.kind}`}
                    >
                      Review revocation of this {item.remediation.kind}
                    </Link>
                  ) : (
                    <p>No active grant to revoke.</p>
                  )}
                </article>
              ))}
              <p>
                {page.completeness === 'MORE'
                  ? 'More authority paths remain to be reviewed.'
                  : 'End of the authority paths in this privacy context.'}
              </p>
              {page.nextCursor ? (
                <button
                  className={button}
                  disabled={busy}
                  onClick={() => void review(page.nextCursor!)}
                >
                  Next authority paths
                </button>
              ) : null}
            </div>
          ) : null}
        </>
      )}
    </section>
  );
}
