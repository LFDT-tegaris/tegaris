'use client';

import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { z } from 'zod';
import {
  recoveryActor,
  recoveryCaseReadback,
  recoveryQualification,
  recoverySavedReview,
  recoveryStepUp,
  type RecoveryMutation,
  type RecoveryReview,
} from '../lib/recovery-workflow';
import { LocalSessionSurface } from './local-session';
import { readBoundPolicyState, writeBoundPolicyState } from './policy-workflow-storage';

const endpoint = '/api/v1/ui/recovery-workbench';
const storageKey = 'openpc:recovery-workflow:v1';
const panel = 'min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const field =
  'min-w-0 w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60';
const labels: Record<RecoveryMutation, string> = {
  QUALIFY: 'Qualify recovery executor',
  REVOKE: 'Revoke recovery executor',
  BEGIN: 'Open recovery case',
  CUSTODY: 'Record custodian consent',
  COMPLETE: 'Execute recovery',
  POST_REVIEW: 'Complete post-recovery review',
};
const approvalSchema = z.object({
  approvalRequestId: z.string(),
  candidateDigest: z.string(),
  state: z.string(),
  revision: z.string(),
  makerSubjectRef: z.string(),
  checkerSubjectRef: z.string().nullable(),
  proposal: z.object({
    mutation: z.enum(['QUALIFY', 'REVOKE', 'BEGIN', 'CUSTODY', 'COMPLETE', 'POST_REVIEW']),
    resourceId: z.uuid(),
    expectedRevision: z.string(),
    state: z.string(),
    expiresAt: z.string(),
    candidate: z.record(z.string(), z.unknown()),
    approval: z.object({ reason: z.string().nullable() }).optional(),
  }),
  stepUp: recoveryStepUp,
  recoveryContext: recoveryCaseReadback.optional(),
});
const stateSchema = z.object({
  actor: recoveryActor,
  approvals: z.array(approvalSchema),
  approvalListAccess: z.enum(['AVAILABLE', 'DENIED', 'NOT_REQUESTED']).default('AVAILABLE'),
  recovery: recoveryCaseReadback.optional(),
  qualification: recoveryQualification.optional(),
  nextCursor: z.string().nullable(),
  completeness: z.enum(['COMPLETE', 'UNKNOWN']),
});
type State = z.infer<typeof stateSchema>;
type Ceremony = {
  actor: string;
  selection: string;
  controller: AbortController;
  sent: boolean;
};
async function json(response: Response): Promise<unknown> {
  const value = await response.json().catch(() => undefined);
  if (!response.ok)
    throw new Error(
      `${value?.title ?? 'The request was not completed.'}${value?.code ? ` (${value.code})` : ''}`,
    );
  return value;
}
function Candidate({ value }: { value: Record<string, unknown> }) {
  const names: Record<string, string> = {
    recoveryId: 'Recovery case',
    participantId: 'Participant',
    subjectId: 'Account to recover',
    recoveryPrincipalId: 'Recovery executor',
    custodianPrincipalIds: 'Required custodians',
    purposeDigest: 'Purpose digest',
    principalId: 'Principal',
    credentialId: 'Authenticator',
    principalEpoch: 'Account epoch',
    credentialEpoch: 'Authenticator epoch',
    state: 'Requested state',
    note: 'Post-recovery review',
  };
  return (
    <dl className="grid min-w-0 gap-2 text-sm">
      {Object.entries(value)
        .filter(([key]) => key !== 'actionIntentId')
        .map(([key, item]) => (
          <div key={key}>
            <dt className="font-semibold">{names[key] ?? key}</dt>
            <dd className="break-all">{Array.isArray(item) ? item.join(', ') : String(item)}</dd>
          </div>
        ))}
    </dl>
  );
}
function CaseDetail({ value }: { value: z.infer<typeof recoveryCaseReadback> }) {
  const item = value.effect;
  if ('purpose' in item)
    return (
      <div className="grid gap-3">
        <p className="font-semibold">Signer recovery state: {item.state}</p>
        <p>
          This is an identity envelope signer repair case. Authority: NONE. Post-review uses
          independent ordinary governance.
        </p>
        <Candidate
          value={{
            recoveryId: item.recoveryId,
            issuerPrincipalId: item.issuerPrincipalId,
            executorPrincipalId: item.executorPrincipalId,
            rotationId: item.rotationId,
            intentDigest: item.intentDigest,
          }}
        />
        <p>
          Revision {item.revision}. Post-recovery review: {item.postReviewStatus}.
        </p>
        <p className="break-all">
          Original activation operation: {item.activationOperationId ?? 'Not activated'}. Review
          operation: {value.operationId ?? 'No committed review'}.
        </p>
      </div>
    );
  return (
    <div className="grid gap-3">
      <p className="font-semibold">Recovery state: {item.state}</p>
      <Candidate
        value={{
          recoveryId: item.recoveryId,
          subjectId: item.subjectId,
          recoveryPrincipalId: item.recoveryPrincipalId,
          purposeDigest: item.purposeDigest,
        }}
      />
      <p>
        Revision {item.revision} · Original account epoch {item.subjectEpoch}
      </p>
      <p>
        Lease {item.leaseExpired ? 'expired' : 'expires'}:{' '}
        <time dateTime={item.expiresAt}>{item.expiresAt}</time>
      </p>
      <ul>
        {item.custodians.map((custodian) => (
          <li className="break-all" key={custodian.principalId}>
            {custodian.principalId}:{' '}
            {custodian.approvedAt ? 'Consent recorded' : 'Consent required'}
          </li>
        ))}
      </ul>
      <p>Replacement authenticator: {item.replacementState}</p>
      <p>Post-recovery review: {item.postReviewStatus}</p>
      {item.reviewNote && <p className="break-words">{item.reviewNote}</p>}
      <p className="break-all">
        Last committed operation: {value.operationId ?? 'No committed operation reported'}
      </p>
    </div>
  );
}
export function RecoveryWorkflow() {
  const [state, setState] = useState<State>();
  const [review, setReview] = useState<RecoveryReview>();
  const [lane, setLane] = useState<'maker' | 'checker'>('checker');
  const [mutation, setMutation] = useState<RecoveryMutation>('BEGIN');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [lookupCase, setLookupCase] = useState('');
  const [lookupPrincipal, setLookupPrincipal] = useState('');
  const [fields, setFields] = useState({
    principalId: '',
    credentialId: '',
    credentialEpoch: '1',
    subjectId: '',
    recoveryPrincipalId: '',
    custodianOne: '',
    custodianTwo: '',
    checkerPrincipalId: '',
    recoveryId: '',
    reason: '',
    purposeDigest: '',
    note: '',
  });
  const actorRef = useRef<State['actor'] | undefined>(undefined);
  const lock = useRef(false);
  const mounted = useRef(false);
  const readGeneration = useRef(0);
  const activeRead = useRef<AbortController | undefined>(undefined);
  const selection = useRef('');
  const ceremony = useRef<Ceremony | undefined>(undefined);
  const cancelled = () =>
    new DOMException(
      'Recovery context changed. Read the original request before retrying.',
      'AbortError',
    );
  function current(token: Ceremony) {
    return (
      mounted.current &&
      ceremony.current === token &&
      !token.controller.signal.aborted &&
      token.actor === JSON.stringify(actorRef.current) &&
      token.selection === selection.current
    );
  }
  function ensure(token: Ceremony) {
    if (!current(token)) throw cancelled();
  }
  useLayoutEffect(() => {
    selection.current = JSON.stringify([
      state,
      review,
      lane,
      mutation,
      fields,
      lookupCase,
      lookupPrincipal,
    ]);
    if (ceremony.current && !ceremony.current.sent && !current(ceremony.current))
      ceremony.current.controller.abort();
  });
  function save(value: RecoveryReview) {
    if (!mounted.current || !actorRef.current) return;
    setReview(value);
    writeBoundPolicyState(storageKey, actorRef.current, value);
  }
  function showMessage(value: string) {
    if (mounted.current) setMessage(value);
  }
  async function load(
    options: {
      lane?: 'maker' | 'checker';
      recoveryId?: string;
      principalId?: string;
      cursor?: string;
      approvalRequestId?: string;
    } = {},
    expectedActor?: string,
  ) {
    if (!mounted.current) throw cancelled();
    const generation = ++readGeneration.current;
    activeRead.current?.abort();
    const controller = new AbortController();
    activeRead.current = controller;
    const parameters = new URLSearchParams({ lane, ...options });
    const value = stateSchema.parse(
      await json(
        await fetch(`${endpoint}?${parameters}`, {
          cache: 'no-store',
          signal: controller.signal,
        }),
      ),
    );
    if (!mounted.current || controller.signal.aborted || generation !== readGeneration.current)
      throw cancelled();
    // Original sent custody is retained even if the current account can no longer read it.
    if (expectedActor && JSON.stringify(value.actor) !== expectedActor) {
      actorRef.current = undefined;
      setState(undefined);
      setReview(undefined);
      throw cancelled();
    }
    if (JSON.stringify(value.actor) !== JSON.stringify(actorRef.current)) {
      actorRef.current = value.actor;
      setReview(
        readBoundPolicyState(
          storageKey,
          value.actor,
          (stored): stored is RecoveryReview => recoverySavedReview.safeParse(stored).success,
        ),
      );
    }
    setState(value);
    return value;
  }
  useEffect(() => {
    mounted.current = true;
    void load({ lane: 'checker' }).catch((cause: unknown) => {
      if (mounted.current && !(cause instanceof DOMException && cause.name === 'AbortError'))
        setError(
          cause instanceof Error ? cause.message : 'Sign in and select a Participant context.',
        );
    });
    return () => {
      mounted.current = false;
      readGeneration.current += 1;
      activeRead.current?.abort();
      if (ceremony.current && !ceremony.current.sent) ceremony.current.controller.abort();
    };
  }, []);
  async function run(work: () => Promise<void>) {
    if (!mounted.current || lock.current) return;
    lock.current = true;
    setBusy(true);
    setError('');
    setMessage('');
    try {
      await work();
    } catch (cause) {
      if (mounted.current)
        setError(
          cause instanceof Error
            ? cause.message
            : 'The operation could not be confirmed. Refresh authoritative state before retrying.',
        );
    } finally {
      ceremony.current = undefined;
      lock.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  async function post(body: unknown) {
    if (!mounted.current) throw cancelled();
    const value = await json(
      await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
    );
    if (!mounted.current) throw cancelled();
    return value;
  }
  async function authorizeCeremony(
    step: RecoveryReview['review']['stepUp'],
    approvalRequestId: string,
    selectedLane: 'maker' | 'checker',
  ) {
    if (!mounted.current || !actorRef.current) throw cancelled();
    const token: Ceremony = {
      actor: JSON.stringify(actorRef.current),
      selection: selection.current,
      controller: new AbortController(),
      sent: false,
    };
    ceremony.current = token;
    await performWebAuthnStepUp({ ...step, stepUp: 'FRESH_WEBAUTHN_MAX_5M' }, step, {
      signal: token.controller.signal,
      isCurrent: () => current(token),
    });
    ensure(token);
    const parameters = new URLSearchParams({ lane: selectedLane, approvalRequestId });
    const value = stateSchema.parse(
      await json(
        await fetch(`${endpoint}?${parameters}`, {
          cache: 'no-store',
          signal: token.controller.signal,
        }),
      ),
    );
    ensure(token);
    if (JSON.stringify(value.actor) !== token.actor) {
      token.controller.abort();
      actorRef.current = undefined;
      setState(undefined);
      setReview(undefined);
      throw cancelled();
    }
    if (selectedLane === 'checker') {
      const before = state?.approvals.find((item) =>
        item.approvalRequestId.endsWith(approvalRequestId),
      );
      const after = value.approvals.find((item) =>
        item.approvalRequestId.endsWith(approvalRequestId),
      );
      if (!before || !after || JSON.stringify(before) !== JSON.stringify(after)) {
        token.controller.abort();
        setState(value);
        throw cancelled();
      }
    }
    ensure(token);
    return token;
  }
  function input(
    name: keyof typeof fields,
    label: string,
    options: { multiline?: boolean; required?: boolean } = {},
  ) {
    return (
      <label className="grid min-w-0 gap-1">
        {label}
        {options.multiline ? (
          <textarea
            className={field}
            value={fields[name]}
            maxLength={1024}
            minLength={10}
            required={options.required !== false}
            onChange={(event) => setFields({ ...fields, [name]: event.target.value })}
          />
        ) : (
          <input
            className={field}
            value={fields[name]}
            required={options.required !== false}
            onChange={(event) => setFields({ ...fields, [name]: event.target.value })}
          />
        )}
      </label>
    );
  }
  async function preview() {
    const common = {
      mutation,
      checkerPrincipalId: fields.checkerPrincipalId,
      reason: fields.reason,
    };
    const command =
      mutation === 'QUALIFY'
        ? {
            ...common,
            principalId: fields.principalId,
            credentialId: fields.credentialId,
            credentialEpoch: fields.credentialEpoch,
          }
        : mutation === 'REVOKE'
          ? { ...common, principalId: fields.principalId }
          : mutation === 'BEGIN'
            ? {
                ...common,
                ...(fields.recoveryId ? { recoveryId: fields.recoveryId } : {}),
                ...(fields.purposeDigest ? { purposeDigest: fields.purposeDigest } : {}),
                subjectId: fields.subjectId,
                recoveryPrincipalId: fields.recoveryPrincipalId,
                custodianPrincipalIds: [fields.custodianOne, fields.custodianTwo],
              }
            : {
                ...common,
                recoveryId: fields.recoveryId,
                ...(fields.purposeDigest ? { purposeDigest: fields.purposeDigest } : {}),
                ...(mutation === 'POST_REVIEW' ? { note: fields.note } : {}),
              };
    save(recoverySavedReview.parse(await post({ command: 'PREVIEW', input: command })));
    showMessage('Review the exact transition, purpose, and checker before submitting it.');
  }
  async function submit() {
    if (!review) return;
    const result = z
      .object({
        reviewToken: z.string(),
        review: recoverySavedReview.shape.review,
        approval: z.object({ approvalRequestId: z.string() }),
      })
      .parse(await post({ command: 'SUBMIT', reviewToken: review.reviewToken }));
    save({
      reviewToken: result.reviewToken,
      review: result.review,
      approvalRequestId: result.approval.approvalRequestId.slice(-36),
    });
    await load({ lane: 'maker', approvalRequestId: result.approval.approvalRequestId.slice(-36) });
    if (mounted.current) setLane('maker');
    showMessage(
      'Approval requested. No recovery transition has executed. The selected checker must review this request in their own session.',
    );
  }
  async function readSavedResult(saved = review, expectedActor?: string) {
    if (!saved || !mounted.current) return;
    const principal = ['QUALIFY', 'REVOKE'].includes(saved.review.mutation);
    const resourceId = saved.review.resourceId;
    if (principal) setLookupPrincipal(resourceId);
    else setLookupCase(resourceId);
    await load(
      {
        lane: 'maker',
        ...(saved.approvalRequestId ? { approvalRequestId: saved.approvalRequestId } : {}),
        ...(principal ? { principalId: resourceId } : { recoveryId: resourceId }),
      },
      expectedActor,
    );
    if (mounted.current) setLane('maker');
  }
  async function commit() {
    if (!review?.approvalRequestId) return;
    const saved = review;
    const token = await authorizeCeremony(saved.review.stepUp, review.approvalRequestId, 'maker');
    ensure(token);
    token.sent = true;
    let result: { truthState: 'SUCCESS' | 'WRITE_AMBIGUITY'; resourceId: string };
    try {
      result = z
        .object({ truthState: z.enum(['SUCCESS', 'WRITE_AMBIGUITY']), resourceId: z.uuid() })
        .parse(
          await post({
            command: 'COMMIT',
            reviewToken: saved.reviewToken,
            approvalRequestId: saved.approvalRequestId,
          }),
        );
      if (result.resourceId !== saved.review.resourceId)
        throw new Error('The owner returned a different recovery resource.');
    } catch (cause) {
      let readbackFailed = false;
      try {
        await readSavedResult(saved, token.actor);
      } catch {
        // A failed readback must not replace the first ambiguous execution failure.
        readbackFailed = true;
      }
      if (mounted.current)
        setMessage(
          readbackFailed
            ? 'The execution response and its readback could not be confirmed. The original saved request remains available.'
            : 'The execution response could not be confirmed. Read the original saved request before retrying.',
        );
      throw cause;
    }
    await readSavedResult(saved, token.actor);
    showMessage(
      result.truthState === 'SUCCESS'
        ? 'The owner committed the transition. Review the authoritative state below.'
        : 'The write response was lost. Authoritative state is shown below; use the saved request for any retry.',
    );
  }
  async function approve(item: State['approvals'][number]) {
    const approvalRequestId = item.approvalRequestId.slice(-36);
    const token = await authorizeCeremony(item.stepUp, approvalRequestId, 'checker');
    ensure(token);
    token.sent = true;
    try {
      await post({
        command: 'APPROVE',
        approvalRequestId,
        candidateDigest: item.candidateDigest,
        expectedRevision: item.revision,
      });
    } catch (cause) {
      let readbackFailed = false;
      try {
        if (mounted.current) await load({ lane: 'checker', approvalRequestId }, token.actor);
      } catch {
        // Keep the first response failure and the original approval selection.
        readbackFailed = true;
      }
      if (mounted.current)
        setMessage(
          readbackFailed
            ? 'The approval response and its readback could not be confirmed. Read the original approval before retrying.'
            : 'The approval response could not be confirmed. The original approval readback is shown below.',
        );
      throw cause;
    }
    await load({ lane: 'checker', approvalRequestId }, token.actor);
    showMessage('Checker approval recorded. The maker must execute the approved transition.');
  }
  const consumed = Boolean(
    review?.approvalRequestId &&
    state?.approvals.some(
      (item) =>
        item.approvalRequestId.endsWith(review.approvalRequestId!) &&
        item.proposal.state === 'CONSUMED',
    ),
  );

  return (
    <section className="mt-6 grid min-w-0 gap-5" aria-label="Account recovery governance">
      <header>
        <h2 className="text-2xl font-semibold">Account recovery</h2>
        <p>
          Recovery uses a separate hardware-qualified executor, two distinct custodians, a
          purpose-bound lease of at most 15 minutes, and mandatory post-recovery review.
        </p>
      </header>
      <LocalSessionSurface />
      {state && (
        <p className="break-all">
          Signed-in principal: {state.actor.principalId}
          <br />
          Participant: {state.actor.participantId}
          <br />
          Privacy domain: {state.actor.privacyDomainId}
        </p>
      )}
      <p role="status">{message}</p>
      {error && (
        <p role="alert" className="break-words">
          {error}
        </p>
      )}
      <form
        className={`${panel} grid gap-3`}
        onSubmit={(event) => {
          event.preventDefault();
          void run(preview);
        }}
      >
        <h3 className="text-lg font-semibold">Prepare recovery transition</h3>
        <label className="grid gap-1">
          Transition
          <select
            aria-label="Transition"
            className={field}
            value={mutation}
            disabled={busy}
            onChange={(event) => setMutation(event.target.value as RecoveryMutation)}
          >
            {Object.entries(labels).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        {(mutation === 'QUALIFY' || mutation === 'REVOKE') &&
          input('principalId', 'Recovery executor principal ID')}
        {mutation === 'QUALIFY' && (
          <>
            {input('credentialId', 'Hardware authenticator credential ID')}
            {input('credentialEpoch', 'Authenticator epoch')}
            <p>
              Identity verifies the registered authenticator’s hardware provenance and current
              account epoch before qualification.
            </p>
          </>
        )}
        {mutation === 'BEGIN' && (
          <>
            {input('recoveryId', 'New case ID (optional)', { required: false })}
            {input('subjectId', 'Account to recover')}
            {input('recoveryPrincipalId', 'Qualified recovery executor')}
            {input('custodianOne', 'First custodian')}
            {input('custodianTwo', 'Second custodian')}
          </>
        )}
        {['CUSTODY', 'COMPLETE', 'POST_REVIEW'].includes(mutation) &&
          input('recoveryId', 'Recovery case ID')}
        {input(
          'reason',
          ['CUSTODY', 'COMPLETE', 'POST_REVIEW'].includes(mutation)
            ? 'Original recovery purpose'
            : mutation === 'BEGIN'
              ? 'Recovery purpose'
              : 'Reason for this transition',
          { multiline: true },
        )}
        {!['QUALIFY', 'REVOKE'].includes(mutation) && (
          <>
            {input('purposeDigest', 'Explicit purpose digest (optional)', { required: false })}
            <p>
              Leave the digest blank to derive it from the purpose text. For a purpose bound to an
              external record, enter its SHA-256 digest and explain that purpose above. Later
              transitions must match the case’s stored purpose digest.
            </p>
          </>
        )}
        {mutation === 'POST_REVIEW' &&
          input('note', 'Post-recovery findings and resolution', { multiline: true })}
        {input('checkerPrincipalId', 'Distinct checker principal ID')}
        <button className={button} disabled={busy || !state} type="submit">
          Review transition
        </button>
      </form>
      {review && (
        <section className={`${panel} grid gap-3`} aria-label="Saved recovery transition">
          <h3 className="text-lg font-semibold">{labels[review.review.mutation]}</h3>
          <p className="break-words">{review.review.reason}</p>
          <Candidate value={review.review.candidate} />
          <p className="break-all">Checker: {review.review.checkerPrincipalId}</p>
          <p>Expected revision: {review.review.expectedRevision}</p>
          <p className="break-all">Candidate digest: {review.review.candidateDigest}</p>
          {review.approvalRequestId ? (
            <>
              <p className="break-all">Approval request: {review.approvalRequestId}</p>
              <button
                className={button}
                disabled={busy || !state || consumed}
                onClick={() => void run(commit)}
              >
                Verify authenticator and execute approved transition
              </button>
            </>
          ) : (
            <button className={button} disabled={busy || !state} onClick={() => void run(submit)}>
              Request checker approval
            </button>
          )}
          {consumed && <p>This approved request has already executed.</p>}
          <button className={button} disabled={busy} onClick={() => void run(readSavedResult)}>
            Read saved transition result
          </button>
          <p>
            The saved request retains its idempotency key across reloads. Approval alone does not
            execute the transition.
          </p>
        </section>
      )}
      <section className={`${panel} grid gap-3`} aria-label="Recovery approvals">
        <h3 className="text-lg font-semibold">Recovery approval requests</h3>
        <label className="grid gap-1">
          Requests to show
          <select
            aria-label="Requests to show"
            className={field}
            value={lane}
            disabled={busy}
            onChange={(event) => {
              const selected = event.target.value as 'maker' | 'checker';
              setLane(selected);
              void run(async () => {
                await load({ lane: selected });
              });
            }}
          >
            <option value="checker">Assigned to me as checker</option>
            <option value="maker">Submitted by me</option>
          </select>
        </label>
        <button
          className={button}
          disabled={busy}
          onClick={() =>
            void run(async () => {
              await load();
            })
          }
        >
          Refresh recovery approvals
        </button>
        {state?.approvalListAccess === 'DENIED' && (
          <p role="status">
            This account cannot list approval requests. Saved requests and recovery cases are read
            individually through their owners.
          </p>
        )}
        {state?.approvalListAccess === 'AVAILABLE' && state.approvals.length === 0 && (
          <p>No recovery approvals on this page.</p>
        )}
        {state?.approvals.map((item) => (
          <article className={`${panel} grid gap-3`} key={item.approvalRequestId}>
            <h4 className="font-semibold">
              {labels[item.proposal.mutation]} — {item.state}
            </h4>
            <p className="break-words">
              {item.proposal.approval?.reason ?? 'The original request reason is unavailable.'}
            </p>
            <p className="break-all">Request: {item.approvalRequestId.slice(-36)}</p>
            <p className="break-all">Maker: {item.makerSubjectRef.slice(-36)}</p>
            <Candidate value={item.proposal.candidate} />
            {item.recoveryContext && <CaseDetail value={item.recoveryContext} />}
            <p>
              Candidate revision {item.proposal.expectedRevision} · Expires{' '}
              {item.proposal.expiresAt}
            </p>
            {lane === 'checker' && item.state === 'REQUESTED' && (
              <button
                className={button}
                disabled={busy}
                onClick={() => void run(() => approve(item))}
              >
                Verify authenticator and approve this transition
              </button>
            )}
          </article>
        ))}
        {state?.nextCursor && (
          <button
            className={button}
            disabled={busy}
            onClick={() =>
              void run(async () => {
                await load({ cursor: state.nextCursor! });
              })
            }
          >
            Next approval page
          </button>
        )}
        {state?.completeness === 'UNKNOWN' && (
          <p>This page does not establish a complete approval inventory.</p>
        )}
      </section>
      <section className={`${panel} grid gap-3`} aria-label="Authoritative recovery state">
        <h3 className="text-lg font-semibold">Read stored recovery state</h3>
        <label className="grid gap-1">
          Case ID to read
          <input
            className={field}
            value={lookupCase}
            onChange={(event) => setLookupCase(event.target.value)}
          />
        </label>
        <button
          className={button}
          disabled={busy || !lookupCase}
          onClick={() =>
            void run(async () => {
              await load({ recoveryId: lookupCase });
            })
          }
        >
          Read recovery case
        </button>
        {state?.recovery && <CaseDetail value={state.recovery} />}
        <label className="grid gap-1">
          Executor principal ID to read
          <input
            className={field}
            value={lookupPrincipal}
            onChange={(event) => setLookupPrincipal(event.target.value)}
          />
        </label>
        <button
          className={button}
          disabled={busy || !lookupPrincipal}
          onClick={() =>
            void run(async () => {
              await load({ principalId: lookupPrincipal });
            })
          }
        >
          Read executor qualification
        </button>
        {state?.qualification && (
          <>
            <Candidate value={state.qualification.effect} />
            <p>
              Current qualification:{' '}
              {state.qualification.effect.current ? 'Verified by Identity' : 'Not current'}
            </p>
          </>
        )}
      </section>
    </section>
  );
}
