'use client';

import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import {
  credentialState,
  savedCredentialReview,
  type CredentialReview,
} from '../lib/credential-workflow';
import { enrollmentReadbackSchema, type EnrollmentReadback } from '../lib/authenticator-enrollment';
import { readBoundPolicyState, writeBoundPolicyState } from './policy-workflow-storage';
import { LocalSessionSurface } from './local-session';

const endpoint = '/api/v1/ui/credential-workbench';
const storageKey = 'openpc:credential-workflow:v1';
const panel = 'min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const field =
  'min-w-0 w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60';
type State = z.infer<typeof credentialState>;
const failureMessages = {
  unavailable:
    'Credential request could not be confirmed. Read saved registration before retrying.',
  authorization:
    'Credential request was not authorized. Refresh the authenticated context before continuing.',
  conflict: 'Credential state changed. Refresh or read saved registration before retrying.',
  input: 'Credential request was rejected. Check the inputs before continuing.',
  account: 'The saved registration does not belong to this account.',
  authenticator: 'The registration refers to another authenticator.',
  cancelled: 'Authenticator registration was cancelled or unavailable.',
} as const;
class WorkflowFailure extends Error {
  constructor(readonly kind: keyof typeof failureMessages) {
    super(failureMessages[kind]);
  }
}
function failureMessage(error: unknown) {
  return error instanceof WorkflowFailure
    ? failureMessages[error.kind]
    : failureMessages.unavailable;
}
function httpFailure(status: number) {
  return new WorkflowFailure(
    [401, 403, 404].includes(status)
      ? 'authorization'
      : [409, 412, 428].includes(status)
        ? 'conflict'
        : [400, 422].includes(status)
          ? 'input'
          : 'unavailable',
  );
}
async function json(response: Response): Promise<unknown> {
  const value = await response.json().catch(() => undefined);
  if (!response.ok) throw httpFailure(response.status);
  if (value === undefined) throw new WorkflowFailure('unavailable');
  return value;
}
function base64url(value: ArrayBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
}

export function CredentialWorkflow() {
  const [state, setState] = useState<State>();
  const [review, setReview] = useState<CredentialReview>();
  const [readback, setReadback] = useState<EnrollmentReadback>();
  const [lane, setLane] = useState<'maker' | 'checker'>('checker');
  const [credentialId, setCredentialId] = useState('');
  const [checker, setChecker] = useState('');
  const [reason, setReason] = useState('');
  const [hardware, setHardware] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const actor = useRef<State['actor'] | undefined>(undefined);
  const locked = useRef(false);
  const mounted = useRef(false);
  const operationGeneration = useRef(0);
  const operation = useRef<
    | {
        generation: number;
        actor: string;
        controller: AbortController;
        selection?: () => boolean;
      }
    | undefined
  >(undefined);
  const approvalsRef = useRef<State['approvals']>([]);
  const reviewRef = useRef<CredentialReview | undefined>(undefined);
  function cancelOperation() {
    operationGeneration.current += 1;
    operation.current?.controller.abort();
  }
  function isCurrent(token: NonNullable<typeof operation.current>) {
    return (
      mounted.current &&
      operation.current === token &&
      token.generation === operationGeneration.current &&
      !token.controller.signal.aborted &&
      token.actor === JSON.stringify(actor.current) &&
      (token.selection?.() ?? true)
    );
  }
  function assertOperation() {
    const token = operation.current;
    if (!token || !isCurrent(token))
      throw new DOMException('The operation was cancelled.', 'AbortError');
    return token;
  }
  async function verify(
    step: {
      actionIntentId: string;
      actionIntentDigest: string;
      resourceId: string;
      resourceDigest: string;
    },
    selected: CredentialReview | State['approvals'][number],
  ) {
    const token = assertOperation();
    const selection =
      'reviewToken' in selected
        ? () => reviewRef.current === selected
        : () =>
            approvalsRef.current.some((item) => JSON.stringify(item) === JSON.stringify(selected));
    token.selection = selection;
    assertOperation();
    await performWebAuthnStepUp({ ...step, stepUp: 'FRESH_WEBAUTHN_MAX_5M' }, step, {
      signal: token.controller.signal,
      isCurrent: () => isCurrent(token),
    });
    assertOperation();
  }

  const loadGeneration = useRef(0);
  const loadController = useRef<AbortController | undefined>(undefined);
  function save(value: CredentialReview) {
    if (!actor.current) return;
    reviewRef.current = value;
    setReview(value);
    writeBoundPolicyState(storageKey, actor.current, value);
  }
  function adopt(value: State) {
    approvalsRef.current = value.approvals;
    if (operation.current?.selection && !operation.current.selection())
      operation.current.controller.abort();
    if (JSON.stringify(actor.current) !== JSON.stringify(value.actor)) {
      cancelOperation();
      actor.current = value.actor;
      const saved = readBoundPolicyState(
        storageKey,
        value.actor,
        (stored): stored is CredentialReview => savedCredentialReview.safeParse(stored).success,
      );
      reviewRef.current = saved;
      setReview(saved);
      setReadback(undefined);
      setCredentialId('');
    }
    setCredentialId((selected) =>
      value.inventory.items.some((item) => item.active && item.credentialId === selected)
        ? selected
        : '',
    );
    setState(value);
    return value;
  }
  async function load(selected = lane, cursor?: string, credentialCursor?: string) {
    if (!mounted.current) return;
    const generation = ++loadGeneration.current;
    loadController.current?.abort();
    const controller = new AbortController();
    loadController.current = controller;
    const params = new URLSearchParams({
      lane: selected,
      ...(cursor ? { cursor } : {}),
      ...(credentialCursor ? { credentialCursor } : {}),
    });
    try {
      const value = await json(
        await fetch(`${endpoint}?${params}`, { cache: 'no-store', signal: controller.signal }),
      );
      if (!mounted.current || generation !== loadGeneration.current || controller.signal.aborted)
        return;
      return adopt(credentialState.parse(value));
    } catch (cause) {
      if (!mounted.current || generation !== loadGeneration.current || controller.signal.aborted)
        return;
      throw cause;
    } finally {
      if (loadController.current === controller) loadController.current = undefined;
    }
  }
  useLayoutEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      cancelOperation();
      loadGeneration.current += 1;
      loadController.current?.abort();
    };
  }, []);
  useEffect(() => {
    let current = true;
    void load('checker').catch((cause: unknown) => {
      if (current && mounted.current) setError(failureMessage(cause));
    });
    return () => {
      current = false;
    };
  }, []);
  async function run(work: () => Promise<void>) {
    if (!mounted.current || locked.current) return;
    locked.current = true;
    const token = {
      generation: ++operationGeneration.current,
      actor: JSON.stringify(actor.current),
      controller: new AbortController(),
    };
    operation.current = token;
    setBusy(true);
    setError('');
    setMessage('');
    try {
      await work();
    } catch (cause) {
      if (isCurrent(token)) setError(failureMessage(cause));
    } finally {
      if (operation.current === token) operation.current = undefined;
      locked.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  async function post(body: unknown) {
    const token = assertOperation();
    const result = await json(
      await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
    );
    assertOperation();
    // The original command response passed its frontier; subsequent owner reads
    // retain actor/lifecycle fencing without treating an accepted update as a new intent.
    token.selection = undefined;
    return result;
  }
  async function readSaved(enrollmentId = review?.review.enrollmentId) {
    if (!enrollmentId || !actor.current) return;
    assertOperation();
    const result = enrollmentReadbackSchema.parse(
      await json(
        await fetch(`/api/v1/ui/webauthn/enrollment?${new URLSearchParams({ enrollmentId })}`, {
          cache: 'no-store',
        }),
      ),
    );
    assertOperation();
    if (
      result.principalId !== actor.current.principalId ||
      result.participantId !== actor.current.participantId ||
      result.enrollmentId !== enrollmentId
    )
      throw new WorkflowFailure('account');
    setReadback(result);
    return result;
  }
  async function prepare() {
    if (!state) return;
    const selectedActor = state.actor;
    const options = z
      .object({
        enrollmentId: z.uuid(),
        replacedCredentialId: z.uuid(),
        publicKey: z.record(z.string(), z.unknown()),
      })
      .parse(
        await post({
          command: 'OPTIONS',
          replacedCredentialId: credentialId,
          hardwareAttestation: hardware,
          expectedSessionId: selectedActor.sessionId,
        }),
      );
    if (options.replacedCredentialId !== credentialId) throw new WorkflowFailure('authenticator');
    const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
      options.publicKey as unknown as PublicKeyCredentialCreationOptionsJSON,
    );
    const token = assertOperation();
    const registered = await navigator.credentials.create({
      publicKey,
      signal: token.controller.signal,
    });
    assertOperation();
    if (
      !(registered instanceof PublicKeyCredential) ||
      !(registered.response instanceof AuthenticatorAttestationResponse)
    )
      throw new WorkflowFailure('cancelled');
    const response = {
      id: registered.id,
      rawId: base64url(registered.rawId),
      type: 'public-key',
      response: {
        attestationObject: base64url(registered.response.attestationObject),
        clientDataJSON: base64url(registered.response.clientDataJSON),
        transports: registered.response.getTransports(),
      },
      clientExtensionResults: registered.getClientExtensionResults(),
      authenticatorAttachment: registered.authenticatorAttachment,
    };
    save(
      savedCredentialReview.parse(
        await post({
          command: 'PREPARE',
          enrollmentId: options.enrollmentId,
          response,
          reason,
          checkerPrincipalId: checker,
          expectedSessionId: selectedActor.sessionId,
        }),
      ),
    );
    setReadback(undefined);
    setMessage(
      'The new authenticator is prepared. Review and request approval before its registration expires. Your existing authenticator remains active.',
    );
  }
  async function submit() {
    if (!review) return;
    const result = z
      .object({
        reviewToken: savedCredentialReview.shape.reviewToken,
        review: savedCredentialReview.shape.review,
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
    assertOperation();
    setMessage(
      'Approval requested. The checker must inspect and approve the replacement in their own session.',
    );
  }
  async function commit() {
    if (!review?.approvalRequestId) return;
    const before = await readSaved();
    if (before?.state === 'COMPLETED') {
      await load();
      assertOperation();
      setMessage('This replacement is already committed.');
      return;
    }
    await verify(review.review.stepUp, review);
    try {
      const result = z.object({ truthState: z.enum(['SUCCESS', 'WRITE_AMBIGUITY']) }).parse(
        await post({
          command: 'COMMIT',
          reviewToken: review.reviewToken,
          approvalRequestId: review.approvalRequestId,
        }),
      );
      const stored = await readSaved();
      await load();
      assertOperation();
      setMessage(
        stored?.state === 'COMPLETED'
          ? 'Replacement committed. The previous authenticator is revoked. Use the new authenticator for future verification.'
          : result.truthState === 'WRITE_AMBIGUITY'
            ? 'The write response is uncertain. Refresh saved registration before retrying.'
            : 'Refresh saved registration to confirm the resulting credential.',
      );
    } catch (cause) {
      await readSaved();
      await load();
      assertOperation();
      setMessage(
        'The execution response was interrupted. Authoritative registration state is shown below.',
      );
      throw cause;
    }
  }
  const consumed =
    readback?.state === 'COMPLETED' ||
    state?.approvals.some(
      (item) =>
        item.approvalRequestId.endsWith(review?.approvalRequestId ?? 'no-request') &&
        item.proposal.state === 'CONSUMED',
    );
  return (
    <section aria-label="Authenticator lifecycle" className="grid min-w-0 gap-4">
      <LocalSessionSurface />
      <div className={panel}>
        <h2 className="text-xl font-semibold">Replace an authenticator</h2>
        <p>
          Register a new authenticator, obtain independent approval, then verify with your current
          authenticator to commit the replacement.
        </p>
        <p>The previous authenticator is revoked atomically when the replacement becomes active.</p>
        {state && (
          <p className="break-all text-sm">Signed-in principal: {state.actor.principalId}</p>
        )}
      </div>
      {error && (
        <p role="alert" className="break-words text-[color:var(--danger)]">
          {error}
        </p>
      )}
      {message && (
        <p role="status" className="break-words">
          {message}
        </p>
      )}
      <form
        className={`${panel} grid gap-3`}
        onSubmit={(event) => {
          event.preventDefault();
          void run(prepare);
        }}
      >
        <label className="grid gap-1">
          Authenticator to replace
          <select
            className={field}
            value={credentialId}
            required
            disabled={busy || !state}
            onChange={(event) => setCredentialId(event.target.value)}
          >
            <option value="">Select an active authenticator</option>
            {state?.inventory.items
              .filter((item) => item.active)
              .map((item) => (
                <option value={item.credentialId} key={item.credentialId}>
                  {item.credentialId} · epoch {item.credentialEpoch}
                </option>
              ))}
          </select>
        </label>
        {state?.inventory.nextCursor && (
          <button
            type="button"
            className={button}
            disabled={busy}
            onClick={() =>
              void run(async () => {
                setCredentialId('');
                await load(lane, undefined, state.inventory.nextCursor!);
                assertOperation();
              })
            }
          >
            Next authenticators
          </button>
        )}
        <label className="grid gap-1">
          Checker principal ID
          <input
            className={field}
            required
            value={checker}
            onChange={(event) => setChecker(event.target.value)}
          />
        </label>
        <label className="grid gap-1">
          Reason for replacement
          <textarea
            className={field}
            minLength={10}
            maxLength={1024}
            required
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={hardware}
            onChange={(event) => setHardware(event.target.checked)}
          />
          Request hardware-backed attestation
        </label>
        <button className={button} disabled={busy || !state}>
          Register replacement authenticator
        </button>
      </form>
      {review && (
        <div className={`${panel} grid gap-3`}>
          <h3 className="font-semibold">Saved replacement request</h3>
          <p className="break-all">Previous authenticator: {review.review.replacedCredentialId}</p>
          <p className="break-all">Checker: {review.review.checkerPrincipalId}</p>
          <p className="break-words">Reason: {review.review.reason}</p>
          <p>
            Registration expires:{' '}
            <time dateTime={review.review.expiresAt}>{review.review.expiresAt}</time>
          </p>
          <p className="break-all text-sm">Candidate digest: {review.review.candidateDigest}</p>
          {review.approvalRequestId && (
            <p className="break-all">Approval request: {review.approvalRequestId}</p>
          )}
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className={button}
              disabled={busy || Boolean(review.approvalRequestId) || Boolean(consumed)}
              onClick={() => void run(submit)}
            >
              Request replacement approval
            </button>
            <button
              type="button"
              className={button}
              disabled={busy || !review.approvalRequestId || Boolean(consumed)}
              onClick={() => void run(commit)}
            >
              Verify and commit replacement
            </button>
            <button
              type="button"
              className={button}
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  await readSaved();
                  await load();
                  assertOperation();
                })
              }
            >
              Read saved registration
            </button>
          </div>
          {readback && (
            <div aria-label="Replacement registration result" className="break-all">
              <p>Registration state: {readback.state}</p>
              {readback.credential && (
                <p>
                  Resulting credential: {readback.credential.credentialId} ·{' '}
                  {readback.credential.active ? 'ACTIVE' : 'INACTIVE'} · epoch{' '}
                  {readback.credential.credentialEpoch}
                </p>
              )}
            </div>
          )}
        </div>
      )}
      <div className={`${panel} grid gap-3`}>
        <h3 className="font-semibold">Replacement approvals</h3>
        <label>
          Approval lane
          <select
            className={field}
            value={lane}
            disabled={busy}
            onChange={(event) => {
              const selected = event.target.value as 'maker' | 'checker';
              setLane(selected);
              void run(async () => {
                await load(selected);
                assertOperation();
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
            void run(async () => {
              await load();
              assertOperation();
            })
          }
        >
          Refresh replacement approvals
        </button>
        {state?.approvals.length === 0 && <p>No replacement approvals on this page.</p>}
        {state?.approvals.map((item) => (
          <article key={item.approvalRequestId} className={`${panel} grid gap-2 break-all`}>
            <h4 className="font-semibold">
              Replacement approval {item.approvalRequestId.slice(-36)}
            </h4>
            <p>Maker: {item.proposal.makerPrincipalId}</p>
            <p>Previous authenticator: {item.proposal.resourceId}</p>
            <p>New public-key fingerprint: {item.proposal.candidate.publicKeyDigest}</p>
            <p>
              Hardware attestation:{' '}
              {item.proposal.candidate.hardwareAttestation?.profileId ?? 'Not hardware-qualified'}
            </p>
            <p className="break-words">Reason: {item.proposal.approval?.reason}</p>
            <p>
              Approval state: {item.state} · Proposal state: {item.proposal.state}
            </p>
            {lane === 'checker' && item.state === 'REQUESTED' && (
              <button
                className={button}
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    await verify(item.stepUp, item);
                    await post({
                      command: 'APPROVE',
                      approvalRequestId: item.approvalRequestId.slice(-36),
                      candidateDigest: item.candidateDigest,
                      expectedRevision: item.revision,
                    });
                    await load();
                    assertOperation();
                    setMessage('Replacement approved. The maker must still verify and commit it.');
                  })
                }
              >
                Verify and approve replacement
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
                await load(lane, state.nextCursor!);
                assertOperation();
              })
            }
          >
            Next approval page
          </button>
        )}
      </div>
    </section>
  );
}
