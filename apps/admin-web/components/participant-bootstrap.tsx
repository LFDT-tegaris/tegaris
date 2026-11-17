'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { LocalSessionSurface } from './local-session';
import { sessionTransitionEvent, sessionTransitionStorageKey } from './session-transition';
import {
  firstAdministratorGovernanceProposal as firstAdministratorCreationProposal,
  firstAdministratorCandidate,
  firstAdministratorCustody,
} from '../lib/first-administrator-contract';
const step = z.strictObject({
  actionIntentId: z.string(),
  actionIntentDigest: z.string(),
  resourceId: z.uuid(),
  resourceDigest: z.string(),
});
const reviewSchema = z.strictObject({
  candidate: firstAdministratorCandidate,
  candidateDigest: z.string(),
  reviewToken: z.string(),
  stepUp: step,
});
const commitReceiptSchema = z.strictObject({
  operationId: z.uuid(),
  participantId: z.uuid(),
  state: z.enum(['PROVISIONING', 'ACTIVE', 'CANCELLED']),
  invitationLink: z.url().optional(),
});
const originalReadSchema = z.union([
  commitReceiptSchema,
  z.strictObject({
    state: z.literal('NOT_CONSUMED'),
    proposalState: z.enum(['PROPOSED', 'APPROVAL_REQUESTED', 'APPROVED', 'CANCELLED', 'EXPIRED']),
    participantId: z.uuid(),
    candidateDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  }),
]);
const checkedSchema = z.object({
  proposal: firstAdministratorCreationProposal,
  approval: z.object({ approvalRequestId: z.string(), state: z.string(), revision: z.string() }),
  stepUp: step,
});
const actorSchema = z.object({
  authenticated: z.literal(true),
  sessionId: z.uuid(),
  principalId: z.uuid(),
  participantId: z.uuid(),
  contextMode: z.literal('PLATFORM'),
  privacyDomainId: z
    .uuid()
    .optional()
    .transform((value) => value ?? null),
  contextEpoch: z.string().regex(/^[1-9][0-9]*$/u),
});
type Actor = z.infer<typeof actorSchema>;
const storageKey = 'openpc:first-admin-review';
const savedReviewSchema = z.strictObject({
  actor: actorSchema.extend({ privacyDomainId: z.uuid().nullable() }),
  review: reviewSchema,
  approvalId: z.string(),
  savedAt: z.number(),
});
function sameActor(left: Actor, right: Actor) {
  return JSON.stringify(left) === JSON.stringify(right);
}
function clearSavedReview() {
  try {
    sessionStorage.removeItem(storageKey);
  } catch {
    // Optional tab-local continuity is never an authorization source.
  }
}
async function readActor(signal: AbortSignal): Promise<Actor | undefined> {
  const response = await fetch('/api/v1/ui/local-session', { cache: 'no-store', signal });
  if ([401, 403].includes(response.status)) return undefined;
  if (!response.ok) throw new BootstrapFailure('unavailable');
  const value: unknown = await response.json();
  if (
    z.object({ enabled: z.literal(true), authenticated: z.literal(false) }).safeParse(value).success
  )
    return undefined;
  const parsed = actorSchema
    .extend({ contextMode: z.enum(['PLATFORM', 'PARTICIPANT']) })
    .safeParse(value);
  if (!parsed.success) throw new BootstrapFailure('unavailable');
  return parsed.data.contextMode === 'PLATFORM' ? actorSchema.parse(value) : undefined;
}
// Both successful envelopes are supplied by the existing approval producer.
const approvedResponseSchema = z.union([
  z.object({
    operation: z.object({ operationId: z.uuid(), truthState: z.literal('SUCCESS') }),
    approval: z.object({ state: z.literal('APPROVED') }),
  }),
  z.object({ reconciled: z.literal(true), approval: z.object({ state: z.literal('APPROVED') }) }),
]);
const administrativeActions = [
  ['ACT-PARTICIPANTS_READ_RESOURCE-V1', 'Read Participant administration'],
  ['ACT-PARTICIPANTS_READ_COLLECTION-V1', 'List Participants'],
  ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'Govern roles, envelopes and lifecycle changes'],
  ['ACT-PARTICIPANT_CREATE_MEMBER-V1', 'Govern memberships and assignments'],
  ['ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1', 'Activate approved administrative resources'],
  ['ACT-POLICY_READ_EFFECTIVE_ACCESS-V1', 'Inspect effective access'],
  ['ACT-IDENTITY_CREATE_SESSION-V1', 'Enter Participant context'],
  ['ACT-IDENTITY_DELETE_SESSION-V1', 'End sessions'],
  ['ACT-IDENTITY_UPDATE_STEP_UP-V1', 'Verify authenticators'],
  ['ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1', 'Request independent approval'],
  ['ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1', 'List approval requests'],
  ['ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1', 'Read approval requests'],
  ['ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1', 'Update approval requests'],
  ['ACT-POLICY_APPROVE_REQUEST-V1', 'Approve governed changes'],
] as const;
const failureMessages = {
  unavailable:
    'Participant bootstrap could not be confirmed. Read the original approval or custody before retrying.',
  authorization:
    'Participant bootstrap was not authorized. Refresh the authenticated context before continuing.',
  conflict:
    'Participant bootstrap state changed. Read the original approval or custody before retrying.',
  input: 'Participant bootstrap was rejected. Check the inputs before continuing.',
} as const;
class BootstrapFailure extends Error {
  constructor(readonly kind: keyof typeof failureMessages) {
    super(failureMessages[kind]);
  }
}
function failureMessage(cause: unknown) {
  return cause instanceof BootstrapFailure
    ? failureMessages[cause.kind]
    : failureMessages.unavailable;
}
function httpFailure(status: number) {
  return new BootstrapFailure(
    [401, 403, 404].includes(status)
      ? 'authorization'
      : [409, 412, 428].includes(status)
        ? 'conflict'
        : [400, 422].includes(status)
          ? 'input'
          : 'unavailable',
  );
}
async function bootstrapCommand(input: unknown, signal: AbortSignal) {
  const response = await fetch('/api/v1/ui/participant-bootstrap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
    cache: 'no-store',
    signal,
  });
  const value = await response.json().catch(() => undefined);
  if (!response.ok) throw httpFailure(response.status);
  if (value === undefined) throw new BootstrapFailure('unavailable');
  return value;
}
const field =
  'min-w-0 w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button = 'w-fit rounded border px-3 py-2 disabled:opacity-60';
export function ParticipantBootstrapWorkflow() {
  const [actor, setActor] = useState<Actor>();
  const [checking, setChecking] = useState(true);
  const mounted = useRef(false);
  const changing = useRef(false);
  const generation = useRef(0);
  const read = useRef<AbortController | undefined>(undefined);
  const refresh = useCallback(() => {
    if (changing.current) return;
    const revision = ++generation.current;
    read.current?.abort();
    const controller = new AbortController();
    read.current = controller;
    setChecking(true);
    void readActor(controller.signal)
      .then((value) => {
        if (!mounted.current || revision !== generation.current || controller.signal.aborted)
          return;
        if (!value) clearSavedReview();
        setActor((previous) =>
          previous && value && sameActor(previous, value) ? previous : value,
        );
        setChecking(false);
      })
      .catch(() => {
        if (!mounted.current || revision !== generation.current || controller.signal.aborted)
          return;
        setActor(undefined);
        setChecking(false);
      });
  }, []);
  const invalidateActor = useCallback(() => {
    setActor(undefined);
    refresh();
  }, [refresh]);
  useEffect(() => {
    mounted.current = true;
    refresh();
    const transition = (notification: unknown) => {
      const parsed = z.object({ phase: z.enum(['changing', 'settled']) }).safeParse(notification);
      if (!parsed.success) return;
      if (parsed.data.phase === 'settled') {
        changing.current = false;
        refresh();
      } else {
        changing.current = true;
        generation.current++;
        read.current?.abort();
        setActor(undefined);
        setChecking(true);
      }
    };
    const onTransition = (event: Event) => transition((event as CustomEvent<unknown>).detail);
    const onStorage = (event: StorageEvent) => {
      if (event.key !== sessionTransitionStorageKey) return;
      try {
        transition(JSON.parse(event.newValue ?? 'null'));
      } catch {
        refresh();
      }
    };
    const visible = () => {
      if (document.visibilityState === 'visible') refresh();
    };
    window.addEventListener('focus', refresh);
    window.addEventListener('storage', onStorage);
    window.addEventListener(sessionTransitionEvent, onTransition);
    document.addEventListener('visibilitychange', visible);
    return () => {
      mounted.current = false;
      generation.current++;
      read.current?.abort();
      window.removeEventListener('focus', refresh);
      window.removeEventListener('storage', onStorage);
      window.removeEventListener(sessionTransitionEvent, onTransition);
      document.removeEventListener('visibilitychange', visible);
    };
  }, [refresh]);
  return (
    <>
      <LocalSessionSurface />
      {actor ? (
        <AuthenticatedParticipantBootstrapWorkflow
          key={JSON.stringify(actor)}
          actor={actor}
          checking={checking}
          onActorInvalid={invalidateActor}
        />
      ) : null}
      {!actor || checking ? (
        <p role="status">
          Verify your current Platform session to view Participant administration.
        </p>
      ) : null}
    </>
  );
}
function AuthenticatedParticipantBootstrapWorkflow({
  actor,
  checking,
  onActorInvalid,
}: {
  actor: Actor;
  checking: boolean;
  onActorInvalid: () => void;
}) {
  const [review, setReview] = useState<z.infer<typeof reviewSchema>>(),
    [checked, setChecked] = useState<z.infer<typeof checkedSchema>>();
  const [custody, setCustody] = useState<z.infer<typeof firstAdministratorCustody>>();
  const [custodyParticipant, setCustodyParticipant] = useState('');
  const [checkerApprovalId, setCheckerApprovalId] = useState('');
  const [approvalId, setApprovalId] = useState(''),
    [resourceId, setResourceId] = useState(''),
    [candidateDigest, setCandidateDigest] = useState('');
  const [link, setLink] = useState(''),
    [status, setStatus] = useState(''),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false);
  const [pendingOriginal, setPendingOriginal] = useState(false);
  const mounted = useRef(false);
  const operation = useRef<AbortController | undefined>(undefined);
  useEffect(() => {
    mounted.current = true;
    try {
      const saved = JSON.parse(sessionStorage.getItem(storageKey) ?? 'null');
      const parsed = savedReviewSchema.safeParse(saved);
      if (
        parsed.success &&
        sameActor(parsed.data.actor, actor) &&
        parsed.data.savedAt <= Date.now() &&
        Date.now() - parsed.data.savedAt < 86400000
      ) {
        setReview(parsed.data.review);
        setApprovalId(parsed.data.approvalId);
      } else if (saved !== null) clearSavedReview();
    } catch {
      clearSavedReview();
    }
    return () => {
      mounted.current = false;
      operation.current?.abort();
      operation.current = undefined;
    };
  }, [actor]);
  function assertCurrent(controller = operation.current) {
    if (
      !mounted.current ||
      !controller ||
      controller.signal.aborted ||
      operation.current !== controller
    )
      throw new DOMException('Workflow changed', 'AbortError');
    return controller;
  }
  async function confirmActor(controller: AbortController) {
    assertCurrent(controller);
    let current: Actor | undefined;
    try {
      current = await readActor(controller.signal);
    } catch {
      assertCurrent(controller);
      controller.abort();
      onActorInvalid();
      throw new DOMException('Session unavailable', 'AbortError');
    }
    assertCurrent(controller);
    if (!current || !sameActor(current, actor)) {
      clearSavedReview();
      controller.abort();
      onActorInvalid();
      throw new DOMException('Session changed', 'AbortError');
    }
  }
  async function command(input: unknown) {
    const controller = assertCurrent();
    await confirmActor(controller);
    let value: unknown;
    try {
      value = await bootstrapCommand(input, controller.signal);
    } catch (cause) {
      assertCurrent(controller);
      await confirmActor(controller);
      throw cause;
    }
    assertCurrent(controller);
    await confirmActor(controller);
    return value;
  }
  async function verify(value: z.infer<typeof step>) {
    const controller = assertCurrent();
    await confirmActor(controller);
    await performWebAuthnStepUp({ ...value, stepUp: 'FRESH_WEBAUTHN_MAX_5M' }, value);
    assertCurrent(controller);
    await confirmActor(controller);
  }
  function save(value: z.infer<typeof reviewSchema>, id: string) {
    assertCurrent();
    try {
      sessionStorage.setItem(
        storageKey,
        JSON.stringify({ actor, review: value, approvalId: id, savedAt: Date.now() }),
      );
    } catch {
      /* In-memory review remains usable when tab storage is unavailable. */
    }
  }
  async function run(work: () => Promise<void>) {
    if (!mounted.current || operation.current) return;
    const controller = new AbortController();
    operation.current = controller;
    setBusy(true);
    setError('');
    try {
      await work();
    } catch (cause) {
      if (mounted.current && operation.current === controller && !controller.signal.aborted)
        setError(failureMessage(cause));
    } finally {
      if (mounted.current && operation.current === controller) {
        operation.current = undefined;
        setBusy(false);
      }
    }
  }
  function invalidateOperation() {
    if (!operation.current) return;
    operation.current.abort();
    operation.current = undefined;
    setBusy(false);
    setPendingOriginal(false);
    setStatus(
      'Inputs changed. Read the original outcome before continuing an uncertain operation.',
    );
  }
  async function prepare(form: HTMLFormElement) {
    const data = new FormData(form);
    const value = reviewSchema.parse(
      await command({
        command: 'PREPARE',
        displayName: data.get('participant'),
        administratorName: data.get('administrator'),
        recipientIssuer: data.get('issuer'),
        recipientSubject: data.get('subject'),
        recipientAudience: data.get('audience'),
        ttlMinutes: Number(data.get('ttl')),
        checkerPrincipalId: data.get('checker'),
        reason: data.get('reason'),
        actionIntentIds: data.getAll('action'),
      }),
    );
    save(value, '');
    setReview(value);
    setApprovalId('');
    setLink('');
    setPendingOriginal(false);
    setStatus(
      'Review the exact administrator, provider, capabilities and lifetime before requesting independent approval.',
    );
  }
  function showReceipt(value: z.infer<typeof commitReceiptSchema>) {
    if (value.participantId !== review?.candidate.participantId)
      throw new BootstrapFailure('unavailable');
    setPendingOriginal(false);
    setLink(value.invitationLink ?? '');
    setStatus(
      value.state === 'CANCELLED'
        ? 'The first-administrator invitation is permanently revoked. No administration was activated.'
        : value.state === 'ACTIVE'
          ? 'The replacement invitation is saved with its original deadline. The old link and ceremony session are invalid.'
          : 'The empty Participant and invitation are saved. Administration remains inactive until recipient acceptance.',
    );
  }
  async function readOriginal() {
    if (!review) return;
    setLink('');
    setStatus('');
    setPendingOriginal(false);
    const value = originalReadSchema.parse(
      await command({ command: 'READ_ORIGINAL', reviewToken: review.reviewToken }),
    );
    if (value.state !== 'NOT_CONSUMED') {
      showReceipt(value);
      return;
    }
    if (
      value.participantId !== review.candidate.participantId ||
      value.candidateDigest !== review.candidateDigest
    )
      throw new BootstrapFailure('unavailable');
    const ready = value.proposalState === 'APPROVED';
    setPendingOriginal(ready);
    setStatus(
      ready
        ? 'The original intent has not been consumed. Continue with fresh verification only after independent approval.'
        : `The original intent has not been consumed. Proposal state: ${value.proposalState}. Read the original approval before continuing.`,
    );
  }
  return (
    <section
      className="participant-onboarding mt-6 grid min-w-0 gap-4 [overflow-wrap:anywhere]"
      aria-label="First Participant administrator"
      hidden={checking}
      inert={checking}
      style={checking ? { display: 'none' } : undefined}
    >
      <h2 className="text-xl font-semibold">
        Create a Participant and invite its first administrator
      </h2>
      <p>
        A Platform operator proposes the empty Participant. A different Platform operator approves
        it. The invited administrator proves their exact provider account and accepts with an
        authenticator before any access becomes active.
      </p>
      <ol className="onboarding-steps" aria-label="Participant onboarding steps">
        <li>
          <span>1</span>
          <strong>Propose the Participant</strong>
        </li>
        <li>
          <span>2</span>
          <strong>Independent approval</strong>
        </li>
        <li>
          <span>3</span>
          <strong>Administrator acceptance</strong>
        </li>
      </ol>
      <nav className="onboarding-tasks" aria-label="Participant onboarding tasks">
        <a href="#first-admin-proposal">Create a Participant</a>
        <a href="#first-admin-invitation">Manage an invitation</a>
        <a href="#first-admin-checker">Review an approval</a>
      </nav>
      <button
        className={button}
        disabled={busy}
        onClick={() =>
          void run(async () => {
            const value = z.object({ stepUp: step }).parse(await command({ command: 'SESSION' }));
            await verify(value.stepUp);
            setStatus('Platform authenticator verified.');
          })
        }
      >
        Verify Platform authenticator
      </button>
      {error ? <p role="alert">{error}</p> : null}
      <p role="status">{status}</p>
      <form
        id="first-admin-proposal"
        className="onboarding-card grid min-w-0 gap-3 rounded border p-4"
        onChange={invalidateOperation}
        onSubmit={(event) => {
          event.preventDefault();
          const form = event.currentTarget;
          void run(() => prepare(form));
        }}
      >
        <h3 className="text-lg font-semibold">Propose first administration</h3>
        <div className="onboarding-fields">
          {(
            [
              ['participant', 'New Participant name'],
              ['administrator', 'First administrator name'],
              ['issuer', 'Administrator identity provider issuer'],
              ['subject', 'Exact administrator account subject'],
              ['audience', 'Administrator identity provider audience'],
              ['checker', 'Independent Platform checker ID'],
            ] as const
          ).map(([name, label]) => (
            <label key={name} className="grid min-w-0 gap-1">
              {label}
              <input
                name={name}
                required
                className={field}
                maxLength={name === 'issuer' ? 2048 : 255}
              />
            </label>
          ))}
        </div>
        <p className="onboarding-hint">
          Use the account identifiers issued by your identity provider. The recipient must prove
          this exact account; an account hint does not grant access.
        </p>
        <label className="grid gap-1">
          First-administrator invitation lifetime (minutes)
          <input
            className={field}
            name="ttl"
            type="number"
            min={15}
            max={10080}
            defaultValue={1440}
            required
          />
        </label>
        <p>
          The governed Participant setting allows 15 minutes to 7 days; its default is 24 hours.
        </p>
        <fieldset className="onboarding-capabilities grid gap-2">
          <legend>Administrator capabilities</legend>
          {administrativeActions.map(([id, label]) => (
            <label key={id} className="flex items-start gap-2">
              <input type="checkbox" name="action" value={id} defaultChecked />
              {label}
            </label>
          ))}
        </fieldset>
        <label className="grid gap-1">
          Reason for creating this Participant
          <textarea className={field} name="reason" minLength={10} maxLength={1024} required />
        </label>
        <button className={`${button} onboarding-primary`} disabled={busy} type="submit">
          Prepare first-administrator review
        </button>
      </form>
      <section
        id="first-admin-invitation"
        className="onboarding-card grid gap-3 rounded border p-4"
        aria-label="Manage first-administrator custody"
      >
        <h3 className="text-lg font-semibold">
          Manage an outstanding first-administrator invitation
        </h3>
        <label className="grid gap-1">
          Participant with outstanding first administration
          <input
            className={field}
            value={custodyParticipant}
            onChange={(event) => {
              invalidateOperation();
              setCustodyParticipant(event.target.value);
              setCustody(undefined);
            }}
          />
        </label>
        <button
          className={button}
          disabled={busy}
          onClick={() =>
            void run(async () =>
              setCustody(
                firstAdministratorCustody.parse(
                  await command({ command: 'READ_CUSTODY', participantId: custodyParticipant }),
                ),
              ),
            )
          }
        >
          Read first-administrator custody
        </button>
        {custody ? (
          <>
            <p>
              Custody state: {custody.state}. Invitation version: {custody.tokenVersion}.
            </p>
            <p>Acceptance deadline: {custody.expiresAt}</p>
            <p>
              Original Platform maker: {custody.makerPrincipalId}. Independent checker:{' '}
              {custody.checkerPrincipalId}.
            </p>
            <p>
              Rotation preserves the recipient, role and original deadline. It invalidates the
              previous link and ceremony session, so the recipient must prove their account again.
              Revocation closes this invitation permanently.
            </p>
            <form
              className="grid gap-3"
              onChange={invalidateOperation}
              onSubmit={(event) => {
                event.preventDefault();
                const data = new FormData(event.currentTarget);
                void run(async () => {
                  const value = reviewSchema.parse(
                    await command({
                      command: 'PREPARE_CHANGE',
                      participantId: custody.participantId,
                      mutation: data.get('mutation'),
                      reason: data.get('reason'),
                    }),
                  );
                  save(value, '');
                  setReview(value);
                  setApprovalId('');
                  setLink('');
                  setPendingOriginal(false);
                  setStatus(
                    'Review this custody change and request approval from the original independent checker.',
                  );
                });
              }}
            >
              <label className="grid gap-1">
                First-administrator custody change
                <select className={field} name="mutation">
                  <option value="ROTATE">Rotate invitation link</option>
                  <option value="REVOKE">Revoke invitation permanently</option>
                </select>
              </label>
              <label className="grid gap-1">
                Reason for changing first-administrator custody
                <textarea
                  className={field}
                  name="reason"
                  required
                  minLength={10}
                  maxLength={1024}
                />
              </label>
              <button
                className={button}
                disabled={busy || !['ACTIVE', 'CLAIM_PENDING'].includes(custody.state)}
              >
                Prepare custody change
              </button>
            </form>
          </>
        ) : null}
      </section>
      {review ? (
        <section
          className="onboarding-card grid gap-3 rounded border p-4"
          aria-label="Prepared first administration"
        >
          <h3 className="text-lg font-semibold">Review first administration</h3>
          <Candidate value={review.candidate} />
          <p>Candidate digest: {review.candidateDigest}</p>
          <button className={button} disabled={busy} onClick={() => void run(readOriginal)}>
            Read original invitation outcome
          </button>
          <button
            className={button}
            disabled={busy || !!approvalId}
            onClick={() =>
              void run(async () => {
                const value = z
                  .strictObject({ approvalRequestId: z.uuid() })
                  .parse(await command({ command: 'SUBMIT', reviewToken: review.reviewToken }));
                save(review, value.approvalRequestId);
                setApprovalId(value.approvalRequestId);
                setStatus('Independent approval requested. No invitation has been issued yet.');
              })
            }
          >
            Request first-administrator approval
          </button>
          {approvalId ? (
            <>
              <p>Approval request: {approvalId}</p>
              <p>
                Checker review uses Participant {review.candidate.participantId} and candidate
                digest {review.candidateDigest}.
              </p>
              <button className={button} disabled={busy} onClick={() => void run(readOriginal)}>
                {review && 'change' in review.candidate
                  ? 'Check original custody-change status'
                  : 'Check original invitation status'}
              </button>
              {pendingOriginal ? (
                <button
                  className={`${button} onboarding-primary`}
                  disabled={busy}
                  onClick={() =>
                    void run(async () => {
                      setPendingOriginal(false);
                      setStatus('');
                      await verify(review.stepUp);
                      showReceipt(
                        commitReceiptSchema.parse(
                          await command({
                            command: 'COMMIT',
                            reviewToken: review.reviewToken,
                            approvalRequestId: approvalId,
                          }),
                        ),
                      );
                    })
                  }
                >
                  {'change' in review.candidate
                    ? 'Verify and apply custody change'
                    : 'Verify and issue invitation'}
                </button>
              ) : null}
            </>
          ) : null}
          {link ? (
            <label className="grid gap-1">
              First-administrator invitation link
              <input
                className={field}
                value={link}
                readOnly
                onFocus={(event) => event.target.select()}
              />
            </label>
          ) : null}
        </section>
      ) : null}
      <section
        id="first-admin-checker"
        className="onboarding-card grid gap-3 rounded border p-4"
        aria-label="Independent first-administrator approval"
      >
        <h3 className="text-lg font-semibold">Review as the independent Platform checker</h3>
        <label className="grid gap-1">
          Proposed Participant ID
          <input
            className={field}
            value={resourceId}
            onChange={(event) => {
              invalidateOperation();
              setResourceId(event.target.value);
              setChecked(undefined);
            }}
          />
        </label>
        <label className="grid gap-1">
          First-administrator candidate digest
          <input
            className={field}
            value={candidateDigest}
            onChange={(event) => {
              invalidateOperation();
              setCandidateDigest(event.target.value);
              setChecked(undefined);
            }}
          />
        </label>
        <label className="grid gap-1">
          First-administrator approval request ID
          <input
            className={field}
            value={checkerApprovalId}
            onChange={(event) => {
              invalidateOperation();
              setCheckerApprovalId(event.target.value);
              setChecked(undefined);
            }}
          />
        </label>
        <button
          className={button}
          disabled={busy}
          onClick={() =>
            void run(async () => {
              setChecked(
                checkedSchema.parse(
                  await command({
                    command: 'REVIEW',
                    resourceId,
                    candidateDigest,
                    approvalRequestId: checkerApprovalId,
                  }),
                ),
              );
            })
          }
        >
          Load first-administrator approval
        </button>
        {checked ? (
          <>
            <Candidate value={checked.proposal.candidate} />
            <p>Approval state: {checked.approval.state}</p>
            <button
              className={`${button} onboarding-primary`}
              disabled={busy || checked.approval.state !== 'REQUESTED'}
              onClick={() =>
                void run(async () => {
                  await verify(checked.stepUp);
                  approvedResponseSchema.parse(
                    await command({
                      command: 'APPROVE',
                      resourceId,
                      candidateDigest,
                      approvalRequestId: checkerApprovalId,
                    }),
                  );
                  setChecked(
                    checkedSchema.parse(
                      await command({
                        command: 'REVIEW',
                        resourceId,
                        candidateDigest,
                        approvalRequestId: checkerApprovalId,
                      }),
                    ),
                  );
                  setStatus('Independent approval recorded. The maker can issue the invitation.');
                })
              }
            >
              Approve first administration with authenticator
            </button>
          </>
        ) : null}
      </section>
    </section>
  );
}
function Candidate({ value }: { value: z.infer<typeof firstAdministratorCandidate> }) {
  if ('change' in value)
    return (
      <div className="grid gap-1">
        <p>Participant: {value.participantId}</p>
        <p>
          Custody change:{' '}
          {value.change.mutation === 'ROTATE'
            ? 'Rotate invitation link'
            : 'Revoke invitation permanently'}
        </p>
        <p>
          Invitation: {value.invitationId}. Current version: {value.tokenVersion}. Custody
          generation: {value.custodyGeneration}.
        </p>
        <p>
          The original recipient, administrator role and acceptance deadline remain fixed. Approval
          cannot reopen expired or completed custody.
        </p>
      </div>
    );
  const first = value.firstAdministrator;
  return (
    <div className="grid gap-1">
      <p>
        Participant: {value.displayName} ({value.participantId})
      </p>
      <p>Administrator: {first.displayName}</p>
      <p>Exact provider account: {first.recipientSubject}</p>
      <p>Provider issuer: {first.recipientIssuer}</p>
      <p>Provider audience: {first.recipientAudience}</p>
      <p>
        Invitation lifetime: {first.configuration['participant.first_admin_invite_ttl'] / 60000}{' '}
        minutes
      </p>
      <details>
        <summary>Approved administrator capabilities</summary>
        <ul>
          {first.actionIntentIds.map((id) => (
            <li key={id}>{administrativeActions.find(([action]) => action === id)?.[1] ?? id}</li>
          ))}
        </ul>
      </details>
      <p>
        Platform custody ends when the first administrator accepts. This invitation gives Platform
        operators no runtime access.
      </p>
    </div>
  );
}
