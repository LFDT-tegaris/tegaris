'use client';

import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { actorSchema, canonical, validatedReview, type Review } from './platform-ceiling-review';
import type {
  PlatformScopeReplacementPreparation,
  PlatformScopeReplacementCommit,
} from '../../../services/participant-service/src/contracts/platform-scope-replacement';

import type {
  platformScopeReadinessSchema,
  platformScopeSourceSchema,
} from '../../../services/participant-service/src/contracts/platform-scope-readback';

const endpoint = '/api/v1/ui/platform-ceiling-workbench';
const savedKey = 'openpc:platform-ceiling-review:v1';
const closedRecoverySchema = z.strictObject({
  enrollmentId: z.uuidv7(),
  recoveryId: z.uuidv7(),
  state: z.enum(['EXPIRED', 'REVOKED']),
  authority: z.literal('NONE'),
  intentDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  activationOperationId: z.uuidv7(),
  candidateDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  businessIdempotencyKey: z.string().min(16).max(128),
  principalId: z.uuidv7(),
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
});
const panel = 'rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const field = 'w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button = 'rounded bg-[color:var(--accent)] px-3 py-2 text-white disabled:opacity-60';
interface Actor {
  sessionId: string;
  principalId: string;
  participantId: string;
  privacyDomainId: string;
  contextEpoch: string;
}
interface StepUp {
  actionIntentId: string;
  actionIntentDigest: string;
  resourceId: string;
  resourceDigest: string;
}
const resumeStepUpSchema = z.strictObject({
  actionIntentId: z.literal('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'),
  actionIntentDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  resourceId: z.uuidv7(),
  resourceDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
});
function resumeReceivingStep(approval: ApprovalView, approvalId: string) {
  const parsed = resumeStepUpSchema.safeParse(approval.resumeStepUp);
  return parsed.success && parsed.data.resourceId === approvalId ? parsed.data : undefined;
}

interface ApprovalView {
  actor?: Actor;
  custodyCorrespondence?: {
    retainedReviewTokenDigest: string;
    approvalRequestId: string;
    candidateDigest: string;
    businessIdempotencyKey: string;
    checkerPrincipalId: string;
  };
  approval: { state: string; makerSubjectRef: string; checkerSubjectRef: string };
  candidate?: { canRequestResume?: boolean };
  resumableReview?: Review;
  body: PlatformScopeReplacementPreparation | PlatformScopeReplacementCommit;
  stepUp: StepUp | null;
  resumeStepUp?: StepUp | null;
}
const failureMessages = {
  unavailable:
    'The original request could not be confirmed. Read its authoritative state before retrying.',
  authorization:
    'The request was not authorized. Refresh the authenticated context before continuing.',
  conflict: 'The original state changed. Read its authoritative state before continuing.',
  input: 'The request was rejected. Check the inputs before continuing.',
  storage: 'The original review could not be saved. Restore browser storage before continuing.',
  changed: 'The working context changed. Read the original operation before continuing.',
} as const;
class WorkflowFailure extends Error {
  constructor(readonly kind: keyof typeof failureMessages) {
    super(failureMessages[kind]);
  }
}
const failureMessage = (error: unknown) =>
  error instanceof WorkflowFailure ? failureMessages[error.kind] : failureMessages.unavailable;
async function json<T>(response: Response): Promise<T> {
  if (!response.ok)
    throw new WorkflowFailure(
      [401, 403, 404].includes(response.status)
        ? 'authorization'
        : [409, 412, 428].includes(response.status)
          ? 'conflict'
          : [400, 422].includes(response.status)
            ? 'input'
            : 'unavailable',
    );
  const value = await response.json().catch(() => undefined);
  if (value === undefined) throw new WorkflowFailure('unavailable');
  return value as T;
}
const requestPost = <T,>(body: unknown, signal?: AbortSignal) =>
  fetch(endpoint, {
    method: 'POST',
    signal,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).then(json<T>);
const requestGet = <T,>(query: Record<string, string> = {}, signal?: AbortSignal) =>
  fetch(`${endpoint}?${new URLSearchParams(query)}`, {
    cache: 'no-store',
    signal,
    credentials: 'same-origin',
  }).then(json<T>);
type Custody = Review & {
  actor: Actor;
  disposition: 'REVIEWED' | 'UNCERTAIN' | 'REQUESTED';
  originalReviewToken?: string;
};
// Every writer of the shared active custody key uses the same origin lock.
// Storage equality is checked inside the lock before any replacement/removal.
async function withCustodyLock<T>(work: () => T): Promise<T> {
  try {
    if (!navigator.locks?.request) throw new WorkflowFailure('storage');
    return await navigator.locks.request(savedKey, { mode: 'exclusive' }, work);
  } catch (error) {
    if (error instanceof WorkflowFailure) throw error;
    throw new WorkflowFailure('storage');
  }
}
const list = (value: FormDataEntryValue | null) =>
  String(value ?? '')
    .split(/[\s,]+/u)
    .filter(Boolean);

export function PlatformCeilingWorkflow() {
  const [actor, setActor] = useState<Actor>();
  const actorRef = useRef<Actor | undefined>(undefined);
  const mounted = useRef(false),
    generation = useRef(0);
  const inFlight = useRef<
    { generation: number; actor: string; controller: AbortController } | undefined
  >(undefined);
  const custody = useRef<Custody | undefined>(undefined);
  const custodyRaw = useRef<string | null>(null);
  const blocked = useRef(false);
  const [names, setNames] = useState<Record<string, string>>({});
  const [administratorLifetime, setAdministratorLifetime] = useState<{
    minimumSeconds: number;
    maximumSeconds: number;
    defaultSeconds: number;
  }>();
  const [review, setReview] = useState<Review>();
  const [source, setSource] = useState<z.infer<typeof platformScopeSourceSchema>>();
  const [readiness, setReadiness] = useState<z.infer<typeof platformScopeReadinessSchema>>();
  const [approval, setApproval] = useState<ApprovalView>();
  const [rootId, setRootId] = useState('');
  const [replacementId, setReplacementId] = useState('');
  const [approvalId, setApprovalId] = useState('');
  const [checkerId, setCheckerId] = useState('');
  const [reservationId, setReservationId] = useState('');
  const [reason, setReason] = useState('');
  const [recoveryEnrollmentId, setRecoveryEnrollmentId] = useState('');
  const [recoveryCaseId, setRecoveryCaseId] = useState('');
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState(
    'Load the current Platform source before proposing a replacement.',
  );
  useEffect(() => {
    let current = true;
    mounted.current = true;
    void requestGet<{
      actor: Actor;
      suggestedIds: Record<string, string>;
      administratorLifetime: {
        minimumSeconds: number;
        maximumSeconds: number;
        defaultSeconds: number;
      };
    }>()
      .then(async (state) => {
        if (!current) return;
        const bound = actorSchema.safeParse(state.actor);
        if (!bound.success) throw new WorkflowFailure('authorization');
        actorRef.current = bound.data;
        setActor(bound.data);
        setNames(state.suggestedIds);
        setAdministratorLifetime(state.administratorLifetime);
        setReplacementId(state.suggestedIds.replacementId ?? '');
        try {
          const raw = localStorage.getItem(savedKey);
          custodyRaw.current = raw;
          if (!raw) return;
          const stored = JSON.parse(raw) as Partial<Custody>;
          if (canonical(stored.actor) !== canonical(bound.data)) {
            // Preserve opaque original custody, remove old actor's plaintext view.
            await withCustodyLock(() => {
              if (!current) throw new WorkflowFailure('changed');
              if (localStorage.getItem(savedKey) !== raw) throw new WorkflowFailure('conflict');
              const redacted = JSON.stringify({
                actor: stored.actor,
                reviewToken: stored.reviewToken,
                originalReviewToken: stored.originalReviewToken ?? stored.reviewToken,
                approvalRequestId: stored.approvalRequestId,
                candidateDigest: stored.review?.candidateDigest,
                disposition: stored.disposition === 'REQUESTED' ? 'REQUESTED' : 'UNCERTAIN',
              });
              localStorage.setItem(savedKey, redacted);
              if (localStorage.getItem(savedKey) !== redacted) throw new WorkflowFailure('storage');
              custodyRaw.current = redacted;
            });
            blocked.current = true;
            setStatus(failureMessages.changed);
            return;
          }
          const next = await validatedReview(stored);
          if (!current) return;
          const disposition = stored.disposition ?? 'REVIEWED';
          custody.current = {
            ...next,
            actor: bound.data,
            disposition,
            originalReviewToken: stored.originalReviewToken ?? next.reviewToken,
          };
          setReview(next);
          setRootId(next.review.body.platformContextId);
          setReplacementId(next.review.body.replacementId);
          setCheckerId(next.review.checkerPrincipalId);
          setApprovalId(next.approvalRequestId ?? '');
          setReason(next.review.body.reason);
        } catch {
          if (current) {
            blocked.current = true;
            setReview(undefined);
            setStatus(failureMessages.storage);
          }
        }
      })
      .catch((error: unknown) => {
        if (current) setStatus(failureMessage(error));
      });
    return () => {
      current = false;
      mounted.current = false;
      generation.current += 1;
      inFlight.current?.controller.abort();
    };
  }, []);
  function assertCurrent(token: NonNullable<typeof inFlight.current>) {
    if (
      !mounted.current ||
      inFlight.current !== token ||
      token.generation !== generation.current ||
      token.actor !== canonical(actorRef.current)
    )
      throw new WorkflowFailure('changed');
  }
  async function run(work: () => Promise<void>) {
    if (inFlight.current || !actorRef.current) return;
    const token = {
      generation: generation.current,
      actor: canonical(actorRef.current),
      controller: new AbortController(),
    };
    inFlight.current = token;
    setBusy(true);
    try {
      await work();
    } catch (error) {
      if (mounted.current && token.generation === generation.current)
        setStatus(failureMessage(error));
    } finally {
      if (inFlight.current === token) {
        inFlight.current = undefined;
        if (mounted.current) setBusy(false);
      }
    }
  }
  async function post<T>(body: unknown): Promise<T> {
    const token = inFlight.current;
    if (!token) throw new WorkflowFailure('changed');
    assertCurrent(token);
    if (blocked.current) throw new WorkflowFailure('changed');
    const next = await requestPost<T>(body, token.controller.signal);
    assertCurrent(token);
    return next;
  }
  async function get<T>(query: Record<string, string> = {}): Promise<T> {
    const token = inFlight.current;
    if (!token) throw new WorkflowFailure('changed');
    assertCurrent(token);
    const next = await requestGet<T>(query, token.controller.signal);
    assertCurrent(token);
    return next;
  }
  async function persist(value: Custody) {
    const expected = custodyRaw.current;
    const token = inFlight.current;
    if (!token) throw new WorkflowFailure('changed');
    await withCustodyLock(() => {
      assertCurrent(token);
      if (localStorage.getItem(savedKey) !== expected) throw new WorkflowFailure('conflict');
      const raw = JSON.stringify(value);
      localStorage.setItem(savedKey, raw);
      if (localStorage.getItem(savedKey) !== raw) throw new WorkflowFailure('storage');
      custodyRaw.current = raw;
      custody.current = value;
    });
  }
  function retireCustody(expected: string | null) {
    if (expected === null || localStorage.getItem(savedKey) !== expected)
      throw new WorkflowFailure('conflict');
    localStorage.removeItem(savedKey);
    if (localStorage.getItem(savedKey) !== null) throw new WorkflowFailure('storage');
    custodyRaw.current = null;
    custody.current = undefined;
  }
  async function retain(
    value: unknown,
    provenance: 'PREVIEW' | 'SUBMISSION' | 'OWNER_READBACK' | 'RESUME' = 'PREVIEW',
  ) {
    const token = inFlight.current;
    if (!token) throw new WorkflowFailure('changed');
    assertCurrent(token);
    const next = await validatedReview(value);
    assertCurrent(token);
    if (blocked.current) throw new WorkflowFailure('changed');
    const old = custody.current;
    if (old && old.disposition !== 'REVIEWED' && provenance === 'PREVIEW')
      throw new WorkflowFailure('conflict');
    if (
      old &&
      (old.disposition !== 'REVIEWED' || provenance !== 'PREVIEW') &&
      (old.review.businessIdempotencyKey !== next.review.businessIdempotencyKey ||
        old.review.candidateDigest !== next.review.candidateDigest ||
        canonical(old.review.body) !== canonical(next.review.body) ||
        old.review.checkerPrincipalId !== next.review.checkerPrincipalId)
    )
      throw new WorkflowFailure('conflict');
    const same = old && canonical(old.review) === canonical(next.review);
    const saved = {
      ...next,
      originalReviewToken: old?.originalReviewToken ?? old?.reviewToken ?? next.reviewToken,
      reviewToken: same && provenance === 'SUBMISSION' ? old.reviewToken : next.reviewToken,
      actor: actorRef.current!,
      disposition: next.approvalRequestId
        ? ('REQUESTED' as const)
        : provenance === 'OWNER_READBACK' && old
          ? old.disposition
          : ('REVIEWED' as const),
    };
    await persist(saved);
    assertCurrent(token);
    setReview(saved);
    setApprovalId(saved.approvalRequestId ?? '');
    setReplacementId(saved.review.body.replacementId);
  }
  async function readOriginalApproval(selectedId: string): Promise<ApprovalView> {
    if (!blocked.current) {
      const loaded = await get<ApprovalView>({ approvalRequestId: selectedId });
      if (loaded.resumableReview) await retain(loaded.resumableReview, 'OWNER_READBACK');
      return loaded;
    }
    const token = inFlight.current;
    if (!token) throw new WorkflowFailure('changed');
    assertCurrent(token);
    const expected = custodyRaw.current;
    if (!expected || localStorage.getItem(savedKey) !== expected)
      throw new WorkflowFailure('conflict');
    const original = JSON.parse(expected) as Partial<Custody>;
    const retainedReviewToken = original.originalReviewToken ?? original.reviewToken;
    if (typeof retainedReviewToken !== 'string') throw new WorkflowFailure('storage');
    // This owner read cannot submit, approve or execute the old session's seal.
    const loaded = await requestPost<ApprovalView>(
      { command: 'RECONCILE_APPROVAL_REVIEW', approvalRequestId: selectedId, retainedReviewToken },
      token.controller.signal,
    );
    assertCurrent(token);
    const next = await validatedReview(loaded.resumableReview);
    const actor = actorSchema.safeParse(loaded.actor),
      proof = loaded.custodyCorrespondence;
    const hash = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(canonical(retainedReviewToken)),
    );
    const tokenDigest =
      'sha256:' +
      Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, '0')).join('');
    assertCurrent(token);
    if (
      !actor.success ||
      canonical(actor.data) !== canonical(actorRef.current) ||
      !proof ||
      proof.retainedReviewTokenDigest !== tokenDigest ||
      proof.approvalRequestId !== selectedId ||
      next.approvalRequestId !== selectedId ||
      proof.candidateDigest !== next.review.candidateDigest ||
      proof.businessIdempotencyKey !== next.review.businessIdempotencyKey ||
      proof.checkerPrincipalId !== next.review.checkerPrincipalId ||
      loaded.approval.makerSubjectRef !== `urn:openpc:resource:${actor.data.principalId}` ||
      loaded.candidate?.canRequestResume !== true ||
      (original.approvalRequestId !== undefined && original.approvalRequestId !== selectedId)
    )
      throw new WorkflowFailure('changed');
    if (custodyRaw.current !== expected) throw new WorkflowFailure('conflict');
    const saved: Custody = {
      ...next,
      actor: actor.data,
      originalReviewToken: retainedReviewToken,
      disposition: 'REQUESTED',
    };
    await withCustodyLock(() => {
      assertCurrent(token);
      if (custodyRaw.current !== expected || localStorage.getItem(savedKey) !== expected)
        throw new WorkflowFailure('conflict');
      const raw = JSON.stringify(saved);
      localStorage.setItem(savedKey, raw);
      if (localStorage.getItem(savedKey) !== raw) throw new WorkflowFailure('storage');
      custodyRaw.current = raw;
      custody.current = saved;
      // Adoption and release of the stale-session hold share the origin lock.
      blocked.current = false;
    });
    assertCurrent(token);
    if (localStorage.getItem(savedKey) !== custodyRaw.current) {
      blocked.current = true;
      throw new WorkflowFailure('conflict');
    }
    setReview(saved);
    setApprovalId(selectedId);
    setReplacementId(saved.review.body.replacementId);
    return loaded;
  }
  async function preserveUncertainty(selected: Review) {
    const old = custody.current;
    if (
      !old ||
      old.reviewToken !== selected.reviewToken ||
      canonical(old.review) !== canonical(selected.review) ||
      canonical(old.actor) !== canonical(actorRef.current)
    )
      throw new WorkflowFailure('storage');
    await persist({ ...old, disposition: 'UNCERTAIN' });
  }
  async function verify(step: StepUp) {
    const token = inFlight.current;
    if (!token) throw new WorkflowFailure('changed');
    assertCurrent(token);
    if (blocked.current) throw new WorkflowFailure('changed');
    await performWebAuthnStepUp(
      { ...step, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      { resourceId: step.resourceId, resourceDigest: step.resourceDigest },
      {
        signal: token.controller.signal,
        isCurrent: () =>
          mounted.current &&
          inFlight.current === token &&
          token.generation === generation.current &&
          token.actor === canonical(actorRef.current),
      },
    );
    assertCurrent(token);
  }
  function invalidate() {
    generation.current += 1;
    inFlight.current?.controller.abort();
    setReview(undefined);
    setApproval(undefined);
    setSource(undefined);
    setReadiness(undefined);
    if (custody.current?.disposition === 'REVIEWED') {
      const selectedGeneration = generation.current,
        expected = custodyRaw.current;
      blocked.current = true;
      void withCustodyLock(() => {
        if (!mounted.current || generation.current !== selectedGeneration) return;
        retireCustody(expected);
        blocked.current = false;
      }).catch(() => {
        if (mounted.current && generation.current === selectedGeneration) {
          blocked.current = true;
          setStatus(failureMessages.storage);
        }
      });
    } else if (custody.current) blocked.current = true;
  }
  function invalidateReadSelection() {
    generation.current += 1;
    inFlight.current?.controller.abort();
    setApproval(undefined);
  }
  return (
    <section
      className={panel}
      aria-label="Governed Platform ceiling replacement"
      onChangeCapture={(event) => {
        if ((event.target as HTMLElement).dataset.custodyReadback) invalidateReadSelection();
        else invalidate();
      }}
    >
      <h2 className="text-xl font-semibold">Replace the Platform authority ceiling</h2>
      <p className="mt-2">
        This transition withdraws affected runtime authority before installing the approved
        successor. Administration remains subject to independent approval and a security key.
      </p>
      <fieldset className="mt-4 space-y-3 rounded border p-3">
        <legend>Enrolled recovery handoff</legend>
        <p>
          After recovery activation, the restored maker signs in again and loads the exact reviewed
          handoff. Approval and execution remain separate.
        </p>
        <label className="block">
          Recovery enrollment ID
          <input
            className={field}
            value={recoveryEnrollmentId}
            data-custody-readback="true"
            onChange={(event) => {
              setRecoveryEnrollmentId(event.target.value);
              setReview(undefined);
            }}
          />
        </label>
        <label className="block">
          Recovery case ID
          <input
            className={field}
            value={recoveryCaseId}
            data-custody-readback="true"
            onChange={(event) => {
              setRecoveryCaseId(event.target.value);
              setReview(undefined);
            }}
          />
        </label>
        <button
          type="button"
          className={button}
          disabled={busy || !actor || !recoveryEnrollmentId || !recoveryCaseId}
          onClick={() =>
            void run(async () => {
              setReview(undefined);
              const original = custody.current;
              const next = await post<Review>({
                command: 'PREVIEW_RECOVERY_HANDOFF',
                enrollmentId: recoveryEnrollmentId,
                recoveryId: recoveryCaseId,
                ...(original
                  ? { retainedReviewToken: original.originalReviewToken ?? original.reviewToken }
                  : {}),
              });
              await retain(
                {
                  ...next,
                  ...(original?.approvalRequestId
                    ? { approvalRequestId: original.approvalRequestId }
                    : {}),
                },
                original ? 'OWNER_READBACK' : 'PREVIEW',
              );
              setRootId(next.review.body.platformContextId);
              setCheckerId(next.review.checkerPrincipalId);
              setStatus(
                'The original recovery preparation is loaded for independent approval. No Root handoff has executed.',
              );
            })
          }
        >
          Review original recovery handoff
        </button>
        <button
          type="button"
          className={`${button} ml-3`}
          disabled={busy || !actor || !recoveryEnrollmentId || !recoveryCaseId}
          onClick={() =>
            void run(async () => {
              const token = inFlight.current!;
              assertCurrent(token);
              const raw = localStorage.getItem(savedKey);
              if (!raw) throw new WorkflowFailure('storage');
              const stored = JSON.parse(raw) as Partial<Custody>;
              const retainedReviewToken = stored.originalReviewToken ?? stored.reviewToken;
              if (typeof retainedReviewToken !== 'string') throw new WorkflowFailure('storage');
              // Historical reconciliation is available after a session change.
              // It has no proof, review minting or business submission path.
              const result = await requestPost<{ closedRecovery: unknown }>(
                {
                  command: 'RECONCILE_CLOSED_RECOVERY_HANDOFF',
                  enrollmentId: recoveryEnrollmentId,
                  recoveryId: recoveryCaseId,
                  retainedReviewToken,
                },
                token.controller.signal,
              );
              assertCurrent(token);
              const parsed = closedRecoverySchema.safeParse(result.closedRecovery);
              if (
                !parsed.success ||
                parsed.data.enrollmentId !== recoveryEnrollmentId ||
                parsed.data.recoveryId !== recoveryCaseId ||
                parsed.data.principalId !== actorRef.current?.principalId ||
                parsed.data.participantId !== actorRef.current?.participantId ||
                parsed.data.privacyDomainId !== actorRef.current?.privacyDomainId ||
                (stored.review &&
                  (parsed.data.candidateDigest !== stored.review.candidateDigest ||
                    parsed.data.businessIdempotencyKey !== stored.review.businessIdempotencyKey)) ||
                localStorage.getItem(savedKey) !== raw
              )
                throw new WorkflowFailure('conflict');
              const archiveKey = `${savedKey}:closed:${parsed.data.candidateDigest}`;
              // Keep the exact opaque signed body without leaving an old
              // actor's plaintext intent in historical browser storage.
              const archived = JSON.stringify({
                originalCustody: {
                  actor: stored.actor,
                  reviewToken: stored.reviewToken,
                  originalReviewToken: retainedReviewToken,
                  approvalRequestId: stored.approvalRequestId,
                  disposition: stored.disposition,
                  candidateDigest: parsed.data.candidateDigest,
                  businessIdempotencyKey: parsed.data.businessIdempotencyKey,
                },
                closedRecovery: parsed.data,
                businessOutcome: 'UNRECONCILED',
              });
              await withCustodyLock(() => {
                assertCurrent(token);
                if (localStorage.getItem(savedKey) !== raw) throw new WorkflowFailure('conflict');
                const existing = localStorage.getItem(archiveKey);
                if (existing && existing !== archived) throw new WorkflowFailure('storage');
                localStorage.setItem(archiveKey, archived);
                if (localStorage.getItem(archiveKey) !== archived)
                  throw new WorkflowFailure('storage');
                // Also detects storage replacement during archive persistence.
                assertCurrent(token);
                retireCustody(raw);
              });
              assertCurrent(token);
              blocked.current = false;
              setReview(undefined);
              setApproval(undefined);
              setApprovalId('');
              setStatus(
                'The closed recovery review is retained with its original request outcome. Fresh recovery requires a new governed case.',
              );
            })
          }
        >
          Retain closed recovery review
        </button>
      </fieldset>
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <label>
          Platform context ID
          <input
            className={field}
            value={rootId}
            onChange={(event) => {
              setRootId(event.target.value);
              setSource(undefined);
              setReadiness(undefined);
              setReview(undefined);
              setApproval(undefined);
            }}
          />
        </label>
        <label>
          Replacement ID
          <input
            className={field}
            value={replacementId}
            onChange={(event) => {
              setReplacementId(event.target.value);
              setReadiness(undefined);
              setReview(undefined);
            }}
          />
        </label>
      </div>
      <button
        type="button"
        className={`${button} mt-3`}
        disabled={busy || !actor || !rootId}
        onClick={() =>
          void run(async () => {
            setSource(undefined);
            setReadiness(undefined);
            const result = await get<{ source: z.infer<typeof platformScopeSourceSchema> }>({
              platformContextId: rootId,
            });
            setSource(result.source);
            setStatus('Current root and the complete affected runtime cohort loaded.');
          })
        }
      >
        Load current ceiling
      </button>
      {source && (
        <dl className="mt-3 grid gap-2 text-sm md:grid-cols-2">
          <div>
            <dt>Current epoch and revision</dt>
            <dd>
              {source.epoch} / {source.revision}
            </dd>
          </div>
          <div>
            <dt>Affected runtime targets</dt>
            <dd>{source.affectedTargets.length}</dd>
          </div>
          <div>
            <dt>Current runtime conditions</dt>
            <dd>
              Approval: {String(source.root.grantable.makerCheckerRequired)}; security key:{' '}
              {String(source.root.grantable.stepUpRequired)}
            </dd>
          </div>
          <div>
            <dt>Pending replacement</dt>
            <dd>{source.pending ?? 'None'}</dd>
            {source.pendingIntent && (
              <dd>
                A new reviewed intent will supersede this pending replacement while keeping runtime
                withdrawn.
              </dd>
            )}
          </div>
        </dl>
      )}
      <form
        className="mt-5 space-y-4"
        onSubmit={(event) => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          void run(async () => {
            setReview(undefined);
            const admins = ['maker', 'checker'].map((prefix) => ({
              principalId: prefix === 'maker' ? actor?.principalId : checkerId,
              roleId: String(data.get(`${prefix}RoleId`) ?? ''),
              envelopeId: String(data.get(`${prefix}EnvelopeId`) ?? ''),
              assignmentId: String(data.get(`${prefix}AssignmentId`) ?? ''),
              actionIntentIds: list(data.get(`${prefix}Actions`)),
              resourceIds: list(data.get(`${prefix}Resources`)),
            }));
            const next = await post<Review>({
              command: 'PREVIEW_PREPARATION',
              ...(reservationId ? { resourceReservationId: reservationId } : {}),
              selection: {
                platformContextId: rootId,
                replacementId,
                administrators: admins,
                ...(list(data.get('terminalActions')).length
                  ? { terminalActionIntentIds: list(data.get('terminalActions')) }
                  : {}),
                lifetimeSeconds: Number(data.get('lifetimeSeconds')),
                ...(source?.pendingIntent ? { supersedes: source.pendingIntent } : {}),
                reason,
              },
            });
            await retain(next);
            setStatus(
              'Review the exact successor and explicit administration grants. No authority has changed.',
            );
          });
        }}
      >
        <div className="grid gap-4 md:grid-cols-2">
          <label>
            Distinct checker principal ID
            <input
              className={field}
              value={checkerId}
              onChange={(event) => {
                setCheckerId(event.target.value);
                setReview(undefined);
              }}
              required
            />
          </label>
          <label>
            Additional terminal administration action IDs
            <textarea
              className={field}
              name="terminalActions"
              onChange={() => setReview(undefined)}
              aria-describedby="terminal-actions-help"
            />
            <span id="terminal-actions-help">
              These bounds grant no actor permission. Separate governed or authorized initial trust
              is required to use them.
            </span>
          </label>
          <label>
            Temporary administrator lifetime in seconds
            <input
              className={field}
              name="lifetimeSeconds"
              type="number"
              key={administratorLifetime?.defaultSeconds}
              min={administratorLifetime?.minimumSeconds}
              max={administratorLifetime?.maximumSeconds}
              defaultValue={administratorLifetime?.defaultSeconds}
              disabled={!administratorLifetime}
              onChange={() => setReview(undefined)}
              required
            />
          </label>
        </div>
        <label className="block">
          Reserved approval operation ID, if using a finite grant
          <input
            className={field}
            value={reservationId}
            onChange={(event) => {
              setReservationId(event.target.value);
              setReview(undefined);
            }}
          />
        </label>
        {(['maker', 'checker'] as const).map((prefix) => (
          <fieldset className="space-y-3 rounded border p-3" key={prefix}>
            <legend>
              {prefix === 'maker'
                ? 'Maker successor administration'
                : 'Checker successor administration'}
            </legend>
            {(['RoleId', 'EnvelopeId', 'AssignmentId', 'Actions', 'Resources'] as const).map(
              (suffix) => (
                <label className="block" key={suffix}>
                  {prefix}{' '}
                  {
                    {
                      RoleId: 'role ID',
                      EnvelopeId: 'envelope ID',
                      AssignmentId: 'assignment ID',
                      Actions: 'administration action IDs',
                      Resources: 'finite resource IDs',
                    }[suffix]
                  }
                  {suffix === 'Actions' || suffix === 'Resources' ? (
                    <textarea
                      className={field}
                      name={`${prefix}${suffix}`}
                      required
                      placeholder="Separate exact identifiers with spaces or commas"
                      onChange={() => setReview(undefined)}
                    />
                  ) : (
                    <input
                      className={field}
                      name={`${prefix}${suffix}`}
                      required
                      defaultValue={names[`${prefix}${suffix}`]}
                      key={`${prefix}${suffix}:${names[`${prefix}${suffix}`] ?? ''}`}
                      onChange={() => setReview(undefined)}
                    />
                  )}
                </label>
              ),
            )}
          </fieldset>
        ))}
        <label className="block">
          Replacement reason
          <textarea
            className={field}
            value={reason}
            minLength={10}
            maxLength={1024}
            required
            onChange={(event) => {
              setReason(event.target.value);
              setReview(undefined);
            }}
          />
        </label>
        <button
          className={button}
          type="submit"
          disabled={busy || !actor || !source || (source.pending !== null && !source.pendingIntent)}
        >
          Review successor ceiling
        </button>
      </form>
      {review && (
        <section
          className="mt-5 space-y-3 rounded border p-3"
          aria-label="Immutable Platform replacement review"
        >
          <h3 className="font-semibold">
            {review.review.phase === 'PREPARE'
              ? 'Successor preparation review'
              : 'Ready successor commit review'}
          </h3>
          <p className="break-all text-xs">Candidate digest: {review.review.candidateDigest}</p>
          <p>
            Predecessor epoch: {review.review.body.predecessorEpoch}; checker:{' '}
            {review.review.checkerPrincipalId}
          </p>
          {review.review.body.schema === 'pc.identity.platform-scope-replacement' && (
            <>
              <p>
                Runtime conditions under the successor: approval{' '}
                {String(review.review.body.successorScope.makerCheckerRequired)}, security key{' '}
                {String(review.review.body.successorScope.stepUpRequired)}.
              </p>
              <p>
                Runtime dimensions are retained. {review.review.body.affectedTargets.length} targets
                require signed withdrawal acknowledgement.
              </p>
              {review.review.body.administrators.map((admin) => (
                <article key={admin.principalId} className="break-all rounded border p-2 text-sm">
                  <p>
                    Administrator {admin.principalId}; role revision {admin.expectedRoleRevision}
                  </p>
                  <p>
                    Envelope {admin.envelopeId}; assignment {admin.assignmentId}
                  </p>
                  <p>Actions: {admin.usable.administration.actionIntentIds.join(', ')}</p>
                  <p>Resources: {admin.usable.administration.resourceIds.join(', ')}</p>
                  <p>
                    Approval and security key required; runtime capabilities: none; delegation:
                    none.
                  </p>
                  <p>
                    Expires:{' '}
                    {new Date(Number(BigInt(admin.usable.validUntilNs) / 1000000n)).toISOString()}
                  </p>
                </article>
              ))}
            </>
          )}
          <button
            className={button}
            type="button"
            disabled={busy || !actor || Boolean(review.approvalRequestId)}
            onClick={() =>
              void run(async () => {
                // Commit proof resolves the durable, authenticated candidate.
                // Its approval request stages that candidate first; EXECUTE
                // still obtains fresh maker proof before the business effect.
                await preserveUncertainty(review);
                if (review.review.phase === 'PREPARE') await verify(review.review.stepUp);
                await retain(
                  await post<Review>({ command: 'SUBMIT', reviewToken: review.reviewToken }),
                  'SUBMISSION',
                );
                setStatus(
                  'Independent approval requested. Share the approval ID with the checker.',
                );
              })
            }
          >
            Request independent replacement approval
          </button>
          <button
            className={`${button} ml-3`}
            type="button"
            disabled={busy || !actor || !approvalId || approval?.approval.state !== 'APPROVED'}
            onClick={() =>
              void run(async () => {
                await preserveUncertainty(review);
                await verify(review.review.stepUp);
                const result = await post<{ result: { state: string } }>({
                  command: 'EXECUTE',
                  reviewToken: review.reviewToken,
                  approvalRequestId: approvalId,
                });
                setStatus(
                  result.result.state === 'WITHDRAWING'
                    ? 'Withdrawal started. Prepare both approved administration envelopes and assignments, then read signed readiness.'
                    : 'Successor committed. Establish fresh login and Participant contexts before new work.',
                );
                setReview(undefined);
                const expected = custodyRaw.current;
                await withCustodyLock(() => {
                  assertCurrent(inFlight.current!);
                  retireCustody(expected);
                });
              })
            }
          >
            Execute approved replacement phase
          </button>
        </section>
      )}
      <div className="mt-5 space-y-3 rounded border p-3">
        <label className="block">
          Replacement approval ID
          <input
            className={field}
            data-custody-readback="true"
            value={approvalId}
            onChange={(event) => {
              setApprovalId(event.target.value);
              setApproval(undefined);
            }}
          />
        </label>
        <button
          className={button}
          type="button"
          disabled={busy || !actor || !approvalId}
          onClick={() =>
            void run(async () => {
              setApproval(undefined);
              const selectedId = approvalId;
              const loaded = await readOriginalApproval(selectedId);
              setApproval(loaded);
              setStatus('Authoritative immutable replacement approval loaded.');
            })
          }
        >
          Load replacement approval
        </button>
        {approval && (
          <>
            <p>
              Approval state: {approval.approval.state}; phase:{' '}
              {approval.body.schema === 'pc.identity.platform-scope-replacement'
                ? 'Preparation'
                : 'Commit'}
            </p>
            <p>
              Root: {approval.body.platformContextId}; replacement: {approval.body.replacementId}
            </p>
            {review &&
              approval.candidate?.canRequestResume &&
              approval.approval.makerSubjectRef === `urn:openpc:resource:${actor?.principalId}` && (
                <button
                  className={button}
                  type="button"
                  disabled={busy || !actor || !resumeReceivingStep(approval, approvalId)}
                  onClick={() =>
                    void run(async () => {
                      const step = resumeReceivingStep(approval, approvalId);
                      if (!step) throw new WorkflowFailure('changed');
                      await verify(step);
                      const resumed = await post<Review>({
                        command: 'RESUME',
                        reviewToken: review.reviewToken,
                        approvalRequestId: approvalId,
                      });
                      await retain(resumed, 'RESUME');
                      setApproval(undefined);
                      setStatus(
                        'A successor approval was requested for the unchanged intent. The checker must approve it with a fresh passkey proof.',
                      );
                    })
                  }
                >
                  Request fresh approval for unchanged replacement
                </button>
              )}
            <button
              className={button}
              type="button"
              disabled={busy || !actor || !approval.stepUp}
              onClick={() =>
                void run(async () => {
                  const selectedId = approvalId,
                    selected = approval;
                  if (!selected.stepUp) return;
                  await verify(selected.stepUp);
                  await post({ command: 'APPROVE', approvalRequestId: selectedId });
                  setApproval(await get<ApprovalView>({ approvalRequestId: selectedId }));
                  setStatus('Distinct checker approval recorded.');
                })
              }
            >
              Approve replacement with saved passkey
            </button>
          </>
        )}
      </div>
      <div className="mt-5 space-y-3 rounded border p-3">
        <button
          className={button}
          type="button"
          disabled={busy || !actor || !rootId || !replacementId}
          onClick={() =>
            void run(async () => {
              setReadiness(undefined);
              const next = await get<{ readiness: z.infer<typeof platformScopeReadinessSchema> }>({
                platformContextId: rootId,
                replacementId,
              });
              setReadiness(next.readiness);
              setStatus(
                'Signed withdrawal and explicit administration readiness read from the owner.',
              );
            })
          }
        >
          Read withdrawal and handoff readiness
        </button>
        {readiness && (
          <>
            <p>
              State: {readiness.state}; pending target acknowledgements:{' '}
              {readiness.unacknowledgedTargets}; pending administrators:{' '}
              {readiness.unpreparedAdministrators}
            </p>
            {readiness.administrators.map((admin) => (
              <p className="break-all" key={admin.principalId}>
                {admin.principalId}: {admin.ready ? 'Ready' : 'Not prepared'}
              </p>
            ))}
            <button
              className={button}
              type="button"
              disabled={
                busy ||
                readiness.state !== 'WITHDRAWING' ||
                readiness.unacknowledgedTargets !== 0 ||
                readiness.unpreparedAdministrators !== 0
              }
              onClick={() =>
                void run(async () => {
                  await retain(
                    await post<Review>({
                      command: 'PREVIEW_COMMIT',
                      ...(reservationId ? { resourceReservationId: reservationId } : {}),
                      platformContextId: rootId,
                      replacementId,
                      checkerPrincipalId: checkerId,
                      reason,
                    }),
                  );
                  setStatus(
                    'Fresh commit candidate prepared from exact authoritative readiness. Independent approval is required.',
                  );
                })
              }
            >
              Review ready successor commit
            </button>
          </>
        )}
      </div>
      <p className="mt-4" role="status" aria-live="polite">
        {status}
      </p>
    </section>
  );
}
