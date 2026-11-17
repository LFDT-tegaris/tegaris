'use client';
import { useEffect, useRef, useState } from 'react';
import type { z } from 'zod';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import {
  savedWorkloadReview,
  workloadState,
  workloadCertificate,
  type WorkloadReview,
} from '../lib/workload-workflow';
import type {
  discoveryCertificateRecoverySourceView,
  discoveryCertificateRecoveryDraftView,
  discoveryCertificateRecoveryReceiptView,
} from '../../../services/identity-service/src/contracts/discovery-certificate-recovery';
import type {
  platformRecoveryCommand,
  platformRecoveryChallengeView,
} from '../../../services/identity-service/src/contracts/platform-recovery';
type Source = z.infer<typeof discoveryCertificateRecoverySourceView>;
type Draft = z.infer<typeof discoveryCertificateRecoveryDraftView>;
type Receipt = z.infer<typeof discoveryCertificateRecoveryReceiptView>;
export type DiscoveryRecoveryView = Source | Draft | Receipt;
const button = 'rounded bg-[color:var(--accent)] px-3 py-2 text-white disabled:opacity-60';
const field = 'w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const endpoint = '/api/v1/ui/workload-workbench';
function originalApprovalId(value: unknown): string {
  if (typeof value !== 'string') throw new Error('Read the original approval again.');
  const prefix = 'urn:openpc:resource:';
  return savedWorkloadReview.shape.approvalRequestId
    .unwrap()
    .parse(value.startsWith(prefix) ? value.slice(prefix.length) : value);
}
export function DiscoveryCertificateRecoveryWorkflow(props: {
  view: DiscoveryRecoveryView;
  actor:
    | { sessionId: string; principalId: string; participantId: string; contextEpoch: string }
    | undefined;
  enrollmentId: string;
  privacyDomainId: string;
  recoveryId: string;
  busy: boolean;
  now: number;
  post: (command: z.infer<typeof platformRecoveryCommand>) => Promise<unknown>;
  assertion: (challenge: z.infer<typeof platformRecoveryChallengeView>) => Promise<string>;
  run: (work: () => Promise<void>) => Promise<void>;
  onView: (view: DiscoveryRecoveryView) => void;
  onCase: (id: string) => void;
  onStatus: (status: string) => void;
}) {
  const { view, actor, busy, now, post, assertion, run, onView, onCase, onStatus } = props;
  const [review, setReview] = useState<WorkloadReview>();
  const [retained, setRetained] = useState<WorkloadReview>();
  const [custodyBlocked, setCustodyBlocked] = useState(false);
  const [state, setState] = useState<z.infer<typeof workloadState>>();
  const [certificate, setCertificate] = useState<z.infer<typeof workloadCertificate>>();
  const [reason, setReason] = useState('');
  const [storageWarning, setStorageWarning] = useState('');
  const mounted = useRef(false),
    generation = useRef(0),
    abort = useRef<AbortController | undefined>(undefined);
  const selected = useRef<string | undefined>(undefined);
  const scope = JSON.stringify([
    props.enrollmentId,
    props.privacyDomainId,
    props.recoveryId,
    actor,
  ]);
  const scopeRef = useRef(scope);
  scopeRef.current = scope;
  const receipt = 'revision' in view ? view : undefined,
    intent = 'intent' in view ? view.intent : undefined;
  const [source, setSource] = useState<Source>();
  useEffect(() => {
    if ('source' in view) setSource(view);
  }, [view]);
  const binding = intent?.certificateRecovery ?? source?.certificateRecovery;
  const actors = receipt?.actors ?? source?.source;
  const executor = !!actor && actor.principalId === actors?.executorPrincipalId;
  const custodian = !!actor && !!actors?.custodianPrincipalIds.includes(actor.principalId);
  const approvals = receipt?.proofs.filter((v) => v.phase === 'APPROVE') ?? [];
  const live =
    !!intent && now >= Date.parse(intent.validFrom) && now < Date.parse(intent.validUntil);
  const authority = live ? (receipt?.authority ?? 'NONE') : 'NONE';
  const maker = !!actor && actor.principalId === intent?.administrators[0].principalId;
  const checker = !!actor && actor.principalId === intent?.administrators[1].principalId;
  const storageKey = 'openpc:discovery-certificate-review:' + scope;
  useEffect(() => {
    mounted.current = true;
    setReview(undefined);
    setRetained(undefined);
    setState(undefined);
    setCertificate(undefined);
    setStorageWarning('');
    setCustodyBlocked(false);
    try {
      const saved = localStorage.getItem(storageKey);
      if (saved) {
        const parsed = savedWorkloadReview.safeParse(JSON.parse(saved));
        if (parsed.success) setReview(parsed.data);
        else {
          setCustodyBlocked(true);
          onStatus(
            'Saved rotation custody is unreadable. Read the original rotation before continuing.',
          );
        }
      }
      if (!saved && maker && binding && intent) {
        const originals: WorkloadReview[] = [];
        for (let index = 0; index < localStorage.length; index++) {
          const key = localStorage.key(index);
          if (!key?.startsWith('openpc:discovery-certificate-review:')) continue;
          const sourceScope = JSON.parse(key.slice('openpc:discovery-certificate-review:'.length));
          if (
            !Array.isArray(sourceScope) ||
            sourceScope[1] !== props.privacyDomainId ||
            sourceScope[3]?.principalId !== actor?.principalId ||
            sourceScope[3]?.participantId !== actor?.participantId
          )
            continue;
          const prior = savedWorkloadReview.safeParse(
            JSON.parse(localStorage.getItem(key) ?? 'null'),
          );
          if (!prior.success) {
            setCustodyBlocked(true);
            onStatus(
              'Saved original rotation custody is unreadable. Read the original rotation before continuing.',
            );
            continue;
          }
          if (
            (prior.data.approvalRequestId && intent.schemaVersion !== 2) ||
            prior.data.review.mutation !== 'ROTATE' ||
            prior.data.review.resourceId !== binding.predecessorCredentialId ||
            prior.data.review.expectedRevision !== binding.predecessorRevision ||
            prior.data.review.checkerPrincipalId !== intent.administrators[1].principalId
          )
            continue;
          const candidate = prior.data.review.candidate;
          if (
            !('replacedCredentialId' in candidate) ||
            candidate.credentialId !== binding.successorCredentialId ||
            candidate.publicKeySpkiDer !== binding.successorPublicKeySpkiDer
          )
            continue;
          originals.push(prior.data);
        }
        const approved = originals.filter((value) => value.approvalRequestId);
        if (
          approved.length === 1 &&
          originals.every(
            (value) =>
              value.review.candidateDigest === approved[0]!.review.candidateDigest &&
              value.review.reason === approved[0]!.review.reason &&
              value.review.checkerPrincipalId === approved[0]!.review.checkerPrincipalId,
          )
        )
          setRetained(approved[0]);
        else if (originals.length === 1) setRetained(originals[0]);
        else if (originals.length > 1) {
          setCustodyBlocked(true);
          onStatus('Multiple retained rotation reviews need original readback before continuing.');
        }
      }
    } catch {
      setCustodyBlocked(true);
      onStatus('Saved rotation custody is unavailable. Read the original case before continuing.');
    }
    return () => {
      mounted.current = false;
      generation.current++;
      abort.current?.abort();
    };
  }, [storageKey, onStatus]);
  const recovery = {
    enrollmentId: props.enrollmentId,
    recoveryId: props.recoveryId,
    privacyDomainId: props.privacyDomainId,
  };
  const ensure = (token: {
    generation: number;
    scope: string;
    controller: AbortController;
    selection?: string;
  }) => {
    if (
      !mounted.current ||
      token.generation !== generation.current ||
      token.scope !== scopeRef.current ||
      token.controller.signal.aborted ||
      (token.selection !== undefined && token.selection !== selected.current)
    )
      throw new DOMException('Recovery context changed.', 'AbortError');
  };
  async function operate(
    work: (token: {
      generation: number;
      scope: string;
      controller: AbortController;
      selection?: string;
    }) => Promise<void>,
    selection?: string,
  ) {
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    selected.current = selection;
    const token = { generation: ++generation.current, scope, controller, selection };
    await work(token);
    ensure(token);
  }
  async function workload(
    command: unknown,
    token: { generation: number; scope: string; controller: AbortController; selection?: string },
  ) {
    ensure(token);
    const response = await fetch(endpoint, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...(command as object), discoveryRecovery: recovery }),
      signal: token.controller.signal,
    });
    const body = await response.json().catch(() => undefined);
    ensure(token);
    if (!response.ok || !body)
      throw new Error(
        'The governed certificate command could not be confirmed. Read the original case before retrying.',
      );
    return body;
  }
  async function refresh(token: {
    generation: number;
    scope: string;
    controller: AbortController;
    selection?: string;
  }) {
    ensure(token);
    setState(undefined);
    const response = await fetch(
      endpoint +
        '?' +
        new URLSearchParams({
          lane: maker ? 'maker' : 'checker',
          recoveryEnrollmentId: props.enrollmentId,
          recoveryId: props.recoveryId,
          privacyDomainId: props.privacyDomainId,
          ...((review?.review.resumeDraft?.approvalRequestId ?? retained?.approvalRequestId)
            ? {
                originalApprovalRequestId:
                  review?.review.resumeDraft?.approvalRequestId ?? retained!.approvalRequestId!,
              }
            : {}),
        }),
      { credentials: 'same-origin', cache: 'no-store', signal: token.controller.signal },
    );
    const body = await response.json().catch(() => undefined);
    ensure(token);
    if (!response.ok) throw new Error('Read the authenticated original recovery case again.');
    if (body?.truthState === 'SUCCESS') {
      const parsed = workloadCertificate.parse(body.readback);
      if (parsed.credentialId !== binding?.successorCredentialId)
        throw new Error('The completed certificate differs from the enrolled successor.');
      setCertificate(parsed);
      setState(undefined);
      onStatus(
        'Original governed certificate rotation committed. Certificate readback is available.',
      );
    } else {
      const parsed = workloadState.parse(body);
      if (
        parsed.actor.sessionId !== actor?.sessionId ||
        parsed.actor.principalId !== actor.principalId ||
        parsed.actor.participantId !== actor.participantId ||
        parsed.actor.contextEpoch !== actor.contextEpoch ||
        parsed.actor.privacyDomainId !== props.privacyDomainId
      )
        throw new Error('The authenticated recovery context changed.');
      if (parsed.restoredReview) save(parsed.restoredReview);
      setState(parsed);
    }
  }
  function save(value: WorkloadReview) {
    setReview(value);
    try {
      localStorage.setItem(storageKey, JSON.stringify(value));
      setStorageWarning('');
    } catch {
      setStorageWarning(
        'Original rotation custody is retained in this session. Saved custody is unavailable; read the original case before leaving.',
      );
    }
  }
  async function stepUp(
    step: WorkloadReview['review']['stepUp'],
    token: { generation: number; scope: string; controller: AbortController; selection?: string },
  ) {
    ensure(token);
    await performWebAuthnStepUp({ ...step, stepUp: 'FRESH_WEBAUTHN_MAX_5M' }, step, {
      signal: token.controller.signal,
      isCurrent: () => {
        try {
          ensure(token);
          return true;
        } catch {
          return false;
        }
      },
    });
    ensure(token);
  }
  async function prove(phase: 'REQUEST' | 'APPROVE' | 'ACTIVATE') {
    const challenge = (await post({
      kind: 'CHALLENGE',
      recoveryId: props.recoveryId,
      phase,
    })) as z.infer<typeof platformRecoveryChallengeView>;
    if (
      challenge.phase !== phase ||
      !('intentDigest' in view) ||
      challenge.intentDigest !== view.intentDigest ||
      Date.now() >= Date.parse(challenge.expiresAt)
    )
      throw new Error('Read the original certificate recovery case again.');
    const signed = await assertion(challenge);
    onView(
      (await post({
        kind: 'PROVE',
        recoveryId: props.recoveryId,
        phase,
        proof: {
          challengeId: challenge.challengeId,
          challenge: challenge.challenge,
          intentDigest: challenge.intentDigest,
          assertion: signed,
        },
      })) as Receipt,
    );
    onStatus(phase + ' custody proof recorded.');
  }
  return (
    <div className="space-y-3" aria-label="Discovery certificate recovery">
      <h3 className="text-lg font-semibold">Recover the enrolled discovery certificate</h3>
      <p>
        Independent custody opens a bounded certificate rotation lease. The original workload,
        target, public key and two administrators are fixed by the enrollment.
      </p>
      <p>
        Assurance: {view.assurance}. Current authority: {authority}.
      </p>
      {storageWarning ? <p role="alert">{storageWarning}</p> : null}
      {binding ? (
        <dl className="break-all">
          <dt>Original target</dt>
          <dd>{binding.targetId}</dd>
          <dt>Expired credential</dt>
          <dd>{binding.predecessorCredentialId}</dd>
          <dt>Enrolled successor</dt>
          <dd>{binding.successorCredentialId}</dd>
          <dt>Successor public key digest</dt>
          <dd>{binding.successorPublicKeyDigest}</dd>
        </dl>
      ) : null}
      {source && !intent ? (
        <button
          className={button}
          disabled={busy || !executor}
          onClick={() =>
            void run(async () => {
              const draft = (await post({ kind: 'CREATE' })) as Draft;
              onCase(draft.intent.recoveryId);
              onView(draft);
              onStatus('Certificate recovery draft created without authority.');
            })
          }
        >
          Create reviewed certificate recovery case
        </button>
      ) : null}
      {intent ? (
        <>
          <p>
            Case {'state' in view ? view.state : 'DRAFT'}. Custody deadline: {intent.validUntil}.
            Custodian proofs: {approvals.length}/2.
          </p>
          <details>
            <summary>Review immutable certificate recovery intent</summary>
            <pre className="overflow-auto whitespace-pre-wrap break-all">
              {JSON.stringify(intent, null, 2)}
            </pre>
          </details>
          <div className="flex flex-wrap gap-3">
            <button
              className={button}
              disabled={busy || !executor || !live || ('state' in view && view.state !== 'DRAFT')}
              onClick={() => void run(() => prove('REQUEST'))}
            >
              Executor: verify certificate request
            </button>
            <button
              className={button}
              disabled={
                busy ||
                !custodian ||
                !live ||
                receipt?.state !== 'REQUESTED' ||
                approvals.some((v) => v.principalId === actor?.principalId)
              }
              onClick={() => void run(() => prove('APPROVE'))}
            >
              Custodian: approve certificate recovery
            </button>
            <button
              className={button}
              disabled={
                busy ||
                !executor ||
                !live ||
                receipt?.state !== 'REQUESTED' ||
                approvals.length !== 2
              }
              onClick={() => void run(() => prove('ACTIVATE'))}
            >
              Executor: activate certificate lease
            </button>
          </div>
          {maker || checker ? (
            <>
              <button
                className={button}
                disabled={busy}
                onClick={() => void run(() => operate(refresh))}
              >
                Read original certificate rotation
              </button>
              {maker && authority === 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY' && binding ? (
                <>
                  <label className="block">
                    Certificate rotation reason
                    <textarea
                      className={field}
                      value={reason}
                      disabled={busy}
                      onChange={(e) => {
                        generation.current++;
                        abort.current?.abort();
                        setReason(e.target.value);
                      }}
                    />
                  </label>
                  {custodyBlocked ||
                  (!review && !retained && state?.preapprovalState === 'PRESENT') ? (
                    <p role="status">
                      Original rotation custody needs resolution. Read the original rotation before
                      preparing another request.
                    </p>
                  ) : null}
                  {retained && !review && !custodyBlocked ? (
                    <button
                      className={button}
                      disabled={busy}
                      onClick={() =>
                        void run(() =>
                          operate(async (token) => {
                            const body = await workload(
                              {
                                command: 'PREPARE',
                                originalReviewToken: retained.reviewToken,
                                ...(retained.approvalRequestId
                                  ? { originalApprovalRequestId: retained.approvalRequestId }
                                  : {}),
                                expectedSessionId: actor!.sessionId,
                                reason: retained.review.reason,
                                checkerPrincipalId: intent.administrators[1].principalId,
                                input: {
                                  mutation: 'ROTATE',
                                  replacedCredentialId: binding.predecessorCredentialId,
                                  credentialId: binding.successorCredentialId,
                                  publicKeySpkiDer: binding.successorPublicKeySpkiDer,
                                },
                              },
                              token,
                            );
                            save(savedWorkloadReview.parse(body));
                            onStatus(
                              'Original rotation retained. Fresh verification and checker approval are required.',
                            );
                          }),
                        )
                      }
                    >
                      Continue retained original rotation
                    </button>
                  ) : null}
                  <button
                    className={button}
                    disabled={
                      busy ||
                      custodyBlocked ||
                      state?.preapprovalState !== 'ABSENT' ||
                      reason.trim().length < 10 ||
                      !!review ||
                      !!retained
                    }
                    onClick={() =>
                      void run(() =>
                        operate(async (token) => {
                          const body = await workload(
                            {
                              command: 'PREPARE',
                              expectedSessionId: actor!.sessionId,
                              reason,
                              checkerPrincipalId: intent.administrators[1].principalId,
                              input: {
                                mutation: 'ROTATE',
                                replacedCredentialId: binding.predecessorCredentialId,
                                credentialId: binding.successorCredentialId,
                                publicKeySpkiDer: binding.successorPublicKeySpkiDer,
                              },
                            },
                            token,
                          );
                          save(savedWorkloadReview.parse(body));
                          onStatus(
                            'Exact enrolled rotation prepared. Verify before submitting for approval.',
                          );
                        }),
                      )
                    }
                  >
                    Prepare enrolled certificate rotation
                  </button>
                  {review?.resumeSent ? (
                    <p role="status">
                      The original resume was sent. Read the original certificate rotation to
                      reconcile its successor before continuing.
                    </p>
                  ) : null}
                  {review ? (
                    <>
                      <button
                        className={button}
                        disabled={busy || !!review.approvalRequestId || !!review.resumeSent}
                        onClick={() =>
                          void run(() =>
                            operate(async (token) => {
                              await stepUp(review.review.stepUp, token);
                              if (review.review.resumeDraft) save({ ...review, resumeSent: true });
                              const body = await workload(
                                {
                                  command: review.review.resumeDraft ? 'RESUME' : 'SUBMIT',
                                  reviewToken: review.reviewToken,
                                },
                                token,
                              );
                              if (body.truthState === 'SUCCESS') {
                                await refresh(token);
                                return;
                              }
                              save(
                                savedWorkloadReview.parse({
                                  reviewToken: body.reviewToken,
                                  review: body.review,
                                  approvalRequestId: originalApprovalId(
                                    body.approval?.approvalRequestId,
                                  ),
                                }),
                              );
                              onStatus(
                                'Original candidate submitted. The distinct enrolled checker must approve it.',
                              );
                            }, JSON.stringify(review)),
                          )
                        }
                      >
                        {review.review.resumeDraft
                          ? 'Verify and resume original approval'
                          : 'Verify and submit certificate rotation'}
                      </button>
                      <button
                        className={button}
                        disabled={busy || !review.approvalRequestId || !!review.review.resumeDraft}
                        onClick={() =>
                          void run(() =>
                            operate(async (token) => {
                              await stepUp(review.review.stepUp, token);
                              const body = await workload(
                                {
                                  command: 'COMMIT',
                                  reviewToken: review.reviewToken,
                                  approvalRequestId: review.approvalRequestId,
                                },
                                token,
                              );
                              if (body.truthState !== 'SUCCESS')
                                throw new Error(
                                  'Original rotation outcome is ambiguous. Read the original case before continuing.',
                                );
                              await refresh(token);
                              onView(
                                (await post({
                                  kind: 'READ',
                                  recoveryId: props.recoveryId,
                                })) as Receipt,
                              );
                            }, JSON.stringify(review)),
                          )
                        }
                      >
                        Verify and commit certificate rotation
                      </button>
                    </>
                  ) : null}
                </>
              ) : null}
              {checker && authority === 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY'
                ? state?.approvals
                    .filter((item) => item.state === 'REQUESTED')
                    .map((item) => (
                      <button
                        className={button}
                        key={item.approvalRequestId}
                        disabled={busy}
                        onClick={() =>
                          void run(() =>
                            operate(async (token) => {
                              await stepUp(item.stepUp, token);
                              await workload(
                                {
                                  command: 'APPROVE',
                                  approvalRequestId: originalApprovalId(item.approvalRequestId),
                                  candidateDigest: item.candidateDigest,
                                  expectedRevision: item.revision,
                                },
                                token,
                              );
                              await refresh(token);
                              onStatus(
                                'The distinct checker approved the exact original certificate candidate.',
                              );
                            }, JSON.stringify(item)),
                          )
                        }
                      >
                        Verify and approve certificate candidate {item.approvalRequestId}
                      </button>
                    ))
                : null}
            </>
          ) : null}
        </>
      ) : null}
      <button
        className={button}
        disabled={
          busy ||
          (!executor && !custodian) ||
          !receipt ||
          ['COMPLETED', 'REVOKED', 'EXPIRED'].includes(receipt.state)
        }
        onClick={() =>
          void run(() =>
            operate(async (token) => {
              const next = (await post({ kind: 'CLOSE', recoveryId: props.recoveryId })) as Receipt;
              ensure(token);
              onView(next);
              setState(undefined);
              setCertificate(undefined);
              onStatus(`Case ${next.state}; current authority: ${next.authority}.`);
            }),
          )
        }
      >
        Close certificate recovery case
      </button>
      {receipt?.completion ? (
        <p className="break-all">
          Committed original rotation: {receipt.completion.operationId}. Certificate:{' '}
          {receipt.completion.certificateFingerprint}. Lease authority: NONE.
        </p>
      ) : null}
      {certificate ? (
        <details>
          <summary>Read committed certificate</summary>
          <pre className="overflow-auto whitespace-pre-wrap break-all">
            {JSON.stringify(certificate, null, 2)}
          </pre>
        </details>
      ) : null}
    </div>
  );
}
