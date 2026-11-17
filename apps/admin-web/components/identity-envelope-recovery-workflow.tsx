'use client';
import { useEffect, useState } from 'react';
import type { z } from 'zod';
import type {
  identityEnvelopeRecoverySourceView,
  identityEnvelopeRecoveryDraftView,
  identityEnvelopeRecoveryReceiptView,
  identityEnvelopeRecoveryRotationCreationView,
  identityEnvelopeRecoveryRotationQueueView,
} from '../../../services/identity-service/src/contracts/identity-envelope-recovery';
import type {
  platformRecoveryCommand,
  platformRecoveryChallengeView,
} from '../../../services/identity-service/src/contracts/platform-recovery';
type Source = z.infer<typeof identityEnvelopeRecoverySourceView>;
type Draft = z.infer<typeof identityEnvelopeRecoveryDraftView>;
type Receipt = z.infer<typeof identityEnvelopeRecoveryReceiptView>;
type Creation = z.infer<typeof identityEnvelopeRecoveryRotationCreationView>;
type Queue = z.infer<typeof identityEnvelopeRecoveryRotationQueueView>;
export type EnvelopeRecoveryView = Source | Draft | Receipt;
interface Actor {
  sessionId: string;
  principalId: string;
  participantId: string;
  contextEpoch: string;
}
const button = 'rounded bg-[color:var(--accent)] px-3 py-2 text-white disabled:opacity-60';
const savedPhaseKey = 'openpc:identity-envelope-recovery-phase:v1';

/** Store only original non-secret command identity before dispatch. A lost
 * response must reuse that command; a changed actor/case cannot select it. */
function phaseKey(scope: string, revision: string) {
  let saved: Record<string, string>;
  try {
    saved = JSON.parse(localStorage.getItem(savedPhaseKey) ?? '{}');
    if (!saved || Array.isArray(saved) || typeof saved !== 'object') throw new Error();
  } catch {
    throw new Error(
      'Saved rotation commands are unavailable. Recover the original command before continuing.',
    );
  }
  const identity = JSON.stringify([scope, revision]);
  if (Object.hasOwn(saved, identity)) {
    const original = saved[identity];
    if (typeof original !== 'string' || !/^envelope-recovery-[0-9a-f-]{36}$/u.test(original))
      throw new Error('The original rotation command is invalid. Reconcile it before continuing.');
    return original;
  }
  const original = 'envelope-recovery-' + crypto.randomUUID();
  saved[identity] = original;
  localStorage.setItem(savedPhaseKey, JSON.stringify(saved));
  return original;
}
export function IdentityEnvelopeRecoveryWorkflow(props: {
  view: EnvelopeRecoveryView;
  actor: Actor | undefined;
  enrollmentId: string;
  privacyDomainId: string;
  recoveryId: string;
  busy: boolean;
  now: number;
  post: (command: z.infer<typeof platformRecoveryCommand>) => Promise<unknown>;
  assertion: (challenge: z.infer<typeof platformRecoveryChallengeView>) => Promise<string>;
  run: (work: () => Promise<void>) => Promise<void>;
  onView: (view: EnvelopeRecoveryView) => void;
  onCase: (id: string) => void;
  onStatus: (status: string) => void;
}) {
  const { view, actor, busy, now, post, assertion, run, onView, onCase, onStatus } = props;
  const [source, setSource] = useState<Source>();
  const [creation, setCreation] = useState<Creation>();
  const [queue, setQueue] = useState<Queue>();
  useEffect(() => {
    if ('source' in view) setSource(view);
  }, [view]);
  const receipt = 'revision' in view ? view : undefined;
  const caseView = 'intent' in view ? view : undefined;
  const intent = caseView?.intent;
  const actors = receipt?.actors ?? source?.source;
  const executor = !!actor && actor.principalId === actors?.executorPrincipalId;
  const custodian = !!actor && !!actors?.custodianPrincipalIds.includes(actor.principalId);
  const approvals = receipt?.proofs.filter((proof) => proof.phase === 'APPROVE') ?? [];
  const proofLive = (at: string) => now >= Date.parse(at) && now - Date.parse(at) < 300000;
  const requestFresh = receipt?.proofs.some(
    (proof) => proof.phase === 'REQUEST' && proofLive(proof.verifiedAt),
  );
  const approvalsFresh =
    approvals.length === 2 && approvals.every((proof) => proofLive(proof.verifiedAt));
  const live =
    !!intent &&
    now >= Date.parse(intent.validFrom) &&
    now < Date.parse(intent.validUntil) &&
    (!receipt ||
      (!receipt.expired &&
        receipt.enrollmentState === 'ACTIVE' &&
        receipt.receivingTrustState === 'ACTIVE'));
  const authority =
    live && receipt?.lease && now < Date.parse(receipt.lease.validUntil)
      ? receipt.authority
      : 'NONE';
  const rotationLive =
    executor && authority === 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY' && receipt?.state === 'ACTIVE';
  const prove = async (phase: 'REQUEST' | 'APPROVE' | 'ACTIVATE') => {
    const challenge = (await post({
      kind: 'CHALLENGE',
      recoveryId: props.recoveryId,
      phase,
    })) as z.infer<typeof platformRecoveryChallengeView>;
    if (
      challenge.phase !== phase ||
      challenge.intentDigest !== ('intentDigest' in view ? view.intentDigest : undefined) ||
      Date.now() >= Date.parse(challenge.expiresAt)
    )
      throw new Error('Read the original case again before providing this proof.');
    const signed = await assertion(challenge);
    const next = (await post({
      kind: 'PROVE',
      recoveryId: props.recoveryId,
      phase,
      proof: {
        challengeId: challenge.challengeId,
        challenge: challenge.challenge,
        intentDigest: challenge.intentDigest,
        assertion: signed,
      },
    })) as Receipt;
    onView(next);
    onStatus(`${phase} proof recorded. Original signer recovery case ${next.state}.`);
  };
  const advance = async () => {
    if (!actor || !intent || !creation) throw new Error('Read the original rotation first.');
    // A READY/ambiguous/failed phase keeps its original revision and key. Only
    // a signed COMMITTED result permits the next immutable command.
    const revision =
      queue?.state === 'COMMITTED' && queue.result
        ? queue.result.revision
        : (queue?.fromRevision ?? creation.currentRevision);
    const scope = JSON.stringify([
      actor.participantId,
      actor.principalId,
      props.enrollmentId,
      props.privacyDomainId,
      intent.recoveryId,
      intent.rotationId,
    ]);
    const next = (await post({
      kind: 'ROTATION_ADVANCE',
      recoveryId: intent.recoveryId,
      expectedRevision: revision,
      idempotencyKey: phaseKey(scope, revision),
    })) as Queue;
    setQueue(next);
    onStatus(
      next.state === 'COMMITTED'
        ? `Rotation ${next.result?.state} committed at revision ${next.result?.revision}.`
        : `Original ${next.toState} phase ${next.state}. No committed phase effect is claimed.`,
    );
  };
  const complete =
    queue?.result?.state === 'COMPLETE' || (!queue && creation?.currentState === 'COMPLETE');
  return (
    <div className="space-y-4" aria-label="Identity envelope signer recovery">
      <h3 className="text-lg font-semibold">Identity envelope signer recovery</h3>
      <p>
        This separate RecoveryCase repairs only the enrolled envelope signer. Its lease lasts at
        most 15 minutes, including local QA. The executor and two independent custodians use fresh
        authenticators; no policy, RPC or Root handoff authority is granted.
      </p>
      {actors ? (
        <p className="break-all">
          Executor: {actors.executorPrincipalId}. Custodians:{' '}
          {actors.custodianPrincipalIds.join(', ')}.
        </p>
      ) : null}
      {source && !intent ? (
        <>
          <p>Current Root epoch {source.source.rootEpoch}. Source authority: NONE.</p>
          <details>
            <summary>Review the exact signer repair request</summary>
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all">
              {JSON.stringify(source.request, null, 2)}
            </pre>
          </details>
          {source.liveCase ? (
            <button
              className={button}
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  onCase(source.liveCase!.recoveryId);
                  const next = (await post({
                    kind: 'READ',
                    recoveryId: source.liveCase!.recoveryId,
                  })) as Receipt;
                  onView(next);
                  onStatus(`Original signer case ${next.state} loaded.`);
                })
              }
            >
              Read enrolled live signer case
            </button>
          ) : (
            <button
              className={button}
              disabled={busy || !executor}
              onClick={() =>
                void run(async () => {
                  const next = (await post({ kind: 'CREATE' })) as Draft;
                  onCase(next.intent.recoveryId);
                  onView(next);
                  setCreation(undefined);
                  setQueue(undefined);
                  onStatus(
                    'Draft signer case created without authority. Review the immutable intent and verify the request.',
                  );
                })
              }
            >
              Create reviewed signer recovery case
            </button>
          )}
        </>
      ) : null}
      {intent ? (
        <>
          <p>
            Signer case {caseView?.state}. Authority: {authority}. Assurance:{' '}
            {'assurance' in view ? view.assurance : 'unavailable'}.
          </p>
          <p>
            Lease deadline: {receipt?.lease?.validUntil ?? intent.validUntil}. Custodian approvals:{' '}
            {approvals.length}/2; fresh approvals:{' '}
            {approvals.filter((proof) => proofLive(proof.verifiedAt)).length}/2.
          </p>
          <p className="break-all">
            Reviewed signer intent: {'intentDigest' in view ? view.intentDigest : ''}. Reserved
            rotation: {intent.rotationId}.
          </p>
          <details>
            <summary>Review the immutable signer recovery intent</summary>
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all">
              {JSON.stringify(intent, null, 2)}
            </pre>
          </details>
          <div className="flex flex-wrap gap-3">
            <button
              className={button}
              disabled={busy || !live || !executor || caseView?.state !== 'DRAFT'}
              onClick={() => void run(() => prove('REQUEST'))}
            >
              Executor: verify signer request
            </button>
            <button
              className={button}
              disabled={
                busy ||
                !live ||
                !custodian ||
                receipt?.state !== 'REQUESTED' ||
                !requestFresh ||
                approvals.some((proof) => proof.principalId === actor?.principalId)
              }
              onClick={() => void run(() => prove('APPROVE'))}
            >
              Custodian: approve signer repair
            </button>
            <button
              className={button}
              disabled={
                busy ||
                !live ||
                !executor ||
                receipt?.state !== 'REQUESTED' ||
                !requestFresh ||
                !approvalsFresh
              }
              onClick={() => void run(() => prove('ACTIVATE'))}
            >
              Executor: activate signer repair lease
            </button>
            <button
              className={button}
              disabled={
                busy ||
                (!executor && !custodian) ||
                !receipt ||
                ['COMPLETED', 'REVOKED', 'EXPIRED'].includes(receipt.state)
              }
              onClick={() =>
                void run(async () => {
                  const next = (await post({
                    kind: 'CLOSE',
                    recoveryId: intent.recoveryId,
                  })) as Receipt;
                  onView(next);
                  onStatus(
                    `Signer case ${next.state}; authority ${next.authority}. Post-review remains ${next.postReviewStatus}.`,
                  );
                })
              }
            >
              Close signer recovery case
            </button>
          </div>
          {receipt?.lease ? (
            <>
              <p>
                Activation operation: {receipt.lease.activationOperationId}. Post-review:{' '}
                {receipt.postReviewStatus}.
              </p>
              <button
                className={button}
                disabled={busy || !executor}
                onClick={() =>
                  void run(async () => {
                    const next = (await post({
                      kind: 'ROTATION_CREATE',
                      recoveryId: intent.recoveryId,
                    })) as Creation;
                    setCreation(next);
                    setQueue(undefined);
                    onStatus(
                      `Original rotation ${next.currentState}, revision ${next.currentRevision}. Permission effect: NONE.`,
                    );
                  })
                }
              >
                Create or read reserved signer rotation
              </button>
              {creation ? (
                <>
                  <p>
                    Rotation{' '}
                    {queue?.state === 'COMMITTED' ? queue.result?.state : creation.currentState}.
                    Revision{' '}
                    {queue?.state === 'COMMITTED'
                      ? queue.result?.revision
                      : creation.currentRevision}
                    . Permission effect: NONE.
                  </p>
                  {queue ? (
                    <div>
                      <p>
                        Original phase operation: {queue.operationId}. Queue: {queue.state};{' '}
                        {queue.fromState} → {queue.toState}.
                      </p>
                      <ul>
                        {queue.attempts.map((attempt) => (
                          <li key={attempt.attemptId}>
                            {attempt.method}: {attempt.state}
                            {attempt.ambiguityKind ? ` (${attempt.ambiguityKind})` : ''}
                          </li>
                        ))}
                      </ul>
                      {queue.result ? (
                        <details>
                          <summary>Read the committed phase result</summary>
                          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all">
                            {JSON.stringify(queue.result, null, 2)}
                          </pre>
                        </details>
                      ) : null}
                    </div>
                  ) : null}
                  <button
                    className={button}
                    disabled={busy || !rotationLive || complete || queue?.state === 'FAILED'}
                    onClick={() => void run(advance)}
                  >
                    {queue && queue.state !== 'COMMITTED'
                      ? 'Reconcile original rotation phase'
                      : 'Advance signer rotation'}
                  </button>
                  {queue?.result?.state === 'CUTOVER_FENCED' ||
                  (!queue && creation.currentState === 'CUTOVER_FENCED') ? (
                    <p>
                      A genuine governed typed Platform Root envelope must activate under the
                      selected new signer before observation and old-key retirement.{' '}
                      <a className="underline" href="/govern/participants">
                        Open Participant governance
                      </a>
                      . Keep the current Root unchanged during this lease.
                    </p>
                  ) : null}
                  {complete ? (
                    <p>
                      Private-key retirement is committed. Close this case and complete independent
                      post-review before the separate governed Root and administrator handoff.{' '}
                      <a className="underline" href="/operate/recovery">
                        Open governed recovery review
                      </a>
                      .
                    </p>
                  ) : null}
                </>
              ) : null}
            </>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
