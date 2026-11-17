'use client';
import { useEffect, useState } from 'react';
import type { z } from 'zod';
import type {
  localRootExpiryRecoverySourceView,
  localRootExpiryRecoveryDraftView,
  localRootExpiryRecoveryReceiptView,
} from '../../../services/identity-service/src/contracts/local-root-expiry-recovery';
import type {
  platformRecoveryCommand,
  platformRecoveryChallengeView,
} from '../../../services/identity-service/src/contracts/platform-recovery';
type Source = z.infer<typeof localRootExpiryRecoverySourceView>;
type Draft = z.infer<typeof localRootExpiryRecoveryDraftView>;
type Receipt = z.infer<typeof localRootExpiryRecoveryReceiptView>;
export type RootExpiryRecoveryView = Source | Draft | Receipt;
const button = 'rounded bg-[color:var(--accent)] px-3 py-2 text-white disabled:opacity-60';
export function LocalRootExpiryRecoveryWorkflow(props: {
  view: RootExpiryRecoveryView;
  actor: { principalId: string } | undefined;
  recoveryId: string;
  busy: boolean;
  now: number;
  post: (command: z.infer<typeof platformRecoveryCommand>) => Promise<unknown>;
  assertion: (challenge: z.infer<typeof platformRecoveryChallengeView>) => Promise<string>;
  run: (work: () => Promise<void>) => Promise<void>;
  onView: (view: RootExpiryRecoveryView) => void;
  onCase: (id: string) => void;
  onStatus: (status: string) => void;
}) {
  const { view, actor, busy, now, post, assertion, run, onView, onCase, onStatus } = props;
  const [source, setSource] = useState<Source>();
  useEffect(() => {
    if ('source' in view) setSource(view);
  }, [view]);
  const receipt = 'revision' in view ? view : undefined,
    intent = 'intent' in view ? view.intent : undefined;
  const actors = receipt?.actors ?? source?.actors;
  const pending = intent && intent.schemaVersion !== 1 ? intent.pending : source?.source.pending;
  const ancestry = intent?.schemaVersion === 3 ? intent.rootAncestry : source?.source.rootAncestry;
  const executor = actor?.principalId === actors?.executorPrincipalId;
  const custodian = !!actor && !!actors?.custodianPrincipalIds.includes(actor.principalId);
  const live =
    !!intent && now >= Date.parse(intent.validFrom) && now < Date.parse(intent.validUntil);
  const approvals = receipt?.proofs.filter((v) => v.phase === 'APPROVE') ?? [];
  const prove = async (phase: 'REQUEST' | 'APPROVE' | 'ACTIVATE') => {
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
      throw new Error('Read the original recovery case again.');
    const next = (await post({
      kind: 'PROVE',
      recoveryId: props.recoveryId,
      phase,
      proof: {
        challengeId: challenge.challengeId,
        challenge: challenge.challenge,
        intentDigest: challenge.intentDigest,
        assertion: await assertion(challenge),
      },
    })) as Receipt;
    onView(next);
    onStatus(
      next.state === 'COMPLETED'
        ? 'Root expiry recovery committed. Read the original result before continuing signer recovery.'
        : `${phase} proof recorded.`,
    );
  };
  return (
    <div className="space-y-3" aria-label="Local Root expiry recovery">
      <h2 className="text-lg font-semibold">Recover an expired local Root</h2>
      <p>
        Independent installation custody and two custodians approve this exact successor.
        Permissions stay unchanged. This flow grants no ordinary administration or runtime
        authority.
      </p>
      <p>Assurance: {view.assurance}. Current authority: NONE.</p>
      {pending ? (
        <div aria-label="Pending replacement retained by Root recovery" className="space-y-1">
          <p>
            Pending replacement {pending.replacementId}, revision {pending.replacementRevision},
            stays pending.
          </p>
          <p>
            This recovery preserves its preparation and {pending.affectedTargetCount} affected
            targets. It supplies no target acknowledgment or administrator activation.
          </p>
          <p className="break-all">Preparation receipt: {pending.preparationReceiptDigest}</p>
          <p className="break-all">Pending record: {pending.pendingRecordDigest}</p>
          <p className="break-all">Administrator effects: {pending.administrationEffectsDigest}</p>
          <p className="break-all">Target and administrator readiness: {pending.readinessDigest}</p>
        </div>
      ) : null}
      {ancestry ? (
        <p>
          Verified Root recovery history: {ancestry.receipts.length} completed receipts ending at
          Root epoch {ancestry.rootEpoch}. These receipts grant no current authority.
        </p>
      ) : null}
      {source ? (
        <>
          <p>
            Original Root epoch {source.source.rootEpoch}, revision {source.source.rootRevision},
            expired {source.source.expiredAt}.
          </p>
          <p className="break-all">Original Root digest: {source.source.rootDigest}</p>
          <p>
            Approved successor validity:{' '}
            {new Date(Number(BigInt(source.successorScope.validFromNs) / 1000000n)).toISOString()}{' '}
            to{' '}
            {new Date(Number(BigInt(source.successorScope.validUntilNs) / 1000000n)).toISOString()}.
          </p>
          <details>
            <summary>Review unchanged Root permissions</summary>
            <pre className="overflow-auto whitespace-pre-wrap break-all">
              {JSON.stringify(source.successorScope, null, 2)}
            </pre>
          </details>
          <button
            className={button}
            disabled={busy || !executor || !!source.liveCase}
            onClick={() =>
              void run(async () => {
                const next = (await post({ kind: 'CREATE' })) as Draft;
                onCase(next.intent.recoveryId);
                onView(next);
                onStatus(
                  'Draft created without authority. Request and custodian proofs are required.',
                );
              })
            }
          >
            Create reviewed Root expiry recovery case
          </button>
          {source.liveCase ? (
            <p>Existing case {source.liveCase.recoveryId}. Read its original result.</p>
          ) : null}
        </>
      ) : null}
      {intent ? (
        <>
          <p>
            Case {'state' in view ? view.state : 'DRAFT'}; proof deadline {intent.validUntil}.
          </p>
          <p className="break-all">
            Exact intent digest: {'intentDigest' in view ? view.intentDigest : ''}
          </p>
          <div className="flex flex-wrap gap-3">
            <button
              className={button}
              disabled={busy || !executor || !live || !('state' in view) || view.state !== 'DRAFT'}
              onClick={() => void run(() => prove('REQUEST'))}
            >
              Prove Root expiry recovery request
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
              Approve exact Root expiry successor
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
              Commit governed Root expiry successor
            </button>
            <button
              className={button}
              disabled={busy || !props.recoveryId}
              onClick={() =>
                void run(async () => {
                  onView((await post({ kind: 'READ', recoveryId: props.recoveryId })) as Receipt);
                  onStatus('Original Root expiry case read.');
                })
              }
            >
              Read original Root expiry result
            </button>
            <button
              className={button}
              disabled={
                busy ||
                !(executor || custodian) ||
                !receipt ||
                !['DRAFT', 'REQUESTED'].includes(receipt.state)
              }
              onClick={() =>
                void run(async () => {
                  onView((await post({ kind: 'CLOSE', recoveryId: props.recoveryId })) as Receipt);
                  onStatus('Original case closed without Root authority.');
                })
              }
            >
              Close Root expiry recovery case
            </button>
          </div>
          {receipt?.result ? (
            <>
              <p>
                Committed Root epoch {receipt.result.rootEpoch}, revision{' '}
                {receipt.result.rootRevision}.
              </p>
              <p className="break-all">
                Root digest: {receipt.result.rootDigest}. Operation: {receipt.result.operationId}.
              </p>
            </>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
