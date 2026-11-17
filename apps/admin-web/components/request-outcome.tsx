import { evidenceRemovalSummary } from '../lib/evidence-removal-summary';
import type { TransactionKind } from '../lib/transaction-workflow';
import { approvalTime } from '../lib/approval-catalogue';
import { recordStateLabel } from './contract-record-summary';
import type { PolicyWorkflowActorBinding } from './policy-workflow-storage';
import { walletBindingView } from '../../../services/identity-service/src/contracts/wallet-binding-view';

export function RequestOutcome({
  kind,
  value,
  actor,
  resourceRef,
  operationRef,
}: {
  kind: TransactionKind | undefined;
  value: Record<string, unknown>;
  actor: PolicyWorkflowActorBinding;
  resourceRef: string | undefined;
  operationRef?: string | null;
}) {
  if (kind === 'wallet-binding') {
    const parsed = walletBindingView.safeParse(value);
    if (
      !parsed.success ||
      parsed.data.participantId !== actor.participantId ||
      parsed.data.privacyDomainId !== actor.privacyDomainId ||
      resourceRef !== `urn:openpc:resource:${parsed.data.walletBindingId}` ||
      operationRef !== `urn:openpc:operation:${parsed.data.operationId}`
    )
      return (
        <p role="alert">The wallet binding could not be confirmed. Refresh its saved record.</p>
      );
    const binding = parsed.data;
    return (
      <section className="contract-record-summary" aria-label="Recorded outcome">
        <h3>{binding.state === 'ACTIVE' ? 'Wallet bound' : 'Wallet binding revoked'}</h3>
        <dl className="contract-request-status">
          <div>
            <dt>Wallet address</dt>
            <dd className="break-all">{binding.walletAddress}</dd>
          </div>
          <div>
            <dt>Chain ID</dt>
            <dd>{binding.chainId}</dd>
          </div>
          <div>
            <dt>Binding status</dt>
            <dd>{recordStateLabel(binding.state)}</dd>
          </div>
          <div>
            <dt>Bound identity</dt>
            <dd className="break-all">{binding.subjectId}</dd>
          </div>
          <div>
            <dt>Operation reference</dt>
            <dd className="break-all">{binding.operationId}</dd>
          </div>
        </dl>
        <p>Access is controlled by the active grants and policies.</p>
      </section>
    );
  }
  const removal = evidenceRemovalSummary(kind, value, { ...actor, resourceRef });
  if (removal)
    return (
      <section className="request-outcome" aria-label="Recorded outcome">
        <h3>Local data removed</h3>
        <p>
          {removal.label} · 1 local object · {removal.bytes} bytes
        </p>
        <p className="request-outcome-date">
          Completed <time dateTime={removal.completedAt}>{approvalTime(removal.completedAt)}</time>
        </p>
        {removal.batch ? (
          <p>
            Confirmed batch {removal.batch} of {removal.batches}. Other batches have separate
            requests.
          </p>
        ) : null}
        <p>Original receipts and archived evidence retain their separate lifetimes.</p>
        <details className="request-outcome-receipt">
          <summary>Signed deletion receipt</summary>
          <p className="break-all">{removal.receiptDigest}</p>
        </details>
      </section>
    );
  return (
    <dl className="contract-request-status" aria-label="Recorded outcome">
      <div>
        <dt>{value.admissionState ? 'Command admission' : 'Recorded status'}</dt>
        <dd>{recordStateLabel(String(value.admissionState ?? value.state ?? 'Available'))}</dd>
      </div>
      <div>
        <dt>Physical outcome</dt>
        <dd>
          {recordStateLabel(
            String(
              value.physicalState ??
                value.truthState ??
                value.runtimePermission ??
                value.authority ??
                'Not reported',
            ),
          )}
        </dd>
      </div>
    </dl>
  );
}
