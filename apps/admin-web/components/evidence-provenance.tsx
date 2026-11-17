import type { EvidenceProvenance } from '../../../services/control-api/src/evidence/provenance-contracts';
import { ReceiptProvenanceDetails } from './receipt-provenance';

type Observation = NonNullable<EvidenceProvenance['deployment']>['historical'];
function ObservationView({ title, value }: { title: string; value: Observation }) {
  return (
    <section className="space-y-2 rounded border border-[color:var(--border)] p-3">
      <h3 className="font-semibold">{title}</h3>
      <p>
        Source version {value.sourceVersion} · {value.state} / {value.truthState}
      </p>
      <p>
        Observed {value.observedAt} · Finality: {value.finality}
      </p>
      <p>Receipt: {value.receiptDigest}</p>
      <p>Journal evidence: {value.journalEvidenceDigest}</p>
      {value.occurrence ? (
        <dl>
          <dt>Canonical occurrence at this observation</dt>
          <dd>{value.occurrence.occurrenceId}</dd>
          <dt>Occurrence digest</dt>
          <dd>{value.occurrence.occurrenceDigest}</dd>
          <dt>Block {value.occurrence.blockNumber}</dt>
          <dd>{value.occurrence.blockHash}</dd>
        </dl>
      ) : null}
      {value.invalidation ? (
        <dl>
          <dt>Invalidated occurrence · {value.invalidation.reason}</dt>
          <dd>{value.invalidation.occurrenceId}</dd>
          <dt>Invalidated occurrence digest</dt>
          <dd>{value.invalidation.occurrenceDigest}</dd>
          <dt>Invalidation observation digest</dt>
          <dd>{value.invalidation.observationDigest}</dd>
        </dl>
      ) : null}
    </section>
  );
}

export function EvidenceProvenancePanel({ value }: { value: EvidenceProvenance }) {
  const deployment = value.deployment;
  return (
    <section
      aria-label="Evidence provenance"
      className="space-y-3 break-all rounded border border-[color:var(--border)] p-4"
    >
      <h2 className="text-xl font-semibold">Evidence provenance</h2>
      <p>Source: {value.sourceFormat}</p>
      <p>Record: {value.recordId}</p>
      <p>Receipt digest: {value.recordDigest}</p>
      {deployment ? (
        <>
          <p className="break-normal">
            Original purpose signature verified. These are historical observations; this read does
            not query current chain truth or grant execution or raw receipt access.
          </p>
          <dl>
            <dt>Governed operation</dt>
            <dd>{deployment.operationId}</dd>
            <dt>Attempt</dt>
            <dd>{deployment.attemptId}</dd>
            <dt>Deployment intent</dt>
            <dd>{deployment.deploymentIntentId}</dd>
            <dt>Intent digest</dt>
            <dd>{deployment.intentDigest}</dd>
            <dt>Preparation digest</dt>
            <dd>{deployment.preparationDigest}</dd>
            <dt>Target runtime</dt>
            <dd>{deployment.targetRuntimeId}</dd>
            <dt>Execution principal / workload</dt>
            <dd>
              {deployment.executionPrincipalId} / {deployment.workloadId}
            </dd>
            <dt>Chain {deployment.chainId} genesis</dt>
            <dd>{deployment.genesisDigest}</dd>
            <dt>Signed transaction hash</dt>
            <dd>{deployment.transactionHash}</dd>
          </dl>
          <ObservationView title="Selected historical observation" value={deployment.historical} />
          <ObservationView title="Latest retained observation" value={deployment.latestRetained} />
          <p className="break-normal">
            {deployment.historicalIsLatest
              ? 'The selected observation is the latest retained version.'
              : 'A later observation supersedes the selected version for this readback.'}
          </p>
          <p className="break-normal">
            Retained snapshots: {deployment.history.retainedCount}, versions{' '}
            {deployment.history.firstVersion}–{deployment.history.lastVersion}.{' '}
            {deployment.history.missingVersionsBetweenSnapshots} intermediate versions are not
            retained. The publisher may coalesce snapshots; complete journal history is not
            established.
          </p>
        </>
      ) : (
        <ReceiptProvenanceDetails value={value} />
      )}
      <h3 className="font-semibold">Recorded archive checkpoints</h3>
      <p>
        Stream {value.custody.streamId} · Sequence {value.custody.sequence}
      </p>
      <p>Segment {value.custody.segmentId}</p>
      {value.custody.checkpoints.length === 0 ? (
        <p>No checkpoint is recorded for this segment.</p>
      ) : (
        <ul className="space-y-2">
          {value.custody.checkpoints.map((checkpoint) => (
            <li key={checkpoint.sinkId}>
              <p>
                {checkpoint.sinkId} · Through {checkpoint.throughSequence} · {checkpoint.assurance}
              </p>
              <p>Object version: {checkpoint.versionId}</p>
              <p>Checkpoint: {checkpoint.checkpointDigest}</p>
              <p>Previous: {checkpoint.previousCheckpointDigest ?? 'First checkpoint'}</p>
              <p>Acknowledged: {checkpoint.acknowledgedAt}</p>
            </li>
          ))}
        </ul>
      )}
      <p className="break-normal">
        Checkpoint metadata records past durability admission. Archive availability has not been
        rechecked; this view does not establish remote WORM assurance, retention or deletion
        eligibility.
      </p>
    </section>
  );
}
