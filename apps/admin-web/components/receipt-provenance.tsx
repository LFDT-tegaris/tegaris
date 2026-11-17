import type { EvidenceProvenance } from '../../../services/control-api/src/evidence/provenance-contracts';

function References({ values }: { values: [string, string | null][] }) {
  return (
    <dl>
      {values.map(([name, value]) => (
        <div key={name}>
          <dt className="font-semibold">{name}</dt>
          <dd>{value ?? 'Not recorded'}</dd>
        </div>
      ))}
    </dl>
  );
}

export function ReceiptProvenanceDetails({ value }: { value: EvidenceProvenance }) {
  const auth = value.authentication,
    business = value.business,
    rejection = value.rejection,
    rpc = value.rpc,
    fact = value.fact;
  if (auth)
    return (
      <>
        <h3 className="font-semibold">Authentication occurrence</h3>
        <p className="break-normal">
          Immutable Identity database record of a past authentication. This is not a signed Identity
          authorization assertion and grants no permission or current step-up. Chain finality does
          not apply.
        </p>
        <References
          values={[
            ['Method / context', `${auth.method} / ${auth.contextMode}`],
            ['Occurred', auth.occurredAt],
            ['Occurrence', auth.occurrenceId],
            ['Operation', auth.operationId],
            ['Source', auth.sourceId],
            ['Principal', auth.principalId],
            ['Credential digest', auth.credentialDigest],
            ['Proof digest', auth.proofDigest],
            ['Context binding digest', auth.contextBindingDigest],
          ]}
        />
      </>
    );
  if (business)
    return (
      <>
        <h3 className="font-semibold">Committed business transition</h3>
        <p className="break-normal">
          Original profile-bound COSE signature and retained commit/outbox references verified.
          These are historical state versions; current object state has not been queried. This
          receipt does not establish a provider effect or current authority. Chain finality does not
          apply.
        </p>
        <References
          values={[
            ['Receipt', business.receiptId],
            ['Operation', business.operationId],
            ['Idempotency record', business.idempotencyRecordId],
            ['Profile', `${business.profileId} / ${business.profileVersion}`],
            ['Profile digest', business.profileDigest],
            ['Action / operation', `${business.actionIntentId} / ${business.catalogOperationId}`],
            ['Object', `${business.aggregateType} / ${business.aggregateId}`],
            ['Recorded', business.recordedAt],
            [
              'Before revision / existence',
              `${business.before.revision} / ${business.before.existence}`,
            ],
            ['Before state digest', business.before.stateDigest],
            [
              'After revision / existence',
              `${business.after.revision} / ${business.after.existence}`,
            ],
            ['After state digest', business.after.stateDigest],
            ['Candidate digest', business.candidateDigest],
            ['Request digest', business.requestDigest],
            ['Actor digest', business.actorKeyDigest],
            ['Authority digest', business.authorityDigest],
            ['Signer', business.signerId],
            ['Retained signing trust', business.signerTrustDigest],
            ['Payload digest', business.payloadDigest],
          ]}
        />
        <h4 className="font-semibold">Authorization references</h4>
        <ul>
          {business.authorizationReferences.map((ref) => (
            <li key={`${ref.kind}:${ref.evidenceId}`}>
              {ref.kind} · {ref.evidenceId} · {ref.evidenceDigest}
            </li>
          ))}
        </ul>
        <h4 className="font-semibold">Outbox references</h4>
        {business.outboxReferences.length ? (
          <ul>
            {business.outboxReferences.map((ref) => (
              <li key={ref.eventId}>
                <p>
                  {ref.eventType} · {ref.eventId} · Sequence {ref.sequence}
                </p>
                <p>
                  Correlation: {ref.correlationId} · Causation: {ref.causationId ?? 'Not recorded'}
                </p>
                <p>Payload digest: {ref.payloadDigest}</p>
              </li>
            ))}
          </ul>
        ) : (
          <p>This profile committed no outbox event.</p>
        )}
      </>
    );
  if (rejection)
    return (
      <>
        <h3 className="font-semibold">Terminal pre-handoff rejection</h3>
        <p className="break-normal">
          Original purpose signature verified against the consumed command and attempt. No target
          handoff was made. The transaction hash identifies the rejected intent; it does not
          establish a chain transaction or effect. Chain finality does not apply.
        </p>
        <References
          values={[
            ['State', `${rejection.state} / ${rejection.truthState}`],
            ['Source version', rejection.sourceVersion],
            ['Operation', rejection.operationId],
            ['Attempt', rejection.attemptId],
            ['Observed', rejection.observedAt],
            ['Transaction hash', rejection.transactionHash],
            ['Candidate digest', rejection.candidateDigest],
            ['Authorization evidence', rejection.authorizationEvidenceDigest],
          ]}
        />
      </>
    );
  if (fact)
    return (
      <>
        <h3 className="font-semibold">Canonical Fact history</h3>
        <p className="break-normal">
          The custody worker verified the original Fact signature, immutable identity and source
          provenance. These historical references remain available after expiry or reorg. Current
          readiness and chain finality have not been checked. The Fact subject and value remain
          protected.
        </p>
        <References
          values={[
            ['Fact', fact.lineage.factId],
            ['Fact type', fact.lineage.factType],
            ['Fact profile', fact.lineage.factProfileId],
            ['Preservation key digest', fact.lineage.factKeyDigest],
            ['Fact digest', fact.lineage.factDigest],
            ['Canonical generation', fact.lineage.canonicalGeneration],
            ['Projection', fact.lineage.projectionId],
            ['Source profile / sequence', `${fact.sourceProfileId} / ${fact.sourceSequence}`],
            ['Candidate', fact.candidateId],
            ['Admitted', fact.admittedAt],
            ['Chain / block', `${fact.lineage.chainId} / ${fact.lineage.blockNumber}`],
            ['Genesis digest', fact.lineage.genesisDigest],
            ['Block hash', fact.lineage.blockHash],
            ['Predecessor', fact.lineage.predecessorDigest],
            ['Relationship predecessor', fact.lineage.relationshipPredecessorDigest],
            ['Reorg predecessor', fact.lineage.reorgReplacementOf],
            ['Verification key', fact.verificationKeyId],
            ['Verification key digest', fact.verificationKeyDigest],
          ]}
        />
      </>
    );
  if (rpc)
    return (
      <>
        <h3 className="font-semibold">Runtime decision transition</h3>
        <p className="break-normal">
          The custody worker verified the encrypted journal chain and the separately signed
          activation receipt. This read checks the retained projection, exact source digest and
          completed activation binding. The decision is not individually signed. Provider effect,
          current authority and chain finality are not established.
        </p>
        <References
          values={[
            ['Phase', rpc.transition.phase],
            ['Decision', rpc.decisionId],
            ['Trace', rpc.transition.traceId],
            ['Decision effect', rpc.transition.decisionEffect],
            ['Result code', rpc.transition.pcCode],
            ['Denial boundary', rpc.transition.boundary],
            ['Target runtime', rpc.targetRuntimeId],
            ['Spool / source sequence', `${rpc.spoolId} / ${rpc.sourceSequence}`],
            ['Source segment', rpc.transition.sourceSegmentId],
            ['Source record digest', rpc.transition.sourceRecordDigest],
            ['Capsule digest', rpc.capsuleDigest],
            ['Reserved / occurred (UTC nanoseconds)', `${rpc.reservedAtNs} / ${rpc.occurredAtNs}`],
            ['Admitted (UTC nanoseconds)', rpc.transition.admittedAtNs],
            ['Request digest', rpc.transition.requestDigest],
            ['Decision digest', rpc.transition.decisionDigest],
            ['Response digest', rpc.transition.responseDigest],
            ['Source scope digest', rpc.transition.sourceScopeDigest],
            ['Authority binding digest', rpc.transition.authorityBindingDigest],
            ['Status operation', rpc.transition.operationId],
            ['Activation operation', rpc.activation.operationId],
            ['Activation attempt', rpc.activation.attemptId],
            ['Configuration work', rpc.activation.configurationWorkId],
            ['Generation', rpc.activation.generationId],
            ['Generation digest', rpc.activation.generationDigest],
            ['Activation receipt digest', rpc.activation.receiptDigest],
            ['Activation signer', rpc.activation.signerId],
            ['Verification key digest', rpc.activation.verificationKeyDigest],
          ]}
        />
      </>
    );
  return (
    <p className="break-normal">
      {value.status === 'PROJECTION_RETIRED'
        ? 'This normalized projection was retired by an approved deletion. Original evidence and preservation references retain their separate lifetimes.'
        : value.status === 'SOURCE_RECONCILIATION_REQUIRED'
          ? 'This historical source requires reconciliation by its original custody worker before verified details are available.'
          : 'Source verification details are not yet supported for this receipt format.'}{' '}
      Catalogue membership does not establish signature meaning or chain finality.
    </p>
  );
}
