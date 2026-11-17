import type { PoolClient } from 'pg';
import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import { readVerifiedDeploymentRejection } from '../configuration/deployment/rejection-readback.js';
import {
  verifyAuthenticationSource,
  type AuthenticationSourceRow,
} from './authentication-source.js';
import {
  businessSourceSelect,
  businessOccurrenceTime,
  verifyBusinessSource,
  type BusinessSourceRow,
} from './business-source.js';
import type { ProvenanceSource } from './deployment-provenance.js';
import { effectOccurrenceTime } from './effect-source.js';
import type { EvidenceProvenance } from './provenance-contracts.js';

const fail = () => new ConfigurationRepositoryError('PC-DATA-6007');
const hash = (bytes: Buffer) => `sha256:${bytes.toString('hex')}`;
const historicalOnly = {
  authority: 'NONE',
  currentAuthority: 'NOT_ESTABLISHED',
  chainFinality: 'NOT_APPLICABLE',
} as const;

export async function readAuthenticationProvenance(
  client: PoolClient,
  record: ProvenanceSource,
): Promise<NonNullable<EvidenceProvenance['authentication']>> {
  z.uuidv7().parse(record.recordId);
  const selected = await client.query<AuthenticationSourceRow>(
    `select occurrence_id::text id,receipt,receipt_digest as "receiptDigest"
     from control.authentication_occurrence where occurrence_id=$1 and participant_id=$2 and privacy_domain_id=$3`,
    [record.recordId, record.participantId, record.privacyDomainId],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) throw fail();
  const receipt = verifyAuthenticationSource(row, record);
  if (record.recordDigest !== hash(row.receiptDigest) || record.occurredAt !== receipt.occurredAt)
    throw fail();
  return {
    ...historicalOnly,
    integrity: receipt.integrity,
    occurrenceId: receipt.occurrenceId,
    operationId: `urn:openpc:operation:${receipt.operationId}`,
    sourceId: receipt.sourceId,
    principalId: receipt.principalId,
    method: receipt.method,
    contextMode: receipt.contextMode,
    occurredAt: receipt.occurredAt,
    credentialDigest: receipt.credentialDigest,
    proofDigest: receipt.proofDigest,
    contextBindingDigest:
      receipt.method === 'TLS13_MTLS'
        ? receipt.transportBindingDigest
        : receipt.sessionBindingDigest,
  };
}

export async function readBusinessProvenance(
  client: PoolClient,
  record: ProvenanceSource,
  format: string,
): Promise<NonNullable<EvidenceProvenance['business']>> {
  z.uuidv7().parse(record.recordId);
  const selected = await client.query<BusinessSourceRow>(
    `${businessSourceSelect} and e.evidence_record_id=$3`,
    [record.participantId, record.privacyDomainId, record.recordId],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) throw fail();
  const receipt = verifyBusinessSource(row, record);
  const recordedAt = businessOccurrenceTime(receipt.recordedAtNs);
  if (
    sha256(row.coseSign1) !== record.recordDigest ||
    recordedAt !== record.occurredAt ||
    row.evidenceFormat !== format
  )
    throw fail();
  // Immutable commit-time state is bound to the admitted receipt. A later object
  // revision and today's signer lifecycle cannot reinterpret that historical act.
  const committed = await client.query(
    `select 1 from control.audit_occurrence a join control.idempotency_record i
     on i.participant_id=a.participant_id and i.privacy_domain_id=a.privacy_domain_id
      and i.operation_id=a.operation_id and i.idempotency_record_id=a.idempotency_record_id
     where a.participant_id=$1 and a.privacy_domain_id=$2 and a.receipt_id=$3
      and i.terminal_state='COMMITTED' and i.input_digest=a.candidate_digest
      and i.action_intent_id=a.action_intent_id and i.catalog_operation_id=a.catalog_operation_id
      and a.before_revision=$4 and a.after_revision=$5 and a.before_state_digest=$6 and a.after_state_digest=$7
      and a.aggregate_id=$8 and a.aggregate_type=$9 and a.idempotency_record_id=$10
      and a.candidate_digest=$11 and a.pre_commit_authority_digest=$12
      and sha256(a.before_state_preimage)=a.before_state_digest and sha256(a.after_state_preimage)=a.after_state_digest
      and sha256(a.authority_snapshot)=a.pre_commit_authority_digest`,
    [
      record.participantId,
      record.privacyDomainId,
      receipt.receiptId,
      String(receipt.before.revision),
      String(receipt.after.revision),
      receipt.before.stateDigest,
      receipt.after.stateDigest,
      receipt.aggregateId,
      receipt.aggregateType,
      receipt.idempotencyRecordId,
      receipt.candidateDigest,
      receipt.preCommitAuthorityDigest,
    ],
  );
  if (committed.rowCount !== 1) throw fail();
  const events = await client.query<{
    eventId: string;
    eventType: string;
    sequence: string;
    correlationId: string;
    causationId: string | null;
    payloadDigest: string;
  }>(
    `select event_id::text as "eventId",event_type as "eventType",business_sequence::text as sequence,
     correlation_id::text as "correlationId",causation_id::text as "causationId",'sha256:'||encode(payload_digest,'hex') as "payloadDigest"
     from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and receipt_id=$3
      and proof_kind='BUSINESS_RECEIPT_REFERENCE' and payload_digest=sha256(payload_cbor) order by business_sequence limit 17`,
    [record.participantId, record.privacyDomainId, receipt.receiptId],
  );
  const outboxReferences = receipt.outboxEvents.map((event) => ({
    eventId: event.eventId,
    eventType: event.eventType,
    sequence: String(event.aggregateSequence),
    correlationId: event.correlationId,
    causationId: event.causationId ?? null,
    payloadDigest: hash(event.payloadDigest),
  }));
  if (sha256(events.rows) !== sha256(outboxReferences)) throw fail();
  const state = (value: typeof receipt.before) => ({
    existence: value.existence,
    revision: String(value.revision),
    stateDigest: hash(value.stateDigest),
  });
  return {
    ...historicalOnly,
    integrity: 'VERIFIED_PROFILE_COSE',
    meaning: 'COMMITTED_BUSINESS_TRANSITION',
    providerEffect: 'NOT_ESTABLISHED',
    currentObjectState: 'NOT_QUERIED',
    receiptId: receipt.receiptId,
    operationId: `urn:openpc:operation:${receipt.operationId}`,
    idempotencyRecordId: receipt.idempotencyRecordId,
    profileId: receipt.transitionProfileId,
    profileVersion: String(receipt.transitionProfileVersion),
    profileDigest: hash(receipt.transitionProfileDigest),
    actionIntentId: receipt.actionIntentId,
    catalogOperationId: receipt.catalogOperationId,
    aggregateType: receipt.aggregateType,
    aggregateId: receipt.aggregateId,
    candidateDigest: hash(receipt.candidateDigest),
    requestDigest: hash(receipt.requestDigest),
    actorKeyDigest: hash(receipt.actorKeyDigest),
    authorityDigest: hash(receipt.preCommitAuthorityDigest),
    signerId: receipt.signerId,
    signerTrustDigest: hash(receipt.signerTrustSnapshotDigest),
    payloadDigest: hash(row.payloadDigest),
    recordedAt,
    before: state(receipt.before),
    after: state(receipt.after),
    authorizationReferences: receipt.authorizationEvidence.map((value) => ({
      kind: value.kind,
      evidenceId: value.evidenceId,
      evidenceDigest: hash(value.evidenceDigest),
    })),
    outboxReferences,
  };
}

export async function readRejectionProvenance(
  client: PoolClient,
  record: ProvenanceSource,
): Promise<NonNullable<EvidenceProvenance['rejection']>> {
  const identity = /^deployment:([0-9a-f-]{36}):1$/u.exec(record.recordId);
  if (!identity) throw fail();
  const command = z.uuidv7().parse(identity[1]);
  const source = await readVerifiedDeploymentRejection(
    client,
    command,
    record.participantId,
    record.privacyDomainId,
  );
  if (!source) throw fail();
  const result = source.result;
  if (
    `sha256:${result.resultDigest}` !== record.recordDigest ||
    effectOccurrenceTime(result.observedAt) !== record.occurredAt ||
    result.sequence !== '1' ||
    result.status.state !== 'REJECTED' ||
    result.status.truthState !== 'DENIED' ||
    result.outcome.attempt !== null ||
    result.outcome.occurrence !== null ||
    result.outcome.invalidation !== null
  )
    throw fail();
  return {
    ...historicalOnly,
    integrity: 'VERIFIED_PURPOSE_SIGNATURE',
    meaning: 'TERMINAL_PRE_HANDOFF_REJECTION',
    sourceVersion: '1',
    operationId: result.status.operationId,
    attemptId: result.attemptId,
    observedAt: result.observedAt,
    state: 'REJECTED',
    truthState: 'DENIED',
    transactionHash: result.status.signedTransactionHash,
    candidateDigest: source.candidateDigest,
    authorizationEvidenceDigest: source.authorizationEvidenceDigest,
    execution: 'NO_HANDOFF',
  };
}
